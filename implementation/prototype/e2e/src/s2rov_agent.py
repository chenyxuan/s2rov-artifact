#!/usr/bin/env python3
"""S2-ROV shadow validator and FRR policy compiler.

Routinator remains the cryptographic relying party.  This program consumes
only Routinator's validated JSON payload set, preserves authorization
provenance as four states, and compiles those decisions into per-neighbor FRR
route maps.  It deliberately does not label Delegated as RPKI Valid.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import statistics
import sys
import time
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


STATES = ("Explicit", "Delegated", "Invalid", "NotFound")
LOCAL_PREFERENCE = {
    "Explicit": 300,
    "Delegated": 200,
    "NotFound": 100,
}
COMMUNITY = {
    "Explicit": "65000:10",
    "Delegated": "65000:20",
    "NotFound": "65000:40",
}


def eligible_delegated_origin(asn: int) -> bool:
    """Apply the same conservative public-origin gate as the reference model."""
    if asn <= 0 or asn > 0xFFFFFFFF or asn == 23456:
        return False
    if 64496 <= asn <= 65535:
        return False
    if 65536 <= asn <= 65551:
        return False
    if 65552 <= asn <= 131071:
        return False
    if 4200000000 <= asn <= 4294967295:
        return False
    return True


def parse_asn(value: Any) -> int:
    text = str(value)
    if text.upper().startswith("AS"):
        text = text[2:]
    return int(text)


def load_json(source: str | Path) -> Any:
    source_text = str(source)
    if source_text.startswith(("http://", "https://")):
        with urllib.request.urlopen(source_text, timeout=10) as response:
            return json.load(response)
    with Path(source_text).open(encoding="utf-8") as handle:
        return json.load(handle)


@dataclass(frozen=True)
class Stripe:
    network: ipaddress.IPv4Network
    min_length: int
    max_length: int
    origins: frozenset[int]
    is_open: bool
    trust_anchors: frozenset[str]

    def covers(self, route: ipaddress.IPv4Network) -> bool:
        """Return prefix coverage independently of the permitted length range."""
        return route.subnet_of(self.network)


class Policy:
    def __init__(self, stripes: Iterable[Stripe]):
        self.stripes = tuple(
            sorted(
                stripes,
                key=lambda item: (
                    -item.network.prefixlen,
                    int(item.network.network_address),
                    item.is_open,
                ),
            )
        )
        by_prefix: dict[ipaddress.IPv4Network, list[Stripe]] = defaultdict(list)
        for stripe in self.stripes:
            by_prefix[stripe.network].append(stripe)
        self._by_prefix = {
            prefix: tuple(entries) for prefix, entries in by_prefix.items()
        }
        markers = [stripe for stripe in self.stripes if stripe.is_open]
        for marker in markers:
            if (
                marker.min_length != marker.network.prefixlen
                or marker.max_length <= marker.network.prefixlen
            ):
                raise ValueError(
                    "OpenScope marker requires minLength equal to its prefix "
                    "length and maxLength greater than its prefix length: "
                    f"{marker.network}: {marker.min_length}-{marker.max_length}"
                )
        for index, marker in enumerate(markers):
            for other in markers[index + 1 :]:
                if (
                    marker.network.version == other.network.version
                    and marker.network.overlaps(other.network)
                ):
                    raise ValueError(
                        "OpenScope markers must be pairwise prefix-disjoint: "
                        f"{marker.network} and {other.network}"
                    )

    @classmethod
    def from_routinator(cls, document: dict[str, Any]) -> "Policy":
        grouped: dict[
            tuple[str, int, int, bool], dict[str, set[Any]]
        ] = defaultdict(lambda: {"origins": set(), "tas": set()})

        for roa in document.get("roas", []):
            network = ipaddress.ip_network(roa["prefix"], strict=False)
            if network.version != 4:
                continue
            mode = roa.get("inclusivity")
            if mode not in (None, "inclusive", "exclusive"):
                raise ValueError(f"unknown inclusivity value: {mode!r}")
            is_open = mode == "inclusive"
            key = (
                str(network),
                int(roa.get("minLength", network.prefixlen)),
                int(roa.get("maxLength", network.prefixlen)),
                is_open,
            )
            grouped[key]["origins"].add(parse_asn(roa["asn"]))
            grouped[key]["tas"].add(str(roa.get("ta", "unknown")))

        stripes = []
        for (prefix, min_len, max_len, is_open), values in grouped.items():
            network = ipaddress.ip_network(prefix)
            if not (
                network.prefixlen <= min_len <= max_len <= network.max_prefixlen
            ):
                raise ValueError(
                    f"invalid length interval {prefix}: {min_len}-{max_len}"
                )
            stripes.append(
                Stripe(
                    network=network,
                    min_length=min_len,
                    max_length=max_len,
                    origins=frozenset(values["origins"]),
                    is_open=is_open,
                    trust_anchors=frozenset(str(v) for v in values["tas"]),
                )
            )
        return cls(stripes)

    def _covering(self, prefix: str) -> tuple[ipaddress.IPv4Network, list[Stripe]]:
        route = ipaddress.ip_network(prefix, strict=False)
        if route.version != 4:
            return route, []
        covering = []
        for length in range(route.prefixlen, -1, -1):
            candidate_prefix = route.supernet(new_prefix=length)
            covering.extend(self._by_prefix.get(candidate_prefix, ()))
        return route, covering

    @staticmethod
    def _best_evidence(entries: Iterable[Stripe]) -> Stripe:
        """Choose deterministic evidence, not a rule controlling the state."""
        return max(
            entries,
            key=lambda item: (
                item.network.prefixlen,
                not item.is_open,
                item.min_length,
                item.max_length,
            ),
        )

    def validate(self, prefix: str, origin: int) -> tuple[str, Stripe | None]:
        route, covering = self._covering(prefix)
        if not covering:
            return "NotFound", None

        explicit = [
            stripe
            for stripe in covering
            if stripe.min_length <= route.prefixlen <= stripe.max_length
            and origin in stripe.origins
        ]
        if explicit:
            return "Explicit", self._best_evidence(explicit)

        if eligible_delegated_origin(origin):
            markers = [
                stripe
                for stripe in covering
                if stripe.is_open
                and stripe.min_length <= route.prefixlen <= stripe.max_length
                and route.prefixlen > stripe.network.prefixlen
            ]
            if markers:
                if len(markers) != 1:
                    raise ValueError(f"multiple OpenScope markers cover {route}")
                return "Delegated", markers[0]
        return "Invalid", None

    def validate_baseline(
        self, prefix: str, origin: int
    ) -> tuple[str, Stripe | None]:
        """Evaluate RFC 6811 covering and matching sets.

        A ROA whose maxLength is too short still *covers* a more-specific
        route and therefore makes it Invalid rather than NotFound.
        """
        route = ipaddress.ip_network(prefix, strict=False)
        covering = [
            stripe for stripe in self.stripes if route.subnet_of(stripe.network)
        ]
        if not covering:
            return "NotFound", None
        matching = [
            stripe
            for stripe in covering
            if (
                stripe.min_length <= route.prefixlen <= stripe.max_length
                and origin in stripe.origins
            )
        ]
        if matching:
            return "Valid", max(
                matching, key=lambda item: item.network.prefixlen
            )
        return "Invalid", max(
            covering, key=lambda item: item.network.prefixlen
        )


def evaluate_cases(
    policy: Policy, cases: list[dict[str, Any]], mode: str = "da"
) -> list[dict[str, Any]]:
    results = []
    for case in cases:
        expected_key = "expected_da"
        if mode == "baseline":
            state, stripe = policy.validate_baseline(
                case["prefix"], int(case["origin"])
            )
            expected_key = "expected_baseline"
        else:
            state, stripe = policy.validate(case["prefix"], int(case["origin"]))
        result = dict(case)
        result.update(
            {
                "state": state,
                "pass": state == case.get(expected_key, state),
                "evidence_prefix": str(stripe.network) if stripe else None,
                "evidence_open_scope": stripe.is_open if stripe else None,
                "evidence_origins": sorted(stripe.origins) if stripe else [],
                "evidence_trust_anchors": (
                    sorted(stripe.trust_anchors) if stripe else []
                ),
            }
        )
        results.append(result)
    return results


def extract_frr_paths(document: dict[str, Any]) -> set[tuple[str, int, str | None]]:
    """Extract (prefix, origin, peer) tuples from common FRR JSON layouts."""
    routes = document.get("routes", document)
    found: set[tuple[str, int, str | None]] = set()
    if not isinstance(routes, dict):
        return found

    for prefix, payload in routes.items():
        if "/" not in str(prefix):
            continue
        paths = payload if isinstance(payload, list) else payload.get("paths", [])
        if isinstance(paths, dict):
            paths = [paths]
        for path in paths:
            aspath = path.get("path", path.get("aspath", ""))
            if isinstance(aspath, dict):
                aspath = aspath.get("string", aspath.get("segments", ""))
            tokens = [
                int(token)
                for token in str(aspath).replace("{", " ").replace("}", " ").split()
                if token.isdigit()
            ]
            if not tokens:
                continue
            peer = path.get("peerId") or path.get("peer")
            if isinstance(peer, dict):
                peer = peer.get("peerId") or peer.get("hostname")
            found.add((str(prefix), tokens[-1], str(peer) if peer else None))
    return found


def extract_frr_records(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract selected path attributes used by the enforcement assertions."""
    routes = document.get("routes", document)
    records = []
    if not isinstance(routes, dict):
        return records
    for prefix, payload in routes.items():
        if "/" not in str(prefix):
            continue
        paths = payload if isinstance(payload, list) else payload.get("paths", [])
        if isinstance(paths, dict):
            paths = [paths]
        for path in paths:
            aspath = path.get("path", path.get("aspath", ""))
            if isinstance(aspath, dict):
                aspath = aspath.get("string", aspath.get("segments", ""))
            tokens = [
                int(token)
                for token in str(aspath).replace("{", " ").replace("}", " ").split()
                if token.isdigit()
            ]
            if not tokens:
                continue
            peer = path.get("peerId") or path.get("peer")
            if isinstance(peer, dict):
                peer = peer.get("peerId") or peer.get("hostname")
            records.append(
                {
                    "prefix": str(prefix),
                    "origin": tokens[-1],
                    "peer": str(peer) if peer else None,
                    "local_preference": path.get(
                        "locPrf", path.get("localPreference")
                    ),
                }
            )
    return records


def check_observed(
    cases: list[dict[str, Any]], document: dict[str, Any]
) -> list[dict[str, Any]]:
    paths = extract_frr_paths(document)
    results = []
    for case in cases:
        prefix = case["prefix"]
        origin = int(case["origin"])
        peer = case["peer"]
        exact = (prefix, origin, peer) in paths
        loose = any(pfx == prefix and asn == origin for pfx, asn, _ in paths)
        results.append(
            {
                "name": case["name"],
                "prefix": prefix,
                "origin": origin,
                "peer": peer,
                "observed": exact or loose,
                "peer_exact": exact,
            }
        )
    return results


def check_enforced(
    decisions: list[dict[str, Any]], document: dict[str, Any]
) -> list[dict[str, Any]]:
    records = extract_frr_records(document)
    expected_preferences = dict(LOCAL_PREFERENCE)
    expected_preferences["Valid"] = LOCAL_PREFERENCE["Explicit"]
    results = []
    for decision in decisions:
        prefix = decision["prefix"]
        origin = int(decision["origin"])
        matches = [
            item
            for item in records
            if item["prefix"] == prefix and item["origin"] == origin
        ]
        present = bool(matches)
        expected_present = decision["state"] != "Invalid"
        expected_preference = (
            expected_preferences[decision["state"]] if expected_present else None
        )
        observed_preferences = sorted(
            {
                item["local_preference"]
                for item in matches
                if item["local_preference"] is not None
            }
        )
        preference_ok = (
            not expected_present or expected_preference in observed_preferences
        )
        results.append(
            {
                "name": decision["name"],
                "prefix": prefix,
                "origin": origin,
                "state": decision["state"],
                "expected_present": expected_present,
                "present": present,
                "expected_local_preference": expected_preference,
                "observed_local_preferences": observed_preferences,
                "pass": present == expected_present and preference_ok,
            }
        )
    return results


def safe_policy_id(value: str) -> str:
    """Return an FRR identifier component for a peer address or name."""
    return re.sub(r"[^A-Za-z0-9]", "-", value).strip("-")


def _results_by_peer(
    results: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Group and canonicalize route decisions, rejecting contradictions."""
    unique: dict[tuple[str, str, int], dict[str, Any]] = {}
    for result in results:
        key = (
            str(result["peer"]),
            str(result["prefix"]),
            int(result["origin"]),
        )
        previous = unique.get(key)
        if previous is not None and previous["state"] != result["state"]:
            raise ValueError(f"conflicting decisions for route {key!r}")
        unique[key] = result

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in unique.values():
        grouped[str(result["peer"])].append(result)
    for peer_results in grouped.values():
        peer_results.sort(
            key=lambda item: (str(item["prefix"]), int(item["origin"]))
        )
    return dict(sorted(grouped.items()))


def policy_commands(
    results: list[dict[str, Any]],
    previous_results: list[dict[str, Any]] | None = None,
    router_asn: int = 65000,
) -> str:
    """Compile one origin-specific inbound route map per neighbor.

    A route map is the unit FRR attaches to a neighbor, so compiling one map
    per route causes later routes from the same neighbor to overwrite earlier
    ones. Stable per-neighbor maps also let a recompilation replace every
    clause before it is reattached. ``previous_results`` is optional for
    compatibility, but when supplied it additionally removes maps and match
    objects for peers/routes that disappeared from the new decision set.
    """
    current = _results_by_peer(results)
    previous = _results_by_peer(previous_results or [])
    lines = ["configure terminal"]

    # Clear every current map and every match object that may have been
    # generated by the previous compilation before rebuilding its clauses.
    for peer in sorted(set(current) | set(previous)):
        peer_id = safe_policy_id(peer)
        route_map = f"DA-IN-{peer_id}"
        lines.append(f"no route-map {route_map}")
        prior_count = len(previous.get(peer, ()))
        current_count = len(current.get(peer, ()))
        for index in range(1, max(prior_count, current_count) + 1):
            lines.extend(
                [
                    f"no ip prefix-list DA-P-{peer_id}-{index}",
                    f"no bgp as-path access-list DA-A-{peer_id}-{index}",
                ]
            )

    for peer, peer_results in current.items():
        peer_id = safe_policy_id(peer)
        route_map = f"DA-IN-{peer_id}"
        for index, result in enumerate(peer_results, start=1):
            prefix_list = f"DA-P-{peer_id}-{index}"
            as_path_list = f"DA-A-{peer_id}-{index}"
            state = str(result["state"])
            action_state = "Explicit" if state == "Valid" else state
            lines.extend(
                [
                    f"ip prefix-list {prefix_list} seq 5 permit {result['prefix']}",
                    (
                        f"bgp as-path access-list {as_path_list} "
                        f"permit _{int(result['origin'])}$"
                    ),
                ]
            )
            sequence = index * 10
            if state == "Invalid":
                lines.extend(
                    [
                        f"route-map {route_map} deny {sequence}",
                        f" match ip address prefix-list {prefix_list}",
                        f" match as-path {as_path_list}",
                    ]
                )
            else:
                lines.extend(
                    [
                        f"route-map {route_map} permit {sequence}",
                        f" match ip address prefix-list {prefix_list}",
                        f" match as-path {as_path_list}",
                        f" set local-preference {LOCAL_PREFERENCE[action_state]}",
                        f" set community {COMMUNITY[action_state]}",
                    ]
                )
        lines.append(f"route-map {route_map} deny 9990")

    # Bind each current peer once. A peer removed since the previous compile
    # is returned to the conventional RPKI map before its stale DA map is
    # deleted below.
    lines.extend(
        [
            f"router bgp {router_asn}",
            " address-family ipv4 unicast",
        ]
    )
    legacy_results = previous_results if previous_results is not None else results
    for index, result in enumerate(legacy_results, start=1):
        lines.append(
            f"  no neighbor {result['peer']} route-map DA-IN-{index} in"
        )
    for peer in current:
        route_map = f"DA-IN-{safe_policy_id(peer)}"
        lines.extend(
            [
                f"  no neighbor {peer} route-map RPKI-IN in",
                f"  neighbor {peer} route-map {route_map} in",
            ]
        )
    for peer in sorted(set(previous) - set(current)):
        route_map = f"DA-IN-{safe_policy_id(peer)}"
        lines.extend(
            [
                f"  no neighbor {peer} route-map {route_map} in",
                f"  neighbor {peer} route-map RPKI-IN in",
            ]
        )
    lines.extend([" exit-address-family", "exit"])

    # Remove objects emitted by the old per-route compiler after all peers
    # have moved to stable maps. With no previous manifest, the current
    # result count is the best migration inventory and covers existing runs.
    for index, _result in enumerate(legacy_results, start=1):
        lines.extend(
            [
                f"no route-map DA-IN-{index}",
                f"no ip prefix-list DA-P-{index}",
            ]
        )

    for peer in sorted(set(previous) - set(current)):
        lines.append(f"no route-map DA-IN-{safe_policy_id(peer)}")
    lines.append("end")
    return "\n".join(lines) + "\n"


def benchmark(
    policy: Policy, cases: list[dict[str, Any]], repetitions: int
) -> dict[str, Any]:
    samples = []
    checksum = 0
    for _ in range(7):
        start = time.perf_counter_ns()
        for _ in range(repetitions):
            for case in cases:
                state, _ = policy.validate(case["prefix"], int(case["origin"]))
                checksum += STATES.index(state)
        elapsed = time.perf_counter_ns() - start
        samples.append(elapsed / (repetitions * len(cases)))
    return {
        "queries_per_sample": repetitions * len(cases),
        "samples": len(samples),
        "median_ns_per_query": round(statistics.median(samples)),
        "min_ns_per_query": round(min(samples)),
        "max_ns_per_query": round(max(samples)),
        "checksum": checksum,
    }


def dump_json(value: Any, output: str | None) -> None:
    text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("--vrps", required=True)
    evaluate.add_argument("--cases", required=True)
    evaluate.add_argument("--output")
    evaluate.add_argument("--policy-output")
    evaluate.add_argument("--previous-decisions")
    evaluate.add_argument("--mode", choices=("baseline", "da"), default="da")
    evaluate.add_argument("--fail-on-mismatch", action="store_true")

    observed = subparsers.add_parser("check-observed")
    observed.add_argument("--routes", required=True)
    observed.add_argument("--cases", required=True)
    observed.add_argument("--output")
    observed.add_argument("--fail-on-missing", action="store_true")

    enforced = subparsers.add_parser("check-enforced")
    enforced.add_argument("--routes", required=True)
    enforced.add_argument("--decisions", required=True)
    enforced.add_argument("--output")
    enforced.add_argument("--fail-on-mismatch", action="store_true")

    bench = subparsers.add_parser("benchmark")
    bench.add_argument("--vrps", required=True)
    bench.add_argument("--cases", required=True)
    bench.add_argument("--repetitions", type=int, default=20_000)
    bench.add_argument("--output")

    args = parser.parse_args()
    if args.command == "check-enforced":
        results = check_enforced(
            load_json(args.decisions), load_json(args.routes)
        )
        dump_json(results, args.output)
        return int(
            args.fail_on_mismatch and not all(item["pass"] for item in results)
        )

    if args.command == "check-observed":
        cases = load_json(args.cases)
        results = check_observed(cases, load_json(args.routes))
        dump_json(results, args.output)
        return int(args.fail_on_missing and not all(item["observed"] for item in results))

    cases = load_json(args.cases)
    policy = Policy.from_routinator(load_json(args.vrps))
    if args.command == "evaluate":
        results = evaluate_cases(policy, cases, mode=args.mode)
        dump_json(results, args.output)
        if args.policy_output:
            previous_results = (
                load_json(args.previous_decisions)
                if args.previous_decisions
                else None
            )
            Path(args.policy_output).write_text(
                policy_commands(results, previous_results), encoding="utf-8"
            )
        return int(args.fail_on_mismatch and not all(item["pass"] for item in results))

    dump_json(benchmark(policy, cases, args.repetitions), args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
