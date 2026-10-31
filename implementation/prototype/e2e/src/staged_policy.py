#!/usr/bin/env python3
"""Compile per-router S2-ROV policy for the staged-deployment prototype.

The compiler consumes only Routinator's validated HTTP output and routes
actually present in a router's pre-policy Adj-RIB-In.  It emits one inbound
route map per upstream peer and matches both prefix and origin AS, allowing
valid and invalid paths for the same prefix to be handled independently.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from s2rov_agent import COMMUNITY, LOCAL_PREFERENCE, load_json
from s2rov_policy_dualstack import Policy


def origin_from_path(value: Any) -> int | None:
    if isinstance(value, dict):
        value = value.get("string", value.get("segments", ""))
    tokens = [
        int(token)
        for token in re.findall(r"(?<!\d)\d+(?!\d)", str(value))
    ]
    return tokens[-1] if tokens else None


def received_records(document: dict[str, Any], peer: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    received = document.get("receivedRoutes")
    if isinstance(received, dict):
        for prefix, payload in received.items():
            origin = origin_from_path(payload.get("path", ""))
            if origin is not None:
                records.append({"prefix": str(prefix), "origin": origin, "peer": peer})
        return records

    routes = document.get("routes", document)
    if not isinstance(routes, dict):
        return records
    for prefix, payload in routes.items():
        if "/" not in str(prefix):
            continue
        paths = payload if isinstance(payload, list) else payload.get("paths", [])
        if isinstance(paths, dict):
            paths = [paths]
        for path in paths:
            origin = origin_from_path(path.get("aspath", path.get("path", "")))
            if origin is not None:
                records.append({"prefix": str(prefix), "origin": origin, "peer": peer})
    return records


def evaluate_received(
    policy: Policy,
    received: list[dict[str, Any]],
    cases: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    case_index = {
        (str(case["prefix"]), int(case["origin"])): case for case in cases
    }
    results = []
    seen: set[tuple[str, int, str]] = set()
    for route in received:
        key = (route["prefix"], int(route["origin"]), route["peer"])
        if key in seen:
            continue
        seen.add(key)
        state, stripe = policy.validate(route["prefix"], int(route["origin"]))
        case = case_index.get((route["prefix"], int(route["origin"])))
        expected = case.get("expected_da") if case else None
        results.append(
            {
                "name": case.get("name") if case else None,
                "prefix": route["prefix"],
                "origin": int(route["origin"]),
                "peer": route["peer"],
                "state": state,
                "expected_state": expected,
                "pass": expected is None or state == expected,
                "evidence_prefix": str(stripe.network) if stripe else None,
                "evidence_open_scope": stripe.is_open if stripe else None,
                "evidence_origins": sorted(stripe.origins) if stripe else [],
                "action": "reject" if state == "Invalid" else "retain",
                "local_preference": LOCAL_PREFERENCE.get(state),
            }
        )
    return sorted(
        results,
        key=lambda item: (item["peer"], item["prefix"], item["origin"]),
    )


def safe_id(peer: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "-", peer).strip("-")


def policy_commands(
    results: list[dict[str, Any]],
    router_asn: int,
    managed_peers: Iterable[str] | None = None,
    address_family: str = "ipv4",
) -> str:
    if address_family == "ipv4":
        version = 4
        prefix_command = "ip"
        match_command = "ip address"
        frr_family = "ipv4 unicast"
    elif address_family == "ipv6":
        version = 6
        prefix_command = "ipv6"
        match_command = "ipv6 address"
        frr_family = "ipv6 unicast"
    else:
        raise ValueError(f"unsupported address family: {address_family!r}")

    for result in results:
        network = ipaddress.ip_network(str(result["prefix"]), strict=False)
        if network.version != version:
            raise ValueError(
                f"{result['prefix']} does not belong to {address_family}"
            )

    by_peer: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for peer in managed_peers or ():
        by_peer[str(peer)]
    for result in results:
        by_peer[result["peer"]].append(result)

    lines = ["configure terminal"]
    for peer, peer_results in sorted(by_peer.items()):
        peer_id = safe_id(peer)
        route_map = f"STG-IN-{peer_id}"
        lines.append(f"no route-map {route_map}")
        for index, result in enumerate(peer_results, start=1):
            prefix_list = f"STG-P-{peer_id}-{index}"
            as_path_list = f"STG-A-{peer_id}-{index}"
            lines.extend(
                [
                    f"no {prefix_command} prefix-list {prefix_list}",
                    f"no bgp as-path access-list {as_path_list}",
                    (
                        f"{prefix_command} prefix-list {prefix_list} seq 5 "
                        f"permit {result['prefix']}"
                    ),
                    (
                        f"bgp as-path access-list {as_path_list} "
                        f"permit _{result['origin']}$"
                    ),
                ]
            )
            sequence = index * 10
            if result["state"] == "Invalid":
                lines.extend(
                    [
                        f"route-map {route_map} deny {sequence}",
                        f" match {match_command} prefix-list {prefix_list}",
                        f" match as-path {as_path_list}",
                    ]
                )
            else:
                lines.extend(
                    [
                        f"route-map {route_map} permit {sequence}",
                        f" match {match_command} prefix-list {prefix_list}",
                        f" match as-path {as_path_list}",
                        f" set local-preference {LOCAL_PREFERENCE[result['state']]}",
                        f" set community {COMMUNITY[result['state']]}",
                    ]
                )
        lines.extend(
            [
                f"route-map {route_map} deny 9990",
                f"router bgp {router_asn}",
                f" address-family {frr_family}",
                f"  neighbor {peer} route-map {route_map} in",
                " exit-address-family",
                "exit",
            ]
        )
    lines.append("end")
    return "\n".join(lines) + "\n"


def parse_received(values: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for value in values:
        peer, separator, path = value.partition("=")
        if not separator or not peer or not path:
            raise ValueError(f"expected PEER=PATH, got {value!r}")
        records.extend(received_records(load_json(path), peer))
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vrps", required=True)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--received", action="append", required=True)
    parser.add_argument("--router-asn", type=int, required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--policy-output")
    parser.add_argument(
        "--address-family", choices=("ipv4", "ipv6"), default="ipv4"
    )
    parser.add_argument("--fail-on-mismatch", action="store_true")
    args = parser.parse_args()

    policy = Policy.from_routinator(load_json(args.vrps))
    cases = load_json(args.cases)
    received = parse_received(args.received)
    results = evaluate_received(policy, received, cases)
    Path(args.output).write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if args.policy_output:
        Path(args.policy_output).write_text(
            policy_commands(
                results,
                args.router_asn,
                (value.partition("=")[0] for value in args.received),
                args.address_family,
            ),
            encoding="utf-8",
        )
    return int(args.fail_on_mismatch and not all(item["pass"] for item in results))


if __name__ == "__main__":
    raise SystemExit(main())
