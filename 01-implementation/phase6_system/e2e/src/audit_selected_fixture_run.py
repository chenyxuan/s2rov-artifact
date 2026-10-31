#!/usr/bin/env python3
"""Independently audit the selected 124-snapshot system fixture run.

The auditor consumes Routinator payloads and raw FRR RIB captures directly.
It deliberately neither imports nor calls the production evaluator.  For each
of 124 snapshots, it recomputes seven route states, derives the corresponding
accept/reject and local-preference action, and cross-checks the stored decision
and enforcement artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


STATE_ACTION = {
    "Valid": ("accept", 300),
    "Explicit": ("accept", 300),
    "Delegated": ("accept", 200),
    "NotFound": ("accept", 100),
    "Invalid": ("reject", None),
}
EXPECTED_TRIALS = tuple(f"trial-{index:02d}" for index in range(1, 31))
SCHEMA_VERSION = "q2-aggregate-audit/v1"


class AuditError(RuntimeError):
    """Raised when an input is missing, malformed, or fails an audit check."""


@dataclass(frozen=True)
class PolicyEntry:
    """One independently parsed authorization group."""

    network: Any
    min_length: int
    max_length: int
    origins: frozenset[int]
    is_open: bool
    trust_anchors: frozenset[str]


@dataclass(frozen=True)
class Classification:
    """An independently computed state and its supporting policy evidence."""

    state: str
    evidence: PolicyEntry | None


@dataclass(frozen=True)
class Snapshot:
    """The four evidence artifacts needed to audit one installed policy."""

    name: str
    category: str
    mode: str
    oracle_profile: str
    policy: Path
    decisions: Path
    rib: Path
    enforcement: Path


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditError(message)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError(f"cannot read JSON artifact {path}: {exc}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise AuditError(f"cannot hash artifact {path}: {exc}") from exc
    return digest.hexdigest()


def _relative(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError as exc:
        raise AuditError(f"artifact is outside repository: {path}") from exc


def _parse_asn(value: Any) -> int:
    text = str(value).strip()
    if text.upper().startswith("AS"):
        text = text[2:]
    try:
        return int(text)
    except ValueError as exc:
        raise AuditError(f"invalid ASN value: {value!r}") from exc


def eligible_delegated_origin(asn: int) -> bool:
    """Return whether an ASN passes the independent public-origin gate."""

    if asn <= 0 or asn > 0xFFFFFFFF or asn == 23456:
        return False
    if 64496 <= asn <= 65535:
        return False
    if 65536 <= asn <= 131071:
        return False
    if 4200000000 <= asn <= 4294967295:
        return False
    return True


def parse_policy(document: dict[str, Any]) -> tuple[PolicyEntry, ...]:
    """Parse and group a Routinator JSON payload without evaluator code."""

    roas = document.get("roas", [])
    _require(isinstance(roas, list), "Routinator payload field 'roas' is not a list")
    grouped: dict[tuple[str, int, int, bool], dict[str, set[Any]]] = defaultdict(
        lambda: {"origins": set(), "trust_anchors": set()}
    )
    networks: dict[str, Any] = {}
    for raw in roas:
        _require(isinstance(raw, dict), "Routinator payload contains a non-object ROA")
        try:
            network = ipaddress.ip_network(str(raw["prefix"]), strict=False)
        except (KeyError, ValueError) as exc:
            raise AuditError(f"invalid Routinator prefix entry: {raw!r}") from exc
        mode = raw.get("inclusivity")
        _require(
            mode in (None, "inclusive", "exclusive"),
            f"unknown inclusivity value {mode!r} for {network}",
        )
        min_length = int(raw.get("minLength", network.prefixlen))
        max_length = int(raw.get("maxLength", network.prefixlen))
        _require(
            network.prefixlen <= min_length <= max_length <= network.max_prefixlen,
            f"invalid prefix-length interval {network}: {min_length}-{max_length}",
        )
        if mode == "inclusive":
            _require(
                min_length == network.prefixlen
                and max_length > network.prefixlen,
                "OpenScope marker requires minLength equal to its prefix "
                "length and maxLength greater than its prefix length: "
                f"{network}: {min_length}-{max_length}",
            )
        canonical = str(network)
        key = (canonical, min_length, max_length, mode == "inclusive")
        networks[canonical] = network
        grouped[key]["origins"].add(_parse_asn(raw["asn"]))
        grouped[key]["trust_anchors"].add(str(raw.get("ta", "unknown")))

    entries = []
    for (prefix, min_length, max_length, is_open), values in grouped.items():
        entries.append(
            PolicyEntry(
                network=networks[prefix],
                min_length=min_length,
                max_length=max_length,
                origins=frozenset(int(value) for value in values["origins"]),
                is_open=is_open,
                trust_anchors=frozenset(
                    str(value) for value in values["trust_anchors"]
                ),
            )
        )
    result = tuple(
        sorted(
            entries,
            key=lambda entry: (
                -entry.network.prefixlen,
                entry.network.version,
                int(entry.network.network_address),
                entry.is_open,
                entry.min_length,
                entry.max_length,
            ),
        )
    )
    markers = [entry for entry in result if entry.is_open]
    for index, marker in enumerate(markers):
        for other in markers[index + 1 :]:
            _require(
                marker.network.version != other.network.version
                or not marker.network.overlaps(other.network),
                "OpenScope markers must be pairwise prefix-disjoint: "
                f"{marker.network} and {other.network}",
            )
    return result


def _covers(entry: PolicyEntry, route: Any) -> bool:
    return entry.network.version == route.version and route.subnet_of(entry.network)


def _best_evidence(entries: Iterable[PolicyEntry]) -> PolicyEntry:
    """Choose deterministic evidence without giving it policy precedence."""

    return max(
        entries,
        key=lambda entry: (
            entry.network.prefixlen,
            not entry.is_open,
            entry.min_length,
            entry.max_length,
        ),
    )


def classify_da(entries: Iterable[PolicyEntry], prefix: str, origin: int) -> Classification:
    """Classify using explicit matches first, then one OpenScope marker."""

    route = ipaddress.ip_network(prefix, strict=False)
    covering = [entry for entry in entries if _covers(entry, route)]
    if not covering:
        return Classification("NotFound", None)

    explicit = [
        entry
        for entry in covering
        if entry.min_length <= route.prefixlen <= entry.max_length
        and origin in entry.origins
    ]
    if explicit:
        return Classification("Explicit", _best_evidence(explicit))

    if eligible_delegated_origin(origin):
        markers = [
            entry
            for entry in covering
            if entry.is_open
            and entry.min_length <= route.prefixlen <= entry.max_length
            and route.prefixlen > entry.network.prefixlen
        ]
        if markers:
            _require(
                len(markers) == 1,
                f"multiple OpenScope markers cover {route}",
            )
            return Classification("Delegated", markers[0])
    return Classification("Invalid", None)


def classify_baseline(
    entries: Iterable[PolicyEntry], prefix: str, origin: int
) -> Classification:
    """Independently apply RFC 6811 covering and matching-set semantics."""

    route = ipaddress.ip_network(prefix, strict=False)
    covering = [entry for entry in entries if _covers(entry, route)]
    if not covering:
        return Classification("NotFound", None)
    matching = [
        entry
        for entry in covering
        if entry.min_length <= route.prefixlen <= entry.max_length
        and origin in entry.origins
    ]
    evidence = max(
        matching or covering,
        key=lambda entry: entry.network.prefixlen,
    )
    return Classification("Valid" if matching else "Invalid", evidence)


def classify(
    entries: Iterable[PolicyEntry], mode: str, prefix: str, origin: int
) -> Classification:
    if mode == "baseline":
        return classify_baseline(entries, prefix, origin)
    _require(mode == "da", f"unknown classification mode: {mode}")
    return classify_da(entries, prefix, origin)


def _as_path_text(path: dict[str, Any]) -> str:
    value = path.get("path", path.get("aspath", ""))
    if isinstance(value, dict):
        if value.get("string") is not None:
            return str(value["string"])
        segments = value.get("segments", [])
        flattened = []
        if isinstance(segments, list):
            for segment in segments:
                if isinstance(segment, dict) and isinstance(segment.get("list"), list):
                    flattened.extend(str(item) for item in segment["list"])
        return " ".join(flattened)
    return str(value)


def extract_rib_records(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract route, origin, peer, and preference from common FRR JSON."""

    routes = document.get("routes", document)
    _require(isinstance(routes, dict), "FRR RIB does not contain a route mapping")
    default_preference = int(document.get("defaultLocPrf", 100))
    records = []
    for raw_prefix, payload in routes.items():
        if "/" not in str(raw_prefix):
            continue
        try:
            prefix = str(ipaddress.ip_network(str(raw_prefix), strict=False))
        except ValueError as exc:
            raise AuditError(f"invalid FRR route prefix: {raw_prefix!r}") from exc
        if isinstance(payload, list):
            paths = payload
        elif isinstance(payload, dict):
            paths = payload.get("paths", [])
            if isinstance(paths, dict):
                paths = [paths]
        else:
            raise AuditError(f"invalid FRR path payload for {prefix}")
        _require(isinstance(paths, list), f"FRR paths for {prefix} are not a list")
        for path in paths:
            _require(isinstance(path, dict), f"FRR path for {prefix} is not an object")
            tokens = re.findall(r"(?<!\d)\d+(?!\d)", _as_path_text(path))
            if not tokens:
                continue
            peer: Any = path.get("peerId", path.get("peer"))
            if isinstance(peer, dict):
                peer = peer.get("peerId", peer.get("hostname"))
            preference = path.get(
                "locPrf", path.get("localPreference", default_preference)
            )
            records.append(
                {
                    "prefix": prefix,
                    "origin": int(tokens[-1]),
                    "peer": str(peer) if peer is not None else None,
                    "local_preference": int(preference),
                }
            )
    return records


def _index_named_records(records: Any, label: str) -> dict[str, dict[str, Any]]:
    _require(isinstance(records, list), f"{label} is not a list")
    indexed: dict[str, dict[str, Any]] = {}
    for record in records:
        _require(isinstance(record, dict), f"{label} contains a non-object")
        name = str(record.get("name", ""))
        _require(name, f"{label} contains an unnamed record")
        _require(name not in indexed, f"{label} contains duplicate case {name}")
        indexed[name] = record
    return indexed


def _expected_state(case: dict[str, Any], profile: str) -> str:
    if profile == "baseline":
        return str(case["expected_baseline"])
    if profile == "da":
        return str(case["expected_da"])
    _require(profile == "remove", f"unknown oracle profile: {profile}")
    if case["name"] == "listed_customer":
        return "Delegated"
    return str(case["expected_da"])


def _entry_summary(entry: PolicyEntry | None) -> dict[str, Any] | None:
    if entry is None:
        return None
    return {
        "prefix": str(entry.network),
        "min_length": entry.min_length,
        "max_length": entry.max_length,
        "origins": sorted(entry.origins),
        "open_scope_marker": entry.is_open,
        "trust_anchors": sorted(entry.trust_anchors),
    }


def _artifact_ref(path: Path, repo_root: Path) -> dict[str, str]:
    return {"path": _relative(path, repo_root), "sha256": _sha256(path)}


def _assert_trial_inventory(root: Path) -> None:
    expected = set(EXPECTED_TRIALS)
    for directory in (
        root / "updates",
        root / "failures" / "routinator-restart",
        root / "failures" / "frr-restart",
    ):
        actual = {path.name for path in directory.glob("trial-*") if path.is_dir()}
        _require(
            actual == expected,
            f"unexpected trial inventory under {directory}: "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}",
        )


def snapshot_inventory(run_dir: Path) -> list[Snapshot]:
    """Build the complete, fixed inventory of 124 audited snapshots."""

    _assert_trial_inventory(run_dir)
    baseline = run_dir / "baseline"
    da = run_dir / "da"
    outage = run_dir / "failures" / "routinator-outage"
    snapshots = [
        Snapshot(
            "baseline",
            "baseline",
            "baseline",
            "baseline",
            baseline / "routinator-vrps.json",
            baseline / "decisions.json",
            baseline / "bgp-rib.json",
            baseline / "enforcement.json",
        ),
        Snapshot(
            "initial_da",
            "initial_da",
            "da",
            "da",
            da / "routinator-vrps.json",
            da / "decisions.json",
            da / "final" / "bgp-rib.json",
            da / "enforcement.json",
        ),
        Snapshot(
            "routinator_outage_during",
            "routinator_outage",
            "da",
            "da",
            da / "routinator-vrps.json",
            da / "decisions.json",
            outage / "during.json",
            outage / "enforcement.json",
        ),
        Snapshot(
            "routinator_outage_recovered",
            "routinator_outage",
            "da",
            "da",
            outage / "routinator-vrps.json",
            outage / "recovered" / "decisions.json",
            outage / "recovered" / "bgp-rib.json",
            outage / "recovered" / "enforcement.json",
        ),
    ]
    for trial in EXPECTED_TRIALS:
        root = run_dir / "failures" / "routinator-restart" / trial
        snapshots.append(
            Snapshot(
                f"routinator_restart_{trial[-2:]}",
                "routinator_restart",
                "da",
                "da",
                root / "routinator-vrps.json",
                root / "recovered" / "decisions.json",
                root / "recovered" / "bgp-rib.json",
                root / "recovered" / "enforcement.json",
            )
        )
    for trial in EXPECTED_TRIALS:
        for phase, profile in (("remove", "remove"), ("restore", "da")):
            root = run_dir / "updates" / trial / phase
            snapshots.append(
                Snapshot(
                    f"closed_override_{phase}_{trial[-2:]}",
                    f"closed_override_{phase}",
                    "da",
                    profile,
                    root / "routinator-vrps.json",
                    root / "decisions.json",
                    root / "bgp-rib.json",
                    root / "enforcement.json",
                )
            )
    restored_policy = run_dir / "updates" / "restored-vrps.json"
    for trial in EXPECTED_TRIALS:
        root = run_dir / "failures" / "frr-restart" / trial / "recovered"
        snapshots.append(
            Snapshot(
                f"frr_restart_{trial[-2:]}",
                "frr_restart",
                "da",
                "da",
                restored_policy,
                root / "decisions.json",
                root / "bgp-rib.json",
                root / "enforcement.json",
            )
        )
    _require(len(snapshots) == 124, f"expected 124 snapshots, found {len(snapshots)}")
    _require(
        len({snapshot.name for snapshot in snapshots}) == 124,
        "snapshot names are not unique",
    )
    for snapshot in snapshots:
        for path in (
            snapshot.policy,
            snapshot.decisions,
            snapshot.rib,
            snapshot.enforcement,
        ):
            _require(path.is_file(), f"missing snapshot artifact: {path}")
    return snapshots


def _verify_source_manifest(
    run_dir: Path, e2e_root: Path, repo_root: Path
) -> dict[str, Any]:
    manifest = run_dir / "source.sha256"
    entries = []
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise AuditError(f"cannot read source manifest {manifest}: {exc}") from exc
    for line in lines:
        if not line.strip():
            continue
        fields = line.split(maxsplit=1)
        _require(len(fields) == 2, f"malformed source manifest line: {line!r}")
        expected, raw_path = fields
        source = e2e_root / raw_path.strip()
        actual = _sha256(source)
        entries.append(
            {
                "path": _relative(source, repo_root),
                "expected_sha256": expected,
                "actual_sha256": actual,
                "match": actual == expected,
            }
        )
    _require(entries, "source manifest is empty")
    _require(
        all(entry["match"] for entry in entries),
        "one or more accepted source-manifest hashes do not match",
    )
    return {
        "path": _relative(manifest, repo_root),
        "sha256": _sha256(manifest),
        "entry_count": len(entries),
        "all_entries_match": True,
        "entries": entries,
    }


def _canonical_inventory(
    roles_by_path: dict[Path, set[str]], repo_root: Path
) -> dict[str, Any]:
    entries = []
    for path, roles in sorted(
        roles_by_path.items(), key=lambda item: _relative(item[0], repo_root)
    ):
        entries.append(
            {
                "path": _relative(path, repo_root),
                "sha256": _sha256(path),
                "roles": sorted(roles),
            }
        )
    lines = "".join(
        f"{entry['sha256']}  {entry['path']}\n" for entry in entries
    )
    unique_by_role = Counter()
    for entry in entries:
        unique_by_role.update(entry["roles"])
    return {
        "canonicalization": "sorted '<sha256>  <repo-relative-path>\\n' lines",
        "canonical_sha256": hashlib.sha256(lines.encode("utf-8")).hexdigest(),
        "unique_file_count": len(entries),
        "unique_files_by_role": dict(sorted(unique_by_role.items())),
        "entries": entries,
    }


def _audit_snapshot(
    snapshot: Snapshot,
    cases: list[dict[str, Any]],
    repo_root: Path,
) -> tuple[dict[str, Any], list[str], list[dict[str, str]]]:
    policy = parse_policy(_read_json(snapshot.policy))
    decisions = _index_named_records(
        _read_json(snapshot.decisions), f"{snapshot.name} decisions"
    )
    enforcement = _index_named_records(
        _read_json(snapshot.enforcement), f"{snapshot.name} enforcement"
    )
    rib_records = extract_rib_records(_read_json(snapshot.rib))
    case_names = {str(case["name"]) for case in cases}
    _require(set(decisions) == case_names, f"{snapshot.name}: decision case set differs")
    _require(
        set(enforcement) == case_names,
        f"{snapshot.name}: enforcement case set differs",
    )

    errors: list[str] = []
    state_counts = Counter()
    action_counts = Counter()
    legacy_false = []
    computed_states = {}
    computed_actions = {}
    observed_rib_actions = {}
    audit_rows = []
    for case in cases:
        name = str(case["name"])
        prefix = str(ipaddress.ip_network(str(case["prefix"]), strict=False))
        origin = int(case["origin"])
        peer = str(case["peer"])
        result = classify(policy, snapshot.mode, prefix, origin)
        oracle_state = _expected_state(case, snapshot.oracle_profile)
        disposition, expected_preference = STATE_ACTION[result.state]
        expected_present = disposition == "accept"
        loose_matches = [
            record
            for record in rib_records
            if record["prefix"] == prefix and record["origin"] == origin
        ]
        exact_matches = [
            record for record in loose_matches if record["peer"] == peer
        ]
        observed_preferences = sorted(
            {record["local_preference"] for record in loose_matches}
        )
        peer_preferences = sorted(
            {record["local_preference"] for record in exact_matches}
        )
        present = bool(loose_matches)
        peer_exact = bool(exact_matches)
        action_matches = (
            not present
            if not expected_present
            else peer_exact and expected_preference in peer_preferences
        )

        decision = decisions[name]
        stored_enforcement = enforcement[name]
        evidence = _entry_summary(result.evidence)
        decision_identity = (
            str(decision.get("prefix")) == prefix
            and int(decision.get("origin")) == origin
            and str(decision.get("peer")) == peer
        )
        decision_metadata_matches = (
            decision.get("evidence_prefix")
            == (evidence["prefix"] if evidence is not None else None)
            and decision.get("evidence_open_scope")
            == (
                evidence["open_scope_marker"]
                if evidence is not None
                else None
            )
            and sorted(
                int(value) for value in decision.get("evidence_origins", [])
            )
            == (evidence["origins"] if evidence is not None else [])
        )
        decision_matches = (
            decision_identity
            and str(decision.get("state")) == result.state
            and decision_metadata_matches
        )

        stored_observed_preferences = sorted(
            int(value)
            for value in stored_enforcement.get("observed_local_preferences", [])
        )
        enforcement_matches = (
            str(stored_enforcement.get("prefix")) == prefix
            and int(stored_enforcement.get("origin")) == origin
            and str(stored_enforcement.get("state")) == result.state
            and stored_enforcement.get("expected_present") is expected_present
            and stored_enforcement.get("present") is present
            and stored_enforcement.get("expected_local_preference")
            == expected_preference
            and stored_observed_preferences == observed_preferences
            and stored_enforcement.get("pass") is True
        )
        legacy_key = "expected_baseline" if snapshot.mode == "baseline" else "expected_da"
        expected_legacy_flag = result.state == str(decision.get(legacy_key))
        legacy_flag_consistent = decision.get("pass") is expected_legacy_flag
        if decision.get("pass") is False:
            legacy_false.append(name)

        checks = {
            "state_matches_case_oracle": result.state == oracle_state,
            "raw_rib_matches_state_action": action_matches,
            "stored_decision_matches_recomputation": decision_matches,
            "stored_enforcement_matches_recomputation": enforcement_matches,
            "legacy_decision_pass_flag_is_internally_consistent": (
                legacy_flag_consistent
            ),
        }
        for check, passed in checks.items():
            if not passed:
                errors.append(f"{snapshot.name}/{name}: {check}")
        state_counts[result.state] += 1
        action_key = (
            "reject"
            if disposition == "reject"
            else f"accept_lp_{expected_preference}"
        )
        action_counts[action_key] += 1
        computed_states[name] = result.state
        computed_actions[name] = action_key
        if not present:
            observed_rib_actions[name] = "absent"
        elif len(observed_preferences) == 1:
            observed_rib_actions[name] = f"present_lp_{observed_preferences[0]}"
        else:
            joined = ",".join(str(value) for value in observed_preferences)
            observed_rib_actions[name] = f"present_lp_[{joined}]"
        audit_rows.append(
            {"name": name, "state": result.state, "action": action_key}
        )

    if snapshot.oracle_profile == "remove":
        _require(
            legacy_false == ["listed_customer"],
            f"{snapshot.name}: unexpected legacy pass=false records {legacy_false}",
        )
    else:
        _require(
            not legacy_false,
            f"{snapshot.name}: unexpected legacy pass=false records {legacy_false}",
        )
    return (
        {
            "name": snapshot.name,
            "category": snapshot.category,
            "classification_mode": snapshot.mode,
            "oracle_profile": snapshot.oracle_profile,
            "inputs": {
                "policy": _relative(snapshot.policy, repo_root),
                "decisions": _relative(snapshot.decisions, repo_root),
                "raw_rib": _relative(snapshot.rib, repo_root),
                "enforcement": _relative(snapshot.enforcement, repo_root),
            },
            "state_counts": dict(sorted(state_counts.items())),
            "action_counts": dict(sorted(action_counts.items())),
            "computed_states": computed_states,
            "computed_actions": computed_actions,
            "observed_rib_actions": observed_rib_actions,
            "legacy_pass_false_cases": legacy_false,
            "checks": {
                "states_match_oracle": not any(
                    error.endswith("state_matches_case_oracle") for error in errors
                ),
                "raw_rib_actions_match": not any(
                    error.endswith("raw_rib_matches_state_action") for error in errors
                ),
                "stored_decisions_match": not any(
                    error.endswith("stored_decision_matches_recomputation")
                    for error in errors
                ),
                "stored_enforcement_matches": not any(
                    error.endswith("stored_enforcement_matches_recomputation")
                    for error in errors
                ),
                "legacy_pass_flags_internally_consistent": not any(
                    error.endswith(
                        "legacy_decision_pass_flag_is_internally_consistent"
                    )
                    for error in errors
                ),
            },
            "passed": not errors,
        },
        errors,
        audit_rows,
    )


def _current_unbound_files(repo_root: Path, e2e_root: Path) -> list[dict[str, Any]]:
    candidates = (
        e2e_root / "scripts" / "build-images.sh",
        e2e_root / "scripts" / "krill-entrypoint.sh",
        e2e_root / "scripts" / "routinator-entrypoint.sh",
        repo_root / "phase6_system" / "dockerfiles" / "stripe-roa-system.zip",
    )
    records = []
    for path in candidates:
        record: dict[str, Any] = {
            "path": _relative(path, repo_root),
            "accepted_manifest_bound": False,
            "interpretation": "current-checkout identity only; not attributable to the run",
        }
        if path.is_file():
            record["current_sha256"] = _sha256(path)
        else:
            record["current_sha256"] = None
            record["current_file_present"] = False
        records.append(record)
    return records


def audit_run(run_dir: Path) -> dict[str, Any]:
    """Audit the fixture and return a deterministic JSON-serializable report."""

    run_dir = run_dir.resolve()
    _require(run_dir.is_dir(), f"run directory does not exist: {run_dir}")
    e2e_root = run_dir.parents[1]
    repo_root = e2e_root.parents[1]
    cases_path = e2e_root / "config" / "cases.json"
    raw_cases = _read_json(cases_path)
    cases_by_name = _index_named_records(raw_cases, "case configuration")
    cases = [cases_by_name[str(record["name"])] for record in raw_cases]
    _require(len(cases) == 7, f"expected seven configured cases, found {len(cases)}")
    snapshots = snapshot_inventory(run_dir)
    source_manifest = _verify_source_manifest(run_dir, e2e_root, repo_root)

    roles_by_path: dict[Path, set[str]] = defaultdict(set)
    roles_by_path[cases_path].add("case_configuration")
    snapshot_reports = []
    all_errors: list[str] = []
    state_counts = Counter()
    action_counts = Counter()
    category_counts = Counter()
    case_state_counts: dict[str, Counter[str]] = defaultdict(Counter)
    case_action_counts: dict[str, Counter[str]] = defaultdict(Counter)
    legacy_false_count = 0
    for snapshot in snapshots:
        for role, path in (
            ("validated_policy_payload", snapshot.policy),
            ("stored_decisions", snapshot.decisions),
            ("raw_frr_rib", snapshot.rib),
            ("stored_enforcement", snapshot.enforcement),
        ):
            roles_by_path[path].add(role)
        report, errors, audit_rows = _audit_snapshot(snapshot, cases, repo_root)
        snapshot_reports.append(report)
        all_errors.extend(errors)
        category_counts[snapshot.category] += 1
        state_counts.update(report["state_counts"])
        action_counts.update(report["action_counts"])
        legacy_false_count += len(report["legacy_pass_false_cases"])
        for row in audit_rows:
            case_state_counts[row["name"]][row["state"]] += 1
            case_action_counts[row["name"]][row["action"]] += 1

    _require(not all_errors, "audit mismatches:\n" + "\n".join(all_errors[:25]))
    evaluation_count = len(snapshots) * len(cases)
    _require(evaluation_count == 868, f"expected 868 evaluations, found {evaluation_count}")
    _require(sum(state_counts.values()) == 868, "state counts do not sum to 868")
    _require(sum(action_counts.values()) == 868, "action counts do not sum to 868")

    summary_path = run_dir / "summary.json"
    environment_path = run_dir / "environment.txt"
    auditor_path = Path(__file__).resolve()
    per_case = []
    for case in cases:
        name = str(case["name"])
        per_case.append(
            {
                "name": name,
                "state_counts": dict(sorted(case_state_counts[name].items())),
                "action_counts": dict(sorted(case_action_counts[name].items())),
                "evaluation_count": sum(case_state_counts[name].values()),
            }
        )
    report = {
        "schema_version": SCHEMA_VERSION,
        "run_identity": {
            "run_id": run_dir.name,
            "run_directory": _relative(run_dir, repo_root),
            "derived_summary": {
                **_artifact_ref(summary_path, repo_root),
                "used_as_audit_evidence": False,
            },
            "environment_capture": _artifact_ref(environment_path, repo_root),
            "accepted_source_manifest": source_manifest,
        },
        "implementation": {
            "auditor": _artifact_ref(auditor_path, repo_root),
            "production_evaluator_imports": [],
            "method": (
                "independent standard-library parser and classifier over validated "
                "Routinator JSON plus independent FRR RIB action extraction"
            ),
            "self_checks_run": True,
        },
        "verification": {
            "status": "VERIFIED_OUTCOME_AGGREGATE",
            "passed": True,
            "snapshot_count": len(snapshots),
            "configured_case_count": len(cases),
            "evaluation_count": evaluation_count,
            "category_counts": dict(sorted(category_counts.items())),
            "state_counts": dict(sorted(state_counts.items())),
            "action_counts": dict(sorted(action_counts.items())),
            "per_case": per_case,
            "legacy_decision_pass_false_count": legacy_false_count,
            "legacy_pass_false_interpretation": (
                "Thirty removal snapshots retain the static expected_da label "
                "for listed_customer; their recomputed Delegated state is the "
                "intended removal oracle and their stored enforcement passes."
            ),
            "checks": {
                "all_124_snapshots_present": True,
                "all_868_states_match_case_oracles": True,
                "all_868_raw_rib_actions_match_recomputed_states": True,
                "all_868_stored_decisions_match_recomputed_states": True,
                "all_868_stored_enforcement_records_match_recomputation": True,
                "all_868_stored_enforcement_pass_flags_true": True,
                "accepted_source_manifest_entries_match_current_checkout": True,
            },
            "snapshots": snapshot_reports,
        },
        "evidence_inventory": _canonical_inventory(roles_by_path, repo_root),
        "provenance": {
            "status": "PARTIAL",
            "known_gaps": [
                {
                    "gap": "validated payloads are present, but raw RPKI signed objects and trust-chain artifacts are absent",
                    "impact": "this audit does not repeat cryptographic validation upstream of Routinator JSON",
                },
                {
                    "gap": "the accepted source manifest omits image-build and container-entrypoint inputs",
                    "impact": "the exact container construction cannot be bound to this run from the accepted manifest alone",
                },
                {
                    "gap": "container image digests are absent",
                    "impact": "reported software versions do not identify immutable runtime images",
                },
            ],
            "unbound_current_files": _current_unbound_files(repo_root, e2e_root),
        },
    }
    return report


def run_self_checks() -> None:
    """Exercise classifier and RIB parser invariants without fixture files."""

    baseline = parse_policy(
        {
            "roas": [
                {
                    "asn": "AS64501",
                    "prefix": "10.0.0.0/16",
                    "minLength": 16,
                    "maxLength": 24,
                    "inclusivity": None,
                    "ta": "test",
                }
            ]
        }
    )
    _require(classify_baseline(baseline, "10.0.0.0/16", 64501).state == "Valid", "self-check: baseline valid")
    _require(classify_baseline(baseline, "10.0.1.0/24", 8075).state == "Invalid", "self-check: baseline invalid")
    _require(classify_baseline(baseline, "192.0.2.0/24", 64496).state == "NotFound", "self-check: baseline not found")
    delegated = parse_policy(
        {
            "roas": [
                {
                    "asn": "AS8075",
                    "prefix": "10.0.1.0/24",
                    "minLength": 24,
                    "maxLength": 24,
                    "inclusivity": None,
                    "ta": "test",
                },
                {
                    "asn": "AS64501",
                    "prefix": "10.0.0.0/16",
                    "minLength": 16,
                    "maxLength": 24,
                    "inclusivity": "inclusive",
                    "ta": "test",
                },
            ]
        }
    )
    _require(classify_da(delegated, "10.0.1.0/24", 8075).state == "Explicit", "self-check: exact match")
    _require(classify_da(delegated, "10.0.1.0/24", 64501).state == "Explicit", "self-check: covering explicit match")
    _require(classify_da(delegated, "10.0.1.0/24", 18403).state == "Delegated", "self-check: exact entry does not shadow marker")
    _require(classify_da(delegated, "10.0.2.0/24", 18403).state == "Delegated", "self-check: delegated public origin")
    _require(classify_da(delegated, "10.0.0.0/16", 13335).state == "Invalid", "self-check: aggregate self-protection")
    _require(classify_da(delegated, "10.0.4.0/24", 64513).state == "Invalid", "self-check: private origin gate")
    records = extract_rib_records(
        {
            "defaultLocPrf": 100,
            "routes": {
                "10.0.2.0/24": [
                    {
                        "path": "65010 18403",
                        "peerId": "172.31.0.13",
                        "locPrf": 200,
                    }
                ],
                "192.0.2.0/24": [
                    {"path": "64496", "peerId": "172.31.0.17"}
                ],
            },
        }
    )
    _require(
        records
        == [
            {
                "prefix": "10.0.2.0/24",
                "origin": 18403,
                "peer": "172.31.0.13",
                "local_preference": 200,
            },
            {
                "prefix": "192.0.2.0/24",
                "origin": 64496,
                "peer": "172.31.0.17",
                "local_preference": 100,
            },
        ],
        "self-check: FRR parser",
    )


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        temporary.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise AuditError(f"cannot write audit artifact {path}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    e2e_root = Path(__file__).resolve().parents[1]
    default_run = e2e_root / "outputs" / "run-20260823T024129Z"
    default_output = (
        e2e_root
        / "audits"
        / "run-20260823T024129Z"
        / "q2_aggregate_audit.json"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, default=default_run)
    parser.add_argument("--output", type=Path, default=default_output)
    parser.add_argument("--self-check-only", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        run_self_checks()
        if arguments.self_check_only:
            print("self-checks passed")
            return 0
        report = audit_run(arguments.run_dir)
        _write_json_atomic(arguments.output, report)
    except AuditError as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"verified {report['verification']['evaluation_count']} route decisions "
        f"across {report['verification']['snapshot_count']} snapshots"
    )
    print(f"wrote {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
