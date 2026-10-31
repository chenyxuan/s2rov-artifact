#!/usr/bin/env python3
"""Assert and summarize the real staged-deployment prototype observations."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from pathlib import Path
from typing import Any

from daroa_agent import extract_frr_records
from staged_policy import received_records


TRANSITS = ("t1", "t2", "t3")


def nearest_rank(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("nearest_rank requires at least one observation")
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def route_set(path: Path) -> set[tuple[str, int]]:
    document = load_json(path)
    return {
        (item["prefix"], int(item["origin"]))
        for item in extract_frr_records(document)
    }


def received_set(directory: Path) -> set[tuple[str, int]]:
    routes: set[tuple[str, int]] = set()
    for path in sorted(directory.glob("*.json")):
        peer = path.stem.replace("_", ".")
        for item in received_records(load_json(path), peer):
            routes.add((item["prefix"], int(item["origin"])))
    return routes


def forwarding_state(case: dict[str, Any], capability: str) -> str:
    if capability == "D":
        return str(case["expected_da"])
    return str(case["expected_baseline"])


def expected_sets(
    cases: list[dict[str, Any]], pattern: str
) -> tuple[dict[str, set[tuple[str, int]]], dict[str, set[tuple[str, int]]]]:
    all_routes = {(case["prefix"], int(case["origin"])) for case in cases}
    post: dict[str, set[tuple[str, int]]] = {}
    received: dict[str, set[tuple[str, int]]] = {"t1": set(all_routes)}
    upstream = set(all_routes)
    for node, capability in zip(TRANSITS, pattern):
        accepted = {
            (case["prefix"], int(case["origin"]))
            for case in cases
            if (case["prefix"], int(case["origin"])) in upstream
            and forwarding_state(case, capability) != "Invalid"
        }
        post[node] = accepted
        upstream = accepted
        if node != "t3":
            received[TRANSITS[TRANSITS.index(node) + 1]] = set(accepted)
    post["sink"] = set(upstream)
    received["sink"] = set(upstream)
    return post, received


def check_legacy_view(stage_dir: Path) -> list[dict[str, Any]]:
    expected = {
        ("10.0.0.0", 16, 16, 64501),
        ("10.0.1.0", 24, 24, 8075),
    }
    checks = []
    for node in TRANSITS:
        cache = load_json(stage_dir / node / "rpki-cache.json")
        connected = any(
            item.get("state") == "connected"
            for item in cache.get("connections", [])
        )
        checks.append(
            {
                "check": "legacy_rtr_connected",
                "node": node,
                "expected": True,
                "actual": connected,
                "pass": connected,
            }
        )

        table = load_json(stage_dir / node / "rpki-prefix-table.json")
        actual = {
            (
                str(item.get("prefix")),
                int(item.get("prefixLenMin")),
                int(item.get("prefixLenMax")),
                int(item.get("asn")),
            )
            for item in table.get("prefixes", [])
        }
        checks.append(
            {
                "check": "conservative_fallback_exact",
                "node": node,
                "expected": sorted(expected),
                "actual": sorted(actual),
                "pass": actual == expected,
            }
        )
    return checks


def check_decisions(
    stage_dir: Path,
    pattern: str,
    expected_received: dict[str, set[tuple[str, int]]],
) -> list[dict[str, Any]]:
    checks = []
    for node, capability in zip(TRANSITS, pattern):
        path = stage_dir / node / "decisions.json"
        if capability not in {"S", "D"}:
            continue
        exists = path.exists()
        checks.append(
            {
                "check": "da_decisions_recorded",
                "node": node,
                "expected": True,
                "actual": exists,
                "pass": exists,
            }
        )
        if not exists:
            continue
        decisions = load_json(path)
        actual_routes = {
            (item["prefix"], int(item["origin"])) for item in decisions
        }
        state_ok = all(item.get("pass") is True for item in decisions)
        checks.extend(
            [
                {
                    "check": "decision_input_matches_adj_rib_in",
                    "node": node,
                    "expected": sorted(expected_received[node]),
                    "actual": sorted(actual_routes),
                    "pass": actual_routes == expected_received[node],
                },
                {
                    "check": "four_state_decisions",
                    "node": node,
                    "expected": True,
                    "actual": state_ok,
                    "pass": state_ok,
                },
            ]
        )
    return checks


def check_stage(stage_dir: Path) -> dict[str, Any]:
    metadata = load_json(stage_dir / "stage.json")
    cases = load_json(Path(metadata["cases_file"]))
    pattern = str(metadata["pattern"])
    expected_post, expected_received = expected_sets(cases, pattern)
    checks = check_legacy_view(stage_dir)

    for node in (*TRANSITS, "sink"):
        actual_post = route_set(stage_dir / node / "bgp-rib.json")
        actual_received = received_set(stage_dir / node / "received")
        checks.extend(
            [
                {
                    "check": "post_policy_routes",
                    "node": node,
                    "expected": sorted(expected_post[node]),
                    "actual": sorted(actual_post),
                    "pass": actual_post == expected_post[node],
                },
                {
                    "check": "adj_rib_in_routes",
                    "node": node,
                    "expected": sorted(expected_received[node]),
                    "actual": sorted(actual_received),
                    "pass": actual_received == expected_received[node],
                },
            ]
        )

    checks.extend(check_decisions(stage_dir, pattern, expected_received))
    sink_routes = route_set(stage_dir / "sink" / "bgp-rib.json")
    if ("10.0.2.0/24", 18403) in sink_routes:
        sink_outcome = "correct_delegate"
    elif ("10.0.0.0/16", 64501) in sink_routes:
        sink_outcome = "covering_aggregate"
    else:
        sink_outcome = "no_route"

    result = {
        **metadata,
        "sink_outcome": sink_outcome,
        "checks": checks,
        "check_count": len(checks),
        "passed": all(item["pass"] for item in checks),
    }
    (stage_dir / "checks.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def write_report(run_dir: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Staged-deployment prototype report",
        "",
        f"- Passed: `{str(summary['passed']).lower()}`",
        f"- Stages checked: {summary['stage_count']}",
        f"- Assertions checked: {summary['assertion_count']}",
        f"- Upgrade/rollback cycles: {summary['transition_cycles']}",
        f"- Capability transitions: {summary['transition_observations']}",
        f"- Complete transition matrix: `{str(summary['transition_matrix_complete']).lower()}`",
        "",
        "| Stage | Publication | Pattern | Sink outcome | Passed |",
        "|---|---|---:|---|:---:|",
    ]
    for stage in summary["stages"]:
        lines.append(
            "| {label} | {publication} | `{pattern}` | {sink_outcome} | {passed} |".format(
                label=stage["label"],
                publication=stage["publication"],
                pattern=stage["pattern"],
                sink_outcome=stage["sink_outcome"],
                passed="yes" if stage["passed"] else "no",
            )
        )
    lines.extend(
        [
            "",
            "| Transition | Observations | Median (ms) | p95 (ms) |",
            "|---|---:|---:|---:|",
        ]
    )
    for transition in ("rollback", "upgrade"):
        timing = summary["transition_timing_ms"].get(transition)
        if timing:
            lines.append(
                f"| {transition} | {timing['count']} | "
                f"{timing['median']:.3f} | {timing['p95']} |"
            )
    lines.extend(
        [
            "",
            "`Delegated` denotes holder-authorized open scope, not authentication of",
            "the observed public origin. The arbitrary eligible-origin control is",
            "therefore expected to follow the same staged reachability boundary as",
            "the intended delegated route.",
            "",
        ]
    )
    (run_dir / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")


def summarize_run(run_dir: Path, output: Path) -> dict[str, Any]:
    stages = [check_stage(path.parent) for path in sorted((run_dir / "stages").glob("*/stage.json"))]
    environment = (run_dir / "environment.txt").read_text(encoding="utf-8")
    expected_cycles = next(
        int(line.split("=", 1)[1])
        for line in environment.splitlines()
        if line.startswith("transition_trials=")
    )
    transition_path = run_dir / "transition-trials.csv"
    transition_rows = []
    if transition_path.exists():
        with transition_path.open(encoding="utf-8", newline="") as handle:
            transition_rows = list(csv.DictReader(handle))
    transitions_pass = all(row.get("passed") == "true" for row in transition_rows)
    transition_cycles = len({row.get("trial") for row in transition_rows})
    transition_timing: dict[str, dict[str, int | float]] = {}
    for transition in ("rollback", "upgrade"):
        values = [
            int(row["milliseconds"])
            for row in transition_rows
            if row.get("transition") == transition
        ]
        if values:
            transition_timing[transition] = {
                "count": len(values),
                "minimum": min(values),
                "median": statistics.median(values),
                "p95": nearest_rank(values, 0.95),
                "maximum": max(values),
            }
    transition_matrix_complete = (
        transition_cycles == expected_cycles
        and len(transition_rows) == expected_cycles * 2
        and all(
            transition_timing.get(name, {}).get("count") == expected_cycles
            for name in ("rollback", "upgrade")
        )
    )
    summary = {
        "passed": bool(stages)
        and all(stage["passed"] for stage in stages)
        and transitions_pass
        and transition_matrix_complete,
        "stage_count": len(stages),
        "assertion_count": sum(stage["check_count"] for stage in stages),
        "expected_transition_cycles": expected_cycles,
        "transition_cycles": transition_cycles,
        "transition_observations": len(transition_rows),
        "transition_observations_passed": sum(
            row.get("passed") == "true" for row in transition_rows
        ),
        "transition_matrix_complete": transition_matrix_complete,
        "transition_timing_ms": transition_timing,
        "stages": [
            {
                "label": stage["label"],
                "publication": stage["publication"],
                "pattern": stage["pattern"],
                "sink_outcome": stage["sink_outcome"],
                "passed": stage["passed"],
                "elapsed_ms": stage.get("elapsed_ms"),
            }
            for stage in stages
        ],
    }
    output.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_report(run_dir, summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--stage-dir", type=Path)
    group.add_argument("--run-dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if args.stage_dir:
        result = check_stage(args.stage_dir)
    else:
        output = args.output or args.run_dir / "summary.json"
        result = summarize_run(args.run_dir, output)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
