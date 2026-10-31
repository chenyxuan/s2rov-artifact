#!/usr/bin/env python3
"""Independent raw-to-summary audit for the controlled policy benchmark."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Sequence


SCRIPT = Path(__file__).resolve()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def percentile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower] * (1 - weight) + ordered[upper] * weight)


def close(left: float, right: float) -> bool:
    return math.isclose(left, right, rel_tol=1e-12, abs_tol=1e-12)


def audit(run_dir: Path) -> dict[str, Any]:
    config = json.loads((run_dir / "run_config.json").read_text(encoding="utf-8"))
    schedule = json.loads((run_dir / "schedule.json").read_text(encoding="utf-8"))
    selection = json.loads(
        (run_dir / "selection_manifest.json").read_text(encoding="utf-8")
    )
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    records = []
    missing = []
    for condition in schedule:
        path = Path(condition["raw_json"])
        if not path.exists():
            missing.append(str(path))
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        records.append(record)

    expected_cells = {
        (worker, ip_version, subprefixes)
        for worker in ("load", "classify")
        for ip_version in (4, 6)
        for subprefixes in config["subprefix_counts"]
    }
    observed_cells = {
        (
            record["worker"],
            int(record["ip_version"]),
            int(record["subprefix_entries"]),
        )
        for record in records
    }
    grouped: dict[tuple[str, int, int], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[
            (
                record["worker"],
                int(record["ip_version"]),
                int(record["subprefix_entries"]),
            )
        ].append(record)

    expected_repetitions = {
        "load": int(config["load_repetitions"]),
        "classify": int(config["classify_repetitions"]),
    }
    repetition_counts_match = all(
        len(grouped[cell]) == expected_repetitions[cell[0]] for cell in expected_cells
    )
    cpu_match = all(record["cpu_affinity"] == config["cpu"] for record in records)
    schedule_identity_match = all(
        int(record["schedule_index"]) == int(condition["schedule_index"])
        and record["worker"] == condition["worker"]
        and int(record["ip_version"]) == int(condition["ip_version"])
        and int(record["subprefix_entries"])
        == int(condition["subprefix_entries"])
        and int(record["repetition"]) == int(condition["repetition"])
        for record, condition in zip(records, schedule)
    ) if not missing else False

    policy_hashes_match = True
    for record in records:
        policy_path = run_dir / "policies" / (
            f"ipv{record['ip_version']}-subprefixes-"
            f"{record['subprefix_entries']}.bin"
        )
        if (
            not policy_path.exists()
            or sha256_file(policy_path) != record["serialized_sha256"]
            or policy_path.stat().st_size != int(record["serialized_bytes"])
        ):
            policy_hashes_match = False

    query_hashes_match = True
    for ip_version in (4, 6):
        query_path = run_dir / "queries" / f"ipv{ip_version}-queries.json"
        family_records = [
            record
            for record in records
            if record["worker"] == "classify"
            and int(record["ip_version"]) == ip_version
        ]
        expected_hash = sha256_file(query_path)
        if any(record["query_file_sha256"] != expected_hash for record in family_records):
            query_hashes_match = False

    all_open_scope = all(
        record.get("all_results_open_scope") is True
        and record.get("state_counts")
        == {"Delegated": int(config["timed_calls_per_classify_worker"])}
        for record in records
        if record["worker"] == "classify"
    )
    all_roundtrips = all(record["roundtrip_identical"] for record in records)

    family_fixed_results = {}
    for ip_version in (4, 6):
        family_records = [
            record
            for record in records
            if record["worker"] == "classify"
            and int(record["ip_version"]) == ip_version
        ]
        values = {
            "query_file": {record["query_file_sha256"] for record in family_records},
            "query_content": {
                record["query_content_sha256"] for record in family_records
            },
            "result": {record["result_checksum_sha256"] for record in family_records},
            "state": {
                json.dumps(record["state_counts"], sort_keys=True)
                for record in family_records
            },
        }
        family_fixed_results[str(ip_version)] = {
            "one_query_file": len(values["query_file"]) == 1,
            "one_query_content": len(values["query_content"]) == 1,
            "one_result_checksum": len(values["result"]) == 1,
            "one_state_vector": len(values["state"]) == 1,
        }

    summary_checks = []
    recomputed_rows = []
    for reported in summary["rows"]:
        ip_version = int(reported["ip_version"])
        subprefixes = int(reported["subprefix_entries"])
        load = grouped[("load", ip_version, subprefixes)]
        classify = grouped[("classify", ip_version, subprefixes)]
        load_ms = [float(record["load_ns"]) / 1e6 for record in load]
        classify_kpps = [
            float(record["pairs_per_second"]) / 1000 for record in classify
        ]
        batch_ms = [
            float(batch["elapsed_ns"]) / 1e6
            for record in classify
            for batch in record["batches"]
        ]
        recomputed = {
            "ip_version": ip_version,
            "subprefix_entries": subprefixes,
            "load_ms_mean": statistics.fmean(load_ms),
            "load_ms_median": statistics.median(load_ms),
            "load_ms_q1": percentile(load_ms, 0.25),
            "load_ms_q3": percentile(load_ms, 0.75),
            "classify_kpairs_s_mean": statistics.fmean(classify_kpps),
            "classify_kpairs_s_median": statistics.median(classify_kpps),
            "classify_kpairs_s_min": min(classify_kpps),
            "classify_kpairs_s_max": max(classify_kpps),
            "batch_ms_p50": percentile(batch_ms, 0.50),
            "batch_ms_p95": percentile(batch_ms, 0.95),
            "batch_ms_p99": percentile(batch_ms, 0.99),
        }
        fields = [key for key in recomputed if key not in {"ip_version", "subprefix_entries"}]
        matches = all(close(float(recomputed[key]), float(reported[key])) for key in fields)
        summary_checks.append(
            {
                "ip_version": ip_version,
                "subprefix_entries": subprefixes,
                "matches": matches,
            }
        )
        recomputed_rows.append(recomputed)

    input_hashes_match = True
    for ip_version in (4, 6):
        family = selection["families"][str(ip_version)]
        workload_path = Path(family["workload_path"])
        if not workload_path.exists() or sha256_file(workload_path) != family["workload_sha256"]:
            input_hashes_match = False

    checks = {
        "no_missing_raw_records": not missing,
        "exact_cell_matrix": observed_cells == expected_cells,
        "repetition_counts_match": repetition_counts_match,
        "schedule_identity_match": schedule_identity_match,
        "cpu_affinity_match": cpu_match,
        "policy_hashes_match": policy_hashes_match,
        "query_hashes_match": query_hashes_match,
        "input_hashes_match": input_hashes_match,
        "all_roundtrips_identical": all_roundtrips,
        "all_results_open_scope": all_open_scope,
        "fixed_results_by_family": family_fixed_results,
        "all_summary_cells_recomputed": all(item["matches"] for item in summary_checks),
        "runner_hash_matches_config": (
            sha256_file(Path(config["script"])) == config["script_sha256"]
        ),
    }
    scalar_checks = [value for value in checks.values() if isinstance(value, bool)]
    nested_checks = [
        value
        for family in family_fixed_results.values()
        for value in family.values()
    ]
    checks["all_checks_pass"] = all(scalar_checks + nested_checks)
    result = {
        "schema_version": "controlled-policy-processing-independent-audit-v1",
        "run_dir": str(run_dir.resolve()),
        "auditor": str(SCRIPT),
        "auditor_sha256": sha256_file(SCRIPT),
        "missing_raw_records": missing,
        "summary_cell_checks": summary_checks,
        "recomputed_rows": recomputed_rows,
        "checks": checks,
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    result = audit(run_dir)
    output = args.output or (run_dir / "independent_audit.json")
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["checks"], indent=2, sort_keys=True))
    return 0 if result["checks"]["all_checks_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
