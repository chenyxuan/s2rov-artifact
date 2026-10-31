#!/usr/bin/env python3
"""Independent raw audit for the dual-stack policy update benchmark."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Sequence


SCRIPT = Path(__file__).resolve()
REPO_ROOT = SCRIPT.parents[3]
S2ROV_CODEC_SCRIPTS = REPO_ROOT / "implementation" / "s2rov_codec" / "scripts"
if str(S2ROV_CODEC_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(S2ROV_CODEC_SCRIPTS))

from utils.s2rov import S2ROV, ValidationState  # noqa: E402


SCHEMA_VERSION = "same-size-policy-update-v1"
AUDIT_SCHEMA_VERSION = "same-size-policy-update-independent-audit-v1"
IP_VERSIONS = (4, 6)
RULE_COUNTS = (1, 64, 256, 1024, 4096)
REPETITIONS = 20
CPU = 31


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def percentile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)


def close(left: float, right: float) -> bool:
    return math.isclose(left, right, rel_tol=1e-12, abs_tol=1e-12)


def expected_schedule(seed: int) -> list[dict[str, Any]]:
    conditions = [
        {
            "ip_version": ip_version,
            "rules": rules,
            "repetition": repetition,
            "cpu": CPU,
            "nonce": sha256_text(
                f"{seed}|ipv{ip_version}|rules={rules}|rep={repetition}"
            )[:24],
        }
        for ip_version in IP_VERSIONS
        for rules in RULE_COUNTS
        for repetition in range(1, REPETITIONS + 1)
    ]
    random.Random(seed).shuffle(conditions)
    result = []
    for index, condition in enumerate(conditions):
        result.append(
            {
                "schedule_index": index,
                **condition,
                "raw_json": (
                    f"raw/{index:03d}-ipv{condition['ip_version']}-"
                    f"rules-{condition['rules']}-rep-{condition['repetition']}.json"
                ),
            }
        )
    return result


def policy_semantic_delta(open_policy: S2ROV, closed_policy: S2ROV) -> list[dict[str, Any]]:
    deltas = []
    for before, after in zip(open_policy.stripes, closed_policy.stripes):
        before_row = (before.prefix, tuple(sorted(before.as_set)), before.is_open)
        after_row = (after.prefix, tuple(sorted(after.as_set)), after.is_open)
        if before_row != after_row:
            deltas.append(
                {
                    "before": before_row,
                    "after": after_row,
                }
            )
    return deltas


def verify_artifact_hashes(run_dir: Path, artifact: dict[str, Any]) -> tuple[bool, list[str]]:
    mismatches = []
    for section in ("input_sha256", "output_sha256"):
        for relative, expected_hash in artifact.get(section, {}).items():
            path = run_dir / relative
            if not path.is_file() or sha256_file(path) != expected_hash:
                mismatches.append(f"{section}:{relative}")
    return not mismatches, mismatches


def audit(run_dir: Path) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    config = json.loads((run_dir / "run_config.json").read_text(encoding="utf-8"))
    schedule = json.loads((run_dir / "schedule.json").read_text(encoding="utf-8"))
    inputs = json.loads((run_dir / "input_manifest.json").read_text(encoding="utf-8"))
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    artifact = json.loads((run_dir / "artifact_manifest.json").read_text(encoding="utf-8"))

    checks: dict[str, Any] = {
        "schema_versions_match": all(
            document.get("schema_version") == SCHEMA_VERSION
            for document in (config, inputs, summary, artifact)
        ),
        "formal_ip_versions": config.get("ip_versions") == list(IP_VERSIONS),
        "formal_rule_counts": config.get("rule_counts") == list(RULE_COUNTS),
        "formal_repetitions": config.get("repetitions_per_cell") == REPETITIONS,
        "formal_cpu": config.get("cpu") == CPU,
        "formal_worker_count": config.get("expected_worker_records") == 200,
        "input_manifest_hash_matches_config": (
            sha256_file(run_dir / "input_manifest.json")
            == config.get("input_manifest_sha256")
        ),
        "schedule_hash_matches_config": (
            sha256_file(run_dir / "schedule.json") == config.get("schedule_sha256")
        ),
    }

    expected = expected_schedule(int(config["seed"]))
    checks["schedule_has_200_conditions"] = len(schedule) == 200
    checks["schedule_reproduces_from_seed"] = schedule == expected
    checks["schedule_is_randomized"] = [
        (item["ip_version"], item["rules"], item["repetition"])
        for item in schedule
    ] != sorted(
        (item["ip_version"], item["rules"], item["repetition"])
        for item in schedule
    )

    source_hash_mismatches = []
    for name, metadata in inputs.get("accepted_source_metadata", {}).items():
        source_path = Path(metadata["path"])
        if not source_path.is_file() or sha256_file(source_path) != metadata["sha256"]:
            source_hash_mismatches.append(name)
    checks["accepted_source_metadata_hashes_match"] = not source_hash_mismatches

    input_policy_checks = []
    policy_lookup: dict[tuple[int, int], dict[str, Any]] = {}
    query_lookup: dict[int, dict[str, Any]] = {}
    for ip_version in IP_VERSIONS:
        family = inputs["families"][str(ip_version)]
        query = family["query"]
        source_query = Path(query["source_path"])
        frozen_query = Path(query["frozen_path"])
        query_hash_ok = (
            source_query.is_file()
            and frozen_query.is_file()
            and sha256_file(source_query) == query["source_sha256"]
            and sha256_file(frozen_query) == query["frozen_sha256"]
            and query["source_sha256"] == query["frozen_sha256"]
        )
        query_document = json.loads(frozen_query.read_text(encoding="utf-8"))
        probe = query_document["queries"][int(query["probe_index"])]
        probe_identity_ok = (
            str(probe["prefix"]) == query["probe_prefix"]
            and int(probe["origin"]) == int(query["probe_origin"])
            and int(query_document["ip_version"]) == ip_version
        )
        query_lookup[ip_version] = {
            **query,
            "actual_sha256": sha256_file(frozen_query),
        }

        for rules in RULE_COUNTS:
            policy_meta = family["policies"][str(rules)]
            source_open = Path(policy_meta["source_open_path"])
            frozen_open = Path(policy_meta["frozen_open_path"])
            frozen_closed = Path(policy_meta["frozen_closed_path"])
            source_open_hash = sha256_file(source_open) if source_open.is_file() else None
            frozen_open_hash = sha256_file(frozen_open) if frozen_open.is_file() else None
            frozen_closed_hash = sha256_file(frozen_closed) if frozen_closed.is_file() else None
            hashes_ok = (
                source_open_hash == policy_meta["source_open_sha256"]
                and frozen_open_hash == policy_meta["frozen_open_sha256"]
                and frozen_closed_hash == policy_meta["frozen_closed_sha256"]
                and source_open_hash == frozen_open_hash
            )

            open_payload = frozen_open.read_bytes()
            closed_payload = frozen_closed.read_bytes()
            open_policy = S2ROV.deserialize(open_payload)
            closed_policy = S2ROV.deserialize(closed_payload)
            roundtrips_ok = (
                open_policy.serialize() == open_payload
                and closed_policy.serialize() == closed_payload
            )
            entry_counts_ok = (
                len(open_policy.stripes) == rules
                and len(closed_policy.stripes) == rules
                and int(policy_meta["total_policy_entries"]) == rules
            )
            serialized_sizes_ok = (
                len(open_payload) == len(closed_payload)
                and int(policy_meta["open_serialized_bytes"]) == len(open_payload)
                and int(policy_meta["closed_serialized_bytes"]) == len(closed_payload)
                and policy_meta.get("same_serialized_size") is True
            )
            deltas = policy_semantic_delta(open_policy, closed_policy)
            semantic_delta_ok = False
            if len(deltas) == 1:
                before = deltas[0]["before"]
                after = deltas[0]["after"]
                semantic_delta_ok = (
                    before[0] == open_policy.base_prefix
                    and before[0] == after[0]
                    and before[1] == after[1]
                    and before[2] is True
                    and after[2] is False
                )
            all_children_unmarked = all(
                not stripe.is_open
                for stripe in open_policy.stripes
                if stripe.prefix != open_policy.base_prefix
            ) and all(
                not stripe.is_open
                for stripe in closed_policy.stripes
                if stripe.prefix != closed_policy.base_prefix
            )
            probe_prefix = query["probe_prefix"]
            probe_origin = int(query["probe_origin"])
            closed_state = closed_policy.validate_route(probe_prefix, probe_origin)
            open_state = open_policy.validate_route(probe_prefix, probe_origin)
            states_ok = (
                closed_state is ValidationState.INVALID
                and open_state is ValidationState.DELEGATED
            )
            cell_check = {
                "ip_version": ip_version,
                "rules": rules,
                "query_hash_ok": query_hash_ok,
                "probe_identity_ok": probe_identity_ok,
                "hashes_ok": hashes_ok,
                "roundtrips_ok": roundtrips_ok,
                "entry_counts_ok": entry_counts_ok,
                "serialized_sizes_ok": serialized_sizes_ok,
                "semantic_delta_ok": semantic_delta_ok,
                "all_children_unmarked": all_children_unmarked,
                # Frozen schema compatibility alias.
                "all_children_closed": all_children_unmarked,
                "states_ok": states_ok,
            }
            cell_check["pass"] = all(
                value for key, value in cell_check.items() if isinstance(value, bool)
            )
            input_policy_checks.append(cell_check)
            policy_lookup[(ip_version, rules)] = {
                **policy_meta,
                "actual_open_sha256": frozen_open_hash,
                "actual_closed_sha256": frozen_closed_hash,
            }
    checks["all_input_policy_checks_pass"] = all(
        item["pass"] for item in input_policy_checks
    )

    missing_raw = []
    raw_records = []
    raw_parse_errors = []
    for item in schedule:
        raw_path = run_dir / item["raw_json"]
        if not raw_path.is_file():
            missing_raw.append(item["raw_json"])
            continue
        try:
            raw_records.append(json.loads(raw_path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raw_parse_errors.append({"path": item["raw_json"], "error": str(exc)})
    checks["no_missing_raw_records"] = not missing_raw
    checks["no_raw_parse_errors"] = not raw_parse_errors
    checks["exactly_200_raw_records"] = len(raw_records) == 200

    schedule_by_index = {int(item["schedule_index"]): item for item in schedule}
    raw_identity_ok = True
    raw_input_hashes_ok = True
    raw_states_ok = True
    raw_roundtrips_ok = True
    raw_exclusions_ok = True
    raw_pointer_ok = True
    raw_timings_ok = True
    cell_counts: Counter[tuple[int, int]] = Counter()
    for record in raw_records:
        index = int(record["schedule_index"])
        scheduled = schedule_by_index.get(index)
        if scheduled is None:
            raw_identity_ok = False
            continue
        identity_fields = ("ip_version", "rules", "repetition", "nonce")
        if any(record[field] != scheduled[field] for field in identity_fields):
            raw_identity_ok = False
        if record.get("requested_cpu") != scheduled["cpu"]:
            raw_identity_ok = False

        ip_version = int(record["ip_version"])
        rules = int(record["rules"])
        cell_counts[(ip_version, rules)] += 1
        policy = policy_lookup.get((ip_version, rules))
        query = query_lookup.get(ip_version)
        if policy is None or query is None:
            raw_input_hashes_ok = False
        else:
            raw_input_hashes_ok &= (
                record.get("open_payload_sha256") == policy["actual_open_sha256"]
                and record.get("closed_payload_sha256") == policy["actual_closed_sha256"]
                and record.get("query_sha256") == query["actual_sha256"]
                and int(record.get("open_serialized_bytes", -1))
                == int(policy["open_serialized_bytes"])
                and int(record.get("closed_serialized_bytes", -1))
                == int(policy["closed_serialized_bytes"])
                and record.get("probe_prefix") == query["probe_prefix"]
                and int(record.get("probe_origin", -1)) == int(query["probe_origin"])
                and int(record.get("probe_index", -1)) == int(query["probe_index"])
            )
        raw_states_ok &= (
            record.get("closed_state") == ValidationState.INVALID.value
            and record.get("updated_state") == ValidationState.DELEGATED.value
            and record.get("manuscript_state") == "OpenScope"
        )
        raw_roundtrips_ok &= (
            record.get("closed_roundtrip_identical") is True
            and record.get("open_roundtrip_identical") is True
        )
        raw_exclusions_ok &= (
            record.get("file_reads_excluded") is True
            and record.get("closed_policy_preload_excluded") is True
            and record.get("probe_precheck_excluded") is True
            and record.get("gc_collection_excluded") is True
        )
        raw_pointer_ok &= record.get("active_pointer_is_updated_policy") is True
        raw_timings_ok &= (
            isinstance(record.get("update_ns"), int)
            and not isinstance(record.get("update_ns"), bool)
            and int(record.get("update_ns", 0)) > 0
            and close(float(record.get("update_ms", -1)), int(record.get("update_ns", 0)) / 1e6)
        )

    expected_cells = {(ip_version, rules) for ip_version in IP_VERSIONS for rules in RULE_COUNTS}
    checks.update(
        {
            "raw_schedule_identity_roundtrip": raw_identity_ok and len(raw_records) == len(schedule),
            "raw_input_hashes_match": raw_input_hashes_ok,
            "raw_states_match_protocol": raw_states_ok,
            "raw_policy_roundtrips_identical": raw_roundtrips_ok,
            "raw_timing_exclusions_confirmed": raw_exclusions_ok,
            "raw_pointer_replacements_confirmed": raw_pointer_ok,
            "raw_timings_are_positive_and_consistent": raw_timings_ok,
            "exact_2_by_5_matrix": set(cell_counts) == expected_cells,
            "twenty_observations_per_cell": all(
                cell_counts[cell] == REPETITIONS for cell in expected_cells
            ),
            "all_workers_pinned_to_cpu_31": all(
                record.get("cpu_affinity") == [CPU]
                and record.get("requested_cpu") == CPU
                for record in raw_records
            ),
            "all_worker_pids_fresh": (
                len({int(record["worker_pid"]) for record in raw_records}) == 200
                and all(int(record["worker_pid"]) != int(record["parent_pid"]) for record in raw_records)
            ),
            "one_orchestrator_parent_pid": len(
                {int(record["parent_pid"]) for record in raw_records}
            ) == 1,
        }
    )

    grouped: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    for record in raw_records:
        grouped[(int(record["ip_version"]), int(record["rules"]))].append(record)
    recomputed_rows = []
    summary_cell_checks = []
    reported_lookup = {
        (int(row["ip_version"]), int(row["rules"])): row for row in summary["rows"]
    }
    for ip_version in IP_VERSIONS:
        for rules in RULE_COUNTS:
            cell = grouped[(ip_version, rules)]
            values = [int(record["update_ns"]) / 1e6 for record in cell]
            recomputed = {
                "ip_version": ip_version,
                "label": f"IPv{ip_version}",
                "rules": rules,
                "repetitions": len(cell),
                "open_serialized_bytes": int(cell[0]["open_serialized_bytes"]),
                "closed_serialized_bytes": int(cell[0]["closed_serialized_bytes"]),
                "update_ms_mean": statistics.fmean(values),
                "update_ms_median": statistics.median(values),
                "update_ms_q1": percentile(values, 0.25),
                "update_ms_q3": percentile(values, 0.75),
            }
            reported = reported_lookup.get((ip_version, rules), {})
            exact_fields = (
                "ip_version", "label", "rules", "repetitions",
                "open_serialized_bytes", "closed_serialized_bytes",
            )
            numeric_fields = (
                "update_ms_mean", "update_ms_median", "update_ms_q1", "update_ms_q3",
            )
            matches = all(reported.get(field) == recomputed[field] for field in exact_fields)
            matches &= all(
                field in reported and close(float(reported[field]), float(recomputed[field]))
                for field in numeric_fields
            )
            summary_cell_checks.append(
                {"ip_version": ip_version, "rules": rules, "matches": bool(matches)}
            )
            recomputed_rows.append(recomputed)
    checks["summary_has_exact_ten_cells"] = set(reported_lookup) == expected_cells and len(summary["rows"]) == 10
    checks["all_summary_statistics_recomputed"] = all(
        item["matches"] for item in summary_cell_checks
    )

    with (run_dir / "summary.csv").open(newline="", encoding="utf-8") as handle:
        csv_rows = list(csv.DictReader(handle))
    csv_ok = len(csv_rows) == 10
    if csv_ok:
        for csv_row, json_row in zip(csv_rows, summary["rows"]):
            for field in ("ip_version", "rules", "repetitions", "open_serialized_bytes", "closed_serialized_bytes"):
                csv_ok &= int(csv_row[field]) == int(json_row[field])
            csv_ok &= csv_row["label"] == json_row["label"]
            for field in ("update_ms_mean", "update_ms_median", "update_ms_q1", "update_ms_q3"):
                csv_ok &= close(float(csv_row[field]), float(json_row[field]))
    checks["summary_csv_matches_json"] = bool(csv_ok)

    artifact_hashes_ok, artifact_hash_mismatches = verify_artifact_hashes(run_dir, artifact)
    checks["artifact_input_output_hashes_match"] = artifact_hashes_ok
    checks["runner_hash_matches_config"] = (
        Path(config["script"]).is_file()
        and sha256_file(Path(config["script"])) == config["script_sha256"]
    )
    checks["auditor_hash_matches_config"] = (
        Path(config["auditor"]).is_file()
        and sha256_file(Path(config["auditor"])) == config["auditor_sha256"]
        and Path(config["auditor"]).resolve() == SCRIPT
    )
    checks["classifier_hash_matches_config"] = (
        Path(config["classifier"]).is_file()
        and sha256_file(Path(config["classifier"])) == config["classifier_sha256"]
    )

    bool_checks = [value for value in checks.values() if isinstance(value, bool)]
    checks["all_checks_pass"] = all(bool_checks)
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "run_dir": str(run_dir),
        "auditor": str(SCRIPT),
        "auditor_sha256": sha256_file(SCRIPT),
        "matrix": {
            "ip_versions": list(IP_VERSIONS),
            "rule_counts": list(RULE_COUNTS),
            "repetitions_per_cell": REPETITIONS,
            "raw_records": len(raw_records),
            "cell_counts": {
                f"ipv{ip_version}-rules-{rules}": cell_counts[(ip_version, rules)]
                for ip_version in IP_VERSIONS for rules in RULE_COUNTS
            },
        },
        "missing_raw_records": missing_raw,
        "raw_parse_errors": raw_parse_errors,
        "source_hash_mismatches": source_hash_mismatches,
        "artifact_hash_mismatches": artifact_hash_mismatches,
        "input_policy_checks": input_policy_checks,
        "summary_cell_checks": summary_cell_checks,
        "recomputed_rows": recomputed_rows,
        "checks": checks,
        "claim_boundary": (
            "The audit verifies the frozen inputs, process matrix, state transition, "
            "timing arithmetic, and descriptive summaries. It does not validate "
            "Internet-scale convergence or infer a causal IPv4/IPv6 difference."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.run_dir)
    output = args.output or (args.run_dir / "independent_audit.json")
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["checks"], indent=2, sort_keys=True))
    return 0 if result["checks"]["all_checks_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
