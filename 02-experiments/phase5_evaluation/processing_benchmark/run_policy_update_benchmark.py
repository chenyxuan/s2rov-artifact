#!/usr/bin/env python3
"""Dual-stack same-size OpenScope-marker replacement benchmark.

For each IP version and policy size, a fresh worker starts with an unmarked policy
already loaded.  The timed interval deserializes the corresponding marked policy,
replaces one active-policy pointer, and classifies one fixed probe route.  File
I/O, unmarked-policy loading, and garbage collection are outside the interval.

Frozen output fields and paths named ``open`` or ``closed`` are compatibility
aliases for marked and unmarked payloads, respectively.
"""

from __future__ import annotations

import argparse
import csv
import gc
import hashlib
import json
import math
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


SCRIPT = Path(__file__).resolve()
BENCHMARK_DIR = SCRIPT.parent
REPO_ROOT = SCRIPT.parents[2]
PHASE4_SCRIPTS = REPO_ROOT / "phase4_encoding" / "scripts"
if str(PHASE4_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PHASE4_SCRIPTS))

from utils.daroa import DAROA, Stripe, ValidationState  # noqa: E402


SCHEMA_VERSION = "same-size-policy-update-v1"
AUDIT_SCRIPT = BENCHMARK_DIR / "audit_policy_update_benchmark.py"
DEFAULT_OUTPUT_ROOT = BENCHMARK_DIR / "outputs"
DEFAULT_SOURCE_RUN = (
    DEFAULT_OUTPUT_ROOT / "controlled-processing-20260830T-marker-final-v1"
)
RULE_COUNTS = (1, 64, 256, 1024, 4096)
IP_VERSIONS = (4, 6)
DEFAULT_REPETITIONS = 20
DEFAULT_CPU = 31
DEFAULT_SEED = 20260830


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def percentile(values: Sequence[float], probability: float) -> float:
    if not values:
        raise ValueError("cannot summarize an empty sample")
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)


def pin_to_cpu(cpu: int) -> list[int]:
    if not hasattr(os, "sched_setaffinity"):
        raise RuntimeError("CPU affinity is unavailable on this platform")
    os.sched_setaffinity(0, {cpu})
    observed = sorted(os.sched_getaffinity(0))
    if observed != [cpu]:
        raise RuntimeError(f"failed to pin worker to CPU {cpu}: {observed}")
    return observed


def policy_rows(policy: DAROA) -> list[dict[str, Any]]:
    return [
        {
            "prefix": stripe.prefix,
            "origins": sorted(stripe.as_set),
            "open": stripe.is_open,
        }
        for stripe in policy.stripes
    ]


def build_unmarked_counterpart(marked_payload: bytes) -> tuple[bytes, dict[str, Any]]:
    """Build an unmarked counterpart while retaining frozen schema aliases.

    The serialized ``is_open`` bit is only the OpenScope marker bit. Clearing
    it does not create a restrictive region or affect explicit origin records.
    """
    open_payload = marked_payload
    open_policy = DAROA.deserialize(open_payload)
    if open_policy.serialize() != open_payload:
        raise ValueError("source marked payload is not canonical")
    base_matches = [
        stripe for stripe in open_policy.stripes
        if stripe.prefix == open_policy.base_prefix
    ]
    if len(base_matches) != 1 or not base_matches[0].is_open:
        raise ValueError("source policy must have exactly one marked base record")
    if any(
        stripe.is_open
        for stripe in open_policy.stripes
        if stripe.prefix != open_policy.base_prefix
    ):
        raise ValueError("all non-base source records must already be unmarked")

    closed_stripes = tuple(
        Stripe(
            stripe.prefix,
            stripe.as_set,
            False if stripe.prefix == open_policy.base_prefix else stripe.is_open,
        )
        for stripe in open_policy.stripes
    )
    closed_policy = DAROA(
        open_policy.base_prefix,
        open_policy.max_length,
        open_policy.holder_asn,
        closed_stripes,
    )
    closed_payload = closed_policy.serialize()
    roundtrip = DAROA.deserialize(closed_payload)
    if roundtrip.serialize() != closed_payload:
        raise AssertionError("constructed unmarked policy is not canonical")
    if len(open_policy.stripes) != len(closed_policy.stripes):
        raise AssertionError("unmarked counterpart changed the policy size")
    if len(open_payload) != len(closed_payload):
        raise AssertionError("base-bit replacement changed serialized size")

    open_rows = policy_rows(open_policy)
    closed_rows = policy_rows(closed_policy)
    deltas = []
    for before, after in zip(open_rows, closed_rows):
        if before != after:
            deltas.append({"before": before, "after": after})
    if len(deltas) != 1:
        raise AssertionError(f"expected one semantic delta, found {len(deltas)}")
    delta = deltas[0]
    if not (
        delta["before"]["prefix"] == open_policy.base_prefix
        and delta["before"]["origins"] == delta["after"]["origins"]
        and delta["before"]["open"] is True
        and delta["after"]["open"] is False
    ):
        raise AssertionError(
            "unmarked counterpart changed more than the base marker bit"
        )

    return closed_payload, {
        "ip_version": open_policy.ip_version,
        "base_prefix": open_policy.base_prefix,
        "holder_asn": open_policy.holder_asn,
        "total_policy_entries": len(open_policy.stripes),
        "open_serialized_bytes": len(open_payload),
        "closed_serialized_bytes": len(closed_payload),
        "open_sha256": sha256_bytes(open_payload),
        "closed_sha256": sha256_bytes(closed_payload),
        "semantic_delta": deltas,
        "same_entry_count": True,
        "same_serialized_size": True,
        "only_base_marker_bit_changed": True,
        "only_base_open_bit_changed": True,
        "compatibility_aliases": {
            "open": "marked",
            "closed": "unmarked",
        },
    }


def build_closed_counterpart(open_payload: bytes) -> tuple[bytes, dict[str, Any]]:
    """Compatibility alias for :func:`build_unmarked_counterpart`."""
    return build_unmarked_counterpart(open_payload)


def read_probe(query_path: Path, probe_index: int = 0) -> tuple[str, int, dict[str, Any]]:
    document = json.loads(query_path.read_text(encoding="utf-8"))
    queries = document.get("queries", [])
    if not 0 <= probe_index < len(queries):
        raise ValueError(f"probe index {probe_index} is outside the query file")
    item = queries[probe_index]
    return str(item["prefix"]), int(item["origin"]), document


def source_policy_path(source_run: Path, ip_version: int, rules: int) -> Path:
    return source_run / "policies" / (
        f"ipv{ip_version}-subprefixes-{rules - 1}.bin"
    )


def prepare_inputs(run_dir: Path, source_run: Path) -> dict[str, Any]:
    """Freeze accepted marked payloads and derive unmarked counterparts."""
    source_run = source_run.resolve()
    if not source_run.is_dir():
        raise FileNotFoundError(f"accepted source run not found: {source_run}")
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "created_utc": utc_now(),
        "accepted_source_run": str(source_run),
        "accepted_source_metadata": {},
        "families": {},
    }
    for metadata_name in ("run_config.json", "selection_manifest.json"):
        metadata_path = source_run / metadata_name
        if not metadata_path.is_file():
            raise FileNotFoundError(metadata_path)
        manifest["accepted_source_metadata"][metadata_name] = {
            "path": str(metadata_path),
            "sha256": sha256_file(metadata_path),
        }

    for ip_version in IP_VERSIONS:
        source_query = source_run / "queries" / f"ipv{ip_version}-queries.json"
        if not source_query.is_file():
            raise FileNotFoundError(source_query)
        frozen_query = run_dir / "inputs" / "queries" / f"ipv{ip_version}-queries.json"
        frozen_query.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_query, frozen_query)
        probe_prefix, probe_origin, query_document = read_probe(frozen_query)
        if int(query_document["ip_version"]) != ip_version:
            raise ValueError("query file address family mismatch")
        if query_document.get("expected_internal_state") != ValidationState.DELEGATED.value:
            raise ValueError("accepted query file is not an OpenScope query set")

        family: dict[str, Any] = {
            "ip_version": ip_version,
            "query": {
                "source_path": str(source_query),
                "source_sha256": sha256_file(source_query),
                "frozen_path": str(frozen_query.resolve()),
                "frozen_sha256": sha256_file(frozen_query),
                "probe_index": 0,
                "probe_prefix": probe_prefix,
                "probe_origin": probe_origin,
            },
            "policies": {},
        }
        for rules in RULE_COUNTS:
            source_open = source_policy_path(source_run, ip_version, rules)
            if not source_open.is_file():
                raise FileNotFoundError(source_open)
            open_payload = source_open.read_bytes()
            closed_payload, counterpart = build_unmarked_counterpart(open_payload)
            if counterpart["ip_version"] != ip_version:
                raise ValueError("source policy address family mismatch")
            if counterpart["total_policy_entries"] != rules:
                raise ValueError(
                    f"source payload has {counterpart['total_policy_entries']} rules; "
                    f"expected {rules}"
                )

            frozen_open = run_dir / "inputs" / "open" / (
                f"ipv{ip_version}-rules-{rules}.bin"
            )
            frozen_closed = run_dir / "inputs" / "closed" / (
                f"ipv{ip_version}-rules-{rules}.bin"
            )
            frozen_open.parent.mkdir(parents=True, exist_ok=True)
            frozen_closed.parent.mkdir(parents=True, exist_ok=True)
            frozen_open.write_bytes(open_payload)
            frozen_closed.write_bytes(closed_payload)

            open_policy = DAROA.deserialize(open_payload)
            closed_policy = DAROA.deserialize(closed_payload)
            open_state = open_policy.validate_route(probe_prefix, probe_origin)
            closed_state = closed_policy.validate_route(probe_prefix, probe_origin)
            if closed_state is not ValidationState.INVALID:
                raise AssertionError(
                    f"unmarked preflight failed for IPv{ip_version}, {rules} rules: "
                    f"{closed_state.value}"
                )
            if open_state is not ValidationState.DELEGATED:
                raise AssertionError(
                    f"marked preflight failed for IPv{ip_version}, {rules} rules: "
                    f"{open_state.value}"
                )

            family["policies"][str(rules)] = {
                **counterpart,
                "source_open_path": str(source_open),
                "source_open_sha256": sha256_file(source_open),
                "frozen_open_path": str(frozen_open.resolve()),
                "frozen_open_sha256": sha256_file(frozen_open),
                "frozen_closed_path": str(frozen_closed.resolve()),
                "frozen_closed_sha256": sha256_file(frozen_closed),
                "probe_closed_state": closed_state.value,
                "probe_open_state": open_state.value,
                "probe_manuscript_state": "OpenScope",
            }
        manifest["families"][str(ip_version)] = family

    write_json(run_dir / "input_manifest.json", manifest)
    return manifest


def schedule_nonce(seed: int, ip_version: int, rules: int, repetition: int) -> str:
    return sha256_text(f"{seed}|ipv{ip_version}|rules={rules}|rep={repetition}")[:24]


def build_schedule(
    run_dir: Path,
    *,
    repetitions: int = DEFAULT_REPETITIONS,
    seed: int = DEFAULT_SEED,
    cpu: int = DEFAULT_CPU,
) -> list[dict[str, Any]]:
    conditions = [
        {
            "ip_version": ip_version,
            "rules": rules,
            "repetition": repetition,
            "cpu": cpu,
            "nonce": schedule_nonce(seed, ip_version, rules, repetition),
        }
        for ip_version in IP_VERSIONS
        for rules in RULE_COUNTS
        for repetition in range(1, repetitions + 1)
    ]
    random.Random(seed).shuffle(conditions)
    schedule = []
    for schedule_index, condition in enumerate(conditions):
        raw_name = (
            f"{schedule_index:03d}-ipv{condition['ip_version']}-"
            f"rules-{condition['rules']}-rep-{condition['repetition']}.json"
        )
        schedule.append(
            {
                "schedule_index": schedule_index,
                **condition,
                "raw_json": f"raw/{raw_name}",
            }
        )
    write_json(run_dir / "schedule.json", schedule)
    return schedule


def worker_update(args: argparse.Namespace) -> int:
    affinity = pin_to_cpu(args.cpu)

    # Every operation below is deliberately outside the timed interval until
    # the explicit perf_counter_ns call.
    open_payload = args.open_policy.read_bytes()
    closed_payload = args.closed_policy.read_bytes()
    probe_prefix, probe_origin, query_document = read_probe(
        args.queries, args.probe_index
    )
    closed_policy = DAROA.deserialize(closed_payload)
    if len(closed_policy.stripes) != args.rules:
        raise AssertionError("unmarked policy size mismatch")
    if int(query_document["ip_version"]) != closed_policy.ip_version:
        raise AssertionError("query and policy address families differ")
    closed_state = closed_policy.validate_route(probe_prefix, probe_origin)
    if closed_state is not ValidationState.INVALID:
        raise AssertionError(
            f"unmarked probe must be Invalid, got {closed_state.value}"
        )
    active_policy = [closed_policy]

    gc.collect()
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        started_ns = time.perf_counter_ns()
        updated_policy = DAROA.deserialize(open_payload)
        active_policy[0] = updated_policy
        updated_state = active_policy[0].validate_route(probe_prefix, probe_origin)
        update_ns = time.perf_counter_ns() - started_ns
    finally:
        if gc_was_enabled:
            gc.enable()

    if updated_state is not ValidationState.DELEGATED:
        raise AssertionError(
            f"updated probe must be Delegated/OpenScope, got {updated_state.value}"
        )
    if len(updated_policy.stripes) != args.rules:
        raise AssertionError("updated policy size mismatch")
    if updated_policy.ip_version != args.ip_version:
        raise AssertionError("updated policy address family mismatch")

    result = {
        "schema_version": SCHEMA_VERSION,
        "created_utc": utc_now(),
        "worker": "same-size-policy-update",
        "schedule_index": args.schedule_index,
        "nonce": args.nonce,
        "ip_version": updated_policy.ip_version,
        "rules": args.rules,
        "repetition": args.repetition,
        "requested_cpu": args.cpu,
        "cpu_affinity": affinity,
        "worker_pid": os.getpid(),
        "parent_pid": os.getppid(),
        "probe_index": args.probe_index,
        "probe_prefix": probe_prefix,
        "probe_origin": probe_origin,
        "closed_state": closed_state.value,
        "updated_state": updated_state.value,
        "manuscript_state": "OpenScope",
        "open_policy_path": str(args.open_policy.resolve()),
        "open_payload_sha256": sha256_bytes(open_payload),
        "open_serialized_bytes": len(open_payload),
        "closed_policy_path": str(args.closed_policy.resolve()),
        "closed_payload_sha256": sha256_bytes(closed_payload),
        "closed_serialized_bytes": len(closed_payload),
        "query_path": str(args.queries.resolve()),
        "query_sha256": sha256_file(args.queries),
        "closed_roundtrip_identical": closed_policy.serialize() == closed_payload,
        "open_roundtrip_identical": updated_policy.serialize() == open_payload,
        "active_pointer_is_updated_policy": active_policy[0] is updated_policy,
        "update_ns": update_ns,
        "update_ms": update_ns / 1_000_000,
        "timed_scope": [
            "DAROA.deserialize(open_payload)",
            "active_policy_pointer_replacement",
            "first_validate_route",
        ],
        "file_reads_excluded": True,
        "closed_policy_preload_excluded": True,
        "probe_precheck_excluded": True,
        "gc_collection_excluded": True,
        "python": sys.version,
        "platform": platform.platform(),
    }
    write_json(args.output, result)
    print(
        f"update IPv{updated_policy.ip_version} rules={args.rules} "
        f"rep={args.repetition} {result['update_ms']:.3f} ms",
        flush=True,
    )
    return 0


def load_raw_records(run_dir: Path, schedule: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        json.loads((run_dir / item["raw_json"]).read_text(encoding="utf-8"))
        for item in schedule
    ]


def summarize(
    run_dir: Path,
    schedule: Sequence[dict[str, Any]],
    *,
    expected_repetitions: int = DEFAULT_REPETITIONS,
    expected_cpu: int = DEFAULT_CPU,
) -> dict[str, Any]:
    records = load_raw_records(run_dir, schedule)
    grouped: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[(int(record["ip_version"]), int(record["rules"]))].append(record)

    expected_cells = {(ip_version, rules) for ip_version in IP_VERSIONS for rules in RULE_COUNTS}
    observed_cells = set(grouped)
    rows = []
    for ip_version in IP_VERSIONS:
        for rules in RULE_COUNTS:
            cell = grouped[(ip_version, rules)]
            update_ms = [float(record["update_ns"]) / 1_000_000 for record in cell]
            rows.append(
                {
                    "ip_version": ip_version,
                    "label": f"IPv{ip_version}",
                    "rules": rules,
                    "repetitions": len(cell),
                    "open_serialized_bytes": int(cell[0]["open_serialized_bytes"]),
                    "closed_serialized_bytes": int(cell[0]["closed_serialized_bytes"]),
                    "update_ms_mean": statistics.fmean(update_ms),
                    "update_ms_median": statistics.median(update_ms),
                    "update_ms_q1": percentile(update_ms, 0.25),
                    "update_ms_q3": percentile(update_ms, 0.75),
                }
            )

    counts = Counter((int(r["ip_version"]), int(r["rules"])) for r in records)
    gates = {
        "raw_worker_records": len(records),
        "expected_worker_records": len(IP_VERSIONS) * len(RULE_COUNTS) * expected_repetitions,
        "exact_cell_matrix": observed_cells == expected_cells,
        "twenty_fresh_workers_per_cell": all(
            counts[cell] == expected_repetitions for cell in expected_cells
        ),
        "all_workers_on_cpu": all(r["cpu_affinity"] == [expected_cpu] for r in records),
        "all_worker_pids_unique": len({int(r["worker_pid"]) for r in records}) == len(records),
        "all_workers_are_child_processes": all(int(r["worker_pid"]) != int(r["parent_pid"]) for r in records),
        "all_closed_probes_invalid": all(r["closed_state"] == ValidationState.INVALID.value for r in records),
        "all_updated_probes_open_scope": all(
            r["updated_state"] == ValidationState.DELEGATED.value
            and r["manuscript_state"] == "OpenScope"
            for r in records
        ),
        "all_roundtrips_identical": all(
            r["closed_roundtrip_identical"] is True
            and r["open_roundtrip_identical"] is True
            for r in records
        ),
        "all_pointer_replacements_confirmed": all(
            r["active_pointer_is_updated_policy"] is True for r in records
        ),
        "all_exclusions_confirmed": all(
            r["file_reads_excluded"] is True
            and r["closed_policy_preload_excluded"] is True
            and r["probe_precheck_excluded"] is True
            and r["gc_collection_excluded"] is True
            for r in records
        ),
    }
    gates["all_gates_pass"] = all(
        value for key, value in gates.items()
        if isinstance(value, bool) and key != "all_gates_pass"
    ) and gates["raw_worker_records"] == gates["expected_worker_records"]
    if not gates["all_gates_pass"]:
        raise AssertionError(f"policy update benchmark gates failed: {gates}")

    summary = {
        "schema_version": SCHEMA_VERSION,
        "created_utc": utc_now(),
        "rows": rows,
        "gates": gates,
        "claim_boundary": (
            "Descriptive latency of one single-core Python reference-engine policy "
            "replacement and first classification. It excludes file acquisition and "
            "distribution, relying-party refresh, RTR, router installation, and forwarding."
        ),
    }
    write_json(run_dir / "summary.json", summary)
    fields = [
        "ip_version", "label", "rules", "repetitions",
        "open_serialized_bytes", "closed_serialized_bytes",
        "update_ms_mean", "update_ms_median", "update_ms_q1", "update_ms_q3",
    ]
    with (run_dir / "summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return summary


def write_artifact_manifest(run_dir: Path) -> dict[str, Any]:
    input_paths = [run_dir / "input_manifest.json"] + sorted(
        path for path in (run_dir / "inputs").rglob("*") if path.is_file()
    )
    output_paths = [
        run_dir / "run_config.json",
        run_dir / "schedule.json",
        run_dir / "summary.json",
        run_dir / "summary.csv",
        run_dir / "RUN_REPORT.md",
    ] + sorted((run_dir / "raw").glob("*.json"))
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "created_utc": utc_now(),
        "run_dir": str(run_dir.resolve()),
        "input_sha256": {
            str(path.relative_to(run_dir)): sha256_file(path) for path in input_paths
        },
        "output_sha256": {
            str(path.relative_to(run_dir)): sha256_file(path) for path in output_paths
        },
        "mutable_non_evidence_files_excluded": ["driver.log", "independent_audit.json"],
    }
    write_json(run_dir / "artifact_manifest.json", manifest)
    return manifest


def build_run_config(
    run_dir: Path,
    source_run: Path,
    *,
    repetitions: int,
    cpu: int,
    seed: int,
) -> dict[str, Any]:
    git_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    git_dirty = bool(subprocess.run(
        ["git", "status", "--porcelain"], cwd=REPO_ROOT, check=True,
        capture_output=True, text=True,
    ).stdout)
    config = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_dir.name,
        "created_utc": utc_now(),
        "accepted_source_run": str(source_run.resolve()),
        "ip_versions": list(IP_VERSIONS),
        "rule_counts": list(RULE_COUNTS),
        "repetitions_per_cell": repetitions,
        "expected_cells": len(IP_VERSIONS) * len(RULE_COUNTS),
        "expected_worker_records": len(IP_VERSIONS) * len(RULE_COUNTS) * repetitions,
        "cpu": cpu,
        "seed": seed,
        "probe_query_index": 0,
        "worker_process_model": "one fresh subprocess per observation",
        "schedule_model": "one seeded shuffle of all AF-size-repetition conditions",
        "timed_scope": [
            "DAROA.deserialize(open_payload)",
            "active_policy_pointer_replacement",
            "first_validate_route",
        ],
        "excluded_scope": [
            "file_reading", "closed_policy_deserialization", "closed_probe_precheck",
            "garbage_collection", "policy_distribution", "router_installation",
        ],
        "script": str(SCRIPT),
        "script_sha256": sha256_file(SCRIPT),
        "auditor": str(AUDIT_SCRIPT.resolve()),
        "auditor_sha256": sha256_file(AUDIT_SCRIPT),
        "classifier": str(PHASE4_SCRIPTS / "utils" / "daroa.py"),
        "classifier_sha256": sha256_file(PHASE4_SCRIPTS / "utils" / "daroa.py"),
        "input_manifest_sha256": sha256_file(run_dir / "input_manifest.json"),
        "schedule_sha256": sha256_file(run_dir / "schedule.json"),
        "source_git_commit": git_commit,
        "source_worktree_dirty": git_dirty,
        "python": sys.version,
        "platform": platform.platform(),
    }
    write_json(run_dir / "run_config.json", config)
    return config


def run_orchestrator(args: argparse.Namespace) -> int:
    if args.repetitions != DEFAULT_REPETITIONS:
        raise ValueError(f"formal protocol requires {DEFAULT_REPETITIONS} repetitions")
    if args.cpu != DEFAULT_CPU:
        raise ValueError(f"formal protocol requires CPU {DEFAULT_CPU}")
    if not hasattr(os, "sched_getaffinity"):
        raise RuntimeError("formal protocol requires Linux CPU affinity")
    available = sorted(os.sched_getaffinity(0))
    if args.cpu not in available:
        raise ValueError(f"CPU {args.cpu} is unavailable: {available}")

    run_id = args.run_id or datetime.now(timezone.utc).strftime(
        "policy-update-%Y%m%dT%H%M%SZ"
    )
    run_dir = args.output_root.resolve() / run_id
    if run_dir.exists():
        raise FileExistsError(f"refusing to overwrite existing run: {run_dir}")
    (run_dir / "raw").mkdir(parents=True)
    log_path = run_dir / "driver.log"

    def log(message: str) -> None:
        line = f"[{utc_now()}] {message}"
        print(line, flush=True)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    source_run = args.source_run.resolve()
    log("freezing accepted marked policies and constructing unmarked counterparts")
    inputs = prepare_inputs(run_dir, source_run)
    schedule = build_schedule(
        run_dir, repetitions=args.repetitions, seed=args.seed, cpu=args.cpu
    )
    build_run_config(
        run_dir, source_run, repetitions=args.repetitions, cpu=args.cpu, seed=args.seed
    )

    environment = os.environ.copy()
    environment.update({"PYTHONHASHSEED": "0", "LC_ALL": "C"})
    for condition in schedule:
        ip_version = int(condition["ip_version"])
        rules = int(condition["rules"])
        family = inputs["families"][str(ip_version)]
        policy = family["policies"][str(rules)]
        command = [
            sys.executable, str(SCRIPT), "worker-update",
            "--open-policy", policy["frozen_open_path"],
            "--closed-policy", policy["frozen_closed_path"],
            "--queries", family["query"]["frozen_path"],
            "--probe-index", str(family["query"]["probe_index"]),
            "--rules", str(rules),
            "--ip-version", str(ip_version),
            "--repetition", str(condition["repetition"]),
            "--schedule-index", str(condition["schedule_index"]),
            "--nonce", condition["nonce"],
            "--cpu", str(args.cpu),
            "--output", str(run_dir / condition["raw_json"]),
        ]
        completed = subprocess.run(
            command, check=True, capture_output=True, text=True, env=environment
        )
        for line in completed.stdout.splitlines():
            log(line)
        for line in completed.stderr.splitlines():
            log(f"worker stderr: {line}")

    summary = summarize(
        run_dir, schedule,
        expected_repetitions=args.repetitions,
        expected_cpu=args.cpu,
    )
    report = f"""# Dual-stack same-size policy update benchmark

Run: `{run_id}`  
Generated: {utc_now()}

Each of the ten IPv4/IPv6-by-size cells contains twenty fresh worker
processes pinned to CPU {args.cpu}.  Every worker begins with a same-size unmarked
policy and an Invalid fixed probe.  The timed update deserializes the accepted
marked payload, replaces the active-policy pointer, and classifies that probe as
Delegated (`OpenScope`).

## Protocol

- Rules: {', '.join(str(value) for value in RULE_COUNTS)}
- Repetitions per cell: {args.repetitions}
- Worker records: {len(schedule)}
- Schedule: one seeded random permutation of all conditions
- All in-run gates pass: {summary['gates']['all_gates_pass']}

## Claim boundary

The results describe one single-process, single-core Python reference engine.
They exclude file acquisition, policy distribution, relying-party refresh, RTR,
router installation, forwarding, and end-to-end convergence.  IPv4/IPv6 values
are descriptive and do not establish address-family equivalence or causality.
"""
    (run_dir / "RUN_REPORT.md").write_text(report, encoding="utf-8")
    write_artifact_manifest(run_dir)

    audit_command = [
        sys.executable, str(AUDIT_SCRIPT), str(run_dir),
        "--output", str(run_dir / "independent_audit.json"),
    ]
    completed = subprocess.run(
        audit_command, check=True, capture_output=True, text=True,
        env=environment,
    )
    for line in completed.stdout.splitlines():
        log(f"audit: {line}")
    log("run complete; independent raw audit passed")
    print(str(run_dir), flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run")
    run.add_argument("--run-id")
    run.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    run.add_argument("--source-run", type=Path, default=DEFAULT_SOURCE_RUN)
    run.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS)
    run.add_argument("--cpu", type=int, default=DEFAULT_CPU)
    run.add_argument("--seed", type=int, default=DEFAULT_SEED)
    run.set_defaults(handler=run_orchestrator)

    worker = subparsers.add_parser("worker-update")
    worker.add_argument("--open-policy", type=Path, required=True)
    worker.add_argument("--closed-policy", type=Path, required=True)
    worker.add_argument("--queries", type=Path, required=True)
    worker.add_argument("--probe-index", type=int, required=True)
    worker.add_argument("--rules", type=int, required=True)
    worker.add_argument("--ip-version", type=int, choices=IP_VERSIONS, required=True)
    worker.add_argument("--repetition", type=int, required=True)
    worker.add_argument("--schedule-index", type=int, required=True)
    worker.add_argument("--nonce", required=True)
    worker.add_argument("--cpu", type=int, required=True)
    worker.add_argument("--output", type=Path, required=True)
    worker.set_defaults(handler=worker_update)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
