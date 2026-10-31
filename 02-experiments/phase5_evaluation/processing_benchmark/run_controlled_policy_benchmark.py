#!/usr/bin/env python3
"""Controlled dual-stack OpenScope-marker processing benchmark.

The benchmark separates in-memory policy loading from steady-state route
classification.  Within each address family, every policy size reuses one
fixed query set and produces one fixed state vector.
"""

from __future__ import annotations

import argparse
import csv
import gc
import hashlib
import ipaddress
import json
import math
import os
import platform
import random
import resource
import statistics
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


SCRIPT = Path(__file__).resolve()
BENCHMARK_DIR = SCRIPT.parent
REPO_ROOT = SCRIPT.parents[2]
PHASE4_SCRIPTS = REPO_ROOT / "phase4_encoding" / "scripts"
if str(PHASE4_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PHASE4_SCRIPTS))

from utils.daroa import (  # noqa: E402
    DAROA,
    Stripe,
    ValidationState,
    is_eligible_delegated_origin,
)


SCHEMA_VERSION = "controlled-policy-processing-v1"
DEFAULT_OUTPUT_ROOT = BENCHMARK_DIR / "outputs"
DEFAULT_IPV4_WORKLOAD = (
    BENCHMARK_DIR
    / "outputs"
    / "processing-ipv4-dualstack-20260828"
    / "input"
    / "rrc00_20260624_ipv4_prefix_origins.csv"
)
DEFAULT_IPV6_WORKLOAD = (
    BENCHMARK_DIR
    / "outputs"
    / "processing-ipv6-dualstack-20260829"
    / "input"
    / "rrc00_20260624_ipv6_prefix_origins.csv"
)
FAMILY_CONFIG = {
    4: {
        "label": "IPv4",
        "base_prefix": "38.0.0.0/8",
        "holder_asn": 174,
        "max_length": 32,
    },
    6: {
        "label": "IPv6",
        "base_prefix": "2409:8000::/20",
        "holder_asn": 9808,
        "max_length": 128,
    },
}
DEFAULT_SUBPREFIX_COUNTS = (0, 64, 256)
DEFAULT_LOAD_REPETITIONS = 20
DEFAULT_CLASSIFY_REPETITIONS = 5
DEFAULT_QUERY_COUNT = 8192
DEFAULT_QUERY_LOOPS = 16
DEFAULT_BATCH_SIZE = 4096
DEFAULT_WARMUP = 8192
DEFAULT_SEED = 20260829
STATE_CODE = {
    ValidationState.EXPLICIT: 1,
    ValidationState.DELEGATED: 2,
    ValidationState.INVALID: 3,
    ValidationState.NOT_FOUND: 4,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def percentile(values: Sequence[float], probability: float) -> float:
    if not values:
        raise ValueError("cannot compute a percentile of an empty sequence")
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    fraction = position - lower
    return float(ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction)


def max_rss_kib() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform == "darwin":
        value //= 1024
    return value


def current_rss_kib() -> int | None:
    status = Path("/proc/self/status")
    if not status.exists():
        return None
    for line in status.read_text(encoding="utf-8").splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return None


def pin_to_cpu(cpu: int | None) -> int | None:
    if cpu is None or not hasattr(os, "sched_setaffinity"):
        return None
    os.sched_setaffinity(0, {cpu})
    observed = sorted(os.sched_getaffinity(0))
    if observed != [cpu]:
        raise RuntimeError(f"failed to pin worker to CPU {cpu}: {observed}")
    return cpu


def network_key(network: ipaddress._BaseNetwork) -> tuple[int, int]:
    return network.prefixlen, int(network.network_address)


def ancestor_key(
    network: ipaddress._BaseNetwork, prefix_length: int
) -> tuple[int, int]:
    address_bits = network.max_prefixlen
    address = int(network.network_address)
    if prefix_length == 0:
        return 0, 0
    full_mask = (1 << address_bits) - 1
    mask = (full_mask << (address_bits - prefix_length)) & full_mask
    return prefix_length, address & mask


def deterministic_order(
    values: Iterable[tuple[str, int]], *, seed: int, role: str
) -> list[tuple[str, int]]:
    return sorted(
        values,
        key=lambda item: (
            sha256_text(f"{seed}|{role}|{item[0]}|{item[1]}"),
            item[0],
            item[1],
        ),
    )


def read_family_rows(
    workload_path: Path,
    *,
    ip_version: int,
    base_prefix: str,
) -> tuple[list[tuple[str, int]], dict[str, Any]]:
    base = ipaddress.ip_network(base_prefix, strict=True)
    if base.version != ip_version:
        raise ValueError("base prefix and requested IP version differ")
    rows: list[tuple[str, int]] = []
    scanned = 0
    with workload_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ["prefix", "origin_as"]:
            raise ValueError(f"unexpected workload header: {reader.fieldnames!r}")
        for raw in reader:
            scanned += 1
            network = ipaddress.ip_network(raw["prefix"], strict=True)
            if network.version != ip_version:
                raise ValueError(f"mixed address family in {workload_path}: {network}")
            if network.subnet_of(base):
                rows.append((str(network), int(raw["origin_as"])))
    if not rows:
        raise ValueError(f"no rows under {base_prefix} in {workload_path}")
    return rows, {
        "workload_path": str(workload_path.resolve()),
        "workload_sha256": sha256_file(workload_path),
        "rows_scanned": scanned,
        "rows_under_base": len(rows),
    }


def select_fixture(
    rows: Sequence[tuple[str, int]],
    *,
    ip_version: int,
    base_prefix: str,
    holder_asn: int,
    max_subprefixes: int,
    query_count: int,
    seed: int,
) -> dict[str, Any]:
    """Select pairwise noncovering child entries and fixed OpenScope queries."""
    base = ipaddress.ip_network(base_prefix, strict=True)
    by_prefix: dict[str, set[int]] = {}
    for prefix, origin in rows:
        network = ipaddress.ip_network(prefix, strict=True)
        if network.version != ip_version or not network.subnet_of(base):
            raise ValueError(f"row outside fixture base: {prefix}")
        by_prefix.setdefault(str(network), set()).add(int(origin))

    observed_base_origins = by_prefix.get(str(base), set())
    if holder_asn not in observed_base_origins:
        raise ValueError(
            f"frozen base origin AS{holder_asn} not observed at {base_prefix}: "
            f"{sorted(observed_base_origins)}"
        )

    prefix_records = {
        prefix: (ipaddress.ip_network(prefix, strict=True), min(origins))
        for prefix, origins in by_prefix.items()
    }
    key_to_prefix = {
        network_key(network): prefix
        for prefix, (network, _origin) in prefix_records.items()
    }
    nonleaf_keys: set[tuple[int, int]] = set()
    for network, _origin in prefix_records.values():
        for length in range(base.prefixlen, network.prefixlen):
            key = ancestor_key(network, length)
            if key in key_to_prefix:
                nonleaf_keys.add(key)

    leaves = []
    for prefix, (network, origin) in prefix_records.items():
        key = network_key(network)
        if network == base or key in nonleaf_keys:
            continue
        leaves.append((prefix, origin))
    ordered_leaves = deterministic_order(leaves, seed=seed, role=f"ipv{ip_version}-child")
    if len(ordered_leaves) < max_subprefixes:
        raise ValueError(
            f"need {max_subprefixes} leaf prefixes under {base}, found "
            f"{len(ordered_leaves)}"
        )
    selected_children = ordered_leaves[:max_subprefixes]
    selected_index = {
        network_key(ipaddress.ip_network(prefix, strict=True))
        for prefix, _origin in selected_children
    }

    def covered_by_selected(network: ipaddress._BaseNetwork) -> bool:
        for length in range(network.prefixlen, base.prefixlen - 1, -1):
            if ancestor_key(network, length) in selected_index:
                return True
        return False

    query_candidates: set[tuple[str, int]] = set()
    for prefix, origin in rows:
        network = ipaddress.ip_network(prefix, strict=True)
        if network == base:
            continue
        if origin == holder_asn or not is_eligible_delegated_origin(origin):
            continue
        if covered_by_selected(network):
            continue
        query_candidates.add((str(network), int(origin)))
    ordered_queries = deterministic_order(
        query_candidates,
        seed=seed,
        role=f"ipv{ip_version}-query",
    )
    if len(ordered_queries) < query_count:
        raise ValueError(
            f"need {query_count} fixed queries under {base}, found "
            f"{len(ordered_queries)}"
        )
    queries = ordered_queries[:query_count]

    return {
        "ip_version": ip_version,
        "label": FAMILY_CONFIG[ip_version]["label"],
        "base_prefix": str(base),
        "holder_asn": holder_asn,
        "unique_observed_prefixes": len(prefix_records),
        "multi_origin_prefixes": sum(len(origins) > 1 for origins in by_prefix.values()),
        "leaf_prefixes": len(leaves),
        "selected_children": [
            {"prefix": prefix, "origin": origin}
            for prefix, origin in selected_children
        ],
        "selected_children_sha256": sha256_text(
            "".join(f"{prefix},{origin}\n" for prefix, origin in selected_children)
        ),
        "eligible_query_candidates": len(ordered_queries),
        "queries": [
            {"prefix": prefix, "origin": origin} for prefix, origin in queries
        ],
        "queries_sha256": sha256_text(
            "".join(f"{prefix},{origin}\n" for prefix, origin in queries)
        ),
    }


def build_policy(
    fixture: dict[str, Any], subprefix_count: int
) -> tuple[DAROA, bytes, dict[str, Any]]:
    children = fixture["selected_children"]
    if not 0 <= subprefix_count <= len(children):
        raise ValueError(f"invalid subprefix count: {subprefix_count}")
    base_prefix = fixture["base_prefix"]
    holder_asn = int(fixture["holder_asn"])
    stripes = [Stripe(base_prefix, frozenset({holder_asn}), True)]
    for child in children[:subprefix_count]:
        stripes.append(
            Stripe(
                str(child["prefix"]),
                frozenset({int(child["origin"])}),
                False,
            )
        )
    policy = DAROA(
        base_prefix,
        int(FAMILY_CONFIG[int(fixture["ip_version"])]["max_length"]),
        holder_asn,
        stripes,
    )
    payload = policy.serialize()
    decoded = DAROA.deserialize(payload)
    if decoded.serialize() != payload:
        raise AssertionError("policy round trip is not byte-identical")
    if len(decoded.stripes) != subprefix_count + 1:
        raise AssertionError("policy entry count mismatch")
    spec = {
        "schema_version": SCHEMA_VERSION,
        "ip_version": fixture["ip_version"],
        "base_prefix": base_prefix,
        "holder_asn": holder_asn,
        "max_length": FAMILY_CONFIG[int(fixture["ip_version"])]["max_length"],
        "subprefix_entries": subprefix_count,
        "total_policy_entries": subprefix_count + 1,
        "construction": (
            "one observed base entry carrying an OpenScope marker plus a "
            "fixed-seed prefix of the ordered unmarked observed leaf entries"
        ),
        "entries": [
            {
                "prefix": stripe.prefix,
                "origins": sorted(stripe.as_set),
                "open": stripe.is_open,
            }
            for stripe in decoded.stripes
        ],
        "serialized_bytes": len(payload),
        "serialized_sha256": hashlib.sha256(payload).hexdigest(),
        "roundtrip_identical": True,
    }
    return decoded, payload, spec


def write_query_file(path: Path, fixture: dict[str, Any]) -> dict[str, Any]:
    document = {
        "schema_version": SCHEMA_VERSION,
        "ip_version": fixture["ip_version"],
        "base_prefix": fixture["base_prefix"],
        "holder_asn": fixture["holder_asn"],
        "expected_internal_state": ValidationState.DELEGATED.value,
        "manuscript_state": "OpenScope",
        "queries": fixture["queries"],
    }
    write_json(path, document)
    return {
        "path": str(path.resolve()),
        "file_sha256": sha256_file(path),
        "content_sha256": fixture["queries_sha256"],
        "query_count": len(fixture["queries"]),
    }


def read_queries(path: Path) -> tuple[list[tuple[str, int]], dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    queries = [
        (str(item["prefix"]), int(item["origin"])) for item in document["queries"]
    ]
    return queries, document


def worker_load(args: argparse.Namespace) -> int:
    cpu = pin_to_cpu(args.cpu)
    payload = args.policy.read_bytes()
    rss_before = current_rss_kib()
    gc.collect()
    started = time.perf_counter_ns()
    policy = DAROA.deserialize(payload)
    load_ns = time.perf_counter_ns() - started
    rss_after = current_rss_kib()
    roundtrip_identical = policy.serialize() == payload
    if not roundtrip_identical:
        raise AssertionError("load worker policy round trip failed")
    result = {
        "schema_version": SCHEMA_VERSION,
        "created_utc": utc_now(),
        "worker": "load",
        "ip_version": policy.ip_version,
        "subprefix_entries": len(policy.stripes) - 1,
        "total_policy_entries": len(policy.stripes),
        "repetition": args.repetition,
        "schedule_index": args.schedule_index,
        "cpu_affinity": cpu,
        "worker_pid": os.getpid(),
        "serialized_bytes": len(payload),
        "serialized_sha256": hashlib.sha256(payload).hexdigest(),
        "load_ns": load_ns,
        "load_scope": (
            "in-memory decoding, canonicalization, validation, and index construction"
        ),
        "file_read_excluded": True,
        "rss_before_kib": rss_before,
        "rss_after_kib": rss_after,
        "rss_delta_kib": (
            None if rss_before is None or rss_after is None else rss_after - rss_before
        ),
        "peak_rss_kib": max_rss_kib(),
        "roundtrip_identical": roundtrip_identical,
        "python": sys.version,
        "platform": platform.platform(),
    }
    write_json(args.output, result)
    print(
        f"load IPv{policy.ip_version} subprefixes={len(policy.stripes)-1} "
        f"rep={args.repetition} {load_ns / 1e6:.3f} ms",
        flush=True,
    )
    return 0


def worker_classify(args: argparse.Namespace) -> int:
    cpu = pin_to_cpu(args.cpu)
    payload = args.policy.read_bytes()
    policy = DAROA.deserialize(payload)
    queries, query_document = read_queries(args.queries)
    if not queries:
        raise ValueError("query set is empty")
    if len(queries) != args.query_count:
        raise ValueError(f"query count mismatch: {len(queries)} != {args.query_count}")

    for index in range(args.warmup):
        prefix, origin = queries[index % len(queries)]
        policy.validate_route(prefix, origin)

    counts: Counter[str] = Counter()
    checksum = hashlib.sha256()
    batch_records: list[dict[str, int]] = []
    gc.collect()
    gc.disable()
    try:
        for loop_index in range(args.query_loops):
            for begin in range(0, len(queries), args.batch_size):
                batch = queries[begin : begin + args.batch_size]
                codes = bytearray()
                started = time.perf_counter_ns()
                for prefix, origin in batch:
                    state = policy.validate_route(prefix, origin)
                    codes.append(STATE_CODE[state])
                    counts[state.value] += 1
                elapsed_ns = time.perf_counter_ns() - started
                checksum.update(codes)
                batch_records.append(
                    {
                        "loop": loop_index,
                        "begin": begin,
                        "rows": len(batch),
                        "elapsed_ns": elapsed_ns,
                    }
                )
    finally:
        gc.enable()

    timed_calls = sum(item["rows"] for item in batch_records)
    timed_ns = sum(item["elapsed_ns"] for item in batch_records)
    expected_calls = args.query_count * args.query_loops
    if timed_calls != expected_calls:
        raise AssertionError(f"timed call count mismatch: {timed_calls} != {expected_calls}")
    expected_state = query_document["expected_internal_state"]
    if counts != Counter({expected_state: expected_calls}):
        raise AssertionError(f"fixed-state gate failed: {dict(counts)}")

    result = {
        "schema_version": SCHEMA_VERSION,
        "created_utc": utc_now(),
        "worker": "classify",
        "ip_version": policy.ip_version,
        "subprefix_entries": len(policy.stripes) - 1,
        "total_policy_entries": len(policy.stripes),
        "repetition": args.repetition,
        "schedule_index": args.schedule_index,
        "cpu_affinity": cpu,
        "worker_pid": os.getpid(),
        "serialized_bytes": len(payload),
        "serialized_sha256": hashlib.sha256(payload).hexdigest(),
        "query_file_sha256": sha256_file(args.queries),
        "query_content_sha256": sha256_text(
            "".join(f"{prefix},{origin}\n" for prefix, origin in queries)
        ),
        "distinct_queries": len(queries),
        "query_loops": args.query_loops,
        "warmup_calls": args.warmup,
        "timed_calls": timed_calls,
        "timed_ns": timed_ns,
        "pairs_per_second": timed_calls * 1_000_000_000 / timed_ns,
        "batch_size": args.batch_size,
        "batches": batch_records,
        "result_checksum_sha256": checksum.hexdigest(),
        "state_counts": dict(sorted(counts.items())),
        "all_results_open_scope": counts == Counter({expected_state: expected_calls}),
        "peak_rss_kib": max_rss_kib(),
        "roundtrip_identical": policy.serialize() == payload,
        "timed_scope": "validate_route plus state capture over preloaded query tuples",
        "internal_cidr_parsing_included": True,
        "python": sys.version,
        "platform": platform.platform(),
    }
    write_json(args.output, result)
    print(
        f"classify IPv{policy.ip_version} subprefixes={len(policy.stripes)-1} "
        f"rep={args.repetition} {result['pairs_per_second'] / 1000:.1f} k pairs/s",
        flush=True,
    )
    return 0


def summarize(run_dir: Path, schedule: Sequence[dict[str, Any]]) -> dict[str, Any]:
    raw_records = [
        json.loads(Path(item["raw_json"]).read_text(encoding="utf-8"))
        for item in schedule
    ]
    rows = []
    for ip_version in sorted(FAMILY_CONFIG):
        for subprefixes in sorted(
            {
                int(record["subprefix_entries"])
                for record in raw_records
                if int(record["ip_version"]) == ip_version
            }
        ):
            load = [
                record
                for record in raw_records
                if record["worker"] == "load"
                and int(record["ip_version"]) == ip_version
                and int(record["subprefix_entries"]) == subprefixes
            ]
            classify = [
                record
                for record in raw_records
                if record["worker"] == "classify"
                and int(record["ip_version"]) == ip_version
                and int(record["subprefix_entries"]) == subprefixes
            ]
            load_ms = [float(record["load_ns"]) / 1e6 for record in load]
            classify_kpps = [
                float(record["pairs_per_second"]) / 1000 for record in classify
            ]
            batch_ms = [
                float(batch["elapsed_ns"]) / 1e6
                for record in classify
                for batch in record["batches"]
            ]
            payload_values = {
                int(record["serialized_bytes"]) for record in load + classify
            }
            if len(payload_values) != 1:
                raise AssertionError("multiple payload sizes within one cell")
            rows.append(
                {
                    "ip_version": ip_version,
                    "label": FAMILY_CONFIG[ip_version]["label"],
                    "subprefix_entries": subprefixes,
                    "total_policy_entries": subprefixes + 1,
                    "serialized_bytes": payload_values.pop(),
                    "load_repetitions": len(load),
                    "load_ms_mean": statistics.fmean(load_ms),
                    "load_ms_median": statistics.median(load_ms),
                    "load_ms_q1": percentile(load_ms, 0.25),
                    "load_ms_q3": percentile(load_ms, 0.75),
                    "classify_repetitions": len(classify),
                    "classify_kpairs_s_mean": statistics.fmean(classify_kpps),
                    "classify_kpairs_s_median": statistics.median(classify_kpps),
                    "classify_kpairs_s_min": min(classify_kpps),
                    "classify_kpairs_s_max": max(classify_kpps),
                    "batch_ms_p50": percentile(batch_ms, 0.50),
                    "batch_ms_p95": percentile(batch_ms, 0.95),
                    "batch_ms_p99": percentile(batch_ms, 0.99),
                }
            )

    classify_records = [record for record in raw_records if record["worker"] == "classify"]
    load_records = [record for record in raw_records if record["worker"] == "load"]
    gates: dict[str, Any] = {
        "raw_worker_records": len(raw_records),
        "expected_worker_records": len(schedule),
        "all_worker_records_present": len(raw_records) == len(schedule),
        "all_workers_on_scheduled_cpu": all(
            record["cpu_affinity"] == schedule_item["cpu"]
            for record, schedule_item in zip(raw_records, schedule)
        ),
        "all_roundtrips_identical": all(
            bool(record["roundtrip_identical"]) for record in raw_records
        ),
        "all_classification_results_open_scope": all(
            bool(record["all_results_open_scope"]) for record in classify_records
        ),
        "expected_load_records": sum(item["worker"] == "load" for item in schedule),
        "observed_load_records": len(load_records),
        "expected_classify_records": sum(
            item["worker"] == "classify" for item in schedule
        ),
        "observed_classify_records": len(classify_records),
    }
    per_family = {}
    for ip_version in sorted(FAMILY_CONFIG):
        selected = [
            record
            for record in classify_records
            if int(record["ip_version"]) == ip_version
        ]
        per_family[str(ip_version)] = {
            "query_file_sha256_values": sorted(
                {record["query_file_sha256"] for record in selected}
            ),
            "query_content_sha256_values": sorted(
                {record["query_content_sha256"] for record in selected}
            ),
            "result_checksum_values": sorted(
                {record["result_checksum_sha256"] for record in selected}
            ),
            "state_count_vectors": sorted(
                {
                    json.dumps(record["state_counts"], sort_keys=True)
                    for record in selected
                }
            ),
        }
        per_family[str(ip_version)]["one_query_file_across_sizes"] = (
            len(per_family[str(ip_version)]["query_file_sha256_values"]) == 1
        )
        per_family[str(ip_version)]["one_query_content_across_sizes"] = (
            len(per_family[str(ip_version)]["query_content_sha256_values"]) == 1
        )
        per_family[str(ip_version)]["one_result_checksum_across_sizes"] = (
            len(per_family[str(ip_version)]["result_checksum_values"]) == 1
        )
        per_family[str(ip_version)]["one_state_vector_across_sizes"] = (
            len(per_family[str(ip_version)]["state_count_vectors"]) == 1
        )
    gates["per_family"] = per_family
    gate_values = [
        gates["all_worker_records_present"],
        gates["all_workers_on_scheduled_cpu"],
        gates["all_roundtrips_identical"],
        gates["all_classification_results_open_scope"],
        gates["expected_load_records"] == gates["observed_load_records"],
        gates["expected_classify_records"] == gates["observed_classify_records"],
    ]
    for family in per_family.values():
        gate_values.extend(
            [
                family["one_query_file_across_sizes"],
                family["one_query_content_across_sizes"],
                family["one_result_checksum_across_sizes"],
                family["one_state_vector_across_sizes"],
            ]
        )
    gates["all_gates_pass"] = all(gate_values)
    if not gates["all_gates_pass"]:
        raise AssertionError(f"controlled benchmark gates failed: {gates}")

    summary = {
        "schema_version": SCHEMA_VERSION,
        "created_utc": utc_now(),
        "rows": rows,
        "gates": gates,
    }
    write_json(run_dir / "summary.json", summary)

    with (run_dir / "summary.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = [
            "ip_version",
            "label",
            "subprefix_entries",
            "total_policy_entries",
            "serialized_bytes",
            "load_repetitions",
            "load_ms_mean",
            "load_ms_median",
            "load_ms_q1",
            "load_ms_q3",
            "classify_repetitions",
            "classify_kpairs_s_mean",
            "classify_kpairs_s_median",
            "classify_kpairs_s_min",
            "classify_kpairs_s_max",
            "batch_ms_p50",
            "batch_ms_p95",
            "batch_ms_p99",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    table_lines = [
        r"\begin{tabular}{@{}lrrr@{}}",
        r"\toprule",
        r"IP version & Rules & Load & Classify \\",
        r" & & (ms) & (k pairs/s) \\",
        r"\midrule",
    ]
    for row in rows:
        table_lines.append(
            f"{row['label']} & {row['total_policy_entries']:,} & "
            f"{row['load_ms_mean']:.1f} & "
            f"{row['classify_kpairs_s_mean']:.1f} \\\\" 
        )
    table_lines.extend([r"\bottomrule", r"\end{tabular}", ""])
    (run_dir / "paper_table.tex").write_text("\n".join(table_lines), encoding="utf-8")
    return summary


def build_schedule(
    run_dir: Path,
    *,
    subprefix_counts: Sequence[int],
    load_repetitions: int,
    classify_repetitions: int,
    seed: int,
    cpu: int,
) -> list[dict[str, Any]]:
    schedule = []
    rng = random.Random(seed)
    index = 0
    for worker, repetitions in (
        ("load", load_repetitions),
        ("classify", classify_repetitions),
    ):
        for repetition in range(1, repetitions + 1):
            cells = [
                (ip_version, subprefixes)
                for ip_version in sorted(FAMILY_CONFIG)
                for subprefixes in subprefix_counts
            ]
            rng.shuffle(cells)
            for ip_version, subprefixes in cells:
                raw_path = run_dir / "raw" / (
                    f"{index:03d}-{worker}-ipv{ip_version}-subprefixes-"
                    f"{subprefixes}-rep-{repetition}.json"
                )
                schedule.append(
                    {
                        "schedule_index": index,
                        "worker": worker,
                        "repetition": repetition,
                        "ip_version": ip_version,
                        "subprefix_entries": subprefixes,
                        "cpu": cpu,
                        "raw_json": str(raw_path.resolve()),
                    }
                )
                index += 1
    write_json(run_dir / "schedule.json", schedule)
    return schedule


def run_orchestrator(args: argparse.Namespace) -> int:
    run_id = args.run_id or datetime.now(timezone.utc).strftime(
        "controlled-processing-%Y%m%dT%H%M%SZ"
    )
    run_dir = args.output_root.resolve() / run_id
    if run_dir.exists():
        raise FileExistsError(f"refusing to overwrite existing run: {run_dir}")
    (run_dir / "raw").mkdir(parents=True)
    (run_dir / "policies").mkdir()
    (run_dir / "queries").mkdir()
    log_path = run_dir / "driver.log"

    def log(message: str) -> None:
        line = f"[{utc_now()}] {message}"
        print(line, flush=True)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    workload_paths = {4: args.ipv4_workload.resolve(), 6: args.ipv6_workload.resolve()}
    max_subprefixes = max(args.subprefix_counts)
    fixture_manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "created_utc": utc_now(),
        "seed": args.seed,
        "max_selected_subprefixes": max_subprefixes,
        "query_count": args.query_count,
        "families": {},
    }
    policy_paths: dict[tuple[int, int], Path] = {}
    query_paths: dict[int, Path] = {}

    for ip_version in sorted(FAMILY_CONFIG):
        config = FAMILY_CONFIG[ip_version]
        log(f"selecting controlled {config['label']} fixture")
        rows, workload_manifest = read_family_rows(
            workload_paths[ip_version],
            ip_version=ip_version,
            base_prefix=str(config["base_prefix"]),
        )
        fixture = select_fixture(
            rows,
            ip_version=ip_version,
            base_prefix=str(config["base_prefix"]),
            holder_asn=int(config["holder_asn"]),
            max_subprefixes=max_subprefixes,
            query_count=args.query_count,
            seed=args.seed,
        )
        query_path = run_dir / "queries" / f"ipv{ip_version}-queries.json"
        query_manifest = write_query_file(query_path, fixture)
        query_paths[ip_version] = query_path
        fixture_manifest["families"][str(ip_version)] = {
            **workload_manifest,
            **{key: value for key, value in fixture.items() if key not in {"queries"}},
            "query_file": query_manifest,
        }
        log(
            f"{config['label']}: {fixture['leaf_prefixes']:,} observed leaves; "
            f"{fixture['eligible_query_candidates']:,} eligible query candidates"
        )

        for subprefixes in args.subprefix_counts:
            _policy, payload, spec = build_policy(fixture, subprefixes)
            policy_path = run_dir / "policies" / (
                f"ipv{ip_version}-subprefixes-{subprefixes}.bin"
            )
            policy_path.write_bytes(payload)
            spec_path = policy_path.with_suffix(".json")
            spec["serialized_path"] = str(policy_path.resolve())
            spec["spec_path"] = str(spec_path.resolve())
            write_json(spec_path, spec)
            policy_paths[(ip_version, subprefixes)] = policy_path
            log(
                f"{config['label']} subprefixes={subprefixes}: "
                f"{len(payload):,} bytes"
            )

    write_json(run_dir / "selection_manifest.json", fixture_manifest)

    cpu = args.cpu
    available = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else []
    if available and cpu not in available:
        raise ValueError(f"CPU {cpu} is not available: {available}")
    git_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    git_dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    config = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "created_utc": utc_now(),
        "subprefix_counts": list(args.subprefix_counts),
        "load_repetitions": args.load_repetitions,
        "classify_repetitions": args.classify_repetitions,
        "query_count": args.query_count,
        "query_loops": args.query_loops,
        "timed_calls_per_classify_worker": args.query_count * args.query_loops,
        "batch_size": args.batch_size,
        "warmup": args.warmup,
        "seed": args.seed,
        "cpu": cpu,
        "ipv4_workload": str(workload_paths[4]),
        "ipv6_workload": str(workload_paths[6]),
        "script": str(SCRIPT),
        "script_sha256": sha256_file(SCRIPT),
        "classifier": str(PHASE4_SCRIPTS / "utils" / "daroa.py"),
        "classifier_sha256": sha256_file(PHASE4_SCRIPTS / "utils" / "daroa.py"),
        "source_git_commit": git_commit,
        "source_worktree_dirty": git_dirty,
        "python": sys.version,
        "platform": platform.platform(),
    }
    write_json(run_dir / "run_config.json", config)

    schedule = build_schedule(
        run_dir,
        subprefix_counts=args.subprefix_counts,
        load_repetitions=args.load_repetitions,
        classify_repetitions=args.classify_repetitions,
        seed=args.seed,
        cpu=cpu,
    )
    environment = os.environ.copy()
    environment.update({"PYTHONHASHSEED": "0", "LC_ALL": "C"})
    for condition in schedule:
        policy_path = policy_paths[
            (int(condition["ip_version"]), int(condition["subprefix_entries"]))
        ]
        command = [
            sys.executable,
            str(SCRIPT),
            f"worker-{condition['worker']}",
            "--policy",
            str(policy_path),
            "--repetition",
            str(condition["repetition"]),
            "--schedule-index",
            str(condition["schedule_index"]),
            "--cpu",
            str(cpu),
            "--output",
            condition["raw_json"],
        ]
        if condition["worker"] == "classify":
            command.extend(
                [
                    "--queries",
                    str(query_paths[int(condition["ip_version"])]),
                    "--query-count",
                    str(args.query_count),
                    "--query-loops",
                    str(args.query_loops),
                    "--batch-size",
                    str(args.batch_size),
                    "--warmup",
                    str(args.warmup),
                ]
            )
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        for line in completed.stdout.splitlines():
            log(line)
        if completed.stderr:
            for line in completed.stderr.splitlines():
                log(f"worker stderr: {line}")

    summary = summarize(run_dir, schedule)
    report = f"""# Controlled dual-stack policy processing run

Run: `{run_id}`  
Generated: {utc_now()}

The run separates in-memory policy loading from steady-state classification.
Each address family reuses one fixed {args.query_count:,}-pair RRC00 query set at every policy
size.  All timed classifications return the internal `Delegated` state, which
corresponds to `OpenScope` in the manuscript.

## Configuration

- Subprefix entries: {', '.join(str(value) for value in args.subprefix_counts)}
- Load repetitions per cell: {args.load_repetitions}
- Classification repetitions per cell: {args.classify_repetitions}
- Timed calls per classification worker: {args.query_count * args.query_loops:,}
- Warm-up calls per classification worker: {args.warmup:,}
- CPU: {cpu}

## Result gate

- All scheduled worker records present: {summary['gates']['all_worker_records_present']}
- All workers pinned to CPU {cpu}: {summary['gates']['all_workers_on_scheduled_cpu']}
- All policy round trips byte-identical: {summary['gates']['all_roundtrips_identical']}
- Every timed result is OpenScope: {summary['gates']['all_classification_results_open_scope']}
- All gates pass: {summary['gates']['all_gates_pass']}

## Claim boundary

The measurements describe one single-process, single-core Python reference
implementation with one already selected policy.  They do not measure a
relying party, RTR transfer, FRR installation, forwarding, or line rate.
"""
    (run_dir / "RUN_REPORT.md").write_text(report, encoding="utf-8")
    log(f"run complete; all gates pass={summary['gates']['all_gates_pass']}")
    print(str(run_dir), flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run")
    run.add_argument("--run-id")
    run.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    run.add_argument("--ipv4-workload", type=Path, default=DEFAULT_IPV4_WORKLOAD)
    run.add_argument("--ipv6-workload", type=Path, default=DEFAULT_IPV6_WORKLOAD)
    run.add_argument(
        "--subprefix-counts",
        type=int,
        nargs="+",
        default=list(DEFAULT_SUBPREFIX_COUNTS),
    )
    run.add_argument("--load-repetitions", type=int, default=DEFAULT_LOAD_REPETITIONS)
    run.add_argument(
        "--classify-repetitions", type=int, default=DEFAULT_CLASSIFY_REPETITIONS
    )
    run.add_argument("--query-count", type=int, default=DEFAULT_QUERY_COUNT)
    run.add_argument("--query-loops", type=int, default=DEFAULT_QUERY_LOOPS)
    run.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    run.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    run.add_argument("--seed", type=int, default=DEFAULT_SEED)
    run.add_argument("--cpu", type=int, default=31)
    run.set_defaults(handler=run_orchestrator)

    load = subparsers.add_parser("worker-load")
    load.add_argument("--policy", type=Path, required=True)
    load.add_argument("--repetition", type=int, required=True)
    load.add_argument("--schedule-index", type=int, required=True)
    load.add_argument("--cpu", type=int, required=True)
    load.add_argument("--output", type=Path, required=True)
    load.set_defaults(handler=worker_load)

    classify = subparsers.add_parser("worker-classify")
    classify.add_argument("--policy", type=Path, required=True)
    classify.add_argument("--queries", type=Path, required=True)
    classify.add_argument("--query-count", type=int, required=True)
    classify.add_argument("--query-loops", type=int, required=True)
    classify.add_argument("--batch-size", type=int, required=True)
    classify.add_argument("--warmup", type=int, required=True)
    classify.add_argument("--repetition", type=int, required=True)
    classify.add_argument("--schedule-index", type=int, required=True)
    classify.add_argument("--cpu", type=int, required=True)
    classify.add_argument("--output", type=Path, required=True)
    classify.set_defaults(handler=worker_classify)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "run":
        if sorted(set(args.subprefix_counts)) != sorted(args.subprefix_counts):
            raise ValueError("subprefix counts must be unique and sorted")
        if min(args.subprefix_counts) < 0:
            raise ValueError("subprefix counts cannot be negative")
        if args.batch_size <= 0 or args.query_count <= 0 or args.query_loops <= 0:
            raise ValueError("query and batch parameters must be positive")
        if args.query_count % args.batch_size:
            raise ValueError("query count must be divisible by batch size")
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
