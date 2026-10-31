#!/usr/bin/env python3
"""Reproducible single-core IPv6 replay for the S2-ROV-encoding classifier.

The source is the mixed-family RRC00 prefix-origin CSV used by the IPv4
benchmark.  This companion filters it to canonical, scalar-origin IPv6 pairs
and evaluates deterministic IPv6 policies in one fresh worker per condition.

The two timing scopes are identical in intent to the IPv4 benchmark:

* ``parse_excluded`` preloads ``(prefix, origin)`` pairs before timing.
* ``parse_included`` additionally times CSV decoding and ASN conversion.

The public classifier parses the textual CIDR in both scopes.  This is a
reference-classifier benchmark, not an FRR, RTR, forwarding, or line-rate test.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import platform
import random
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


SCRIPT = Path(__file__).resolve()
BENCHMARK_DIR = SCRIPT.parent
REPO_ROOT = SCRIPT.parents[2]
S2ROV_CODEC_SCRIPTS = REPO_ROOT / "implementation" / "s2rov_codec" / "scripts"
LEGACY_BENCHMARK = BENCHMARK_DIR / "run_processing_benchmark.py"
sys.path.insert(0, str(BENCHMARK_DIR))
sys.path.insert(0, str(S2ROV_CODEC_SCRIPTS))

# Reuse only family-neutral, non-reporting mechanics from the audited IPv4
# driver.  IPv6 preparation, policy construction, labels, reports, and output
# paths remain independent in this file.
from run_processing_benchmark import (  # noqa: E402
    CODE_STATE,
    STATE_CODE,
    current_cpu,
    independent_origin_is_eligible,
    iter_workload,
    max_rss_kib,
    percentile,
    pin_to_cpu,
    process_preloaded,
    process_streaming,
    sha256_file,
    utc_now,
)
from utils.s2rov import S2ROV, Stripe, ValidationState  # noqa: E402


SCHEMA_VERSION = 1
ADDRESS_FAMILY = "IPv6"
DEFAULT_INPUT = (
    REPO_ROOT
    / "experiments" / "candidates"
    / "allocation_tree"
    / "visibility_experiment"
    / "input"
    / "derived"
    / "rrc00_20260624_origins_fast.csv"
)
DEFAULT_OUTPUT_ROOT = BENCHMARK_DIR / "outputs"
DEFAULT_SIZES = (1, 64, 256, 1024, 4097)
DEFAULT_REPETITIONS = 3
DEFAULT_BATCH_SIZE = 4096
DEFAULT_WARMUP_ROUTES = 8192
DEFAULT_SEED = 20260828
TIMING_MODES = ("parse_excluded", "parse_included")

EXPECTED_SOURCE_ROWS = 1_393_270
EXPECTED_SOURCE_IPV4_ROWS = 1_135_687
EXPECTED_SOURCE_IPV6_ROWS = 257_583
EXPECTED_VALID_IPV6_ROWS = 257_550
EXPECTED_AMBIGUOUS_IPV6_ROWS = 33


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def prepare_ipv6_workload(
    source: Path,
    destination: Path,
    *,
    limit: int | None,
    max_policy_size: int,
    seed: int,
) -> dict[str, Any]:
    """Filter the mixed source into a canonical scalar-origin IPv6 workload."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    selected_children: list[dict[str, Any]] = []
    selected_prefixes: set[str] = set()
    reservoir: list[tuple[str, int]] = []
    rng = random.Random(seed)

    holder_asn: int | None = None
    source_rows = 0
    source_ipv4_rows = 0
    source_ipv6_rows = 0
    ambiguous_ipv6_rows = 0
    valid_ipv6_rows = 0

    with source.open(newline="", encoding="utf-8") as input_handle, destination.open(
        "w", newline="", encoding="utf-8"
    ) as output_handle:
        reader = csv.DictReader(input_handle)
        if reader.fieldnames != ["prefix", "origin_as"]:
            raise ValueError(f"unexpected source header: {reader.fieldnames!r}")
        writer = csv.writer(output_handle, lineterminator="\n")
        writer.writerow(["prefix", "origin_as"])

        for row in reader:
            source_rows += 1
            raw_prefix = row["prefix"]
            if ":" not in raw_prefix:
                source_ipv4_rows += 1
                continue

            source_ipv6_rows += 1
            network = ipaddress.IPv6Network(raw_prefix, strict=True)
            prefix = str(network)
            try:
                origin = int(row["origin_as"])
            except ValueError:
                ambiguous_ipv6_rows += 1
                continue
            if not 1 <= origin <= 0xFFFFFFFF:
                raise ValueError(f"origin ASN out of range at source row {source_rows}")

            if holder_asn is None:
                holder_asn = origin
            writer.writerow([prefix, origin])
            valid_ipv6_rows += 1

            if (
                prefix != "::/0"
                and prefix not in selected_prefixes
                and len(selected_children) < max_policy_size - 1
            ):
                selected_prefixes.add(prefix)
                selected_children.append({"prefix": prefix, "origin": origin})

            candidate = (prefix, origin)
            if len(reservoir) < 64:
                reservoir.append(candidate)
            else:
                replacement = rng.randrange(valid_ipv6_rows)
                if replacement < len(reservoir):
                    reservoir[replacement] = candidate

            if limit is not None and valid_ipv6_rows >= limit:
                break

    if holder_asn is None:
        raise ValueError("no scalar-origin IPv6 rows found")
    required_children = max_policy_size - 1
    if len(selected_children) < required_children:
        raise ValueError(
            f"need {required_children} unique non-/0 IPv6 prefixes, found "
            f"{len(selected_children)}"
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "address_family": ADDRESS_FAMILY,
        "source": str(source.resolve()),
        "source_sha256": sha256_file(source),
        "source_rows_scanned": source_rows,
        "source_ipv4_rows_skipped": source_ipv4_rows,
        "source_ipv6_rows": source_ipv6_rows,
        "source_ipv6_ambiguous_markers_excluded": ambiguous_ipv6_rows,
        "derived_workload": str(destination.resolve()),
        "derived_sha256": sha256_file(destination),
        "derived_bytes": destination.stat().st_size,
        "ipv6_rows": valid_ipv6_rows,
        "limit": limit,
        "holder_asn": holder_asn,
        "selected_children": selected_children,
        "reservoir_spots": [
            {"prefix": prefix, "origin": origin} for prefix, origin in reservoir
        ],
    }


def independent_ipv6_oracle(
    stripes: Sequence[dict[str, Any]],
    prefix: str,
    origin: int,
    *,
    base_prefix: str = "::/0",
    max_length: int = 128,
) -> str:
    """Independent conventional-match oracle for untimed IPv6 spot checks."""
    route = ipaddress.IPv6Network(prefix, strict=True)
    base = ipaddress.IPv6Network(base_prefix, strict=True)
    if not route.subnet_of(base):
        return ValidationState.NOT_FOUND.value
    if route.prefixlen > max_length:
        return ValidationState.INVALID.value

    covering: list[tuple[ipaddress.IPv6Network, dict[str, Any]]] = []
    for raw_stripe in stripes:
        stripe_net = ipaddress.IPv6Network(raw_stripe["prefix"], strict=True)
        if route.subnet_of(stripe_net):
            covering.append((stripe_net, raw_stripe))
    if not covering:
        return ValidationState.NOT_FOUND.value

    for network, stripe in covering:
        if origin not in stripe["origins"]:
            continue
        if network == base or network == route:
            return ValidationState.EXPLICIT.value

    if (
        independent_origin_is_eligible(origin)
        and any(
            stripe["is_open"] and route.prefixlen > network.prefixlen
            for network, stripe in covering
        )
    ):
        return ValidationState.DELEGATED.value
    return ValidationState.INVALID.value


def create_ipv6_policies(
    run_dir: Path,
    input_manifest: dict[str, Any],
    sizes: Sequence[int],
) -> dict[int, dict[str, Any]]:
    policies_dir = run_dir / "policies"
    policies_dir.mkdir(parents=True, exist_ok=True)
    holder = int(input_manifest["holder_asn"])
    children = list(input_manifest["selected_children"])
    reservoir = list(input_manifest["reservoir_spots"])
    policies: dict[int, dict[str, Any]] = {}

    for size in sizes:
        raw_stripes: list[dict[str, Any]] = [
            {"prefix": "::/0", "origins": [holder], "is_open": True}
        ]
        for item in children[: size - 1]:
            raw_stripes.append(
                {
                    "prefix": item["prefix"],
                    "origins": [int(item["origin"])],
                    "is_open": False,
                }
            )

        policy = S2ROV(
            "::/0",
            128,
            holder,
            [
                Stripe(
                    stripe["prefix"],
                    frozenset(int(value) for value in stripe["origins"]),
                    bool(stripe["is_open"]),
                )
                for stripe in raw_stripes
            ],
        )
        payload = policy.serialize()
        roundtrip = S2ROV.deserialize(payload)
        if roundtrip.serialize() != payload:
            raise AssertionError(f"IPv6 policy round trip failed for size {size}")
        if roundtrip.ip_version != 6:
            raise AssertionError(f"decoded policy is not IPv6 for size {size}")
        if len(roundtrip.stripes) != size:
            raise AssertionError(
                f"policy size mismatch: {len(roundtrip.stripes)} != {size}"
            )

        policy_path = policies_dir / f"policy-ipv6-{size}.bin"
        policy_path.write_bytes(payload)
        spec_path = policies_dir / f"policy-ipv6-{size}.json"
        spec = {
            "schema_version": SCHEMA_VERSION,
            "address_family": ADDRESS_FAMILY,
            "policy_size_stripes": size,
            "base_prefix": "::/0",
            "max_length": 128,
            "holder_asn": holder,
            "construction": (
                "one IPv6 /0 entry carrying an OpenScope marker plus the first "
                "policy_size-1 unique non-/0 IPv6 prefixes in source order, "
                "each unmarked and naming its first observed scalar origin"
            ),
            "stripes": raw_stripes,
            "serialized_path": str(policy_path.resolve()),
            "serialized_bytes": len(payload),
            "serialized_sha256": hashlib.sha256(payload).hexdigest(),
            "roundtrip_identical": True,
        }
        write_json(spec_path, spec)

        spot_inputs = list(reservoir)
        if size > 1:
            chosen = children[: size - 1]
            step = max(1, len(chosen) // 8)
            for child in chosen[::step][:8]:
                child_origin = int(child["origin"])
                spot_inputs.append(
                    {"prefix": child["prefix"], "origin": child_origin}
                )
                wrong_origin = 15169 if child_origin != 15169 else 18403
                spot_inputs.append(
                    {"prefix": child["prefix"], "origin": wrong_origin}
                )
        spot_inputs.extend(
            [
                {"prefix": "::/0", "origin": holder},
                {"prefix": "::/0", "origin": 15169},
                {"prefix": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "origin": 15169},
                {"prefix": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "origin": 64513},
            ]
        )
        spots = [
            {
                "prefix": item["prefix"],
                "origin": int(item["origin"]),
                "expected": independent_ipv6_oracle(
                    raw_stripes,
                    item["prefix"],
                    int(item["origin"]),
                    base_prefix="::/0",
                    max_length=128,
                ),
            }
            for item in spot_inputs
        ]
        spots_path = policies_dir / f"oracle-spots-ipv6-{size}.json"
        write_json(
            spots_path,
            {
                "schema_version": SCHEMA_VERSION,
                "address_family": ADDRESS_FAMILY,
                "policy_size_stripes": size,
                "oracle": (
                    "independent IPv6 conventional matching with base maxLength "
                    "and exact non-base ROAs, followed by proper-descendant "
                    "OpenScope markers"
                ),
                "checks": spots,
            },
        )

        policies[size] = {
            **spec,
            "spec_path": str(spec_path.resolve()),
            "oracle_spots_path": str(spots_path.resolve()),
            "oracle_spot_count": len(spots),
        }
    return policies


def load_ipv6_policy_and_check(
    policy_path: Path,
    spots_path: Path,
) -> tuple[S2ROV, dict[str, Any]]:
    payload = policy_path.read_bytes()
    parse_started = time.perf_counter_ns()
    policy = S2ROV.deserialize(payload)
    policy_parse_ns = time.perf_counter_ns() - parse_started
    roundtrip_identical = policy.serialize() == payload
    document = json.loads(spots_path.read_text(encoding="utf-8"))
    mismatches = []
    for item in document["checks"]:
        observed = policy.validate_route(item["prefix"], int(item["origin"])).value
        if observed != item["expected"]:
            mismatches.append({**item, "observed": observed})
    check = {
        "address_family_ipv6": policy.ip_version == 6,
        "base_prefix": policy.base_prefix,
        "max_length": policy.max_length,
        "roundtrip_identical": roundtrip_identical,
        "policy_parse_ns": policy_parse_ns,
        "oracle_spot_check_count": len(document["checks"]),
        "oracle_spot_check_mismatches": mismatches,
        "oracle_spot_checks_pass": not mismatches,
    }
    if (
        not check["address_family_ipv6"]
        or check["base_prefix"] != "::/0"
        or check["max_length"] != 128
        or not roundtrip_identical
        or mismatches
    ):
        raise AssertionError(f"IPv6 policy/oracle check failed: {check}")
    return policy, check


def warm_policy(policy: S2ROV, workload: Path, count: int) -> int:
    warmed = 0
    for prefix, origin in iter_workload(workload):
        policy.validate_route(prefix, origin)
        warmed += 1
        if warmed >= count:
            break
    return warmed


def run_worker(args: argparse.Namespace) -> int:
    cpu = pin_to_cpu(args.cpu)
    if cpu != args.cpu:
        raise RuntimeError(
            f"failed to pin worker to requested CPU {args.cpu}; observed {cpu}"
        )
    policy, checks = load_ipv6_policy_and_check(args.policy, args.oracle_spots)
    warmup_count = warm_policy(policy, args.workload, args.warmup_routes)

    preload_elapsed_ns = 0
    workload_rows: list[tuple[str, int]] | None = None
    if args.mode == "parse_excluded":
        preload_started = time.perf_counter_ns()
        workload_rows = list(iter_workload(args.workload))
        preload_elapsed_ns = time.perf_counter_ns() - preload_started

    import gc

    gc.collect()
    gc.disable()
    try:
        if args.mode == "parse_excluded":
            assert workload_rows is not None
            batches, checksum, counts = process_preloaded(
                policy, workload_rows, args.batch_size
            )
        else:
            batches, checksum, counts = process_streaming(
                policy, args.workload, args.batch_size
            )
    finally:
        gc.enable()

    route_count = sum(item["rows"] for item in batches)
    timed_elapsed_ns = sum(item["elapsed_ns"] for item in batches)
    result = {
        "schema_version": SCHEMA_VERSION,
        "created_utc": utc_now(),
        "address_family": ADDRESS_FAMILY,
        "worker_pid": os.getpid(),
        "mode": args.mode,
        "timed_scope": (
            "validate_route plus state capture over preloaded IPv6 prefix-origin pairs"
            if args.mode == "parse_excluded"
            else "IPv6 CSV row decoding, ASN integer conversion, validate_route, and state capture"
        ),
        "classifier_internal_cidr_parse_included_in_both_modes": True,
        "policy_size_stripes": len(policy.stripes),
        "base_prefix": policy.base_prefix,
        "max_length": policy.max_length,
        "serialized_bytes": args.policy.stat().st_size,
        "serialized_sha256": sha256_file(args.policy),
        "workload_path": str(args.workload.resolve()),
        "workload_sha256": sha256_file(args.workload),
        "route_count": route_count,
        "batch_size": args.batch_size,
        "full_batch_count": sum(item["rows"] == args.batch_size for item in batches),
        "partial_batch_count": sum(item["rows"] != args.batch_size for item in batches),
        "warmup_routes": warmup_count,
        "repetition": args.repetition,
        "schedule_index": args.schedule_index,
        "cpu_affinity": cpu,
        "timed_elapsed_ns": timed_elapsed_ns,
        "routes_per_second": route_count * 1_000_000_000 / timed_elapsed_ns,
        "preload_elapsed_ns_excluded_from_timing": preload_elapsed_ns,
        "peak_rss_kib": max_rss_kib(),
        "result_checksum_sha256": checksum,
        "state_counts": {
            name: int(counts.get(name, 0)) for name in CODE_STATE.values()
        },
        "batches": batches,
        "checks": checks,
        "python": sys.version,
        "platform": platform.platform(),
    }
    write_json(args.output, result)
    print(
        f"IPv6 worker {args.schedule_index:02d}: size={len(policy.stripes)} "
        f"mode={args.mode} rep={args.repetition} "
        f"routes/s={result['routes_per_second']:.0f} "
        f"rss={result['peak_rss_kib'] / 1024:.1f} MiB"
    )
    return 0


def markdown_table(rows: Sequence[dict[str, Any]]) -> str:
    lines = [
        "| Rules | Scope | Bytes | routes/s p50 | Batch ms p50/p95/p99 | Route us p50/p95/p99 | Peak RSS MiB |",
        "|---:|:---|---:|---:|:---|:---|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['policy_size_stripes']} | {row['mode']} | "
            f"{row['serialized_bytes']} | {row['routes_per_second_p50']:.0f} | "
            f"{row['batch_ms_p50']:.3f}/{row['batch_ms_p95']:.3f}/{row['batch_ms_p99']:.3f} | "
            f"{row['amortized_route_us_p50']:.3f}/{row['amortized_route_us_p95']:.3f}/{row['amortized_route_us_p99']:.3f} | "
            f"{row['peak_rss_mib_max']:.1f} |"
        )
    return "\n".join(lines)


def write_paper_table(
    path: Path,
    rows: Sequence[dict[str, Any]],
    batch_size: int,
) -> None:
    by_size: dict[int, dict[str, dict[str, Any]]] = {}
    for row in rows:
        by_size.setdefault(int(row["policy_size_stripes"]), {})[row["mode"]] = row
    lines = [
        r"% Generated from the IPv6 summary.csv; do not edit numeric values manually.",
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{IPv6 reference-classifier processing cost.}",
        r"\label{tab:processing-benchmark-ipv6}",
        r"\scriptsize",
        r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{rrrrr}",
        r"\toprule",
        r"Rules & Serialized KiB & \multicolumn{2}{c}{Throughput (k routes/s)} & Peak RSS MiB \\",
        r"\cmidrule(lr){3-4}",
        r" & & Parse excluded & Parse included & \\",
        r"\midrule",
    ]
    for size in sorted(by_size):
        excluded = by_size[size]["parse_excluded"]
        included = by_size[size]["parse_included"]
        peak_rss = max(
            float(excluded["peak_rss_mib_max"]),
            float(included["peak_rss_mib_max"]),
        )
        lines.append(
            f"{size} & {excluded['serialized_bytes'] / 1024:.2f} & "
            f"{excluded['routes_per_second_p50'] / 1000:.1f} & "
            f"{included['routes_per_second_p50'] / 1000:.1f} & "
            f"{peak_rss:.1f} \\\\"
        )
    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabular}",
            r"\vspace{1mm}",
            rf"\parbox{{\columnwidth}}{{\footnotesize Rules are classifier policy records. Parse excluded removes CSV decoding and ASN conversion; internal IPv6 CIDR parsing remains in both scopes. Results use one CPU and {batch_size:,}-route batches.}}",
            r"\end{table}",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def aggregate_run(
    run_dir: Path,
    schedule: Sequence[dict[str, Any]],
    expected_cpu: int,
) -> dict[str, Any]:
    raw_records = [
        json.loads(Path(condition["raw_json"]).read_text(encoding="utf-8"))
        for condition in schedule
    ]

    raw_csv_path = run_dir / "raw_runs.csv"
    raw_fields = [
        "schedule_index",
        "worker_pid",
        "repetition",
        "policy_size_stripes",
        "mode",
        "address_family",
        "route_count",
        "batch_size",
        "timed_elapsed_ns",
        "routes_per_second",
        "preload_elapsed_ns_excluded_from_timing",
        "peak_rss_kib",
        "cpu_affinity",
        "serialized_bytes",
        "result_checksum_sha256",
        "oracle_spot_check_count",
        "oracle_spot_checks_pass",
    ]
    with raw_csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=raw_fields, lineterminator="\n")
        writer.writeheader()
        for record in raw_records:
            writer.writerow(
                {
                    **{field: record.get(field, "") for field in raw_fields},
                    "oracle_spot_check_count": record["checks"][
                        "oracle_spot_check_count"
                    ],
                    "oracle_spot_checks_pass": record["checks"][
                        "oracle_spot_checks_pass"
                    ],
                }
            )

    batch_csv_path = run_dir / "raw_batch_samples.csv"
    batch_fields = [
        "schedule_index",
        "repetition",
        "policy_size_stripes",
        "mode",
        "batch_index",
        "batch_rows",
        "batch_elapsed_ns",
        "batch_elapsed_ms",
        "amortized_route_us",
        "full_batch",
    ]
    with batch_csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=batch_fields, lineterminator="\n")
        writer.writeheader()
        for record in raw_records:
            for index, batch in enumerate(record["batches"]):
                writer.writerow(
                    {
                        "schedule_index": record["schedule_index"],
                        "repetition": record["repetition"],
                        "policy_size_stripes": record["policy_size_stripes"],
                        "mode": record["mode"],
                        "batch_index": index,
                        "batch_rows": batch["rows"],
                        "batch_elapsed_ns": batch["elapsed_ns"],
                        "batch_elapsed_ms": f"{batch['elapsed_ns'] / 1_000_000:.9f}",
                        "amortized_route_us": f"{batch['elapsed_ns'] / batch['rows'] / 1000:.9f}",
                        "full_batch": batch["rows"] == record["batch_size"],
                    }
                )

    summary_rows: list[dict[str, Any]] = []
    sizes = sorted({int(row["policy_size_stripes"]) for row in raw_records})
    for size in sizes:
        for mode in TIMING_MODES:
            group = [
                row
                for row in raw_records
                if int(row["policy_size_stripes"]) == size and row["mode"] == mode
            ]
            if not group:
                continue
            full_batch_ns = [
                float(batch["elapsed_ns"])
                for row in group
                for batch in row["batches"]
                if batch["rows"] == row["batch_size"]
            ]
            if not full_batch_ns:
                raise AssertionError(
                    f"condition size={size}, mode={mode} has no full batch"
                )
            route_us = [value / group[0]["batch_size"] / 1000 for value in full_batch_ns]
            throughputs = [float(row["routes_per_second"]) for row in group]
            summary_rows.append(
                {
                    "address_family": ADDRESS_FAMILY,
                    "policy_size_stripes": size,
                    "mode": mode,
                    "repetitions": len(group),
                    "routes_per_repetition": group[0]["route_count"],
                    "batch_size_routes": group[0]["batch_size"],
                    "serialized_bytes": group[0]["serialized_bytes"],
                    "routes_per_second_p50": percentile(throughputs, 0.50),
                    "routes_per_second_min": min(throughputs),
                    "routes_per_second_max": max(throughputs),
                    "batch_ms_p50": percentile(full_batch_ns, 0.50) / 1_000_000,
                    "batch_ms_p95": percentile(full_batch_ns, 0.95) / 1_000_000,
                    "batch_ms_p99": percentile(full_batch_ns, 0.99) / 1_000_000,
                    "amortized_route_us_p50": percentile(route_us, 0.50),
                    "amortized_route_us_p95": percentile(route_us, 0.95),
                    "amortized_route_us_p99": percentile(route_us, 0.99),
                    "peak_rss_mib_max": max(row["peak_rss_kib"] for row in group)
                    / 1024,
                    "policy_parse_us_p50": percentile(
                        [row["checks"]["policy_parse_ns"] / 1000 for row in group],
                        0.50,
                    ),
                    "result_checksum_sha256": group[0]["result_checksum_sha256"],
                    "oracle_spot_checks_per_repetition": group[0]["checks"][
                        "oracle_spot_check_count"
                    ],
                    "all_oracle_spot_checks_pass": all(
                        row["checks"]["oracle_spot_checks_pass"] for row in group
                    ),
                    "all_roundtrips_identical": all(
                        row["checks"]["roundtrip_identical"] for row in group
                    ),
                }
            )

    summary_path = run_dir / "summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=list(summary_rows[0]), lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    checksums_by_size: dict[str, list[str]] = {}
    states_by_size: dict[str, list[dict[str, int]]] = {}
    for size in sizes:
        selected = [row for row in raw_records if row["policy_size_stripes"] == size]
        checksums_by_size[str(size)] = sorted(
            {row["result_checksum_sha256"] for row in selected}
        )
        states_by_size[str(size)] = [
            json.loads(value)
            for value in sorted(
                {json.dumps(row["state_counts"], sort_keys=True) for row in selected}
            )
        ]

    expected_conditions = {
        (
            int(condition["policy_size_stripes"]),
            str(condition["mode"]),
            int(condition["repetition"]),
        )
        for condition in schedule
    }
    observed_conditions = {
        (
            int(row["policy_size_stripes"]),
            str(row["mode"]),
            int(row["repetition"]),
        )
        for row in raw_records
    }
    audit = {
        "schema_version": SCHEMA_VERSION,
        "address_family": ADDRESS_FAMILY,
        "raw_worker_records": len(raw_records),
        "expected_worker_records": len(schedule),
        "all_worker_records_present": len(raw_records) == len(schedule),
        "condition_matrix_exact": observed_conditions == expected_conditions,
        "fresh_worker_per_condition": len({row["worker_pid"] for row in raw_records})
        == len(raw_records),
        "all_workers_ipv6": all(row["address_family"] == ADDRESS_FAMILY for row in raw_records),
        "all_policies_use_ipv6_root": all(
            row["base_prefix"] == "::/0" and row["max_length"] == 128
            for row in raw_records
        ),
        "all_workers_on_fixed_cpu": all(
            row["cpu_affinity"] == expected_cpu for row in raw_records
        ),
        "all_route_counts_match": len({row["route_count"] for row in raw_records}) == 1,
        "one_workload_checksum": len({row["workload_sha256"] for row in raw_records}) == 1,
        "all_oracle_spot_checks_pass": all(
            row["checks"]["oracle_spot_checks_pass"] for row in raw_records
        ),
        "all_policy_roundtrips_identical": all(
            row["checks"]["roundtrip_identical"] for row in raw_records
        ),
        "one_checksum_per_policy_size": all(
            len(values) == 1 for values in checksums_by_size.values()
        ),
        "one_state_count_vector_per_policy_size": all(
            len(values) == 1 for values in states_by_size.values()
        ),
        "checksums_by_policy_size": checksums_by_size,
        "state_counts_by_policy_size": states_by_size,
        "raw_runs_csv_sha256": sha256_file(raw_csv_path),
        "raw_batch_samples_csv_sha256": sha256_file(batch_csv_path),
        "summary_csv_sha256": sha256_file(summary_path),
    }
    boolean_checks = (
        "all_worker_records_present",
        "condition_matrix_exact",
        "fresh_worker_per_condition",
        "all_workers_ipv6",
        "all_policies_use_ipv6_root",
        "all_workers_on_fixed_cpu",
        "all_route_counts_match",
        "one_workload_checksum",
        "all_oracle_spot_checks_pass",
        "all_policy_roundtrips_identical",
        "one_checksum_per_policy_size",
        "one_state_count_vector_per_policy_size",
    )
    audit["all_checks_pass"] = all(audit[key] for key in boolean_checks)
    write_json(run_dir / "recomputation_audit.json", audit)
    write_paper_table(
        run_dir / "paper_table_ipv6.tex",
        summary_rows,
        int(raw_records[0]["batch_size"]),
    )
    write_run_report(run_dir / "RUN_REPORT.md", summary_rows, audit, run_dir)
    return {"summary_rows": summary_rows, "audit": audit}


def write_run_report(
    path: Path,
    rows: Sequence[dict[str, Any]],
    audit: dict[str, Any],
    run_dir: Path,
) -> None:
    config = json.loads((run_dir / "run_config.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "input_manifest.json").read_text(encoding="utf-8"))
    report = f"""# IPv6 reference-classifier processing benchmark

Generated: {utc_now()}

## Scope

This run measures the Python `S2ROV.validate_route` reference classifier on
{manifest['ipv6_rows']:,} valid scalar-origin IPv6 prefix-origin pairs derived from
{manifest['source_ipv6_rows']:,} IPv6 rows encountered in the mixed RRC00 CSV.
Preprocessing excluded {manifest['source_ipv6_ambiguous_markers_excluded']:,} rows
whose origin is the explicit `{{AMBIGUOUS}}` marker. It does not measure FRR, RTR
transfer, router installation, forwarding, or line rate.

`parse_excluded` preloads IPv6 `(prefix string, origin integer)` pairs and times
classifier calls plus state capture. `parse_included` additionally times CSV decoding
and ASN integer conversion. Internal textual IPv6 CIDR parsing remains in both scopes.

Each policy contains one `::/0` entry carrying an OpenScope marker with
`max_length=128` and the first `size-1` unique non-`::/0` prefixes in source order
as unmarked exact-origin records. These are deterministic benchmark policies, not
observed published authorizations.

## Configuration

- Repetitions per condition: {config['repetitions']}
- Batch size: {config['batch_size']} routes
- Warm-up: {config['warmup_routes']} routes per fresh worker
- Schedule seed: {config['seed']}
- Fixed worker CPU: {config['cpu']}
- Python: {config['python']}
- Platform: {config['platform']}
- Source SHA-256: `{manifest['source_sha256']}`
- IPv6 workload SHA-256: `{manifest['derived_sha256']}`
- IPv6 driver SHA-256: `{config['script_sha256']}`
- Classifier SHA-256: `{config['classifier_sha256']}`
- Reused family-neutral helper SHA-256: `{config['legacy_helper_sha256']}`

## Results

Throughput is the median across repetitions. Batch percentiles pool full batches
across repetitions. Route percentiles are amortized values obtained by dividing a
full-batch duration by {config['batch_size']}; they are not individually instrumented
request latencies. Peak RSS is the maximum fresh-worker high-water mark.

{markdown_table(rows)}

## Integrity checks

- Worker records present: {audit['raw_worker_records']}/{audit['expected_worker_records']}
- Exact condition matrix: {audit['condition_matrix_exact']}
- Fresh worker per condition: {audit['fresh_worker_per_condition']}
- Every worker pinned to CPU {config['cpu']}: {audit['all_workers_on_fixed_cpu']}
- Every policy uses IPv6 `::/0`, `max_length=128`: {audit['all_policies_use_ipv6_root']}
- Serialization round trips identical: {audit['all_policy_roundtrips_identical']}
- Independent IPv6 oracle spot checks pass: {audit['all_oracle_spot_checks_pass']}
- One result checksum per policy size across scopes and repetitions: {audit['one_checksum_per_policy_size']}
- One state-count vector per policy size across scopes and repetitions: {audit['one_state_count_vector_per_policy_size']}
- Overall recomputation audit: {audit['all_checks_pass']}

## Artifacts

- `raw/`: one immutable JSON record per fresh worker, including every batch duration
- `raw_runs.csv`: one row per condition
- `raw_batch_samples.csv`: one row per measured batch
- `summary.csv`: recomputed aggregate values
- `recomputation_audit.json`: completeness, affinity, oracle, round-trip, and checksum checks
- `policies/`: IPv6 policy payloads, transparent specifications, and oracle spots
- `paper_table_ipv6.tex`: compact LaTeX suggestion, not inserted automatically

## Claim boundary

These results support only single-process, single-core IPv6 processing-cost claims
for the Python reference implementation on this RRC00-derived workload. They do not
measure full-RIB FRR processing, router data planes, native RTR/RPKI interoperability,
or Internet-wide production capacity.
"""
    path.write_text(report, encoding="utf-8")


def resolve_cpu(requested: int | None) -> int:
    cpu = requested if requested is not None else current_cpu()
    if cpu is None or not hasattr(os, "sched_getaffinity"):
        raise RuntimeError("this benchmark requires supported CPU affinity")
    available = os.sched_getaffinity(0)
    if cpu not in available:
        raise ValueError(f"CPU {cpu} is outside current affinity {sorted(available)}")
    return cpu


def formal_input_counts(manifest: dict[str, Any]) -> dict[str, int]:
    keys = (
        "source_rows_scanned",
        "source_ipv4_rows_skipped",
        "source_ipv6_rows",
        "source_ipv6_ambiguous_markers_excluded",
        "ipv6_rows",
    )
    return {key: int(manifest[key]) for key in keys}


def run_orchestrator(args: argparse.Namespace) -> int:
    run_id = args.run_id or datetime.now(timezone.utc).strftime(
        "processing-ipv6-%Y%m%dT%H%M%SZ"
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

    log(f"preparing IPv6 run {run_id}")
    workload_path = run_dir / "input" / "rrc00_20260624_ipv6_prefix_origins.csv"
    input_manifest = prepare_ipv6_workload(
        args.input.resolve(),
        workload_path,
        limit=args.limit,
        max_policy_size=max(args.sizes),
        seed=args.seed,
    )
    if args.limit is None:
        expected = {
            "source_rows_scanned": EXPECTED_SOURCE_ROWS,
            "source_ipv4_rows_skipped": EXPECTED_SOURCE_IPV4_ROWS,
            "source_ipv6_rows": EXPECTED_SOURCE_IPV6_ROWS,
            "source_ipv6_ambiguous_markers_excluded": EXPECTED_AMBIGUOUS_IPV6_ROWS,
            "ipv6_rows": EXPECTED_VALID_IPV6_ROWS,
        }
        observed = formal_input_counts(input_manifest)
        if observed != expected:
            raise AssertionError(
                f"formal IPv6 input counts differ: observed={observed}, "
                f"expected={expected}"
            )
    write_json(run_dir / "input_manifest.json", input_manifest)
    log(
        f"prepared {input_manifest['ipv6_rows']:,} valid scalar-origin IPv6 pairs "
        f"from {input_manifest['source_ipv6_rows']:,} encountered IPv6 rows; "
        f"excluded {input_manifest['source_ipv6_ambiguous_markers_excluded']:,} "
        f"ambiguous markers ({input_manifest['derived_bytes'] / 1024 / 1024:.1f} MiB)"
    )

    policies = create_ipv6_policies(run_dir, input_manifest, args.sizes)
    for size in args.sizes:
        log(
            f"IPv6 policy {size}: {policies[size]['serialized_bytes']} bytes, "
            f"{policies[size]['oracle_spot_count']} oracle spots"
        )

    cpu = resolve_cpu(args.cpu)
    config = {
        "schema_version": SCHEMA_VERSION,
        "address_family": ADDRESS_FAMILY,
        "run_id": run_id,
        "created_utc": utc_now(),
        "input": str(args.input.resolve()),
        "output": str(run_dir),
        "sizes": list(args.sizes),
        "timing_modes": list(TIMING_MODES),
        "repetitions": args.repetitions,
        "batch_size": args.batch_size,
        "warmup_routes": args.warmup_routes,
        "limit": args.limit,
        "seed": args.seed,
        "cpu": cpu,
        "worker_timeout_seconds": args.worker_timeout,
        "python": sys.version,
        "platform": platform.platform(),
        "script": str(SCRIPT),
        "script_sha256": sha256_file(SCRIPT),
        "classifier": str(S2ROV_CODEC_SCRIPTS / "utils" / "s2rov.py"),
        "classifier_sha256": sha256_file(S2ROV_CODEC_SCRIPTS / "utils" / "s2rov.py"),
        "legacy_helper": str(LEGACY_BENCHMARK),
        "legacy_helper_sha256": sha256_file(LEGACY_BENCHMARK),
        "source_git_commit": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "source_worktree_dirty": bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        ),
    }
    write_json(run_dir / "run_config.json", config)

    schedule = []
    rng = random.Random(args.seed)
    schedule_index = 0
    for repetition in range(1, args.repetitions + 1):
        cells = [(size, mode) for size in args.sizes for mode in TIMING_MODES]
        rng.shuffle(cells)
        for size, mode in cells:
            raw_path = run_dir / "raw" / (
                f"{schedule_index:03d}-ipv6-size-{size}-{mode}-rep-{repetition}.json"
            )
            schedule.append(
                {
                    "schedule_index": schedule_index,
                    "repetition": repetition,
                    "policy_size_stripes": size,
                    "mode": mode,
                    "raw_json": str(raw_path.resolve()),
                }
            )
            schedule_index += 1
    write_json(run_dir / "schedule.json", schedule)

    environment = os.environ.copy()
    environment.update({"PYTHONHASHSEED": "0", "LC_ALL": "C"})
    for condition in schedule:
        size = condition["policy_size_stripes"]
        command = [
            sys.executable,
            str(SCRIPT),
            "worker",
            "--workload",
            str(workload_path),
            "--policy",
            policies[size]["serialized_path"],
            "--oracle-spots",
            policies[size]["oracle_spots_path"],
            "--mode",
            condition["mode"],
            "--repetition",
            str(condition["repetition"]),
            "--schedule-index",
            str(condition["schedule_index"]),
            "--batch-size",
            str(args.batch_size),
            "--warmup-routes",
            str(args.warmup_routes),
            "--cpu",
            str(cpu),
            "--output",
            condition["raw_json"],
        ]
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=args.worker_timeout,
            )
        except subprocess.TimeoutExpired as exc:
            log(
                f"condition {condition['schedule_index']:03d} timed out after "
                f"{args.worker_timeout}s; no retry was attempted"
            )
            if exc.stdout:
                log(f"worker stdout before timeout: {exc.stdout}")
            if exc.stderr:
                log(f"worker stderr before timeout: {exc.stderr}")
            return 124
        for line in completed.stdout.splitlines():
            log(line)
        for line in completed.stderr.splitlines():
            log(f"worker stderr: {line}")
        if completed.returncode != 0:
            log(
                f"condition {condition['schedule_index']:03d} failed with exit "
                f"code {completed.returncode}; no retry was attempted"
            )
            return completed.returncode or 1
        log(
            f"condition {condition['schedule_index']:03d} completed in "
            f"{time.monotonic() - started:.1f}s"
        )

    aggregate = aggregate_run(run_dir, schedule, cpu)
    log(f"aggregation checks pass: {aggregate['audit']['all_checks_pass']}")
    if not aggregate["audit"]["all_checks_pass"]:
        log("integrity audit failed; no retry was attempted")
        return 2
    log(f"complete: {run_dir}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser(
        "run", help="prepare, execute, and aggregate an IPv6 benchmark"
    )
    run.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    run.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    run.add_argument("--run-id")
    run.add_argument("--sizes", nargs="+", type=int, default=list(DEFAULT_SIZES))
    run.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS)
    run.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    run.add_argument("--warmup-routes", type=int, default=DEFAULT_WARMUP_ROUTES)
    run.add_argument("--seed", type=int, default=DEFAULT_SEED)
    run.add_argument("--limit", type=int)
    run.add_argument("--cpu", type=int)
    run.add_argument("--worker-timeout", type=int, default=1800)
    run.set_defaults(function=run_orchestrator)

    worker = subparsers.add_parser("worker", help=argparse.SUPPRESS)
    worker.add_argument("--workload", type=Path, required=True)
    worker.add_argument("--policy", type=Path, required=True)
    worker.add_argument("--oracle-spots", type=Path, required=True)
    worker.add_argument("--mode", choices=TIMING_MODES, required=True)
    worker.add_argument("--repetition", type=int, required=True)
    worker.add_argument("--schedule-index", type=int, required=True)
    worker.add_argument("--batch-size", type=int, required=True)
    worker.add_argument("--warmup-routes", type=int, required=True)
    worker.add_argument("--cpu", type=int, required=True)
    worker.add_argument("--output", type=Path, required=True)
    worker.set_defaults(function=run_worker)
    return parser


def validate_arguments(args: argparse.Namespace) -> None:
    if args.command != "run":
        return
    if not args.sizes or len(set(args.sizes)) != len(args.sizes):
        raise ValueError("policy sizes must be nonempty and unique")
    if any(size < 1 or size > 0xFFFF for size in args.sizes):
        raise ValueError("policy sizes must be in [1, 65535]")
    if args.repetitions < 1:
        raise ValueError("repetitions must be positive")
    if args.batch_size < 1:
        raise ValueError("batch size must be positive")
    if args.warmup_routes < 0:
        raise ValueError("warm-up route count cannot be negative")
    if args.limit is not None and args.limit < args.batch_size:
        raise ValueError("self-test limit must include at least one full batch")
    if args.worker_timeout < 1:
        raise ValueError("worker timeout must be positive")


def main() -> int:
    args = build_parser().parse_args()
    validate_arguments(args)
    return int(args.function(args))


if __name__ == "__main__":
    raise SystemExit(main())
