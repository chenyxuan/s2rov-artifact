#!/usr/bin/env python3
"""Prepare auditable, simulator-independent inputs for routing-model.

This program deliberately performs no inference about real-world delegation.
Rows retained from the allocation-tree source are origin-divergence candidates
that satisfy mechanical prefix and topology invariants only.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


SCRIPT_VERSION = "1.0.0"
PROVENANCE_SCHEMA_VERSION = 1
EXPECTED_CSV_HEADER = (
    "root_prefix",
    "root_status",
    "root_origins",
    "leaf_prefix",
    "leaf_status",
    "leaf_origins",
    "classification",
)
EXPECTED_ROOT_STATUS = "ALLOCATED PA"
EXPECTED_LEAF_STATUSES = {
    "ASSIGNED PA",
    "SUB-ALLOCATED PA",
    "LIR-PARTITIONED PA",
}
EXPECTED_CLASSIFICATION = "disjoint_origin_sets"
EXPECTED_ROV_LABEL = "hlavacek_589"
EXPECTED_ROV_COUNT = 589
EXPECTED_ROV_KEYS = {"label", "rov_ases", "amber_ases"}
ASN_RE = re.compile(r"[1-9][0-9]*\Z")


class InputValidationError(ValueError):
    """Raised when an input does not match the declared source contract."""


@dataclass(frozen=True)
class TopologyEdge:
    source_line: int
    asn1: int
    asn2: int
    relationship_code: int


@dataclass(frozen=True)
class SourceCandidate:
    source_row: int
    root_prefix: str
    root_status: str
    root_origins: tuple[int, ...]
    leaf_prefix: str
    leaf_status: str
    leaf_origins: tuple[int, ...]
    classification: str
    root_network: ipaddress.IPv4Network | ipaddress.IPv6Network
    leaf_network: ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class RetainedCandidate:
    source_row: int
    root_prefix: str
    root_status: str
    holder_asn: int
    leaf_prefix: str
    leaf_status: str
    delegate_asn: int
    classification: str


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _physical_line_count(data: bytes) -> int:
    if not data:
        return 0
    return data.count(b"\n") + (0 if data.endswith(b"\n") else 1)


def _file_record(path: Path, data: bytes | None = None) -> dict[str, Any]:
    resolved = path.resolve()
    raw = resolved.read_bytes() if data is None else data
    return {
        "absolute_path": str(resolved),
        "bytes": len(raw),
        "lines": _physical_line_count(raw),
        "sha256": _sha256_bytes(raw),
    }


def _parse_positive_asn(token: str, context: str) -> int:
    if not ASN_RE.fullmatch(token):
        raise InputValidationError(
            f"{context}: expected a canonical positive decimal ASN, got {token!r}"
        )
    return int(token)


def _parse_origin_set(value: str, context: str) -> tuple[int, ...]:
    if value == "":
        raise InputValidationError(f"{context}: origin set is empty")
    tokens = value.split(";")
    origins = tuple(_parse_positive_asn(token, context) for token in tokens)
    if len(set(origins)) != len(origins):
        raise InputValidationError(f"{context}: origin set contains duplicate ASNs")
    return origins


def parse_topology(raw: bytes, source_path: Path) -> tuple[list[TopologyEdge], set[int]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputValidationError(f"{source_path}: not valid UTF-8: {exc}") from exc

    edges: list[TopologyEdge] = []
    topology_asns: set[int] = set()
    seen_pairs: dict[tuple[int, int], int] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise InputValidationError(f"{source_path}:{line_number}: blank line")
        fields = line.split("|")
        if len(fields) != 3:
            raise InputValidationError(
                f"{source_path}:{line_number}: expected three pipe-separated fields"
            )
        asn1 = _parse_positive_asn(fields[0], f"{source_path}:{line_number}:asn1")
        asn2 = _parse_positive_asn(fields[1], f"{source_path}:{line_number}:asn2")
        if fields[2] not in {"-1", "0"}:
            raise InputValidationError(
                f"{source_path}:{line_number}: unsupported relationship code {fields[2]!r}"
            )
        relationship_code = int(fields[2])
        if asn1 == asn2:
            raise InputValidationError(
                f"{source_path}:{line_number}: self-loop for AS{asn1}"
            )
        unordered_pair = (min(asn1, asn2), max(asn1, asn2))
        if unordered_pair in seen_pairs:
            raise InputValidationError(
                f"{source_path}:{line_number}: repeated AS pair; first seen on line "
                f"{seen_pairs[unordered_pair]}"
            )
        seen_pairs[unordered_pair] = line_number
        edges.append(TopologyEdge(line_number, asn1, asn2, relationship_code))
        topology_asns.update((asn1, asn2))

    if not edges:
        raise InputValidationError(f"{source_path}: topology is empty")
    return edges, topology_asns


def parse_rov_set(raw: bytes, source_path: Path, topology_asns: set[int]) -> tuple[str, list[int]]:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputValidationError(f"{source_path}: invalid JSON: {exc}") from exc
    if not isinstance(document, list) or len(document) != 1:
        raise InputValidationError(f"{source_path}: expected a one-element JSON list")
    deployment = document[0]
    if not isinstance(deployment, dict) or set(deployment) != EXPECTED_ROV_KEYS:
        raise InputValidationError(
            f"{source_path}: expected exactly the keys {sorted(EXPECTED_ROV_KEYS)}"
        )
    if deployment["label"] != EXPECTED_ROV_LABEL:
        raise InputValidationError(
            f"{source_path}: expected label {EXPECTED_ROV_LABEL!r}, got "
            f"{deployment['label']!r}"
        )
    if deployment["amber_ases"] != []:
        raise InputValidationError(f"{source_path}: expected an empty amber_ases list")
    raw_rov = deployment["rov_ases"]
    if not isinstance(raw_rov, list):
        raise InputValidationError(f"{source_path}: rov_ases must be a list")
    if len(raw_rov) != EXPECTED_ROV_COUNT:
        raise InputValidationError(
            f"{source_path}: expected {EXPECTED_ROV_COUNT} ROV ASNs, got {len(raw_rov)}"
        )
    if any(isinstance(asn, bool) or not isinstance(asn, int) or asn <= 0 for asn in raw_rov):
        raise InputValidationError(f"{source_path}: all ROV ASNs must be positive integers")
    if len(set(raw_rov)) != len(raw_rov):
        raise InputValidationError(f"{source_path}: rov_ases contains duplicates")
    absent = sorted(set(raw_rov) - topology_asns)
    if absent:
        raise InputValidationError(
            f"{source_path}: {len(absent)} ROV ASNs are absent from the topology; "
            f"first values: {absent[:10]}"
        )
    return deployment["label"], sorted(raw_rov)


def parse_candidates(raw: bytes, source_path: Path) -> list[SourceCandidate]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputValidationError(f"{source_path}: not valid UTF-8: {exc}") from exc
    reader = csv.DictReader(text.splitlines())
    if reader.fieldnames is None or tuple(reader.fieldnames) != EXPECTED_CSV_HEADER:
        raise InputValidationError(
            f"{source_path}: expected header {EXPECTED_CSV_HEADER}, got {reader.fieldnames}"
        )

    candidates: list[SourceCandidate] = []
    for source_row, row in enumerate(reader, start=2):
        if None in row or set(row) != set(EXPECTED_CSV_HEADER):
            raise InputValidationError(f"{source_path}:{source_row}: malformed CSV row")
        if row["root_status"] != EXPECTED_ROOT_STATUS:
            raise InputValidationError(
                f"{source_path}:{source_row}: unexpected root_status {row['root_status']!r}"
            )
        if row["leaf_status"] not in EXPECTED_LEAF_STATUSES:
            raise InputValidationError(
                f"{source_path}:{source_row}: unexpected leaf_status {row['leaf_status']!r}"
            )
        if row["classification"] != EXPECTED_CLASSIFICATION:
            raise InputValidationError(
                f"{source_path}:{source_row}: unexpected classification "
                f"{row['classification']!r}"
            )
        try:
            root_network = ipaddress.ip_network(row["root_prefix"], strict=True)
            leaf_network = ipaddress.ip_network(row["leaf_prefix"], strict=True)
        except ValueError as exc:
            raise InputValidationError(
                f"{source_path}:{source_row}: invalid canonical prefix: {exc}"
            ) from exc
        if str(root_network) != row["root_prefix"] or str(leaf_network) != row["leaf_prefix"]:
            raise InputValidationError(
                f"{source_path}:{source_row}: prefixes must use canonical notation"
            )
        candidates.append(
            SourceCandidate(
                source_row=source_row,
                root_prefix=row["root_prefix"],
                root_status=row["root_status"],
                root_origins=_parse_origin_set(
                    row["root_origins"], f"{source_path}:{source_row}:root_origins"
                ),
                leaf_prefix=row["leaf_prefix"],
                leaf_status=row["leaf_status"],
                leaf_origins=_parse_origin_set(
                    row["leaf_origins"], f"{source_path}:{source_row}:leaf_origins"
                ),
                classification=row["classification"],
                root_network=root_network,
                leaf_network=leaf_network,
            )
        )
    if not candidates:
        raise InputValidationError(f"{source_path}: candidate table contains no rows")
    return candidates


def _exclusion_reasons(candidate: SourceCandidate, topology_asns: set[int]) -> set[str]:
    reasons: set[str] = set()
    root_singleton = len(candidate.root_origins) == 1
    leaf_singleton = len(candidate.leaf_origins) == 1
    if not root_singleton:
        reasons.add("root_origin_not_singleton")
    if not leaf_singleton:
        reasons.add("leaf_origin_not_singleton")
    if (
        candidate.root_network.version != candidate.leaf_network.version
        or not candidate.leaf_network.subnet_of(candidate.root_network)
        or candidate.leaf_network == candidate.root_network
    ):
        reasons.add("leaf_not_proper_descendant")
    if root_singleton and leaf_singleton and candidate.root_origins[0] == candidate.leaf_origins[0]:
        reasons.add("holder_equals_delegate")
    if root_singleton and candidate.root_origins[0] not in topology_asns:
        reasons.add("holder_absent_from_topology")
    if leaf_singleton and candidate.leaf_origins[0] not in topology_asns:
        reasons.add("delegate_absent_from_topology")
    return reasons


def filter_candidates(
    candidates: Sequence[SourceCandidate], topology_asns: set[int]
) -> tuple[list[RetainedCandidate], dict[str, Any]]:
    reasons_by_row = {
        candidate.source_row: _exclusion_reasons(candidate, topology_asns)
        for candidate in candidates
    }
    independent_counts = Counter(
        reason for reasons in reasons_by_row.values() for reason in reasons
    )
    rule_order = (
        "root_origin_not_singleton",
        "leaf_origin_not_singleton",
        "leaf_not_proper_descendant",
        "holder_equals_delegate",
        "holder_absent_from_topology",
        "delegate_absent_from_topology",
    )
    remaining = list(candidates)
    pipeline: list[dict[str, int | str]] = []
    for rule in rule_order:
        before = len(remaining)
        remaining = [
            candidate
            for candidate in remaining
            if rule not in reasons_by_row[candidate.source_row]
        ]
        pipeline.append(
            {
                "rule": rule,
                "before": before,
                "excluded_at_step": before - len(remaining),
                "remaining": len(remaining),
            }
        )

    retained = [
        RetainedCandidate(
            source_row=candidate.source_row,
            root_prefix=candidate.root_prefix,
            root_status=candidate.root_status,
            holder_asn=candidate.root_origins[0],
            leaf_prefix=candidate.leaf_prefix,
            leaf_status=candidate.leaf_status,
            delegate_asn=candidate.leaf_origins[0],
            classification=candidate.classification,
        )
        for candidate in remaining
    ]

    # Output invariants are asserted separately from filtering so that a future
    # code change cannot accidentally emit a row that merely passed one stage.
    source_by_row = {candidate.source_row: candidate for candidate in candidates}
    for candidate in retained:
        source = source_by_row[candidate.source_row]
        if _exclusion_reasons(source, topology_asns):
            raise AssertionError(f"retained source row {candidate.source_row} violates invariants")

    filter_report: dict[str, Any] = {
        "input_rows": len(candidates),
        "rule_order": list(rule_order),
        "pipeline": pipeline,
        "exclusion_counts_independent": {
            rule: independent_counts.get(rule, 0) for rule in rule_order
        },
        "rows_with_any_exclusion": sum(bool(value) for value in reasons_by_row.values()),
        "retained_candidate_rows": len(retained),
    }
    return retained, filter_report


def _write_csv(path: Path, header: Sequence[str], rows: Iterable[Sequence[Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def _write_outputs(
    staging_dir: Path,
    topology_raw: bytes,
    edges: Sequence[TopologyEdge],
    rov_label: str,
    rov_asns: Sequence[int],
    retained: Sequence[RetainedCandidate],
) -> dict[str, Path]:
    paths = {
        "as_relationship_source_copy": staging_dir / "as-rel-fixed.txt",
        "as_relationship_normalized": staging_dir / "as_relationships.csv",
        "rov_asns_text": staging_dir / "rov_ases.txt",
        "rov_asns_json": staging_dir / "rov_ases.json",
        "candidate_rows": staging_dir / "origin_divergence_candidates.csv",
        "holder_delegate_pairs": staging_dir / "holder_delegate_pairs.csv",
    }
    paths["as_relationship_source_copy"].write_bytes(topology_raw)
    _write_csv(
        paths["as_relationship_normalized"],
        ("source_line", "asn1", "asn2", "relationship_code"),
        (
            (edge.source_line, edge.asn1, edge.asn2, edge.relationship_code)
            for edge in edges
        ),
    )
    paths["rov_asns_text"].write_text(
        "".join(f"{asn}\n" for asn in rov_asns), encoding="utf-8"
    )
    paths["rov_asns_json"].write_text(
        json.dumps(
            {
                "label": rov_label,
                "rov_ases": list(rov_asns),
                "interpretation": "measured ROV set; sorted for deterministic simulator input",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _write_csv(
        paths["candidate_rows"],
        (
            "source_row",
            "root_prefix",
            "root_status",
            "holder_asn",
            "leaf_prefix",
            "leaf_status",
            "delegate_asn",
            "classification",
        ),
        (
            (
                candidate.source_row,
                candidate.root_prefix,
                candidate.root_status,
                candidate.holder_asn,
                candidate.leaf_prefix,
                candidate.leaf_status,
                candidate.delegate_asn,
                candidate.classification,
            )
            for candidate in retained
        ),
    )

    pair_rows: dict[tuple[int, int], list[RetainedCandidate]] = defaultdict(list)
    for candidate in retained:
        pair_rows[(candidate.holder_asn, candidate.delegate_asn)].append(candidate)
    _write_csv(
        paths["holder_delegate_pairs"],
        (
            "holder_asn",
            "delegate_asn",
            "candidate_rows",
            "distinct_root_prefixes",
            "distinct_leaf_prefixes",
        ),
        (
            (
                holder_asn,
                delegate_asn,
                len(group),
                len({candidate.root_prefix for candidate in group}),
                len({candidate.leaf_prefix for candidate in group}),
            )
            for (holder_asn, delegate_asn), group in sorted(pair_rows.items())
        ),
    )
    return paths


def prepare_inputs(
    candidate_csv: Path,
    topology_file: Path,
    rov_json: Path,
    output_dir: Path,
    generated_at_utc: str | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    candidate_csv = candidate_csv.resolve(strict=True)
    topology_file = topology_file.resolve(strict=True)
    rov_json = rov_json.resolve(strict=True)
    output_dir = output_dir.resolve()

    candidate_raw = candidate_csv.read_bytes()
    topology_raw = topology_file.read_bytes()
    rov_raw = rov_json.read_bytes()

    # Parse and validate everything before creating or replacing output files.
    edges, topology_asns = parse_topology(topology_raw, topology_file)
    rov_label, rov_asns = parse_rov_set(rov_raw, rov_json, topology_asns)
    source_candidates = parse_candidates(candidate_raw, candidate_csv)
    retained, filter_report = filter_candidates(source_candidates, topology_asns)
    pair_count = len({(row.holder_asn, row.delegate_asn) for row in retained})

    generated_at = generated_at_utc or datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{output_dir.name}.prepare-", dir=output_dir.parent
    ) as temporary_directory:
        staging_dir = Path(temporary_directory)
        staged_paths = _write_outputs(
            staging_dir, topology_raw, edges, rov_label, rov_asns, retained
        )
        output_records = {
            name: {
                **_file_record(path),
                "absolute_path": str((output_dir / path.name).resolve()),
            }
            for name, path in staged_paths.items()
        }
        relation_counts = Counter(edge.relationship_code for edge in edges)
        provenance = {
            "schema_version": PROVENANCE_SCHEMA_VERSION,
            "generated_at_utc": generated_at,
            "generator": {
                "absolute_path": str(Path(__file__).resolve()),
                "script_version": SCRIPT_VERSION,
                "sha256": _sha256_bytes(Path(__file__).read_bytes()),
                "python": sys.version.split()[0],
            },
            "interpretation_warning": (
                "These rows are empirical origin-divergence candidates only. "
                "They do not assert or infer real-world delegation, authorization, "
                "business relationships, or routing intent."
            ),
            "sources": {
                "allocation_tree_origin_divergence": _file_record(
                    candidate_csv, candidate_raw
                ),
                "as_relationship_topology": _file_record(topology_file, topology_raw),
                "hlavacek_rov_deployment": _file_record(rov_json, rov_raw),
            },
            "topology": {
                "asns": len(topology_asns),
                "relationships": len(edges),
                "relationship_code_counts": {
                    str(code): relation_counts[code] for code in sorted(relation_counts)
                },
            },
            "rov_set": {"label": rov_label, "asns": len(rov_asns)},
            "filtering": {
                **filter_report,
                "unique_holder_delegate_pairs": pair_count,
                "distinct_root_prefixes_retained": len(
                    {row.root_prefix for row in retained}
                ),
                "distinct_leaf_prefixes_retained": len(
                    {row.leaf_prefix for row in retained}
                ),
            },
            "outputs": output_records,
        }
        provenance_path = staging_dir / "provenance.json"
        provenance_path.write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        output_dir.mkdir(parents=True, exist_ok=True)
        for path in [*staged_paths.values(), provenance_path]:
            os.replace(path, output_dir / path.name)

    return {
        "output_dir": str(output_dir),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "topology_asns": len(topology_asns),
        "topology_relationships": len(edges),
        "rov_asns": len(rov_asns),
        "source_candidate_rows": len(source_candidates),
        "retained_candidate_rows": len(retained),
        "unique_holder_delegate_pairs": pair_count,
        "exclusion_counts_independent": filter_report[
            "exclusion_counts_independent"
        ],
    }


def _default_paths() -> tuple[Path, Path, Path, Path]:
    repository_root = Path(__file__).resolve().parents[3]
    return (
        repository_root
        / "experiments/candidates/allocation_tree/outputs/tables/"
        "allocation_tree_origin_divergence.csv",
        Path("<home>/AMBER/data/simulation/topo/as-rel-fixed.txt"),
        Path("<home>/AMBER/data/simulation/deploy/hlavacek_rov.json"),
        repository_root / "experiments/routing_model/data/inputs",
    )


def build_argument_parser() -> argparse.ArgumentParser:
    default_candidates, default_topology, default_rov, default_output = _default_paths()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-csv", type=Path, default=default_candidates)
    parser.add_argument("--topology-file", type=Path, default=default_topology)
    parser.add_argument("--rov-json", type=Path, default=default_rov)
    parser.add_argument("--output-dir", type=Path, default=default_output)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    arguments = parser.parse_args(argv)
    try:
        summary = prepare_inputs(
            candidate_csv=arguments.candidate_csv,
            topology_file=arguments.topology_file,
            rov_json=arguments.rov_json,
            output_dir=arguments.output_dir,
        )
    except (InputValidationError, FileNotFoundError) as exc:
        parser.exit(2, f"input preparation failed: {exc}\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
