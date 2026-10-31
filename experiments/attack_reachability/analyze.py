"""Fail-closed analysis for the attack-reachability sibling endpoint campaign."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np

from experiments.attack_reachability.runner import (
    A1_SIBLING,
    B1_SIBLING,
    BOOTSTRAP_REPLICATES,
    BOOTSTRAP_SEED,
    EXPECTED_HOLDERS,
    EXPECTED_TRIALS,
    ROUTING_MODEL_RAW_RESULTS,
    POPULATIONS,
    REPOSITORY_ROOT,
    SCHEMA_VERSION,
    VERSION_LABEL,
    SiblingUnit,
    atomic_write_json,
    canonical_sha256,
    file_sha256,
    load_manifest,
    require_attack_reachability_path,
    scan_results,
    utc_now,
)


SUMMARY_FIELDS = (
    "estimand",
    "metric_level",
    "population",
    "deployment_percent_target",
    "independent_unit",
    "n_holders",
    "n_ases_as_independent_units",
    "design_population_holders",
    "design_weight_sum",
    "raw_treatment_design_weighted_mean",
    "raw_reference_design_weighted_mean",
    "paired_delta_design_weighted_mean",
    "absolute_paired_delta_design_weighted_mean",
    "pointwise_ci95_lower",
    "pointwise_ci95_upper",
    "paired_delta_weighted_q25",
    "paired_delta_weighted_median",
    "paired_delta_weighted_q75",
    "paired_delta_weighted_iqr",
    "bootstrap_replicates",
    "bootstrap_seed",
    "ci_type",
)


class AttackReachabilityAnalysisError(ValueError):
    """Raised if an analysis input violates its frozen design."""


def fraction(
    row: Mapping[str, Any], population: str, partition: str, outcome: str
) -> float:
    section = row["outcomes"][population]
    return int(section[partition]["counts"][outcome]) / int(section["denominator_asns"])


def weighted_quantile(
    values: Sequence[float], weights: Sequence[float], quantile: float
) -> float:
    if not 0 <= quantile <= 1:
        raise ValueError("quantile must lie in [0, 1]")
    value_array = np.asarray(values, dtype=float)
    weight_array = np.asarray(weights, dtype=float)
    if value_array.size == 0 or value_array.shape != weight_array.shape:
        raise ValueError("values and weights must be nonempty and aligned")
    if np.any(~np.isfinite(value_array)) or np.any(~np.isfinite(weight_array)):
        raise ValueError("values and weights must be finite")
    if np.any(weight_array <= 0):
        raise ValueError("weights must be positive")
    order = np.argsort(value_array, kind="stable")
    cumulative = np.cumsum(weight_array[order])
    target = quantile * cumulative[-1]
    index = int(np.searchsorted(cumulative, target, side="left"))
    return float(value_array[order][min(index, len(order) - 1)])


def bootstrap_weight_matrix(
    holders: Sequence[int],
    unit_by_holder: Mapping[int, SiblingUnit],
    *,
    replicates: int,
    seed: int,
) -> np.ndarray:
    if replicates <= 0:
        raise ValueError("bootstrap replicates must be positive")
    rng = np.random.default_rng(seed)
    matrix = np.zeros((replicates, len(holders)), dtype=float)
    position = {holder: index for index, holder in enumerate(holders)}
    for stratum in ("S1", "S2", "S3", "S4"):
        members = [
            holder
            for holder in holders
            if unit_by_holder[holder].holder_stratum == stratum
        ]
        if len(members) != 50:
            raise AttackReachabilityAnalysisError(
                f"bootstrap stratum {stratum} has {len(members)} holders"
            )
        frame_sizes = {unit_by_holder[holder].N_h for holder in members}
        sample_sizes = {unit_by_holder[holder].n_h for holder in members}
        design_weights = {unit_by_holder[holder].design_weight for holder in members}
        if len(frame_sizes) != 1 or sample_sizes != {50} or len(design_weights) != 1:
            raise AttackReachabilityAnalysisError(f"inconsistent design metadata in {stratum}")
        n_h = len(members)
        N_h = next(iter(frame_sizes))
        counts = rng.multinomial(n_h, np.full(n_h, 1 / n_h), size=replicates).astype(
            float
        )
        rescale = np.sqrt(n_h * (1 - n_h / N_h) / (n_h - 1))
        rescaled_counts = 1 + rescale * (counts - 1)
        matrix[:, [position[holder] for holder in members]] = rescaled_counts * next(
            iter(design_weights)
        )
    return matrix


def build_holder_contrasts(
    rows: Sequence[Mapping[str, Any]], units: Sequence[SiblingUnit]
) -> list[dict[str, Any]]:
    by_holder: dict[int, dict[tuple[str, int], Mapping[str, Any]]] = defaultdict(dict)
    for row in rows:
        holder = int(row["holder_asn"])
        key = (str(row["lane"]), int(row["deployment_percent_target"]))
        if key in by_holder[holder]:
            raise AttackReachabilityAnalysisError(f"duplicate holder/cell {holder}/{key}")
        by_holder[holder][key] = row
    expected_cells = {(B1_SIBLING, 0), (A1_SIBLING, 0), (A1_SIBLING, 100)}
    if set(by_holder) != {unit.holder_asn for unit in units}:
        raise AttackReachabilityAnalysisError("result holders differ from manifest")
    if any(set(cells) != expected_cells for cells in by_holder.values()):
        raise AttackReachabilityAnalysisError("one or more holders lack the exact three cells")
    unit_by_holder = {unit.holder_asn: unit for unit in units}
    metric_specs = (
        ("Delta_E_sibling", "sibling_route", "attacker", "route"),
        (
            "Delta_E_sibling",
            "sibling_destination",
            "attacker",
            "destination",
        ),
        ("Delta_R_leaf", "leaf_route", "delegate", "route"),
        ("Delta_R_leaf", "leaf_destination", "delegate", "destination"),
    )
    contrasts: list[dict[str, Any]] = []
    for holder in sorted(by_holder):
        unit = unit_by_holder[holder]
        reference = by_holder[holder][(B1_SIBLING, 0)]
        for percent in (0, 100):
            treatment = by_holder[holder][(A1_SIBLING, percent)]
            for population in POPULATIONS:
                for estimand, partition, outcome, metric_level in metric_specs:
                    treatment_value = fraction(
                        treatment, population, partition, outcome
                    )
                    reference_value = fraction(
                        reference, population, partition, outcome
                    )
                    contrasts.append(
                        {
                            "holder_asn": holder,
                            "stratum": unit.holder_stratum,
                            "design_weight": unit.design_weight,
                            "estimand": estimand,
                            "metric_level": metric_level,
                            "population": population,
                            "deployment_percent_target": percent,
                            "treatment_fraction": treatment_value,
                            "reference_fraction": reference_value,
                            "delta": treatment_value - reference_value,
                        }
                    )
    expected = EXPECTED_HOLDERS * 2 * len(POPULATIONS) * len(metric_specs)
    if len(contrasts) != expected:
        raise AttackReachabilityAnalysisError(
            f"contrast grid has {len(contrasts)} rows, expected {expected}"
        )
    return contrasts


def summarize(
    contrasts: Sequence[Mapping[str, Any]], units: Sequence[SiblingUnit]
) -> list[dict[str, Any]]:
    cell_fields = (
        "estimand",
        "metric_level",
        "population",
        "deployment_percent_target",
    )
    grouped: dict[tuple[Any, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for item in contrasts:
        grouped[tuple(item[field] for field in cell_fields)].append(item)
    unit_by_holder = {unit.holder_asn: unit for unit in units}
    holders = sorted(unit_by_holder)
    holder_position = {holder: index for index, holder in enumerate(holders)}
    cells = sorted(grouped, key=repr)
    delta_matrix = np.empty((len(holders), len(cells)), dtype=float)
    for column, cell in enumerate(cells):
        group = grouped[cell]
        if len(group) != EXPECTED_HOLDERS:
            raise AttackReachabilityAnalysisError(f"cell {cell} is not holder-complete")
        for item in group:
            delta_matrix[holder_position[int(item["holder_asn"])], column] = float(
                item["delta"]
            )
    bootstrap_weights = bootstrap_weight_matrix(
        holders,
        unit_by_holder,
        replicates=BOOTSTRAP_REPLICATES,
        seed=BOOTSTRAP_SEED,
    )
    bootstrap_means = bootstrap_weights @ delta_matrix
    bootstrap_means /= bootstrap_weights.sum(axis=1, keepdims=True)
    intervals = np.percentile(bootstrap_means, (2.5, 97.5), axis=0, method="linear")
    summary: list[dict[str, Any]] = []
    for column, cell in enumerate(cells):
        group = grouped[cell]
        deltas = np.asarray([float(item["delta"]) for item in group])
        treatments = np.asarray([float(item["treatment_fraction"]) for item in group])
        references = np.asarray([float(item["reference_fraction"]) for item in group])
        weights = np.asarray([float(item["design_weight"]) for item in group])
        q25 = weighted_quantile(deltas, weights, 0.25)
        median = weighted_quantile(deltas, weights, 0.5)
        q75 = weighted_quantile(deltas, weights, 0.75)
        values = dict(zip(cell_fields, cell, strict=True))
        summary.append(
            {
                **values,
                "independent_unit": "holder_asn",
                "n_holders": EXPECTED_HOLDERS,
                "n_ases_as_independent_units": 0,
                "design_population_holders": 691,
                "design_weight_sum": float(weights.sum()),
                "raw_treatment_design_weighted_mean": float(
                    np.average(treatments, weights=weights)
                ),
                "raw_reference_design_weighted_mean": float(
                    np.average(references, weights=weights)
                ),
                "paired_delta_design_weighted_mean": float(
                    np.average(deltas, weights=weights)
                ),
                "absolute_paired_delta_design_weighted_mean": abs(
                    float(np.average(deltas, weights=weights))
                ),
                "pointwise_ci95_lower": float(intervals[0, column]),
                "pointwise_ci95_upper": float(intervals[1, column]),
                "paired_delta_weighted_q25": q25,
                "paired_delta_weighted_median": median,
                "paired_delta_weighted_q75": q75,
                "paired_delta_weighted_iqr": q75 - q25,
                "bootstrap_replicates": BOOTSTRAP_REPLICATES,
                "bootstrap_seed": BOOTSTRAP_SEED,
                "ci_type": (
                    "pointwise_stratified_paired_rescaled_percentile_srswor_fpc"
                ),
            }
        )
    return summary


def load_routing_model_leaf_references() -> dict[tuple[int, str], Mapping[str, Any]]:
    references: dict[tuple[int, str], Mapping[str, Any]] = {}
    with ROUTING_MODEL_RAW_RESULTS.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            role = None
            if row["lane"] == "B1_delegate_only":
                role = "B1"
            elif (
                row["lane"] == "D1_open_delegate_only"
                and row["deployment_percent_target"] == 0
                and row["deployment_strategy"] == "shared"
            ):
                role = "A0"
            elif (
                row["lane"] == "D1_open_delegate_only"
                and row["deployment_percent_target"] == 100
                and row["deployment_strategy"] == "shared"
            ):
                role = "A100"
            if role:
                key = (int(row["holder_asn"]), role)
                if key in references:
                    raise AttackReachabilityAnalysisError(f"duplicate routing-model leaf reference {key}")
                references[key] = row
    if len(references) != EXPECTED_HOLDERS * 3:
        raise AttackReachabilityAnalysisError(
            f"routing-model leaf reference grid has {len(references)} rows"
        )
    return references


def leaf_invariance_audit(
    rows: Sequence[Mapping[str, Any]], units: Sequence[SiblingUnit]
) -> dict[str, Any]:
    routing_model = load_routing_model_leaf_references()
    role_by_cell = {
        (B1_SIBLING, 0): "B1",
        (A1_SIBLING, 0): "A0",
        (A1_SIBLING, 100): "A100",
    }
    mismatches: list[dict[str, Any]] = []
    mismatch_count = 0
    comparisons = 0
    for row in rows:
        holder = int(row["holder_asn"])
        role = role_by_cell[(row["lane"], row["deployment_percent_target"])]
        reference = routing_model[(holder, role)]
        for population in POPULATIONS:
            p8 = row["outcomes"][population]
            p7 = reference["outcomes"][population]
            if (
                int(p7["child"]["counts"].get("attacker", 0)) != 0
                or int(p7["destination"]["counts"].get("attacker", 0)) != 0
            ):
                raise AttackReachabilityAnalysisError(
                    f"routing-model delegate-only reference contains attacker for AS{holder}"
                )
            pairs = (
                (
                    "leaf_route",
                    p8["leaf_route"]["counts"],
                    {key: p7["child"]["counts"][key] for key in ("delegate", "absent")},
                ),
                (
                    "leaf_destination",
                    p8["leaf_destination"]["counts"],
                    {
                        key: p7["destination"]["counts"][key]
                        for key in (
                            "delegate",
                            "holder_fallback",
                            "disconnected",
                            "loop",
                        )
                    },
                ),
            )
            for partition, actual, expected in pairs:
                comparisons += 1
                if actual != expected:
                    mismatch_count += 1
                    if len(mismatches) < 20:
                        mismatches.append(
                            {
                                "holder_asn": holder,
                                "role": role,
                                "population": population,
                                "partition": partition,
                                "attack_reachability": actual,
                                "routing_model": expected,
                            }
                        )
    return {
        "status": "passed" if mismatch_count == 0 else "failed",
        "routing_model_raw_results": ROUTING_MODEL_RAW_RESULTS.relative_to(
            REPOSITORY_ROOT
        ).as_posix(),
        "routing_model_raw_results_sha256": file_sha256(ROUTING_MODEL_RAW_RESULTS),
        "attack_reachability_rows_compared": len(rows),
        "partition_comparisons": comparisons,
        "mismatch_count": mismatch_count,
        "mismatches_shown": mismatches,
        "mismatches_shown_limit": 20,
        "interpretation": (
            "Adding a disjoint sibling announcement did not alter the matched "
            "original-leaf route or destination partitions."
        ),
    }


def scientific_digest(rows: Iterable[Mapping[str, Any]]) -> str:
    semantic_rows = []
    fields = (
        "scenario_id",
        "manifest_sha256",
        "unit_id",
        "pair_index",
        "holder_asn",
        "delegate_asn",
        "attacker_asn",
        "holder_stratum",
        "design_weight",
        "lane",
        "deployment_percent_target",
        "deployment_count",
        "deployment_set_sha256",
        "root_prefix",
        "leaf_prefix",
        "sibling_prefix",
        "policy_max_length",
        "policy_assignment_counts",
        "outcomes",
        "partition_checks",
    )
    for row in rows:
        semantic_rows.append({field: row[field] for field in fields})
    digest = hashlib.sha256()
    for row in sorted(semantic_rows, key=lambda item: item["scenario_id"]):
        digest.update(
            json.dumps(
                row, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
        )
        digest.update(b"\n")
    return digest.hexdigest()


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


def write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def primary_cell(
    summary: Sequence[Mapping[str, Any]], metric_level: str
) -> Mapping[str, Any]:
    matches = [
        row
        for row in summary
        if row["estimand"] == "Delta_E_sibling"
        and row["metric_level"] == metric_level
        and row["population"] == "all"
        and row["deployment_percent_target"] == 100
    ]
    if len(matches) != 1:
        raise AttackReachabilityAnalysisError(f"primary {metric_level} cell is not unique")
    return matches[0]


def results_markdown(
    manifest: Mapping[str, Any],
    summary: Sequence[Mapping[str, Any]],
    leaf_audit: Mapping[str, Any],
) -> str:
    route = primary_cell(summary, "route")
    destination = primary_cell(summary, "destination")

    def pp(value: Any) -> float:
        return 100 * float(value)

    return f"""## Attack reachability Sibling Endpoint Result

- Manifest: `{manifest["manifest_sha256"]}`
- Independent unit: `holder_asn` (n=200; design population 691)
- Frozen topology: {manifest["topology"]["asns"]:,} ASes
- Fixed measured ROV set: {manifest["topology"]["fixed_rov_count"]} ASes
- Physical trials: {EXPECTED_TRIALS}; retries: 0

At 100% of the fixed measured ROV set, open S2-ROV increased design-weighted
sibling-prefix attacker route selection by {pp(route["paired_delta_design_weighted_mean"]):.2f}
percentage points (pointwise 95% interval
[{pp(route["pointwise_ci95_lower"]):.2f}, {pp(route["pointwise_ci95_upper"]):.2f}])
and sibling-prefix attacker destination delivery by
{pp(destination["paired_delta_design_weighted_mean"]):.2f} points
([{pp(destination["pointwise_ci95_lower"]):.2f},
{pp(destination["pointwise_ci95_upper"]):.2f}]).

The exact original-leaf invariance audit compared
{leaf_audit["partition_comparisons"]} population/partition pairs and found
{leaf_audit["mismatch_count"]} mismatches.

These are conditional AS-level route-exposure results for a deterministic
same-length sibling under frozen inputs. They do not estimate traffic impact,
sibling utilization, delegation legitimacy, attack prevalence, or behavior on
other topology/ROV snapshots.
"""


def fallacy_scan() -> list[dict[str, str]]:
    return [
        {
            "fallacy": "Simpson's paradox",
            "status": "checked_no_directional_claim_across_strata",
        },
        {
            "fallacy": "Ecological fallacy",
            "status": "guarded_AS_route_outcomes_not_users_or_traffic",
        },
        {
            "fallacy": "Berkson's paradox",
            "status": "guarded_estimand_conditional_on_filtered_691_holder_frame",
        },
        {
            "fallacy": "Collider bias",
            "status": "checked_no_post_treatment_covariate_adjustment",
        },
        {
            "fallacy": "Base-rate neglect",
            "status": "guarded_no_attack_prevalence_or_legitimacy_inference",
        },
        {
            "fallacy": "Regression to the mean",
            "status": "not_applicable_matched_counterfactual_not_pre_post_extremes",
        },
        {
            "fallacy": "Survivorship bias",
            "status": "checked_all_600_planned_trials_required",
        },
        {
            "fallacy": "Look-elsewhere effect",
            "status": "guarded_primary_sibling_destination_estimand_frozen",
        },
        {
            "fallacy": "Garden of forking paths",
            "status": "guarded_manifest_frozen_before_outcomes",
        },
        {
            "fallacy": "Correlation versus causation",
            "status": "guarded_causal_statement_limited_to_simulated_policy_contrast",
        },
        {
            "fallacy": "Reverse causality",
            "status": "not_applicable_controlled_simulation_assignment",
        },
    ]


def analyze(
    manifest_path: Path, results_path: Path, output_dir: Path
) -> dict[str, Any]:
    manifest_path = require_attack_reachability_path(manifest_path, label="analysis manifest input")
    results_path = require_attack_reachability_path(results_path, label="analysis raw-results input")
    output_dir = require_attack_reachability_path(output_dir, label="analysis output directory")
    manifest = load_manifest(manifest_path)
    row_map, zero_state = scan_results(results_path, manifest)
    if len(row_map) != EXPECTED_TRIALS:
        raise AttackReachabilityAnalysisError(
            f"analysis requires all {EXPECTED_TRIALS} rows, found {len(row_map)}"
        )
    if len(zero_state) != EXPECTED_HOLDERS or any(
        set(cell) != {"reference", "open_zero"} for cell in zero_state.values()
    ):
        raise AttackReachabilityAnalysisError("zero-equivalence grid is incomplete")
    rows = [row_map[key] for key in sorted(row_map)]
    units = tuple(SiblingUnit(**item) for item in manifest["selected_units"])
    contrasts = build_holder_contrasts(rows, units)
    summary = summarize(contrasts, units)
    leaf_audit = leaf_invariance_audit(rows, units)
    if leaf_audit["status"] != "passed":
        raise AttackReachabilityAnalysisError("original-leaf invariance audit failed")
    output_dir.mkdir(parents=True, exist_ok=True)
    contrasts_path = output_dir / "holder_contrasts.jsonl"
    summary_json_path = output_dir / "summary.json"
    summary_csv_path = output_dir / "summary.csv"
    leaf_path = output_dir / "leaf_invariance_audit.json"
    results_md_path = output_dir / "RESULTS.md"
    write_jsonl(contrasts_path, contrasts)
    summary_document = {
        "schema_version": SCHEMA_VERSION,
        "version_label": VERSION_LABEL,
        "manifest_sha256": manifest["manifest_sha256"],
        "independent_unit": "holder_asn",
        "n_holders": EXPECTED_HOLDERS,
        "design_population_holders": 691,
        "bootstrap_replicates": BOOTSTRAP_REPLICATES,
        "bootstrap_seed": BOOTSTRAP_SEED,
        "cells": summary,
    }
    summary_json_path.write_text(
        json.dumps(summary_document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_csv(summary_csv_path, summary)
    leaf_path.write_text(
        json.dumps(leaf_audit, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    results_md_path.write_text(
        results_markdown(manifest, summary, leaf_audit), encoding="utf-8"
    )
    output_files = {
        path.name: file_sha256(path)
        for path in (
            contrasts_path,
            summary_json_path,
            summary_csv_path,
            leaf_path,
            results_md_path,
        )
    }
    checks = {
        "manifest_and_artifact_hashes_valid": True,
        "exact_600_scenario_grid": True,
        "all_rows_first_attempt_success": True,
        "all_outcome_partitions_complete": True,
        "all_equals_rov_plus_non_rov": True,
        "zero_upgrade_announcement_matched": True,
        "holder_is_independent_unit": True,
        "four_stratum_design_weights": True,
        "paired_rescaled_bootstrap_with_fpc": True,
        "original_leaf_exactly_invariant_to_sibling_announcement": True,
        "claim_boundary_explicit": True,
    }
    analysis_manifest = {
        "schema_version": SCHEMA_VERSION,
        "version_label": VERSION_LABEL,
        "created_at_utc": utc_now(),
        "status": "ANALYZED",
        "material_passport": {
            "origin_mode": "validate",
            "origin_date": utc_now()[:10],
            "verification_status": "ANALYZED",
            "version_label": VERSION_LABEL,
        },
        "inputs": {
            "manifest": manifest_path.relative_to(REPOSITORY_ROOT).as_posix(),
            "manifest_file_sha256": file_sha256(manifest_path),
            "raw_results": results_path.relative_to(REPOSITORY_ROOT).as_posix(),
            "raw_results_file_sha256": file_sha256(results_path),
            "raw_results_scientific_sha256": scientific_digest(rows),
            "routing_model_leaf_reference_sha256": file_sha256(ROUTING_MODEL_RAW_RESULTS),
        },
        "outputs": output_files,
        "checks": checks,
        "fallacy_scan": {
            "coverage": "11/11",
            "items": fallacy_scan(),
        },
        "reproducibility": {
            "classification": "deterministic_scientific_outputs",
            "timing_and_rss_excluded_from_scientific_digest": True,
            "verdict": "PENDING_INDEPENDENT_RERUN",
        },
        "claim_boundary": manifest["claim_boundary"],
    }
    analysis_manifest_path = output_dir / "analysis_manifest.json"
    analysis_manifest_path.write_text(
        json.dumps(analysis_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return analysis_manifest


REPRODUCTION_FILES = (
    "holder_contrasts.jsonl",
    "summary.json",
    "summary.csv",
    "leaf_invariance_audit.json",
)


def verify_reproduction(reference_dir: Path, candidate_dir: Path) -> dict[str, Any]:
    """Verify a separately executed analysis by exact scientific-file hashes."""

    reference = require_attack_reachability_path(
        reference_dir, label="reproduction reference directory"
    )
    candidate = require_attack_reachability_path(
        candidate_dir, label="reproduction candidate directory"
    )
    if reference == candidate:
        raise AttackReachabilityAnalysisError("reproduction requires two distinct directories")
    reference_manifest = json.loads(
        (reference / "analysis_manifest.json").read_text(encoding="utf-8")
    )
    candidate_manifest = json.loads(
        (candidate / "analysis_manifest.json").read_text(encoding="utf-8")
    )
    common_inputs = (
        "manifest_file_sha256",
        "raw_results_file_sha256",
        "raw_results_scientific_sha256",
        "routing_model_leaf_reference_sha256",
    )
    input_checks = {
        field: reference_manifest["inputs"].get(field)
        == candidate_manifest["inputs"].get(field)
        for field in common_inputs
    }
    file_checks: dict[str, Any] = {}
    for name in REPRODUCTION_FILES:
        reference_hash = file_sha256(reference / name)
        candidate_hash = file_sha256(candidate / name)
        file_checks[name] = {
            "reference_sha256": reference_hash,
            "candidate_sha256": candidate_hash,
            "exact_match": reference_hash == candidate_hash,
        }
    verified = all(input_checks.values()) and all(
        item["exact_match"] for item in file_checks.values()
    )
    audit = {
        "schema_version": SCHEMA_VERSION,
        "version_label": VERSION_LABEL,
        "created_at_utc": utc_now(),
        "status": "VERIFIED" if verified else "FAILED",
        "verification_scope": (
            "independent analysis rerun with exact scientific-output hashes"
        ),
        "reference_directory": reference.relative_to(REPOSITORY_ROOT).as_posix(),
        "candidate_directory": candidate.relative_to(REPOSITORY_ROOT).as_posix(),
        "input_identity_checks": input_checks,
        "scientific_file_checks": file_checks,
        "excluded_as_nondeterministic": [
            "analysis_manifest.json timestamps",
            "RESULTS.md material-passport date",
        ],
    }
    audit["reproduction_audit_sha256"] = canonical_sha256(
        audit, "reproduction_audit_sha256"
    )
    atomic_write_json(reference / "reproduction_audit.json", audit)
    if not verified:
        raise AttackReachabilityAnalysisError("independent analysis rerun did not reproduce")
    return audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--verify-reference",
        type=Path,
        help=(
            "after analysis, compare exact scientific hashes with this distinct "
            "attack-reachability analysis directory"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = analyze(args.manifest, args.results, args.output_dir)
    if args.verify_reference is not None:
        result = {
            "analysis": result,
            "reproduction": verify_reproduction(args.verify_reference, args.output_dir),
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
