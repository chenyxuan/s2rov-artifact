#!/usr/bin/env python3
"""Build the separated-announcement-set deployment-outcomes figure.

Panel (a) uses the intended-only announcement set and reports absolute
intended-route delivery under S²-ROV, Aggregate-only ROV, and
Exact-match ROV.
Panel (b) uses a different competition announcement set and reports absolute
delivery to a uniform eligible unlisted origin under the same three policies.

The script verifies the frozen Phase 7 raw/analysis artifacts, the Phase 9
selected-unit correction, and the independent Phase 7 deployment-grid
extension before writing source data, figure exports, a machine-readable
manifest, and a claim-boundary report.  It never edits the manuscript.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, Iterable

import matplotlib

matplotlib.use("Agg")
import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FixedLocator, StrMethodFormatter

from figure_typography import BODY_FONT_FAMILY, configure_body_font


SCRIPT = Path(__file__).resolve()
PROJECT = SCRIPT.parent.parent
REPO = PROJECT.parent
FIGURES = PROJECT / "figures"
SOURCE_DATA = FIGURES / "source_data"

PHASE7_ROOT = REPO / "phase7_simulation/results/paper_campaign"
PHASE7_MANIFEST = PHASE7_ROOT / "manifest.json"
PHASE7_RAW = PHASE7_ROOT / "raw_scenarios.jsonl"
PHASE7_ANALYSIS = PHASE7_ROOT / "analysis"
PHASE7_ANALYSIS_MANIFEST = PHASE7_ANALYSIS / "analysis_manifest.json"
PHASE7_HOLDER_CONTRASTS = PHASE7_ANALYSIS / "holder_contrasts.jsonl"
PHASE7_CELL_SUMMARY = PHASE7_ANALYSIS / "raw_cell_summary.csv"
PHASE7_OUTCOME_AUDIT = PHASE7_ANALYSIS / "outcome_partition_audit.json"

PHASE9_ROOT = REPO / "phase9_selected_unit_reanalysis"
PHASE9_CONTRACT = PHASE9_ROOT / "EXPERIMENT_CONTRACT.md"
PHASE9_SCRIPT = PHASE9_ROOT / "reanalyze.py"
PHASE9_COMPETITION = PHASE9_ROOT / "results/competition_cells.csv"
PHASE9_SUMMARY = PHASE9_ROOT / "results/summary.json"

GRID_EXTENSION_ROOT = REPO / "phase7_simulation/results/deployment_grid_extension"
GRID_EXTENSION_MANIFEST = GRID_EXTENSION_ROOT / "manifest.json"
GRID_EXTENSION_RAW = GRID_EXTENSION_ROOT / "raw_scenarios.jsonl"
GRID_EXTENSION_INDEPENDENT_AUDIT = (
    GRID_EXTENSION_ROOT / "independent_audit.json"
)
GRID_EXTENSION_ANALYSIS = GRID_EXTENSION_ROOT / "analysis"
GRID_EXTENSION_ANALYSIS_MANIFEST = GRID_EXTENSION_ANALYSIS / "analysis_manifest.json"
GRID_EXTENSION_ORDER_LEVEL = GRID_EXTENSION_ANALYSIS / "order_level_unit_contrasts.jsonl"
GRID_EXTENSION_UNIT_CONTRASTS = GRID_EXTENSION_ANALYSIS / "unit_contrasts.jsonl"
GRID_EXTENSION_CELL_SUMMARY_JSON = GRID_EXTENSION_ANALYSIS / "cell_summary.json"
GRID_EXTENSION_CELL_SUMMARY = GRID_EXTENSION_ANALYSIS / "cell_summary.csv"
GRID_EXTENSION_ORDER_TRAJECTORIES_JSON = (
    GRID_EXTENSION_ANALYSIS / "order_trajectories.json"
)
GRID_EXTENSION_ORDER_TRAJECTORIES = GRID_EXTENSION_ANALYSIS / "order_trajectories.csv"

SOURCE_CSV = SOURCE_DATA / "fig_deployment_outcomes.csv"
ORDER_SOURCE_CSV = SOURCE_DATA / "fig_deployment_outcomes_orders.csv"
REPORT = FIGURES / "FIG_DEPLOYMENT_OUTCOMES_PROVENANCE.md"
OUTPUT_STEMS = {
    "a": FIGURES / "fig_deployment_outcomes_a",
    "b": FIGURES / "fig_deployment_outcomes_b",
}
OUTPUT_SUFFIXES = (".svg", ".pdf", ".png", ".tiff")
OUTPUTS = {
    f"{panel}_{suffix.removeprefix('.')}": stem.with_suffix(suffix)
    for panel, stem in OUTPUT_STEMS.items()
    for suffix in OUTPUT_SUFFIXES
}
OUTPUT_MANIFEST = FIGURES / "fig_deployment_outcomes.manifest.json"

EXPECTED_INPUT_HASHES = {
    PHASE7_MANIFEST: "a674b87afd90716521f19673c4ddbd1153c1b911ec5021a99e0eabe579bcbeae",
    PHASE7_RAW: "fb9ec8fa80d41b5a98b4bc956d82ebfec0514eaab27fd183f86683dfed6925b7",
    PHASE7_ANALYSIS_MANIFEST: "27298f787bfb8856b23d5c21138526dd9adbb3259a57e64067268eb2fc4c2a73",
    PHASE7_HOLDER_CONTRASTS: "407194fa21a41a7c748caf114ed81183915a538b2d6ebebdbd3805b95edc2413",
    PHASE7_CELL_SUMMARY: "4de8618bd35fe21a4731033cab8a51d766eeb1d03d7aed5cc782fcef6ae86969",
    PHASE7_OUTCOME_AUDIT: "c32643e44ec67d7df5b9ed3f21c1531a7d31246d91d7986b2e3d33e4187df3e2",
    PHASE9_CONTRACT: "acf565552a21a342b20c3806cf15a582bdca491c72c44dd7f3d2559a79ec3b03",
    PHASE9_SCRIPT: "40e78d20f6f11b1cacc808df05dff6a18aa90c31be1c3115245975461a1a39fb",
    PHASE9_COMPETITION: "176547af20b4b661ddbbdf647fc62233602838eaa086ed20237854f7007a170d",
    PHASE9_SUMMARY: "64448d3464f26202436bec12016bceb266d65d40ebd1118115a3c92f75ba716f",
}

# Kept for the fail-closed unit test.  Every formal artifact below must instead
# carry a populated SHA-256 digest before the generator can run.
_PENDING_EXTENSION_HASH = "FILL_AFTER_FORMAL_GRID_EXTENSION_RUN"
EXPECTED_GRID_EXTENSION_HASHES = {
    GRID_EXTENSION_MANIFEST: "f5a20c7a2592b6cac6231fba4d2635806644432da9c6ee207ae97d470a049999",
    GRID_EXTENSION_RAW: "d1ad91a251a06899179e353d0771bca53b2cbd7ffff95dad8dc0d12531878716",
    GRID_EXTENSION_INDEPENDENT_AUDIT: "c5201a212681c150e9574e0c5885eabb607ff990647ab475787c0f0bcd185713",
    GRID_EXTENSION_ANALYSIS_MANIFEST: "51e9488e7d3b1e607581128ee5e89f692bab1ddd64b6902919e92ccaf6591a39",
    GRID_EXTENSION_ORDER_LEVEL: "4bd56f2e20ada3fb764bbabefc89f3a4e5a9e93ca8a890e6cb2a09271dbeb981",
    GRID_EXTENSION_UNIT_CONTRASTS: "e2b7807e64892c90b681217724ca603715705635aa21794411b0c4e2c7e41c7e",
    GRID_EXTENSION_CELL_SUMMARY_JSON: "4e1cf522e822c69fc478ed824d1086f9a837c6f1fb4ab0b79d7b4b26cb7bc0b7",
    GRID_EXTENSION_CELL_SUMMARY: "cd9c3c2966e19c43dc991de1980bf4d80a0f75b4656f84b14bb9e5b7e75042fc",
    GRID_EXTENSION_ORDER_TRAJECTORIES_JSON: "09aaf1e49c5327d95d22bc49e1f1eee432a660f2f6a3463df468198555d933f7",
    GRID_EXTENSION_ORDER_TRAJECTORIES: "267c83c962a051ef480f9b6965deb62ec377db54d8b39d2e3418dab923865bbc",
}

PHASE7_DEPLOYMENT_PERCENTS = [0, 1, 5, 10, 25, 50, 75, 100]
PHASE7_DEPLOYMENT_COUNTS = {
    0: 0,
    1: 5,
    5: 29,
    10: 58,
    25: 147,
    50: 294,
    75: 441,
    100: 589,
}
GRID_EXTENSION_PERCENTS = [20, 30, 40, 60, 70, 80, 90]
FROZEN_ANCHOR_PERCENTS = [0, 10, 50, 100]
DEPLOYMENT_PERCENTS = list(range(0, 101, 10))
DEPLOYMENT_COUNTS = {
    percent: int(589 * percent / 100) for percent in DEPLOYMENT_PERCENTS
}
RANDOM_ORDERS = [f"random_{seed:02d}" for seed in range(1, 6)]
TOL = 1e-12

BLUE = "#0F4D92"
BLUE_FILL = "#DCE8F5"
RED = "#B64342"
RED_FILL = "#F5DEDC"
GREY = "#4D5358"
GREY_MID = "#7B8187"
GREY_LIGHT = "#E7E9EB"
GRID = "#D9DDE0"
WHITE = "#FFFFFF"

ACTIVE_PANEL_FIGSIZE = (3.50, 1.75)
ACTIVE_PANEL_MARGINS = {
    "left": 0.145,
    "right": 0.94,
    "bottom": 0.27,
    "top": 0.89,
}
ACTIVE_BASE_FONTSIZE = 8.4
ACTIVE_TICK_LABELSIZE = 7.56
ACTIVE_AXIS_LABELSIZE = 8.4
ACTIVE_LEGEND_FONTSIZE = 6.96
ACTIVE_TITLE_FONTSIZE = 9.0

S2_ROV_LABEL = "S²-ROV"
AGGREGATE_ROV_LABEL = "Aggregate-only ROV"
EXACT_ROV_LABEL = "Exact-match ROV"
UPGRADE_AXIS_LABEL = "S²-ROV upgraded share (%)"

X_TICKS = (0, 20, 40, 60, 80, 100)
PANEL_A_Y_TICKS = (80, 85, 90, 95, 100)
PANEL_B_Y_TICKS = (0, 10, 20, 30, 40, 50)
INTEGER_TICK_FORMAT = "{x:.0f}"

SOURCE_FIELDS = [
    "panel",
    "announcement_set",
    "series",
    "estimand",
    "metric_level",
    "population",
    "attacker_class",
    "deployment_strategy",
    "deployment_percent",
    "deployment_as_count",
    "treatment_lane",
    "reference_lane",
    "independent_unit",
    "n_selected_units",
    "inference_target",
    "inference_target_units",
    "treatment_delivery_pct",
    "reference_delivery_pct",
    "estimate_pp",
    "interval95_low_pp",
    "interval95_high_pp",
    "interval_interpretation",
    "bootstrap_replicates",
    "bootstrap_seed",
    "point_estimate_source",
    "interval_source",
]

ORDER_SOURCE_FIELDS = [
    "panel",
    "announcement_set",
    "estimand",
    "metric_level",
    "population",
    "attacker_class",
    "deployment_order",
    "deployment_percent",
    "deployment_as_count",
    "estimate_pp",
    "n_selected_units",
    "independent_unit",
    "point_estimate_source",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repo_path(path: Path) -> str:
    return path.relative_to(REPO).as_posix()


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(
    path: Path, rows: Iterable[dict[str, Any]], *, fields: list[str] = SOURCE_FIELDS
) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _is_sha256(value: str) -> bool:
    return re.fullmatch(r"[0-9a-f]{64}", value) is not None


def verify_hashes(
    expected_hashes: dict[Path, str], *, input_group: str
) -> dict[str, str]:
    observed: dict[str, str] = {}
    for path, expected in expected_hashes.items():
        if not _is_sha256(expected):
            raise ValueError(
                f"{input_group} expected SHA-256 is not populated for {repo_path(path)}"
            )
        if not path.is_file():
            raise FileNotFoundError(
                f"required {input_group} input is missing: {repo_path(path)}"
            )
        actual = sha256(path)
        if actual != expected:
            raise ValueError(
                f"{input_group} input hash mismatch: "
                f"{repo_path(path)}: {actual} != {expected}"
            )
        observed[repo_path(path)] = actual
    return observed


def canonical_manifest_sha256(manifest: dict[str, Any]) -> str:
    core = dict(manifest)
    core.pop("manifest_sha256", None)
    encoded = json.dumps(
        core, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def verify_upstream_contracts() -> dict[str, Any]:
    phase7_manifest = load_json(PHASE7_MANIFEST)
    phase7_analysis = load_json(PHASE7_ANALYSIS_MANIFEST)
    phase7_audit = load_json(PHASE7_OUTCOME_AUDIT)
    phase9_summary = load_json(PHASE9_SUMMARY)

    if phase7_analysis.get("status") != "VERIFIED":
        raise ValueError("Phase 7 analysis manifest is not VERIFIED")
    if phase7_analysis.get("scenario_rows") != 36_800:
        raise ValueError("Phase 7 analysis does not contain 36,800 scenarios")
    if phase7_analysis.get("n_independent_holders") != 200:
        raise ValueError("Phase 7 analysis does not contain 200 selected units")
    checks = phase7_analysis.get("checks", {})
    if not checks or any(value is not True for value in checks.values()):
        raise ValueError("at least one Phase 7 analysis check is not true")

    validation = phase7_audit.get("validation", {})
    for key in (
        "all_rows_attempt_1_success",
        "all_rows_destination_partition_sum_1",
        "all_weighted_aggregate_partition_sum_1",
        "scenario_ids_exactly_match_frozen_plan",
        "stored_fractions_match_recomputed_counts",
    ):
        if validation.get(key) is not True:
            raise ValueError(f"Phase 7 outcome audit failed: {key}")
    if validation.get("raw_rows") != 36_800 or validation.get("holders_unique") != 200:
        raise ValueError("Phase 7 outcome audit row/unit counts disagree with the contract")

    if phase9_summary.get("status") != "complete":
        raise ValueError("Phase 9 selected-unit reanalysis is not complete")
    phase9_contract = phase9_summary.get("contract", {})
    if phase9_contract.get("selected_units") != 200:
        raise ValueError("Phase 9 selected-unit target is not 200")
    if phase9_contract.get("finite_population_correction") is not False:
        raise ValueError("Phase 9 corrected intervals unexpectedly use an FPC")
    if not str(phase9_contract.get("interval_interpretation", "")).startswith(
        "descriptive ordinary stratified paired bootstrap stability"
    ):
        raise ValueError("Phase 9 interval interpretation is unexpected")
    if abs(float(phase9_summary["audits"]["phase7_max_point_error_vs_frozen"])) > TOL:
        raise ValueError("Phase 9 point estimates do not reproduce frozen Phase 7")

    phase9_inputs = phase9_summary.get("inputs_sha256", {})
    for path in (PHASE7_HOLDER_CONTRASTS, PHASE7_CELL_SUMMARY):
        if phase9_inputs.get(repo_path(path)) != EXPECTED_INPUT_HASHES[path]:
            raise ValueError(f"Phase 9 input ledger disagrees for {repo_path(path)}")

    percentages = phase7_manifest.get("design", {}).get("deployment_percentages")
    if percentages != PHASE7_DEPLOYMENT_PERCENTS:
        raise ValueError("Phase 7 deployment-percentage grid is unexpected")
    orders = phase7_manifest.get("deployment_orders", [])
    if len(orders) != 7:
        raise ValueError("Phase 7 must contain degree, cone, and five random orders")
    expected_counts_as_text = {
        str(key): value for key, value in PHASE7_DEPLOYMENT_COUNTS.items()
    }
    for order in orders:
        if order.get("deployment_counts") != expected_counts_as_text:
            raise ValueError(f"deployment counts differ for {order.get('order_id')}")

    return {
        "phase7_manifest": phase7_manifest,
        "phase7_analysis": phase7_analysis,
        "phase7_audit": phase7_audit,
        "phase9_summary": phase9_summary,
    }


def verify_grid_extension_contracts(
    observed_hashes: dict[str, str],
) -> dict[str, Any]:
    """Validate the extension independently of the frozen Phase 7/9 checks."""

    manifest = load_json(GRID_EXTENSION_MANIFEST)
    audit = load_json(GRID_EXTENSION_INDEPENDENT_AUDIT)
    analysis = load_json(GRID_EXTENSION_ANALYSIS_MANIFEST)

    if manifest.get("manifest_sha256") != canonical_manifest_sha256(manifest):
        raise ValueError("deployment-grid extension manifest self-hash mismatch")
    design = manifest.get("design", {})
    if design.get("deployment_percentages") != GRID_EXTENSION_PERCENTS:
        raise ValueError("deployment-grid extension does not contain the frozen seven points")
    if design.get("deployment_orders") != RANDOM_ORDERS:
        raise ValueError("deployment-grid extension does not use the five frozen orders")
    if design.get("physical_trials") != 14_000 or design.get("selected_units") != 200:
        raise ValueError("deployment-grid extension trial/unit counts are unexpected")
    if design.get("shares_denominator") != "fixed measured 589-AS ROV set":
        raise ValueError("deployment-grid extension changes the 589-AS denominator")
    source = manifest.get("source_campaign", {})
    if source.get("file_sha256") != EXPECTED_INPUT_HASHES[PHASE7_MANIFEST]:
        raise ValueError("deployment-grid extension is not bound to frozen Phase 7")

    if audit.get("passed") is not True or audit.get("issues") != []:
        raise ValueError("deployment-grid extension independent audit did not pass")
    audit_checks = audit.get("checks", {})
    if len(audit_checks) != 32 or any(value is not True for value in audit_checks.values()):
        raise ValueError("deployment-grid extension independent audit has a failed check")
    audited = audit.get("observed", {})
    if audited.get("manifest_file_sha256") != observed_hashes[
        repo_path(GRID_EXTENSION_MANIFEST)
    ]:
        raise ValueError("independent audit manifest hash disagrees")
    if audited.get("raw_file_sha256") != observed_hashes[repo_path(GRID_EXTENSION_RAW)]:
        raise ValueError("independent audit raw hash disagrees")
    if audited.get("manifest_self_sha256") != manifest.get("manifest_sha256"):
        raise ValueError("independent audit manifest self-hash disagrees")
    if audited.get("raw_rows") != 14_000 or audited.get("unique_scenario_ids") != 14_000:
        raise ValueError("independent audit row or scenario-ID count disagrees")

    if analysis.get("status") != "VERIFIED":
        raise ValueError("deployment-grid extension analysis is not VERIFIED")
    checks = analysis.get("checks", {})
    if not checks or any(value is not True for value in checks.values()):
        raise ValueError("deployment-grid extension analysis has a failed check")
    counts = analysis.get("counts", {})
    expected_counts = {
        "extension_scenarios": 14_000,
        "extension_scenarios_expected": 14_000,
        "selected_units": 200,
        "random_orders": 5,
        "full_grid_percentages": DEPLOYMENT_PERCENTS,
        "order_level_unit_contrasts": 22_000,
        "unit_averaged_contrasts": 4_400,
        "summary_cells": 22,
        "order_trajectory_points": 110,
        "n_random_orders_as_independent_units": 0,
    }
    for key, expected in expected_counts.items():
        if counts.get(key) != expected:
            raise ValueError(
                f"deployment-grid extension analysis count {key} is unexpected"
            )

    input_ledger = analysis.get("inputs", {})
    manifest_input = input_ledger.get("extension_manifest", {})
    if manifest_input.get("file_sha256") != observed_hashes[repo_path(GRID_EXTENSION_MANIFEST)]:
        raise ValueError("extension analysis manifest-input hash disagrees")
    raw_inputs = input_ledger.get("extension_results", [])
    if len(raw_inputs) != 1 or raw_inputs[0].get("file_sha256") != observed_hashes[
        repo_path(GRID_EXTENSION_RAW)
    ]:
        raise ValueError("extension analysis raw-input hash disagrees")

    output_paths = {
        "order_level_unit_contrasts": GRID_EXTENSION_ORDER_LEVEL,
        "unit_contrasts": GRID_EXTENSION_UNIT_CONTRASTS,
        "cell_summary_json": GRID_EXTENSION_CELL_SUMMARY_JSON,
        "cell_summary_csv": GRID_EXTENSION_CELL_SUMMARY,
        "order_trajectories_json": GRID_EXTENSION_ORDER_TRAJECTORIES_JSON,
        "order_trajectories_csv": GRID_EXTENSION_ORDER_TRAJECTORIES,
    }
    output_ledger = analysis.get("outputs_sha256", {})
    for key, path in output_paths.items():
        actual = observed_hashes[repo_path(path)]
        if output_ledger.get(key) != actual:
            raise ValueError(f"extension analysis output hash disagrees for {key}")

    bootstrap = analysis.get("bootstrap", {})
    if bootstrap.get("replicates") != 10_000 or bootstrap.get("seed") != 20_260_804:
        raise ValueError("deployment-grid extension bootstrap contract changed")
    frozen_audit = analysis.get("frozen_intersection_audit", {})
    if frozen_audit.get("frozen_intersection_cells") != 8:
        raise ValueError("deployment-grid extension does not anchor all eight frozen cells")
    if frozen_audit.get("point_and_interval_values_exact_after_anchor") is not True:
        raise ValueError("deployment-grid extension frozen intersections are not exact")

    return {"manifest": manifest, "audit": audit, "analysis": analysis}


def select_rows(
    rows: list[dict[str, str]],
    *,
    estimand: str,
    attacker_class: str,
    strategy: str,
    expected_percentages: list[int] | None = None,
) -> list[dict[str, str]]:
    if expected_percentages is None:
        expected_percentages = DEPLOYMENT_PERCENTS
    selected = [
        row
        for row in rows
        if row["estimand"] == estimand
        and row["metric_level"] == "destination"
        and row["population"] == "all"
        and row["attacker_class"] == attacker_class
        and row["deployment_strategy"] == strategy
    ]
    selected.sort(key=lambda row: int(row["deployment_percent_target"]))
    if [int(row["deployment_percent_target"]) for row in selected] != expected_percentages:
        raise ValueError(
            f"incomplete deployment grid for {estimand}/{attacker_class or 'none'}/{strategy}"
        )
    return selected


def finite(value: Any, label: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"non-finite value in {label}")
    return number


def close(left: float, right: float, label: str, tolerance: float = TOL) -> None:
    if not math.isclose(left, right, rel_tol=0.0, abs_tol=tolerance):
        raise ValueError(f"{label}: {left} != {right}")


def extract_source_rows() -> tuple[
    list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]
]:
    phase7_rows = load_csv(PHASE7_CELL_SUMMARY)
    phase9_rows = load_csv(PHASE9_COMPETITION)
    extension_rows = load_csv(GRID_EXTENSION_CELL_SUMMARY)
    extension_orders = load_csv(GRID_EXTENSION_ORDER_TRAJECTORIES)

    frozen_delegate = select_rows(
        phase7_rows,
        estimand="Delta_R",
        attacker_class="",
        strategy="random",
        expected_percentages=PHASE7_DEPLOYMENT_PERCENTS,
    )
    delegate_vs_exact = select_rows(
        phase7_rows,
        estimand="Delta_R_exact",
        attacker_class="",
        strategy="random",
        expected_percentages=PHASE7_DEPLOYMENT_PERCENTS,
    )
    phase9_exposure = select_rows(
        phase9_rows,
        estimand="Delta_E_rov",
        attacker_class="uniform",
        strategy="random",
        expected_percentages=PHASE7_DEPLOYMENT_PERCENTS,
    )
    phase9_exact = select_rows(
        phase9_rows,
        estimand="Delta_E_exact",
        attacker_class="uniform",
        strategy="random",
        expected_percentages=PHASE7_DEPLOYMENT_PERCENTS,
    )
    delegate = select_rows(
        extension_rows,
        estimand="Delta_R",
        attacker_class="",
        strategy="random_five_order_average",
    )
    exposure = select_rows(
        extension_rows,
        estimand="Delta_E_rov",
        attacker_class="uniform",
        strategy="random_five_order_average",
    )

    old_a = {int(row["deployment_percent_target"]): row for row in frozen_delegate}
    old_b = {int(row["deployment_percent_target"]): row for row in phase9_exposure}
    for row in delegate:
        percent = int(row["deployment_percent_target"])
        if percent not in FROZEN_ANCHOR_PERCENTS:
            continue
        accepted = old_a[percent]
        for new_field, old_field in (
            ("paired_delta_design_weighted_mean", "paired_delta_design_weighted_mean"),
            ("treatment_design_weighted_mean", "raw_treatment_design_weighted_mean"),
            ("reference_design_weighted_mean", "raw_reference_design_weighted_mean"),
            ("pointwise_interval95_lower", "pointwise_ci95_lower"),
            ("pointwise_interval95_upper", "pointwise_ci95_upper"),
        ):
            close(
                finite(row[new_field], f"merged Delta_R {new_field}"),
                finite(accepted[old_field], f"frozen Delta_R {old_field}"),
                f"merged/frozen Delta_R anchor at {percent}%",
            )
    for row in exposure:
        percent = int(row["deployment_percent_target"])
        if percent not in FROZEN_ANCHOR_PERCENTS:
            continue
        accepted = old_b[percent]
        for new_field, old_field in (
            ("paired_delta_design_weighted_mean", "stratum_standardized_selected_unit_mean"),
            ("treatment_design_weighted_mean", "raw_treatment_stratum_standardized_mean"),
            ("reference_design_weighted_mean", "raw_reference_stratum_standardized_mean"),
            ("pointwise_interval95_lower", "resampling_interval95_lower"),
            ("pointwise_interval95_upper", "resampling_interval95_upper"),
        ):
            close(
                finite(row[new_field], f"merged Delta_E_rov {new_field}"),
                finite(accepted[old_field], f"frozen Delta_E_rov {old_field}"),
                f"merged/frozen Delta_E_rov anchor at {percent}%",
            )

    source_rows: list[dict[str, Any]] = []
    aggregate_delivery = finite(
        frozen_delegate[0]["raw_reference_design_weighted_mean"], "aggregate delivery"
    )
    exact_delivery = finite(
        delegate_vs_exact[0]["raw_reference_design_weighted_mean"],
        "exact-child delivery",
    )
    exact_delta = exact_delivery - aggregate_delivery

    full_frozen_delegate = frozen_delegate[-1]
    close(
        finite(
            full_frozen_delegate["raw_treatment_design_weighted_mean"],
            "full OpenScope delivery",
        ),
        exact_delivery,
        "full OpenScope and exact-child intended-only delivery",
    )
    close(
        finite(
            delegate_vs_exact[-1]["paired_delta_design_weighted_mean"],
            "full OpenScope minus exact",
        ),
        0.0,
        "full OpenScope minus exact-child intended-only delta",
    )
    close(
        finite(
            full_frozen_delegate["paired_delta_design_weighted_mean"],
            "full intended delta",
        ),
        exact_delta,
        "exact-child reference delta",
    )

    aggregate_minus_exact = delegate_vs_exact[0]
    close(
        finite(
            aggregate_minus_exact["paired_delta_design_weighted_mean"],
            "aggregate minus exact-child delta",
        ),
        -exact_delta,
        "aggregate-minus-exact reference contrast",
    )
    exact_ci_low = -finite(
        aggregate_minus_exact["pointwise_ci95_upper"],
        "aggregate-minus-exact CI high",
    )
    exact_ci_high = -finite(
        aggregate_minus_exact["pointwise_ci95_lower"],
        "aggregate-minus-exact CI low",
    )

    for row in delegate:
        percent = int(row["deployment_percent_target"])
        treatment = finite(row["treatment_design_weighted_mean"], "delegate treatment")
        reference = finite(row["reference_design_weighted_mean"], "delegate reference")
        estimate = finite(row["paired_delta_design_weighted_mean"], "delegate delta")
        low = finite(row["pointwise_interval95_lower"], "delegate interval low")
        high = finite(row["pointwise_interval95_upper"], "delegate interval high")
        close(treatment - reference, estimate, f"delegate contrast at {percent}%")
        close(reference, aggregate_delivery, f"aggregate delegate baseline at {percent}%")
        if not low <= estimate <= high:
            raise ValueError(f"delegate point estimate lies outside its interval at {percent}%")
        if int(row["n_units"]) != 200 or row["finite_population_correction"] != "True":
            raise ValueError("delegate unit/interval contract changed")
        source_rows.append(
            {
                "panel": "a",
                "announcement_set": "intended_only",
                "series": "OpenScope_minus_aggregate_only",
                "estimand": "Delta_R",
                "metric_level": "destination",
                "population": "all_AS_destinations",
                "attacker_class": "none",
                "deployment_strategy": "random_five_order_average",
                "deployment_percent": percent,
                "deployment_as_count": DEPLOYMENT_COUNTS[percent],
                "treatment_lane": "D1_open_delegate_only",
                "reference_lane": "B1_delegate_only",
                "independent_unit": "holder/root-origin unit",
                "n_selected_units": 200,
                "inference_target": "finite_candidate_root_origin_frame",
                "inference_target_units": 691,
                "treatment_delivery_pct": 100.0 * treatment,
                "reference_delivery_pct": 100.0 * reference,
                "estimate_pp": 100.0 * estimate,
                "interval95_low_pp": 100.0 * low,
                "interval95_high_pp": 100.0 * high,
                "interval_interpretation": "pointwise_95pct_finite_frame_design_CI",
                "bootstrap_replicates": int(row["bootstrap_replicates"]),
                "bootstrap_seed": int(row["bootstrap_seed"]),
                "point_estimate_source": repo_path(GRID_EXTENSION_CELL_SUMMARY),
                "interval_source": repo_path(GRID_EXTENSION_CELL_SUMMARY),
            }
        )

    source_rows.append(
        {
            "panel": "a",
            "announcement_set": "intended_only",
            "series": "exact_child_minus_aggregate_only_reference",
            "estimand": "exact_child_reference_Delta_R",
            "metric_level": "destination",
            "population": "all_AS_destinations",
            "attacker_class": "none",
            "deployment_strategy": "reference",
            "deployment_percent": "",
            "deployment_as_count": "",
            "treatment_lane": "B2_exact_delegate_only",
            "reference_lane": "B1_delegate_only",
            "independent_unit": "holder/root-origin unit",
            "n_selected_units": 200,
            "inference_target": "finite_candidate_root_origin_frame",
            "inference_target_units": 691,
            "treatment_delivery_pct": 100.0 * exact_delivery,
            "reference_delivery_pct": 100.0 * aggregate_delivery,
            "estimate_pp": 100.0 * exact_delta,
            "interval95_low_pp": 100.0 * exact_ci_low,
            "interval95_high_pp": 100.0 * exact_ci_high,
            "interval_interpretation": "pointwise_95pct_finite_frame_design_CI",
            "bootstrap_replicates": int(full_frozen_delegate["bootstrap_replicates"]),
            "bootstrap_seed": int(full_frozen_delegate["bootstrap_seed"]),
            "point_estimate_source": repo_path(PHASE7_CELL_SUMMARY),
            "interval_source": repo_path(PHASE7_CELL_SUMMARY),
        }
    )

    competition_aggregate_delivery = finite(
        phase9_exposure[0]["raw_reference_stratum_standardized_mean"],
        "competition aggregate-only exposure",
    )
    competition_exact_delivery = finite(
        phase9_exact[0]["raw_reference_stratum_standardized_mean"],
        "competition exact-ROA exposure",
    )
    competition_exact_delta = (
        competition_exact_delivery - competition_aggregate_delivery
    )
    aggregate_minus_competition_exact = phase9_exact[0]
    close(
        finite(
            aggregate_minus_competition_exact[
                "raw_treatment_stratum_standardized_mean"
            ],
            "competition aggregate-only exposure in exact contrast",
        ),
        competition_aggregate_delivery,
        "competition aggregate-only exposure across contrasts",
    )
    close(
        finite(
            aggregate_minus_competition_exact[
                "stratum_standardized_selected_unit_mean"
            ],
            "competition aggregate-minus-exact contrast",
        ),
        -competition_exact_delta,
        "competition Exact-match ROV reference contrast",
    )
    competition_exact_ci_low = -finite(
        aggregate_minus_competition_exact["resampling_interval95_upper"],
        "competition aggregate-minus-exact interval high",
    )
    competition_exact_ci_high = -finite(
        aggregate_minus_competition_exact["resampling_interval95_lower"],
        "competition aggregate-minus-exact interval low",
    )
    for exact_row, exposure_row in zip(phase9_exact, phase9_exposure, strict=True):
        percent = int(exact_row["deployment_percent_target"])
        close(
            finite(
                exact_row["raw_treatment_stratum_standardized_mean"],
                f"competition OpenScope exposure in exact contrast at {percent}%",
            ),
            finite(
                exposure_row["raw_treatment_stratum_standardized_mean"],
                f"competition OpenScope exposure in aggregate contrast at {percent}%",
            ),
            f"competition treatment exposure across contrasts at {percent}%",
        )
        close(
            finite(
                exact_row["raw_reference_stratum_standardized_mean"],
                f"competition exact-ROA exposure at {percent}%",
            ),
            competition_exact_delivery,
            f"competition Exact-match ROV reference at {percent}%",
        )

    source_rows.append(
        {
            "panel": "b",
            "announcement_set": "competition_uniform_unlisted_origin",
            "series": "exact_ROA_minus_announcement_matched_aggregate_only_reference",
            "estimand": "exact_ROA_reference_Delta_E",
            "metric_level": "destination",
            "population": "all_AS_destinations",
            "attacker_class": "uniform",
            "deployment_strategy": "reference",
            "deployment_percent": "",
            "deployment_as_count": "",
            "treatment_lane": "B2_exact_competition",
            "reference_lane": "B1_competition",
            "independent_unit": "holder/root-origin unit",
            "n_selected_units": 200,
            "inference_target": "selected_synthetic_units_only",
            "inference_target_units": 200,
            "treatment_delivery_pct": 100.0 * competition_exact_delivery,
            "reference_delivery_pct": 100.0 * competition_aggregate_delivery,
            "estimate_pp": 100.0 * competition_exact_delta,
            "interval95_low_pp": 100.0 * competition_exact_ci_low,
            "interval95_high_pp": 100.0 * competition_exact_ci_high,
            "interval_interpretation": "pointwise_95pct_selected_unit_bootstrap_stability_interval",
            "bootstrap_replicates": int(
                aggregate_minus_competition_exact["bootstrap_replicates"]
            ),
            "bootstrap_seed": int(
                aggregate_minus_competition_exact["bootstrap_seed"]
            ),
            "point_estimate_source": repo_path(PHASE9_COMPETITION),
            "interval_source": repo_path(PHASE9_COMPETITION),
        }
    )

    for row in exposure:
        percent = int(row["deployment_percent_target"])
        estimate = finite(row["paired_delta_design_weighted_mean"], "exposure delta")
        treatment = finite(row["treatment_design_weighted_mean"], "exposure treatment")
        reference = finite(row["reference_design_weighted_mean"], "exposure reference")
        low = finite(row["pointwise_interval95_lower"], "exposure interval low")
        high = finite(row["pointwise_interval95_upper"], "exposure interval high")
        close(treatment - reference, estimate, f"exposure contrast at {percent}%")
        if not low <= estimate <= high:
            raise ValueError(f"exposure point estimate lies outside its interval at {percent}%")
        if int(row["n_units"]) != 200 or row["finite_population_correction"] != "False":
            raise ValueError("exposure unit/interval contract changed")
        if row["interval_type"] != "ordinary_stratified_paired_percentile_selected_unit_stability":
            raise ValueError("exposure interval type is unexpected")
        source_rows.append(
            {
                "panel": "b",
                "announcement_set": "competition_uniform_unlisted_origin",
                "series": "OpenScope_minus_announcement_matched_aggregate_only",
                "estimand": "Delta_E_rov",
                "metric_level": "destination",
                "population": "all_AS_destinations",
                "attacker_class": "uniform",
                "deployment_strategy": "random_five_order_average",
                "deployment_percent": percent,
                "deployment_as_count": DEPLOYMENT_COUNTS[percent],
                "treatment_lane": "A1_open_competition",
                "reference_lane": "B1_competition",
                "independent_unit": "holder/root-origin unit",
                "n_selected_units": 200,
                "inference_target": "selected_synthetic_units_only",
                "inference_target_units": 200,
                "treatment_delivery_pct": 100.0 * treatment,
                "reference_delivery_pct": 100.0 * reference,
                "estimate_pp": 100.0 * estimate,
                "interval95_low_pp": 100.0 * low,
                "interval95_high_pp": 100.0 * high,
                "interval_interpretation": "pointwise_95pct_selected_unit_bootstrap_stability_interval",
                "bootstrap_replicates": int(row["bootstrap_replicates"]),
                "bootstrap_seed": int(row["bootstrap_seed"]),
                "point_estimate_source": repo_path(GRID_EXTENSION_CELL_SUMMARY),
                "interval_source": repo_path(GRID_EXTENSION_CELL_SUMMARY),
            }
        )

    order_rows: list[dict[str, Any]] = []
    expected_order_cells = {
        (estimand, percent, order)
        for estimand in ("Delta_R", "Delta_E_rov")
        for percent in DEPLOYMENT_PERCENTS
        for order in RANDOM_ORDERS
    }
    observed_order_cells: set[tuple[str, int, str]] = set()
    for row in extension_orders:
        estimand = row["estimand"]
        percent = int(row["deployment_percent_target"])
        order = row["deployment_order"]
        cell = (estimand, percent, order)
        if cell in observed_order_cells:
            raise ValueError(f"duplicate order trajectory cell {cell!r}")
        observed_order_cells.add(cell)
        if int(row["deployment_count"]) != DEPLOYMENT_COUNTS[percent]:
            raise ValueError(f"order trajectory deployment count changed at {cell!r}")
        if int(row["n_units"]) != 200 or int(row["n_random_orders_as_independent_units"]) != 0:
            raise ValueError(f"order trajectory unit contract changed at {cell!r}")
        panel = "a" if estimand == "Delta_R" else "b"
        order_rows.append(
            {
                "panel": panel,
                "announcement_set": (
                    "intended_only"
                    if panel == "a"
                    else "competition_uniform_unlisted_origin"
                ),
                "estimand": estimand,
                "metric_level": "destination",
                "population": "all_AS_destinations",
                "attacker_class": "none" if panel == "a" else "uniform",
                "deployment_order": order,
                "deployment_percent": percent,
                "deployment_as_count": DEPLOYMENT_COUNTS[percent],
                "estimate_pp": finite(row["paired_delta_pp"], "order trajectory delta"),
                "n_selected_units": 200,
                "independent_unit": "holder/root-origin unit",
                "point_estimate_source": repo_path(GRID_EXTENSION_ORDER_TRAJECTORIES),
            }
        )
    if observed_order_cells != expected_order_cells or len(order_rows) != 110:
        raise ValueError("order trajectories are not the exact 110-row tidy grid")
    order_rows.sort(
        key=lambda row: (
            row["panel"], row["deployment_order"], row["deployment_percent"]
        )
    )
    for curve_row in source_rows:
        if curve_row["deployment_strategy"] == "reference":
            continue
        values = [
            float(row["estimate_pp"])
            for row in order_rows
            if row["panel"] == curve_row["panel"]
            and row["deployment_percent"] == curve_row["deployment_percent"]
        ]
        if len(values) != 5:
            raise ValueError("curve cell does not have exactly five order values")
        close(
            float(np.mean(values)),
            float(curve_row["estimate_pp"]),
            (
                f"five-order mean at panel {curve_row['panel']} "
                f"{curve_row['deployment_percent']}%"
            ),
        )

    sensitivity: dict[str, dict[str, float]] = {}
    for strategy in ("random", "degree", "customer_cone"):
        reachability = select_rows(
            phase7_rows,
            estimand="Delta_R",
            attacker_class="",
            strategy=strategy,
            expected_percentages=PHASE7_DEPLOYMENT_PERCENTS,
        )
        strategy_exposure = select_rows(
            phase7_rows,
            estimand="Delta_E_rov",
            attacker_class="uniform",
            strategy=strategy,
            expected_percentages=PHASE7_DEPLOYMENT_PERCENTS,
        )
        reachability_5 = next(
            row for row in reachability if int(row["deployment_percent_target"]) == 5
        )
        exposure_5 = next(
            row
            for row in strategy_exposure
            if int(row["deployment_percent_target"]) == 5
        )
        sensitivity[strategy] = {
            "delta_R_5pct_pp": 100.0
            * finite(
                reachability_5["paired_delta_design_weighted_mean"],
                "5% sensitivity Delta_R",
            ),
            "delta_E_5pct_pp": 100.0
            * finite(
                exposure_5["paired_delta_design_weighted_mean"],
                "5% sensitivity Delta_E",
            ),
        }

    return source_rows, order_rows, {
        "aggregate_delivery_pct": 100.0 * aggregate_delivery,
        "exact_delivery_pct": 100.0 * exact_delivery,
        "exact_delta_pp": 100.0 * exact_delta,
        "exact_ci_low_pp": 100.0 * exact_ci_low,
        "exact_ci_high_pp": 100.0 * exact_ci_high,
        "competition_exact_delivery_pct": 100.0 * competition_exact_delivery,
        "competition_aggregate_delivery_pct": 100.0
        * competition_aggregate_delivery,
        "competition_exact_delta_pp": 100.0 * competition_exact_delta,
        "competition_exact_ci_low_pp": 100.0 * competition_exact_ci_low,
        "competition_exact_ci_high_pp": 100.0 * competition_exact_ci_high,
        "sensitivity": sensitivity,
    }


def load_and_validate_source_csv() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = load_csv(SOURCE_CSV)
    if len(rows) != 24:
        raise ValueError("deployment-outcomes source CSV must contain 24 plotted/source rows")
    panel_a = [
        row
        for row in rows
        if row["panel"] == "a" and row["series"] == "OpenScope_minus_aggregate_only"
    ]
    panel_b = [
        row
        for row in rows
        if row["panel"] == "b"
        and row["series"]
        == "OpenScope_minus_announcement_matched_aggregate_only"
    ]
    reference_a = [
        row
        for row in rows
        if row["panel"] == "a"
        and row["series"] == "exact_child_minus_aggregate_only_reference"
    ]
    reference_b = [
        row
        for row in rows
        if row["panel"] == "b"
        and row["series"]
        == "exact_ROA_minus_announcement_matched_aggregate_only_reference"
    ]
    if (
        len(panel_a) != 11
        or len(panel_b) != 11
        or len(reference_a) != 1
        or len(reference_b) != 1
    ):
        raise ValueError("deployment-outcomes source CSV panel/series counts are invalid")
    panel_a.sort(key=lambda row: int(row["deployment_percent"]))
    panel_b.sort(key=lambda row: int(row["deployment_percent"]))
    if [int(row["deployment_percent"]) for row in panel_a] != DEPLOYMENT_PERCENTS:
        raise ValueError("panel (a) source grid is incomplete")
    if [int(row["deployment_percent"]) for row in panel_b] != DEPLOYMENT_PERCENTS:
        raise ValueError("panel (b) source grid is incomplete")
    for row in panel_a + panel_b + reference_a + reference_b:
        for field in (
            "treatment_delivery_pct",
            "reference_delivery_pct",
            "estimate_pp",
            "interval95_low_pp",
            "interval95_high_pp",
        ):
            finite(row[field], f"source CSV {field}")
        treatment = float(row["treatment_delivery_pct"])
        reference = float(row["reference_delivery_pct"])
        estimate = float(row["estimate_pp"])
        if not 0.0 <= treatment <= 100.0 or not 0.0 <= reference <= 100.0:
            raise ValueError("source CSV absolute delivery lies outside [0, 100]")
        close(treatment - reference, estimate, "source CSV absolute/delta identity")
        if not float(row["interval95_low_pp"]) <= estimate <= float(row["interval95_high_pp"]):
            raise ValueError("source CSV estimate lies outside its interval")
    for panel, panel_rows in (("a", panel_a), ("b", panel_b)):
        references = [float(row["reference_delivery_pct"]) for row in panel_rows]
        if not np.allclose(references, references[0], rtol=0.0, atol=TOL):
            raise ValueError(f"panel {panel} aggregate-only reference is not constant")
    return rows, {
        "a": panel_a,
        "b": panel_b,
        "reference_a": reference_a[0],
        "reference_b": reference_b[0],
    }


def load_and_validate_order_source_csv() -> dict[str, list[dict[str, str]]]:
    rows = load_csv(ORDER_SOURCE_CSV)
    if len(rows) != 110:
        raise ValueError("deployment-order source CSV must contain exactly 110 rows")
    result: dict[str, list[dict[str, str]]] = {}
    for panel, estimand in (("a", "Delta_R"), ("b", "Delta_E_rov")):
        panel_rows = [
            row for row in rows if row["panel"] == panel and row["estimand"] == estimand
        ]
        expected = {
            (order, percent) for order in RANDOM_ORDERS for percent in DEPLOYMENT_PERCENTS
        }
        observed = {
            (row["deployment_order"], int(row["deployment_percent"]))
            for row in panel_rows
        }
        if len(panel_rows) != 55 or observed != expected:
            raise ValueError(f"panel {panel} order trajectories are incomplete")
        for row in panel_rows:
            finite(row["estimate_pp"], f"panel {panel} order estimate")
        for percent in (0, 100):
            endpoint_values = [
                float(row["estimate_pp"])
                for row in panel_rows
                if int(row["deployment_percent"]) == percent
            ]
            if len(endpoint_values) != len(RANDOM_ORDERS) or not np.allclose(
                endpoint_values,
                endpoint_values[0],
                rtol=0,
                atol=TOL,
            ):
                raise ValueError(
                    f"panel {panel} shared {percent}% endpoint differs across paths"
                )
        result[panel] = panel_rows
    return result


def configure_style() -> None:
    configure_body_font()
    mpl.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": [BODY_FONT_FAMILY],
            "svg.fonttype": "none",
            "svg.hashsalt": "s2-rov-fig-deployment-outcomes-v6-absolute",
            "pdf.fonttype": 42,
            "font.size": ACTIVE_BASE_FONTSIZE,
            "axes.titlesize": ACTIVE_TITLE_FONTSIZE,
            "axes.labelsize": ACTIVE_AXIS_LABELSIZE,
            "xtick.labelsize": ACTIVE_TICK_LABELSIZE,
            "ytick.labelsize": ACTIVE_TICK_LABELSIZE,
            "legend.fontsize": ACTIVE_LEGEND_FONTSIZE,
            "axes.linewidth": 0.75,
            "axes.spines.top": True,
            "axes.spines.right": True,
            "xtick.direction": "in",
            "ytick.direction": "in",
            "xtick.top": False,
            "ytick.right": False,
            "legend.frameon": False,
            "figure.facecolor": WHITE,
            "axes.facecolor": WHITE,
            "savefig.facecolor": WHITE,
        }
    )


def draw_figure(panel_rows: dict[str, Any]) -> None:
    configure_style()
    a = panel_rows["a"]
    b = panel_rows["b"]
    reference_a = panel_rows["reference_a"]
    reference_b = panel_rows["reference_b"]

    x = np.asarray([float(row["deployment_percent"]) for row in a])
    a_y = np.asarray([float(row["treatment_delivery_pct"]) for row in a])
    b_y = np.asarray([float(row["treatment_delivery_pct"]) for row in b])
    aggregate_a_y = float(a[0]["reference_delivery_pct"])
    aggregate_b_y = float(b[0]["reference_delivery_pct"])
    exact_a_y = float(reference_a["treatment_delivery_pct"])
    exact_b_y = float(reference_b["treatment_delivery_pct"])

    fig_a, ax_a = plt.subplots(figsize=ACTIVE_PANEL_FIGSIZE)
    fig_b, ax_b = plt.subplots(figsize=ACTIVE_PANEL_FIGSIZE)
    fig_a.subplots_adjust(**ACTIVE_PANEL_MARGINS)
    fig_b.subplots_adjust(**ACTIVE_PANEL_MARGINS)

    ax_a.plot(
        x,
        a_y,
        color=BLUE,
        linewidth=1.65,
        marker="o",
        markersize=3.2,
        markerfacecolor=BLUE,
        markeredgecolor=WHITE,
        markeredgewidth=0.45,
        label=S2_ROV_LABEL,
        zorder=3,
        clip_on=False,
    )
    ax_a.axhline(
        aggregate_a_y,
        color=GREY_MID,
        linewidth=1.0,
        linestyle=(0, (5, 2)),
        label=AGGREGATE_ROV_LABEL,
        zorder=2,
    )
    ax_a.axhline(
        exact_a_y,
        color=GREY,
        linewidth=1.1,
        linestyle=(0, (1.5, 1.5)),
        label=EXACT_ROV_LABEL,
        zorder=2.5,
    )
    ax_a.set_ylim(80.0, 101.0)
    ax_a.set_ylabel("Intended delivery (%)")
    ax_a.set_xlabel(UPGRADE_AXIS_LABEL)
    ax_a.legend(
        loc="lower center",
        bbox_to_anchor=(0.45, 1.00),
        ncol=3,
        handlelength=1.8,
        columnspacing=0.8,
        borderaxespad=0.0,
    )
    ax_b.plot(
        x,
        b_y,
        color=RED,
        linewidth=1.65,
        marker="s",
        markersize=3.0,
        markerfacecolor=RED,
        markeredgecolor=WHITE,
        markeredgewidth=0.45,
        label=S2_ROV_LABEL,
        zorder=3,
        clip_on=False,
    )
    ax_b.axhline(
        aggregate_b_y,
        color=GREY_MID,
        linewidth=1.0,
        linestyle=(0, (5, 2)),
        label=AGGREGATE_ROV_LABEL,
        zorder=2,
    )
    ax_b.axhline(
        exact_b_y,
        color=GREY,
        linewidth=1.1,
        linestyle=(0, (1.5, 1.5)),
        label=EXACT_ROV_LABEL,
        zorder=2.5,
    )
    ax_b.set_ylim(0.0, 50.0)
    ax_b.set_ylabel("Unlisted-origin\ndelivery (%)")
    ax_b.set_xlabel(UPGRADE_AXIS_LABEL)
    ax_b.legend(
        loc="lower center",
        bbox_to_anchor=(0.45, 1.00),
        ncol=3,
        handlelength=1.8,
        columnspacing=0.8,
        borderaxespad=0.0,
    )
    for ax, y_ticks in (
        (ax_a, PANEL_A_Y_TICKS),
        (ax_b, PANEL_B_Y_TICKS),
    ):
        ax.set_xlim(0, 100)
        ax.xaxis.set_major_locator(FixedLocator(X_TICKS))
        ax.yaxis.set_major_locator(FixedLocator(y_ticks))
        ax.xaxis.set_major_formatter(StrMethodFormatter(INTEGER_TICK_FORMAT))
        ax.yaxis.set_major_formatter(StrMethodFormatter(INTEGER_TICK_FORMAT))
        ax.grid(axis="y", color=GRID, linewidth=0.45, linestyle=":")
        ax.set_axisbelow(True)
        ax.tick_params(
            axis="both",
            which="both",
            direction="in",
            top=False,
            right=False,
            length=2.5,
            width=0.7,
            pad=1.8,
        )
        for spine in ax.spines.values():
            spine.set_visible(True)

    for panel, fig in (("a", fig_a), ("b", fig_b)):
        creator = f"S2-ROV deployment-outcomes panel {panel} reanalysis"
        common: dict[str, Any] = {"facecolor": WHITE}
        fig.savefig(
            OUTPUTS[f"{panel}_svg"],
            format="svg",
            metadata={"Date": None, "Creator": creator},
            **common,
        )
        fig.savefig(
            OUTPUTS[f"{panel}_pdf"],
            format="pdf",
            metadata={
                "Creator": creator,
                "CreationDate": None,
                "ModDate": None,
            },
            **common,
        )
        fig.savefig(
            OUTPUTS[f"{panel}_png"],
            format="png",
            dpi=300,
            metadata={"Software": creator},
            **common,
        )
        fig.savefig(
            OUTPUTS[f"{panel}_tiff"],
            format="tiff",
            dpi=600,
            pil_kwargs={"compression": "tiff_lzw"},
            **common,
        )
        plt.close(fig)

        svg_path = OUTPUTS[f"{panel}_svg"]
        normalized_svg = "\n".join(
            line.rstrip() for line in svg_path.read_text(encoding="utf-8").splitlines()
        )
        svg_path.write_text(normalized_svg + "\n", encoding="utf-8")


def write_report(
    source_rows: list[dict[str, Any]],
    order_rows: list[dict[str, Any]],
    summary: dict[str, Any],
    upstream: dict[str, Any],
    input_hashes: dict[str, str],
) -> None:
    panel_a = [
        row
        for row in source_rows
        if row["panel"] == "a" and row["series"] == "OpenScope_minus_aggregate_only"
    ]
    panel_b = [
        row
        for row in source_rows
        if row["panel"] == "b"
        and row["series"]
        == "OpenScope_minus_announcement_matched_aggregate_only"
    ]
    reference_b = next(
        row
        for row in source_rows
        if row["panel"] == "b"
        and row["series"]
        == "exact_ROA_minus_announcement_matched_aggregate_only_reference"
    )
    panel_a.sort(key=lambda row: int(row["deployment_percent"]))
    panel_b.sort(key=lambda row: int(row["deployment_percent"]))
    a20 = next(row for row in panel_a if row["deployment_percent"] == 20)
    b20 = next(row for row in panel_b if row["deployment_percent"] == 20)
    a100 = panel_a[-1]
    b100 = panel_b[-1]

    widest_order_spread: dict[str, dict[str, float | int]] = {}
    for panel in ("a", "b"):
        candidates: list[dict[str, float | int]] = []
        for percent in DEPLOYMENT_PERCENTS:
            values = [
                float(row["estimate_pp"])
                for row in order_rows
                if row["panel"] == panel
                and int(row["deployment_percent"]) == percent
            ]
            if len(values) != len(RANDOM_ORDERS):
                raise ValueError(
                    f"panel {panel}/{percent}% lacks five fixed-order values"
                )
            candidates.append(
                {
                    "percent": percent,
                    "count": DEPLOYMENT_COUNTS[percent],
                    "spread_pp": max(values) - min(values),
                }
            )
        widest_order_spread[panel] = max(
            candidates,
            key=lambda item: (float(item["spread_pp"]), -int(item["percent"])),
        )

    hash_table = "\n".join(
        f"| `{path}` | `{digest}` |" for path, digest in sorted(input_hashes.items())
    )
    report = f"""# Deployment Outcomes Figure: Provenance and Claim Boundary

## Verdict

The two panels are valid as **separate conditional comparisons**, not as one
joint benefit and exposure trajectory. Panel (a) uses an intended-only
announcement set. Panel (b) uses a competition announcement set containing a
uniform eligible unlisted origin. Their baselines are separately
announcement-matched.

No manuscript file is read or modified by the generator.

## Figure contract

- Core conclusion: under the fixed routing model, assigning OpenScope improves
  intended-route delivery in the intended-only lane, while a different
  competition lane shows increased delivery to an eligible unlisted origin.
- Archetype: quantitative two-panel grid with random placement as the primary case.
- Panel (a): absolute intended-route delivery under `D1_open_delegate_only`,
  with horizontal `B1_delegate_only` and `B2_exact_delegate_only` references.
- Panel (b): absolute uniform-unlisted-origin delivery under
  `A1_open_competition`, with horizontal `B1_competition` and
  `B2_exact_competition` references. All three lanes contain the same
  competition announcements.
- Main grid: 0, 10, ..., 100% of the fixed 589-AS set. Each curve averages five
  fixed random upgrade orders within unit. Individual order paths remain in the
  source-data audit and are not plotted.
- Backend: Python / matplotlib only.
- Each panel is 3.50 x 1.75 inches and has no embedded panel marker. LaTeX
  composes the two panels with the `subfig` package. Each panel has an
  editable-text SVG, font-embedded PDF, 300-dpi PNG, and 600-dpi LZW TIFF.
- The panels use the shared active axes bounding box, 7.56 pt tick labels,
  8.4 pt axis labels, and 6.96 pt legend text.

Caption-critical statements (kept out of the plot area):

- The x-axis is labeled `S²-ROV upgraded share (%)`. Its denominator is the
  fixed 589-AS set documented in the manuscript and this provenance report.
- The panels use different announcement sets and must not be interpreted as a
  same-scenario joint frontier.
- Both vertical axes report absolute destination percentages. S²-ROV,
  Aggregate-only ROV, and Exact-match ROV are named directly in the legend.
  S²-ROV applies the OpenScope treatment semantics; the other two series use
  conventional ROV with different ROA configurations.
- Both x and y axes use integer tick labels without unit suffixes; percentage
  units appear only in the axis titles.
- The figure omits bands because the accepted intervals target paired changes,
  not absolute outcome levels. Those finite-frame and selected-unit intervals
  remain in the source table and manuscript prose. Fixed-order paths are not
  used as independent samples.
- No endpoint-value annotation is plotted.

## Key values

| Panel | Deployment | Treatment | Reference | Delta | Paired interval |
|---|---:|---:|---:|---:|---:|
| (a) intended-only | 20% / 117 ASes | {a20['treatment_delivery_pct']:.1f}% | {a20['reference_delivery_pct']:.1f}% | {a20['estimate_pp']:.1f} percentage points | [{a20['interval95_low_pp']:.1f}, {a20['interval95_high_pp']:.1f}] percentage points |
| (a) intended-only | 100% / 589 ASes | {a100['treatment_delivery_pct']:.1f}% | {a100['reference_delivery_pct']:.1f}% | {a100['estimate_pp']:.1f} percentage points | [{a100['interval95_low_pp']:.1f}, {a100['interval95_high_pp']:.1f}] percentage points |
| (b) competition | 20% / 117 ASes | {b20['treatment_delivery_pct']:.1f}% | {b20['reference_delivery_pct']:.1f}% | {b20['estimate_pp']:.1f} percentage points | [{b20['interval95_low_pp']:.1f}, {b20['interval95_high_pp']:.1f}] percentage points |
| (b) competition | 100% / 589 ASes | {b100['treatment_delivery_pct']:.1f}% | {b100['reference_delivery_pct']:.1f}% | {b100['estimate_pp']:.1f} percentage points | [{b100['interval95_low_pp']:.1f}, {b100['interval95_high_pp']:.1f}] percentage points |
| (b) Exact-match ROV reference | all targets | {reference_b['treatment_delivery_pct']:.1f}% | {reference_b['reference_delivery_pct']:.1f}% | {reference_b['estimate_pp']:.1f} percentage points | [{reference_b['interval95_low_pp']:.1f}, {reference_b['interval95_high_pp']:.1f}] percentage points |

At the all-589 endpoint in the intended-only lane, S²-ROV delivery is
{summary['exact_delivery_pct']:.1f}% and equals the exact-child reference. The
exact-child-minus-aggregate contrast is {summary['exact_delta_pp']:.1f} percentage points with
a [{summary['exact_ci_low_pp']:.1f}, {summary['exact_ci_high_pp']:.1f}] percentage-point
finite-frame interval. This equality does **not** extend to the competition
lane. In the competition lane, Exact-match ROV reduces eligible-unlisted-origin
delivery from {summary['competition_aggregate_delivery_pct']:.1f}% to
{summary['competition_exact_delivery_pct']:.1f}%, a
{summary['competition_exact_delta_pp']:.1f} percentage-point change with a
[{summary['competition_exact_ci_low_pp']:.1f},
{summary['competition_exact_ci_high_pp']:.1f}] selected-unit stability interval.

## Statistical provenance

- Phase 7 contains {upstream['phase7_analysis']['scenario_rows']:,} successful
  scenarios and {upstream['phase7_analysis']['n_independent_holders']} selected
  synthetic root-origin units. The legacy `holder_asn` field does not establish
  verified resource-holder identity.
- The independent deployment-grid extension contributes
  {upstream['grid_extension_analysis']['counts']['extension_scenarios']:,}
  successful scenarios at 20, 30, 40, 60, 70, 80, and 90%. It reuses the same
  200 units and five frozen random orders; it neither resamples the units nor
  replaces the frozen Phase 7 results.
- Panel (a) is competitor-independent. It retains the frozen Phase 7
  stratified paired SRSWOR-rescaled bootstrap analysis for the finite frame of
  691 candidate root-origin units. Five frozen random deployment orders are
  averaged within unit before inference.
- Panel (b) depends on a competitor assigned only after the 200-unit sample was
  selected. Its 0/10/50/100% anchors reproduce Phase 9 exactly; the added cells
  use the same procedure: 10,000 ordinary paired multinomial bootstrap
  resamples within the four 50-unit strata, without finite-population
  correction.
- Panel (b) intervals are descriptive selected-unit stability intervals, not
  confidence intervals for the 691-unit frame, the Internet, traffic, or
  adversaries.
- The source table retains pointwise paired intervals; neither is simultaneous.
  They are not relabeled as intervals for absolute levels and therefore are not
  drawn in the absolute-value figure. The five fixed orders are descriptive
  repeated blocks, are averaged within unit, and are not used as independent
  units for the intervals.
- Individual order trajectories and their repeated shared endpoints remain in
  the audit table but are intentionally omitted from the main figure.

## Fixed-order placement sensitivity (audit only)

The widest separation among the five fixed-order paths is
{float(widest_order_spread['a']['spread_pp']):.1f} percentage points at
{int(widest_order_spread['a']['percent'])}% / {int(widest_order_spread['a']['count'])}
upgraded ASes in panel (a), and
{float(widest_order_spread['b']['spread_pp']):.1f} percentage points at
{int(widest_order_spread['b']['percent'])}% / {int(widest_order_spread['b']['count'])}
upgraded ASes in panel (b). These ranges are retained in the source-data audit,
not drawn in the figure. They describe only the five frozen paths and are
neither uncertainty intervals nor estimates over a population of possible
upgrade orders.

## Claim boundary

Supported wording:

- In the fixed intended-only model lane, the curve reports absolute intended
  delivery as S²-ROV is assigned to more ASes in the fixed set; at the
  all-589 endpoint it reaches the exact-child outcome in that lane.
- In a separate, announcement-matched competition lane, the figure reports
  absolute delivery to a uniform eligible unlisted origin under S²-ROV,
  Aggregate-only ROV, and Exact-match ROV. Paired changes and intervals may be stated
  separately in prose.
- The two results jointly motivate reporting both operational benefit and the
  lack of origin-specific evidence, while keeping their scenario sets explicit.

Unsupported wording:

- a same-scenario or causal joint frontier;
- equivalence between S²-ROV and Exact-match ROV under origin competition;
- an Internet-wide, traffic-weighted, operator-intent, benefit, or
  security estimate;
- the mean effect for a typical unit;
- statistical superiority of degree or customer-cone placement;
- simultaneous uncertainty for either curve or comparison of the two bands.

All findings remain conditional on one opaque fixed 77,429-AS topology, one
opaque fixed 589-AS scenario set, Gao and Rexford steady-state routing,
mechanically selected synthetic units, fixed attacker assignments, and fixed
upgrade orders.

The frozen extension manifest retains `fixed measured 589-AS ROV set` as a
historical scenario label. That string does not establish that the set is
measured, current, or representative of Internet deployment. This report treats
the denominator only as an opaque fixed 589-AS scenario set.

## Data integrity

- Frozen raw scenarios: 36,800 before / 36,800 after; no row excluded.
- Panel (a): eleven random-deployment cells plus one exact-child reference.
- Panel (b): eleven random-deployment cells plus one Exact-match ROV reference; the
  four frozen Phase 9 anchors match frozen Phase 7 to within
  {float(upstream['phase9_summary']['audits']['phase7_max_point_error_vs_frozen']):.3g}.
- Source-data rows written: {len(source_rows)}.
- Tidy fixed-order rows written: {len(order_rows)}.
- Source data: `{repo_path(SOURCE_CSV)}`.
- Fixed-order source data: `{repo_path(ORDER_SOURCE_CSV)}`.

### Frozen input hashes

| Input | SHA-256 |
|---|---|
{hash_table}

## Reproduction

From the repository root:

```bash
python {repo_path(SCRIPT)}
```

The command verifies every frozen and extension input hash before rebuilding
the two source CSVs, four formats for each panel, this report, and
`{repo_path(OUTPUT_MANIFEST)}`.
"""
    REPORT.write_text(report, encoding="utf-8")


def write_output_manifest(
    input_hashes: dict[str, str],
    source_rows: list[dict[str, Any]],
    order_rows: list[dict[str, Any]],
) -> None:
    manifest = {
        "schema_version": "s2-rov-fig-deployment-outcomes-v6-absolute",
        "backend": "python-matplotlib",
        "generator": {
            "path": repo_path(SCRIPT),
            "sha256": sha256(SCRIPT),
        },
        "figure_contract": {
            "archetype": "quantitative_grid",
            "core_conclusion": (
                "S²-ROV raises intended delivery in an intended-only lane, "
                "while a separate competition lane shows increased eligible-unlisted-origin exposure."
            ),
            "panel_a_announcement_set": "intended_only",
            "panel_b_announcement_set": "competition_uniform_unlisted_origin",
            "latex_composition": "subfig package; panel labels are not embedded in graphics",
            "shared_panel_style": {
                "canvas_inches": list(ACTIVE_PANEL_FIGSIZE),
                "axes_fraction": {
                    "left": ACTIVE_PANEL_MARGINS["left"],
                    "bottom": ACTIVE_PANEL_MARGINS["bottom"],
                    "width": ACTIVE_PANEL_MARGINS["right"]
                    - ACTIVE_PANEL_MARGINS["left"],
                    "height": ACTIVE_PANEL_MARGINS["top"]
                    - ACTIVE_PANEL_MARGINS["bottom"],
                },
                "axis_label_pt": ACTIVE_AXIS_LABELSIZE,
                "tick_label_pt": ACTIVE_TICK_LABELSIZE,
                "legend_pt": ACTIVE_LEGEND_FONTSIZE,
            },
            "cross_panel_warning": "different announcement sets; not a joint frontier",
            "primary_deployment_strategy": "random_five_order_average",
            "deployment_grid_percent": DEPLOYMENT_PERCENTS,
            "deployment_denominator_asns": 589,
            "fixed_order_paths": RANDOM_ORDERS,
            "individual_order_paths_plotted": False,
            "outcome_encoding": (
                "absolute destination percentages for S²-ROV, Aggregate-only ROV, "
                "and Exact-match ROV; no change-score axis"
            ),
            "interval_bands_plotted": False,
            "endpoint_value_annotations": False,
            "tick_label_contract": (
                "fixed integer x/y tick labels without decimal points or percent signs; "
                "percentage units appear only in axis titles"
            ),
            "x_axis_label": UPGRADE_AXIS_LABEL,
            "caption_required": [
                "The x-axis is labeled S²-ROV upgraded share (%); its denominator is the fixed 589-AS set documented outside the plot.",
                "The panels use different announcement sets and are not a same-scenario joint frontier.",
                "Each S²-ROV curve is the within-unit average of five fixed orders; Aggregate-only ROV and Exact-match ROV are absolute horizontal references.",
                "Paired contrast intervals are reported in prose rather than relabeled as absolute-outcome intervals.",
            ],
        },
        "data_integrity": {
            "phase7_raw_rows_before_after": [36_800, 36_800],
            "grid_extension_raw_rows": 14_000,
            "exclusion_rule": "none",
            "selected_synthetic_units": 200,
            "finite_candidate_frame_units_for_panel_a": 691,
            "source_csv_rows": len(source_rows),
            "order_source_csv_rows": len(order_rows),
            "panel_a_curve_rows": 11,
            "panel_a_reference_rows": 1,
            "panel_b_curve_rows": 11,
            "panel_b_reference_rows": 1,
            "order_trajectory_rows_per_panel": 55,
            "random_orders_as_independent_units": 0,
        },
        "statistics": {
            "panel_a": (
                "pointwise stratified paired SRSWOR-rescaled bootstrap percentile 95% CI "
                "for the finite 691-unit candidate frame"
            ),
            "panel_b": (
                "pointwise ordinary stratified paired bootstrap 95% stability interval "
                "over 200 selected synthetic units; no finite-population correction"
            ),
            "bootstrap_replicates": 10_000,
            "bootstrap_seed": 20_260_804,
            "simultaneous_bands": False,
            "paired_intervals_plotted_on_absolute_axis": False,
            "order_paths": "five descriptive within-unit deployment blocks retained in source data and averaged before inference; not plotted individually",
        },
        "claim_boundary": {
            "allowed": [
                "conditional absolute intended-only delivery under all three policies",
                "all-589 equality with exact-child only in the intended-only lane",
                "conditional absolute competition delivery to an eligible unlisted origin under all three policies",
                "paired changes versus the announcement-matched aggregate-only outcome in prose",
            ],
            "forbidden": [
                "same-scenario joint frontier",
                "Exact-match ROV equivalence under competition",
                "Internet-wide or traffic-weighted deployment benefit",
                "typical-unit effect",
                "placement-strategy superiority",
            ],
        },
        "input_sha256": input_hashes,
        "source_data_sha256": {
            repo_path(SOURCE_CSV): sha256(SOURCE_CSV),
            repo_path(ORDER_SOURCE_CSV): sha256(ORDER_SOURCE_CSV),
        },
        "report_sha256": {repo_path(REPORT): sha256(REPORT)},
        "output_sha256": {repo_path(path): sha256(path) for path in OUTPUTS.values()},
    }
    OUTPUT_MANIFEST.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="verify frozen inputs and extracted statistics without writing outputs",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_hashes = verify_hashes(EXPECTED_INPUT_HASHES, input_group="frozen")
    extension_hashes = verify_hashes(
        EXPECTED_GRID_EXTENSION_HASHES, input_group="deployment-grid extension"
    )
    input_hashes.update(extension_hashes)
    upstream = verify_upstream_contracts()
    grid_extension = verify_grid_extension_contracts(extension_hashes)
    upstream["grid_extension_manifest"] = grid_extension["manifest"]
    upstream["grid_extension_audit"] = grid_extension["audit"]
    upstream["grid_extension_analysis"] = grid_extension["analysis"]
    source_rows, order_rows, summary = extract_source_rows()
    if args.verify_only:
        print(
            "verified: frozen inputs, grid extension, contracts, and "
            "deployment-outcomes statistics"
        )
        return

    SOURCE_DATA.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)
    write_csv(SOURCE_CSV, source_rows)
    write_csv(ORDER_SOURCE_CSV, order_rows, fields=ORDER_SOURCE_FIELDS)
    _, panel_rows = load_and_validate_source_csv()
    validated_order_rows = load_and_validate_order_source_csv()
    draw_figure(panel_rows)
    write_report(source_rows, order_rows, summary, upstream, input_hashes)
    write_output_manifest(input_hashes, source_rows, order_rows)
    print(f"wrote {repo_path(SOURCE_CSV)}")
    print(f"wrote {repo_path(ORDER_SOURCE_CSV)}")
    for path in OUTPUTS.values():
        print(f"wrote {repo_path(path)}")
    print(f"wrote {repo_path(REPORT)}")
    print(f"wrote {repo_path(OUTPUT_MANIFEST)}")


if __name__ == "__main__":
    main()
