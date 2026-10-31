"""Independent statistical oracles for the routing-model campaign analysis.

These tests intentionally use non-degenerate within-stratum holder effects.
They guard the analysis unit, design weighting, stratified paired bootstrap,
weighted empirical quantiles, and exact-reference contrasts independently of
the campaign runner.
"""

from __future__ import annotations

from collections import defaultdict

import numpy as np
import pytest

from experiments.routing_model.campaign.analyze_paper_campaign import (
    HolderDesign,
    _bootstrap_weight_matrix,
    analyze_campaign,
    summarize_cells,
)
from experiments.routing_model.campaign.tests.test_analyze_paper_campaign import _fixture


BOOTSTRAP_REPLICATES = 10_000
BOOTSTRAP_SEED = 424242


def _nondegenerate_holder_inputs() -> tuple[
    dict[int, HolderDesign], list[dict[str, object]]
]:
    """Return two unequal holders per stratum with hand-checkable effects."""

    specifications = (
        (101, "S1", 4, 2, 2.0, -0.12, 0.75),
        (102, "S1", 4, 2, 2.0, 0.02, 0.15),
        (201, "S2", 6, 2, 3.0, -0.04, 0.70),
        (202, "S2", 6, 2, 3.0, 0.08, 0.20),
        (301, "S3", 8, 2, 4.0, 0.01, 0.65),
        (302, "S3", 8, 2, 4.0, 0.09, 0.25),
        (401, "S4", 10, 2, 5.0, 0.05, 0.60),
        (402, "S4", 10, 2, 5.0, 0.15, 0.30),
    )
    holder_design: dict[int, HolderDesign] = {}
    contrasts: list[dict[str, object]] = []
    for (
        holder,
        stratum,
        frame_size,
        sample_size,
        weight,
        delta,
        reference,
    ) in specifications:
        holder_design[holder] = HolderDesign(
            holder_asn=holder,
            stratum=stratum,
            frame_size=frame_size,
            sample_size=sample_size,
            design_weight=weight,
        )
        contrasts.append(
            {
                "holder_asn": holder,
                "stratum": stratum,
                "design_weight": weight,
                "estimand": "Delta_R",
                "metric_level": "destination",
                "population": "all",
                "attacker_class": None,
                "deployment_strategy": "degree",
                "deployment_percent_target": 5,
                "random_orders_averaged": 0,
                "treatment_fraction": reference + delta,
                "reference_fraction": reference,
                "delta": delta,
            }
        )
    return holder_design, contrasts


def test_stratified_paired_bootstrap_matches_fixed_nondegenerate_oracle() -> None:
    holder_design, contrasts = _nondegenerate_holder_inputs()
    holders = sorted(holder_design)

    bootstrap_weights = _bootstrap_weight_matrix(
        holders,
        holder_design,
        replicates=BOOTSTRAP_REPLICATES,
        seed=BOOTSTRAP_SEED,
    )
    positions_by_stratum: dict[str, list[int]] = defaultdict(list)
    for position, holder in enumerate(holders):
        positions_by_stratum[holder_design[holder].stratum].append(position)

    # Rescaling is around one, so every replicate retains n_h rescaled counts
    # inside each stratum.  After multiplication by N_h/n_h, the stratum
    # replicate weight therefore remains N_h (up to floating-point roundoff).
    for stratum, positions in positions_by_stratum.items():
        frame_size = holder_design[holders[positions[0]]].frame_size
        np.testing.assert_allclose(
            bootstrap_weights[:, positions].sum(axis=1),
            frame_size,
            rtol=0,
            atol=1e-12,
        )
    np.testing.assert_allclose(bootstrap_weights.sum(axis=1), 28.0, rtol=0, atol=1e-12)

    # Independent variance oracle.  For a stratified sampling without replacement mean, the
    # estimated design variance is
    #   sum_h (N_h/N)^2 (1 - n_h/N_h) s_h^2/n_h.
    # The transformed-count bootstrap matches that target instead of the
    # uncorrected with-replacement empirical-bootstrap variance.
    delta_by_holder = {
        int(item["holder_asn"]): float(item["delta"]) for item in contrasts
    }
    delta_vector = np.asarray([delta_by_holder[holder] for holder in holders])
    bootstrap_estimates = bootstrap_weights @ delta_vector
    bootstrap_estimates /= bootstrap_weights.sum(axis=1)
    total_frame_size = sum(
        holder_design[positions[0]].frame_size
        for positions in (
            [holder for holder in holders if holder_design[holder].stratum == stratum]
            for stratum in ("S1", "S2", "S3", "S4")
        )
    )
    expected_design_variance = 0.0
    for stratum in ("S1", "S2", "S3", "S4"):
        members = [
            holder for holder in holders if holder_design[holder].stratum == stratum
        ]
        frame_size = holder_design[members[0]].frame_size
        sample_size = len(members)
        sample_variance = np.var(
            [delta_by_holder[holder] for holder in members], ddof=1
        )
        expected_design_variance += (
            (frame_size / total_frame_size) ** 2
            * (1 - sample_size / frame_size)
            * sample_variance
            / sample_size
        )
    assert np.var(bootstrap_estimates, ddof=0) == pytest.approx(
        expected_design_variance, rel=0.02
    )

    summary = summarize_cells(
        contrasts,
        [],
        holder_design,
        bootstrap_replicates=BOOTSTRAP_REPLICATES,
        bootstrap_seed=BOOTSTRAP_SEED,
    )
    assert len(summary) == 1
    cell = summary[0]

    # Hand calculation with weights (2,2,3,3,4,4,5,5):
    # weighted sum = 1.32, total weight = 28; weighted quartiles are
    # 0.01, 0.05, and 0.09 under the documented left-continuous rule.
    assert cell["paired_delta_design_weighted_mean"] == pytest.approx(1.32 / 28)
    assert cell["paired_delta_weighted_q25"] == pytest.approx(0.01)
    assert cell["paired_delta_weighted_median"] == pytest.approx(0.05)
    assert cell["paired_delta_weighted_q75"] == pytest.approx(0.09)
    assert cell["paired_delta_weighted_iqr"] == pytest.approx(0.08)
    assert cell["raw_treatment_design_weighted_mean"] - cell[
        "raw_reference_design_weighted_mean"
    ] == pytest.approx(cell["paired_delta_design_weighted_mean"])

    # Fixed-seed regression oracle.  The interval is non-degenerate and is
    # computed from holder-paired deltas, not independent treatment/reference
    # resamples or the AS-level observations inside a propagation run.
    assert cell["pointwise_ci95_lower"] == pytest.approx(0.0005580753257505626)
    assert cell["pointwise_ci95_upper"] == pytest.approx(0.09372763895996374)
    assert cell["ci_type"] == (
        "pointwise_stratified_paired_rescaled_percentile_srswor_fpc"
    )
    assert cell["bootstrap_replicates"] == BOOTSTRAP_REPLICATES
    assert cell["bootstrap_seed"] == BOOTSTRAP_SEED
    assert cell["n_holders"] == 8
    assert cell["n_ases_as_independent_units"] == 0
    assert cell["n_random_orders_as_independent_units"] == 0


def test_rescaled_bootstrap_collapses_when_every_stratum_is_a_census() -> None:
    holder_design: dict[int, HolderDesign] = {}
    holders: list[int] = []
    for stratum_index, stratum in enumerate(("S1", "S2", "S3", "S4"), start=1):
        for member in range(2):
            holder = stratum_index * 100 + member
            holders.append(holder)
            holder_design[holder] = HolderDesign(
                holder_asn=holder,
                stratum=stratum,
                frame_size=2,
                sample_size=2,
                design_weight=1.0,
            )

    weights = _bootstrap_weight_matrix(
        sorted(holders), holder_design, replicates=200, seed=20260804
    )
    np.testing.assert_array_equal(weights, np.ones_like(weights))


def test_b2_exact_reference_differences_are_announcement_matched() -> None:
    rows, manifest, design = _fixture()
    _, summary, _ = analyze_campaign(
        rows,
        manifest,
        bootstrap_replicates=40,
        bootstrap_seed=17,
        expected_holders=8,
        strict_production_strata=False,
        design=design,
    )

    def cell(estimand: str, attacker_class: str | None) -> dict[str, object]:
        return next(
            item
            for item in summary
            if item["estimand"] == estimand
            and item["metric_level"] == "destination"
            and item["population"] == "all"
            and item["attacker_class"] == attacker_class
            and item["deployment_strategy"] == "random"
            and item["deployment_percent_target"] == 5
        )

    delta_r = cell("Delta_R", None)
    delta_r_exact = cell("Delta_R_exact", None)
    delta_e_rov = cell("Delta_E_rov", "uniform")
    delta_e_exact = cell("Delta_E_exact", "uniform")

    # D1 is identical within each comparison; replacing B1 with the B2 exact
    # delegate reference raises the reference delivery fraction by 0.20.
    assert delta_r["raw_treatment_design_weighted_mean"] == pytest.approx(
        delta_r_exact["raw_treatment_design_weighted_mean"]
    )
    assert delta_r["paired_delta_design_weighted_mean"] - delta_r_exact[
        "paired_delta_design_weighted_mean"
    ] == pytest.approx(0.20)

    # A1 is likewise held fixed.  In the fixture, B1 attacker delivery is 0.10
    # and B2 exact attacker delivery is 0.02, so Delta_E_exact exceeds
    # Delta_E_rov by exactly 0.08.
    assert delta_e_rov["raw_treatment_design_weighted_mean"] == pytest.approx(
        delta_e_exact["raw_treatment_design_weighted_mean"]
    )
    assert delta_e_exact["paired_delta_design_weighted_mean"] - delta_e_rov[
        "paired_delta_design_weighted_mean"
    ] == pytest.approx(0.08)
    assert delta_e_rov["raw_reference_design_weighted_mean"] == pytest.approx(0.10)
    assert delta_e_exact["raw_reference_design_weighted_mean"] == pytest.approx(0.02)
