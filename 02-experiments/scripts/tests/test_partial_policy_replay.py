from __future__ import annotations

import importlib.util
import math
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "run_partial_policy_replay.py"
if str(SCRIPT.parent) not in sys.path:
    sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("run_partial_policy_replay", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
REPLAY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = REPLAY
SPEC.loader.exec_module(REPLAY)


class PartialPolicyReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.candidates, cls.input_metadata = REPLAY.load_candidates()
        cls.grid, cls.selection = REPLAY.compute_grid(
            cls.candidates,
            rollout_count=REPLAY.ROLLOUTS,
            master_seed=REPLAY.MASTER_SEED,
        )
        cls.pooled, cls.pooled_selection = REPLAY.compute_pooled_deployment(
            cls.candidates,
            rollout_count=REPLAY.ROLLOUTS,
            master_seed=REPLAY.MASTER_SEED,
        )
        cls.conflicts, cls.conflict_selection = REPLAY.compute_route_state_replay(
            cls.candidates,
            rollout_count=REPLAY.ROLLOUTS,
            master_seed=REPLAY.MASTER_SEED,
        )
        cls.deployment_curves, cls.deployment_selection = (
            REPLAY.compute_deployment_conflict_curves(
                cls.candidates,
                rollout_count=REPLAY.ROLLOUTS,
                master_seed=REPLAY.MASTER_SEED,
            )
        )
        cls.placement, cls.placement_selection = (
            REPLAY.compute_openscope_placement(
                cls.candidates,
                rollout_count=REPLAY.ROLLOUTS,
                master_seed=REPLAY.MASTER_SEED,
            )
        )
        cls.budget = REPLAY.compute_decision_budget(
            cls.candidates,
            rollout_count=64,
            master_seed=REPLAY.MASTER_SEED,
        )
        cls.keyed = REPLAY._rows_by_key(cls.grid)

    def test_pinned_input_and_paper_counts(self) -> None:
        self.assertEqual(
            REPLAY.sha256_file(REPLAY.DEFAULT_INPUT), REPLAY.EXPECTED_INPUT_SHA256
        )
        self.assertEqual(
            self.input_metadata["family_counts"], REPLAY.EXPECTED_FAMILY_COUNTS
        )
        self.assertEqual(
            self.input_metadata["root_counts"], REPLAY.EXPECTED_ROOT_COUNTS
        )
        self.assertEqual(self.input_metadata["multi_origin_endpoint_rows"], 2)
        self.assertEqual(
            self.input_metadata["endpoint_prefix_origin_entries"],
            {"IPv4": 506, "IPv6": 83},
        )
        self.assertEqual(
            self.input_metadata["route_origin_counts"],
            REPLAY.EXPECTED_ROUTE_COUNTS,
        )
        self.assertEqual(self.input_metadata["route_origin_count"], 589)
        self.assertEqual(self.input_metadata["eligible_route_origin_count"], 588)

        scores, score_metadata = REPLAY.load_placement_scores()
        self.assertEqual(len(scores), 37)
        self.assertEqual(
            score_metadata["sha256"], REPLAY.EXPECTED_PLACEMENT_SCORES_SHA256
        )
        self.assertEqual(
            score_metadata["source"]["uncompressed_sha256"],
            REPLAY.EXPECTED_CAIDA_GRAPH_SHA256,
        )
        self.assertEqual(
            {candidate.root_origins[0] for candidate in self.candidates},
            set(scores),
        )
        self.assertEqual(self.input_metadata["ineligible_route_origin_count"], 1)
        self.assertTrue(self.input_metadata["route_origin_tuples_unique"])
        self.assertTrue(self.input_metadata["root_origin_sets_singleton"])
        self.assertTrue(
            all(
                set(candidate.root_origins).isdisjoint(candidate.endpoint_origins)
                for candidate in self.candidates
            )
        )
        self.assertTrue(self.input_metadata["all_prefixes_canonical"])
        self.assertTrue(self.input_metadata["all_endpoints_proper_subprefixes"])
        self.assertTrue(self.input_metadata["endpoint_prefixes_unique"])
        self.assertTrue(self.input_metadata["root_origin_sets_consistent"])
        self.assertTrue(self.input_metadata["retained_roots_non_nested"])
        self.assertTrue(self.input_metadata["retained_endpoints_non_nested"])
        self.assertTrue(
            self.input_metadata["scope_max_lengths_cover_retained_endpoints"]
        )

    def test_factorial_endpoints(self) -> None:
        for family, candidate_count in REPLAY.EXPECTED_FAMILY_COUNTS.items():
            for strategy in REPLAY.STRATEGIES:
                zero = self.keyed[(family, strategy, 0, 0)]
                self.assertEqual(zero["remaining_count_min"], candidate_count)
                self.assertEqual(zero["remaining_count_max"], candidate_count)
                full_scope = self.keyed[(family, strategy, 0, 100)]
                self.assertEqual(full_scope["remaining_count_max"], 0)
                self.assertEqual(full_scope["avoided_count_min"], candidate_count)

    def test_monotonicity_and_avoided_identity(self) -> None:
        REPLAY.validate_grid(self.grid)
        for family, candidate_count in REPLAY.EXPECTED_FAMILY_COUNTS.items():
            for strategy in REPLAY.STRATEGIES:
                for exact_target in REPLAY.TARGET_PERCENTS:
                    baseline = candidate_count - math.floor(
                        candidate_count * exact_target / 100
                    )
                    previous = float("inf")
                    for scope_target in REPLAY.TARGET_PERCENTS:
                        row = self.keyed[
                            (family, strategy, exact_target, scope_target)
                        ]
                        self.assertLessEqual(row["remaining_count_median"], previous)
                        self.assertAlmostEqual(
                            row["remaining_count_median"]
                            + row["avoided_count_median"],
                            baseline,
                        )
                        previous = row["remaining_count_median"]

    def test_full_exact_coverage_is_zero(self) -> None:
        for family in REPLAY.EXPECTED_FAMILY_COUNTS:
            for strategy in REPLAY.STRATEGIES:
                for scope_target in REPLAY.TARGET_PERCENTS:
                    row = self.keyed[(family, strategy, 100, scope_target)]
                    self.assertEqual(row["remaining_count_max"], 0)
                    self.assertEqual(row["avoided_count_max"], 0)

    def test_full_scope_is_zero_and_q50_s10_counts_are_floored(self) -> None:
        for family, candidate_count in REPLAY.EXPECTED_FAMILY_COUNTS.items():
            root_count = REPLAY.EXPECTED_ROOT_COUNTS[family]
            for strategy in REPLAY.STRATEGIES:
                for exact_target in REPLAY.TARGET_PERCENTS:
                    self.assertEqual(
                        self.keyed[(family, strategy, exact_target, 100)][
                            "remaining_count_max"
                        ],
                        0,
                    )
                key = self.keyed[(family, strategy, 50, 10)]
                self.assertEqual(
                    key["exact_selected_count"], math.floor(candidate_count * 0.5)
                )
                self.assertEqual(
                    key["scope_selected_root_count"], math.floor(root_count * 0.1)
                )

    def test_decision_budget_and_efficiency_invariants(self) -> None:
        REPLAY.validate_decision_budget(self.budget)
        keyed = {
            (
                row["family"],
                row["root_order"],
                int(row["configuration_decisions"]),
            ): row
            for row in self.budget
        }
        for family, root_count in REPLAY.EXPECTED_ROOT_COUNTS.items():
            candidate_count = REPLAY.EXPECTED_FAMILY_COUNTS[family]
            for strategy in REPLAY.STRATEGIES:
                zero = keyed[(family, strategy, 0)]
                self.assertEqual(zero["scope_paths_covered_count_max"], 0)
                self.assertIsNone(zero["scope_paths_per_decision_median"])
                full = keyed[(family, strategy, root_count)]
                self.assertEqual(
                    full["scope_paths_covered_count_min"], candidate_count
                )
                self.assertEqual(
                    full["exact_paths_covered_count"], root_count
                )

    def test_partial_deployment_audit_anchors(self) -> None:
        expected = {
            "IPv4": (252.0, 50.0, 233.0, 201.9, 244.0, 129.0, 248.0),
            "IPv6": (42.0, 50.6, 41.0, 27.0, 42.0, 25.0, 41.0),
        }
        for family, values in expected.items():
            roa_count, roa_percent, median, low, high, first, last = values
            baseline = self.keyed[(family, "random", 50, 0)]
            random_row = self.keyed[(family, "random", 50, 10)]
            first_row = self.keyed[(family, "fanout-first", 50, 10)]
            last_row = self.keyed[(family, "fanout-last", 50, 10)]
            observed = (
                baseline["remaining_count_median"],
                baseline["remaining_percent_median"],
                random_row["remaining_count_median"],
                random_row["remaining_count_p05"],
                random_row["remaining_count_p95"],
                first_row["remaining_count_median"],
                last_row["remaining_count_median"],
            )
            for actual, target in zip(
                observed,
                (roa_count, roa_percent, median, low, high, first, last),
            ):
                self.assertEqual(round(float(actual), 1), target)

    def test_pooled_deployment_audit_anchors(self) -> None:
        REPLAY.validate_pooled_deployment(self.pooled)
        keyed = REPLAY._pooled_rows_by_key(self.pooled)
        self.assertEqual(len(self.pooled), 66)
        self.assertEqual(self.pooled_selection["candidate_count"], 587)
        self.assertEqual(self.pooled_selection["root_count"], 97)
        self.assertEqual(
            self.pooled_selection["selection_sha256"],
            "5e6704aacd9746bd04a5416b8dd893f0e15543df6c51fd0033e334e1166398e5",
        )
        expected_roots = {0: 0, 20: 19, 40: 38, 60: 58, 80: 77, 100: 97}
        expected_q50 = {
            0: 294.0,
            20: 239.0,
            40: 179.0,
            60: 116.0,
            80: 57.0,
            100: 0.0,
        }
        for scope_target in REPLAY.POOLED_SCOPE_TARGETS:
            row = keyed[(50, scope_target)]
            self.assertEqual(row["exact_selected_count"], 293)
            self.assertEqual(
                row["scope_selected_root_count"], expected_roots[scope_target]
            )
            self.assertEqual(
                round(float(row["remaining_count_median"]), 1),
                expected_q50[scope_target],
            )
            self.assertEqual(keyed[(100, scope_target)]["remaining_count_max"], 0)
        for exact_target in REPLAY.TARGET_PERCENTS:
            self.assertEqual(keyed[(exact_target, 100)]["remaining_count_max"], 0)

    def test_reference_route_states(self) -> None:
        metadata = self.conflict_selection
        self.assertEqual(metadata["endpoint_prefix_count"], 587)
        self.assertEqual(metadata["route_origin_count"], 589)
        self.assertEqual(metadata["root_count"], 97)
        self.assertEqual(
            metadata["reference_state_counts"]["aggregate_only"],
            {"explicit": 0, "open_scope": 0, "invalid": 589, "not_found": 0},
        )
        self.assertEqual(
            metadata["reference_state_counts"]["marked_root"],
            {"explicit": 0, "open_scope": 588, "invalid": 1, "not_found": 0},
        )
        self.assertEqual(
            metadata["reference_state_counts"]["exact"],
            {"explicit": 589, "open_scope": 0, "invalid": 0, "not_found": 0},
        )
        self.assertEqual(
            metadata["reference_state_counts"]["exact_with_marked_root"],
            {"explicit": 589, "open_scope": 0, "invalid": 0, "not_found": 0},
        )
        self.assertEqual(
            metadata["ineligible_routes"],
            [{"family": "IPv4", "prefix": "46.221.6.0/24", "origin": 65989}],
        )

    def test_exact_record_coexists_with_base_marker(self) -> None:
        policy = REPLAY.DAROA(
            "10.0.0.0/8",
            24,
            15169,
            (
                REPLAY.Stripe("10.0.0.0/8", frozenset({15169}), True),
                REPLAY.Stripe("10.1.0.0/16", frozenset({13335}), False),
            ),
        )
        self.assertIs(
            policy.validate_route("10.1.0.0/16", 13335),
            REPLAY.ValidationState.EXPLICIT,
        )
        self.assertIs(
            policy.validate_route("10.1.0.0/16", 8075),
            REPLAY.ValidationState.OPEN_SCOPE,
        )

    def test_route_state_replay_anchors(self) -> None:
        REPLAY.validate_route_state_replay(self.conflicts)
        keyed = REPLAY._conflict_rows_by_key(self.conflicts)
        self.assertEqual(len(self.conflicts), 66)
        self.assertEqual(keyed[(0, 0)]["invalid_count_min"], 589)
        self.assertEqual(keyed[(0, 100)]["open_scope_count_min"], 588)
        self.assertEqual(keyed[(0, 100)]["invalid_count_max"], 1)
        expected_q50 = {
            0: (295.0, 294.0, 296.0),
            20: (240.0, 201.0, 265.0),
            40: (180.0, 137.0, 221.0),
            60: (117.0, 78.0, 160.0),
            80: (58.0, 31.0, 98.0),
            100: (1.0, 0.0, 1.0),
        }
        for scope_target, expected in expected_q50.items():
            row = keyed[(50, scope_target)]
            observed = (
                round(float(row["invalid_count_median"]), 1),
                round(float(row["invalid_count_p05"]), 1),
                round(float(row["invalid_count_p95"]), 1),
            )
            self.assertEqual(observed, expected)
        for scope_target in REPLAY.POOLED_SCOPE_TARGETS:
            self.assertEqual(keyed[(100, scope_target)]["invalid_count_max"], 0)
            self.assertEqual(keyed[(100, scope_target)]["explicit_count_min"], 589)

    def test_two_panel_deployment_curve_contract(self) -> None:
        REPLAY.validate_deployment_conflict_curves(self.deployment_curves)
        keyed = REPLAY._deployment_curve_rows_by_key(self.deployment_curves)
        self.assertEqual(len(self.deployment_curves), 66)
        self.assertEqual(self.deployment_selection["rollout_count"], 1000)
        self.assertTrue(self.deployment_selection["placements_independent"])
        self.assertEqual(
            self.deployment_selection["selection_sha256"],
            "cd9a10a98e5039eece92e5d9ad08ea5b2623d0b44ebbe5ac2d4f24309c152e51",
        )
        expected_roots = {0: 0, 20: 19, 40: 38, 60: 58, 80: 77, 100: 97}
        expected_q50 = {
            0: (295.0, 145.9),
            20: (237.9, 117.5),
            40: (180.8, 89.7),
            60: (119.9, 59.6),
            80: (61.7, 30.5),
            100: (0.5, 0.2),
        }
        for scope_target, selected in expected_roots.items():
            row = keyed[(50, scope_target)]
            self.assertEqual(
                row["conflict_rate_denominator"],
                REPLAY.CONFLICT_RATE_DENOMINATOR,
            )
            self.assertEqual(row["scope_selected_root_count"], selected)
            self.assertEqual(row["downstream_selected_prefix_count"], 293)
            self.assertEqual(row["root_roa_selected_count"], 48)
            self.assertEqual(
                round(float(row["potential_conflicts_mean"]), 1),
                expected_q50[scope_target][0],
            )
            self.assertEqual(
                round(float(row["observed_conflicts_mean"]), 1),
                expected_q50[scope_target][1],
            )
            for outcome in ("potential_conflicts", "observed_conflicts"):
                self.assertAlmostEqual(
                    float(row[f"{outcome}_percent_mean"]),
                    100.0
                    * float(row[f"{outcome}_mean"])
                    / REPLAY.CONFLICT_RATE_DENOMINATOR,
                )
            for outcome in ("potential_conflicts", "observed_conflicts"):
                self.assertLessEqual(row[f"{outcome}_min"], row[f"{outcome}_mean"])
                self.assertLessEqual(row[f"{outcome}_mean"], row[f"{outcome}_max"])
            self.assertEqual(
                keyed[(100, scope_target)]["potential_conflicts_max"], 0.0
            )
            self.assertEqual(
                keyed[(0, scope_target)]["observed_conflicts_max"], 0.0
            )
            self.assertEqual(
                keyed[(100, scope_target)]["observed_conflicts_max"], 0.0
            )
        self.assertEqual(
            round(keyed[(50, 0)]["potential_conflicts_percent_mean"], 1),
            50.1,
        )
        self.assertEqual(
            round(keyed[(50, 0)]["observed_conflicts_percent_mean"], 1),
            24.8,
        )
        self.assertEqual(
            round(keyed[(50, 80)]["potential_conflicts_percent_mean"], 1),
            10.5,
        )
        self.assertEqual(
            round(keyed[(50, 80)]["observed_conflicts_percent_mean"], 1),
            5.2,
        )
        self.assertEqual(
            round(keyed[(50, 100)]["potential_conflicts_percent_mean"], 1),
            0.1,
        )
        self.assertLess(
            keyed[(50, 100)]["observed_conflicts_percent_mean"], 0.1
        )
        findings = REPLAY.summarize_findings(
            self.grid,
            self.pooled,
            self.conflicts,
            self.deployment_curves,
            self.placement,
            self.budget,
            self.input_metadata,
        )
        full_scope = findings["figure_2_q50_by_scope"]["s100"]
        self.assertGreater(full_scope["observed_conflicts_percent_mean"], 0.0)
        self.assertEqual(
            full_scope["observed_conflicts_percent_mean_display"], "<0.1%"
        )
        self.assertEqual(
            full_scope["potential_conflicts_percent_mean_display"], "0.1%"
        )

    def test_deployment_axis_ticks_are_fixed_integers(self) -> None:
        fig, ax = REPLAY.plt.subplots()
        try:
            REPLAY._set_integer_major_ticks(
                ax,
                x_ticks=[0, 20, 40, 60, 80, 100],
                y_ticks=[0, 25, 50, 75, 100],
            )
            fig.canvas.draw()
            self.assertIsInstance(
                ax.xaxis.get_major_locator(), REPLAY.FixedLocator
            )
            self.assertIsInstance(
                ax.yaxis.get_major_locator(), REPLAY.FixedLocator
            )
            self.assertIsInstance(
                ax.xaxis.get_major_formatter(), REPLAY.StrMethodFormatter
            )
            self.assertIsInstance(
                ax.yaxis.get_major_formatter(), REPLAY.StrMethodFormatter
            )
            self.assertEqual(
                [label.get_text() for label in ax.get_xticklabels()],
                ["0", "20", "40", "60", "80", "100"],
            )
            self.assertEqual(
                [label.get_text() for label in ax.get_yticklabels()],
                ["0", "25", "50", "75", "100"],
            )
        finally:
            REPLAY.plt.close(fig)

    def test_openscope_placement_strategy_anchors(self) -> None:
        REPLAY.validate_openscope_placement(self.placement)
        keyed = REPLAY._placement_rows_by_key(self.placement)
        self.assertEqual(len(self.placement), 44)
        self.assertEqual(self.placement_selection["root_route_load_sum"], 588)
        self.assertEqual(self.placement_selection["root_route_load_min"], 1)
        self.assertEqual(self.placement_selection["root_route_load_median"], 2.0)
        self.assertEqual(self.placement_selection["root_route_load_max"], 64)
        self.assertEqual(
            self.placement_selection["selection_sha256"],
            "55f0d283d39a4ba0dba55658680c81ba681dedfe1c635ebce7f5be66c0f108b7",
        )
        expected = {
            0: (295.0, 295.0, 295.0, 295.0),
            20: (101.4, 218.6, 239.9, 237.9),
            40: (49.2, 165.7, 161.3, 180.8),
            50: (34.2, 147.9, 144.0, 150.8),
            60: (24.1, 130.1, 89.0, 119.9),
            80: (10.6, 45.0, 43.5, 61.7),
            100: (0.5, 0.5, 0.5, 0.5),
        }
        for scope_target, values in expected.items():
            observed = tuple(
                round(
                    float(
                        keyed[(strategy, scope_target)][
                            "potential_conflicts_mean"
                        ]
                    ),
                    1,
                )
                for strategy in REPLAY.PLACEMENT_STRATEGIES
            )
            self.assertEqual(observed, values)
            for strategy in REPLAY.PLACEMENT_STRATEGIES:
                row = keyed[(strategy, scope_target)]
                self.assertEqual(
                    row["conflict_rate_denominator"],
                    REPLAY.CONFLICT_RATE_DENOMINATOR,
                )
                self.assertAlmostEqual(
                    row["potential_conflicts_percent_mean"],
                    100.0
                    * row["potential_conflicts_mean"]
                    / REPLAY.CONFLICT_RATE_DENOMINATOR,
                )

        deployment_keyed = REPLAY._deployment_curve_rows_by_key(
            self.deployment_curves
        )
        for scope_target in REPLAY.POOLED_SCOPE_TARGETS:
            self.assertAlmostEqual(
                keyed[("random", scope_target)]["potential_conflicts_mean"],
                deployment_keyed[(50, scope_target)][
                    "potential_conflicts_mean"
                ],
            )

    def test_openscope_placement_figure_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(
            REPLAY.plt, "close"
        ):
            outputs = REPLAY.draw_openscope_placement(
                self.placement,
                Path(directory) / "placement",
            )
            figure = REPLAY.plt.gcf()
            self.assertEqual(
                {output.suffix for output in outputs},
                {".svg", ".pdf", ".png", ".tiff"},
            )
            self.assertTrue(all(output.is_file() for output in outputs))

        try:
            self.assertEqual(
                tuple(figure.get_size_inches()),
                tuple(REPLAY.DEPLOYMENT_PANEL_FIGSIZE),
            )
            self.assertEqual(len(figure.axes), 1)
            axis = figure.axes[0]
            self.assertEqual(
                [label.get_text() for label in axis.get_xticklabels()],
                ["0", "20", "40", "60", "80", "100"],
            )
            self.assertEqual(
                [label.get_text() for label in axis.get_yticklabels()],
                ["0", "10", "20", "30", "40", "50"],
            )
            self.assertEqual(axis.get_ylabel(), "Conflicting routes (%)")
            self.assertEqual(
                [text.get_text() for text in axis.get_legend().get_texts()],
                ["Route count", "ASRank", "AS degree", "Random"],
            )
            self.assertTrue(
                all(
                    axis.spines[side].get_visible()
                    for side in ("left", "right", "bottom", "top")
                )
            )
        finally:
            REPLAY.plt.close(figure)

    def test_deployment_panels_have_identical_plot_geometry(self) -> None:
        figures = []
        with tempfile.TemporaryDirectory() as directory, patch.object(
            REPLAY.plt, "close"
        ):
            for outcome in REPLAY.DEPLOYMENT_FIGURE_BASENAMES:
                REPLAY.draw_deployment_conflict_panel(
                    self.deployment_curves,
                    outcome,
                    Path(directory) / outcome,
                )
                figures.append(REPLAY.plt.gcf())

        try:
            self.assertEqual(len(figures), 2)
            expected_size = tuple(REPLAY.DEPLOYMENT_PANEL_FIGSIZE)
            expected_bounds = (
                REPLAY.DEPLOYMENT_PANEL_ADJUST["left"],
                REPLAY.DEPLOYMENT_PANEL_ADJUST["bottom"],
                REPLAY.DEPLOYMENT_PANEL_ADJUST["right"]
                - REPLAY.DEPLOYMENT_PANEL_ADJUST["left"],
                REPLAY.DEPLOYMENT_PANEL_ADJUST["top"]
                - REPLAY.DEPLOYMENT_PANEL_ADJUST["bottom"],
            )
            expected_y_ticks = {
                "potential_conflicts": ["0", "25", "50", "75", "100"],
                "observed_conflicts": ["0", "5", "10", "15", "20", "25"],
            }
            for outcome, figure in zip(
                REPLAY.DEPLOYMENT_FIGURE_BASENAMES, figures
            ):
                self.assertEqual(tuple(figure.get_size_inches()), expected_size)
                self.assertEqual(len(figure.axes), 1)
                for actual, expected in zip(
                    figure.axes[0].get_position().bounds, expected_bounds
                ):
                    self.assertAlmostEqual(actual, expected)
                self.assertIsNone(figure.axes[0].get_legend())
                self.assertEqual(figure.legends, [])
                self.assertEqual(
                    [
                        label.get_text()
                        for label in figure.axes[0].get_yticklabels()
                    ],
                    expected_y_ticks[outcome],
                )
                self.assertEqual(
                    figure.axes[0].get_ylabel(), "Conflicting routes (%)"
                )
        finally:
            for figure in figures:
                REPLAY.plt.close(figure)

    def test_deployment_legend_is_a_standalone_six_entry_asset(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(
            REPLAY.plt, "close"
        ):
            outputs = REPLAY.draw_deployment_conflict_legend(
                Path(directory) / "legend"
            )
            figure = REPLAY.plt.gcf()
            self.assertEqual(
                {output.suffix for output in outputs},
                {".svg", ".pdf", ".png", ".tiff"},
            )
            self.assertTrue(all(output.is_file() for output in outputs))

        try:
            self.assertEqual(len(outputs), 4)
            self.assertEqual(
                tuple(figure.get_size_inches()),
                tuple(REPLAY.DEPLOYMENT_LEGEND_FIGSIZE),
            )
            self.assertEqual(len(figure.axes), 0)
            self.assertEqual(len(figure.legends), 1)
            legend = figure.legends[0]
            self.assertEqual(legend._ncols, 6)
            self.assertEqual(
                legend.get_title().get_text(),
                "Aggregate prefixes with S²-ROV policy",
            )
            self.assertEqual(
                [text.get_text() for text in legend.get_texts()],
                ["0%", "20%", "40%", "60%", "80%", "100%"],
            )
            figure.canvas.draw()
            legend_bounds = legend.get_window_extent(
                figure.canvas.get_renderer()
            ).transformed(figure.transFigure.inverted())
            self.assertAlmostEqual(
                legend_bounds.x1,
                REPLAY.ACTIVE_PANEL_MARGINS["right"],
            )
            self.assertAlmostEqual(legend_bounds.x0 + legend_bounds.width / 2, 0.5, places=2)
        finally:
            REPLAY.plt.close(figure)

    def test_deterministic_rerun(self) -> None:
        first_grid, first_selection = REPLAY.compute_grid(
            self.candidates, rollout_count=32, master_seed=REPLAY.MASTER_SEED
        )
        second_grid, second_selection = REPLAY.compute_grid(
            self.candidates, rollout_count=32, master_seed=REPLAY.MASTER_SEED
        )
        self.assertEqual(first_selection, second_selection)
        self.assertEqual(
            REPLAY.grid_csv_text(first_grid), REPLAY.grid_csv_text(second_grid)
        )
        first_budget = REPLAY.compute_decision_budget(
            self.candidates, rollout_count=32, master_seed=REPLAY.MASTER_SEED
        )
        second_budget = REPLAY.compute_decision_budget(
            self.candidates, rollout_count=32, master_seed=REPLAY.MASTER_SEED
        )
        self.assertEqual(
            REPLAY.rows_csv_text(first_budget, REPLAY.BUDGET_FIELDS),
            REPLAY.rows_csv_text(second_budget, REPLAY.BUDGET_FIELDS),
        )
        first_pooled, first_pooled_selection = REPLAY.compute_pooled_deployment(
            self.candidates, rollout_count=32, master_seed=REPLAY.MASTER_SEED
        )
        second_pooled, second_pooled_selection = REPLAY.compute_pooled_deployment(
            self.candidates, rollout_count=32, master_seed=REPLAY.MASTER_SEED
        )
        self.assertEqual(first_pooled_selection, second_pooled_selection)
        self.assertEqual(
            REPLAY.rows_csv_text(first_pooled, REPLAY.GRID_FIELDS),
            REPLAY.rows_csv_text(second_pooled, REPLAY.GRID_FIELDS),
        )
        first_conflicts, first_conflict_selection = REPLAY.compute_route_state_replay(
            self.candidates, rollout_count=32, master_seed=REPLAY.MASTER_SEED
        )
        second_conflicts, second_conflict_selection = REPLAY.compute_route_state_replay(
            self.candidates, rollout_count=32, master_seed=REPLAY.MASTER_SEED
        )
        self.assertEqual(first_conflict_selection, second_conflict_selection)
        self.assertEqual(
            REPLAY.rows_csv_text(first_conflicts, REPLAY.CONFLICT_FIELDS),
            REPLAY.rows_csv_text(second_conflicts, REPLAY.CONFLICT_FIELDS),
        )
        first_curves, first_curve_selection = (
            REPLAY.compute_deployment_conflict_curves(
                self.candidates,
                rollout_count=32,
                master_seed=REPLAY.MASTER_SEED,
            )
        )
        second_curves, second_curve_selection = (
            REPLAY.compute_deployment_conflict_curves(
                self.candidates,
                rollout_count=32,
                master_seed=REPLAY.MASTER_SEED,
            )
        )
        self.assertEqual(first_curve_selection, second_curve_selection)
        self.assertEqual(
            REPLAY.rows_csv_text(first_curves, REPLAY.DEPLOYMENT_CURVE_FIELDS),
            REPLAY.rows_csv_text(second_curves, REPLAY.DEPLOYMENT_CURVE_FIELDS),
        )
        first_placement, first_placement_selection = (
            REPLAY.compute_openscope_placement(
                self.candidates,
                rollout_count=32,
                master_seed=REPLAY.MASTER_SEED,
            )
        )
        second_placement, second_placement_selection = (
            REPLAY.compute_openscope_placement(
                self.candidates,
                rollout_count=32,
                master_seed=REPLAY.MASTER_SEED,
            )
        )
        self.assertEqual(first_placement_selection, second_placement_selection)
        self.assertEqual(
            REPLAY.rows_csv_text(first_placement, REPLAY.PLACEMENT_FIELDS),
            REPLAY.rows_csv_text(second_placement, REPLAY.PLACEMENT_FIELDS),
        )

    def test_figure_text_has_no_forbidden_token(self) -> None:
        text = " ".join(REPLAY.FIGURE_TEXT).lower()
        self.assertNotIn("pp", text)
        self.assertNotIn("csv", text)


if __name__ == "__main__":
    unittest.main()
