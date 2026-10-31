from __future__ import annotations

import copy
import importlib.util
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "build_processing_cost_figure.py"
if str(SCRIPT.parent) not in sys.path:
    sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("build_processing_cost_figure", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
FIGURE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = FIGURE
SPEC.loader.exec_module(FIGURE)


class ProcessingCostFigureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.hashes = FIGURE.verify_inputs()
        cls.rows = FIGURE.load_rows()
        cls.keyed = FIGURE.keyed(cls.rows)
        cls.update_rows = FIGURE.load_update_rows()
        cls.outage = FIGURE.load_outage_control()

    def test_pinned_inputs(self) -> None:
        self.assertEqual(len(self.hashes), 10)
        for path, expected in FIGURE.EXPECTED_HASHES.items():
            with self.subTest(path=path):
                self.assertEqual(
                    self.hashes[FIGURE.repo_path(path)], expected
                )
        self.assertFalse(
            any("handoff" in str(path).lower() for path in FIGURE.EXPECTED_HASHES)
        )

    def test_exact_dual_stack_matrix(self) -> None:
        self.assertEqual(len(self.rows), 10)
        self.assertEqual(
            set(self.keyed),
            {
                (version, size)
                for version in FIGURE.VERSIONS
                for size in FIGURE.POLICY_SIZES
            },
        )

    def test_intervals_contain_medians(self) -> None:
        FIGURE.validate_rows(self.rows)
        for row in self.rows:
            self.assertLessEqual(
                row["classify_pairs_s_min"], row["classify_pairs_s_median"]
            )
            self.assertLessEqual(
                row["classify_pairs_s_median"], row["classify_pairs_s_max"]
            )

    def test_policy_size_and_mean_invariants(self) -> None:
        for row in self.rows:
            self.assertEqual(
                int(row["total_policy_entries"]),
                int(row["subprefix_entries"]) + 1,
            )
            self.assertTrue(
                math.isfinite(float(row["classify_pairs_s_mean"]))
            )

    def test_display_anchors(self) -> None:
        expected = {
            ("IPv4", 1): 30_647.4,
            ("IPv4", 64): 29_423.7,
            ("IPv4", 256): 29_876.4,
            ("IPv4", 1024): 29_571.1,
            ("IPv4", 4096): 29_149.8,
            ("IPv6", 1): 19_794.3,
            ("IPv6", 64): 19_754.7,
            ("IPv6", 256): 18_991.0,
            ("IPv6", 1024): 18_885.8,
            ("IPv6", 4096): 18_346.0,
        }
        for key, target in expected.items():
            row = self.keyed[key]
            observed = round(float(row["classify_pairs_s_mean"]), 1)
            self.assertEqual(observed, target)

    def test_active_panel_set_excludes_load(self) -> None:
        self.assertEqual(FIGURE.PROCESSING_PANELS, ("classify",))
        self.assertEqual(set(FIGURE.OUTPUT_STEMS), {"classify", "update"})
        self.assertFalse(any("load" in key for key in FIGURE.OUTPUTS))

    def test_generated_provenance_excludes_handoff_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory)
            report = output_directory / "report.md"
            manifest = output_directory / "manifest.json"
            outputs = {
                key: output_directory / path.name
                for key, path in FIGURE.OUTPUTS.items()
            }
            for key, path in outputs.items():
                path.write_bytes(f"fixture for {key}\n".encode("utf-8"))
            with (
                mock.patch.object(FIGURE, "REPORT", report),
                mock.patch.object(FIGURE, "MANIFEST", manifest),
                mock.patch.object(FIGURE, "OUTPUTS", outputs),
                mock.patch.object(
                    FIGURE, "repo_path", side_effect=lambda path: path.name
                ),
            ):
                FIGURE.write_report(
                    self.rows, self.update_rows, self.outage, self.hashes
                )
                FIGURE.write_manifest(
                    self.rows, self.update_rows, self.outage, self.hashes
                )

            report_text = report.read_text(encoding="utf-8").lower()
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertNotIn("handoff", report_text)
            self.assertNotIn("table_contract", payload)
            self.assertNotIn("table_sha256", payload)
            self.assertNotIn("handoff", json.dumps(payload).lower())
            self.assertEqual(
                payload["schema_version"],
                "s2-rov-system-cost-figure-v10-routes-s",
            )

    def test_classification_figure_contract(self) -> None:
        expected_pairs_s = [
            [
                30_647.35981851366,
                29_423.718983831416,
                29_876.423555947695,
                29_571.134433523377,
                29_149.84282382185,
            ],
            [
                19_794.272577728015,
                19_754.72942476603,
                18_991.02622867415,
                18_885.772931115217,
                18_345.99111927492,
            ],
        ]
        expected = expected_pairs_s
        figure = FIGURE.draw_panel(self.rows, "classify")
        try:
            self.assertEqual(len(figure.axes), 1)
            axis = figure.axes[0]
            figure.canvas.draw()
            self.assertEqual(
                list(axis.get_yticks()), [0, 10000, 20000, 30000]
            )
            self.assertEqual(
                [label.get_text() for label in axis.get_yticklabels()],
                ["0", "10000", "20000", "30000"],
            )
            self.assertEqual(
                [label.get_text() for label in axis.get_xticklabels()],
                ["1", "64", "256", "1024", "4096"],
            )
            self.assertEqual(axis.get_xlabel(), "Policy size (records)")
            self.assertEqual(axis.get_ylabel(), "Throughput (routes/s)")
            self.assertEqual(
                [text.get_text() for text in axis.get_legend().get_texts()],
                ["IPv4", "IPv6"],
            )
            for observed, target in zip(axis.containers, expected):
                self.assertEqual(len(observed), 5)
                for bar, value in zip(observed, target):
                    self.assertTrue(math.isclose(bar.get_height(), value))
        finally:
            FIGURE.plt.close(figure)

    def test_policy_update_matrix(self) -> None:
        expected = {
            "IPv4": {
                1: 0.3,
                64: 4.6,
                256: 17.3,
                1024: 68.1,
                4096: 273.0,
            },
            "IPv6": {
                1: 0.5,
                64: 7.6,
                256: 28.9,
                1024: 113.7,
                4096: 459.0,
            },
        }
        self.assertEqual(len(self.update_rows), 10)
        for item in self.update_rows:
            version = item["ip_version"]
            rules = item["rules"]
            with self.subTest(version=version, rules=rules):
                self.assertEqual(item["repetitions"], 20)
                self.assertEqual(
                    item["closed_serialized_bytes"],
                    item["open_serialized_bytes"],
                )
                self.assertEqual(
                    round(item["update_ms_mean"], 1), expected[version][rules]
                )
        FIGURE.validate_update_rows(
            self.update_rows,
            FIGURE.load_json(FIGURE.UPDATE_AUDIT),
            FIGURE.load_json(FIGURE.UPDATE_INPUT_MANIFEST),
        )
        self.assertEqual(
            self.outage,
            {
                "episodes": 1,
                "hold_seconds": 15,
                "action_retained": True,
                "checks_passed": 7,
                "checks_total": 7,
            },
        )

    def test_policy_update_corruption_is_rejected(self) -> None:
        corrupted = copy.deepcopy(self.update_rows)
        corrupted[0]["update_ms_mean"] += 0.01
        with self.assertRaisesRegex(ValueError, "differs from the raw audit"):
            FIGURE.validate_update_rows(
                corrupted,
                FIGURE.load_json(FIGURE.UPDATE_AUDIT),
                FIGURE.load_json(FIGURE.UPDATE_INPUT_MANIFEST),
            )

    def test_update_latency_figure_contract(self) -> None:
        expected = [
            [0.331044, 4.6171939, 17.3457573, 68.10254575, 273.04924855],
            [0.46656555, 7.62994275, 28.89234075, 113.67727585, 459.012229],
        ]
        figure = FIGURE.make_update_latency_figure(self.update_rows)
        try:
            self.assertEqual(len(figure.axes), 1)
            axis = figure.axes[0]
            figure.canvas.draw()
            self.assertEqual(list(axis.get_yticks()), [0, 150, 300, 450])
            self.assertEqual(
                [label.get_text() for label in axis.get_yticklabels()],
                ["0", "150", "300", "450"],
            )
            self.assertEqual(
                [label.get_text() for label in axis.get_xticklabels()],
                ["1", "64", "256", "1024", "4096"],
            )
            self.assertEqual(axis.get_xlabel(), "Policy size (records)")
            self.assertEqual(axis.get_ylabel(), "Latency (ms)")
            self.assertIsNone(axis.get_legend())
            self.assertEqual(tuple(figure.get_size_inches()), FIGURE.PANEL_FIGSIZE)
            self.assertEqual(
                axis.get_position().bounds,
                (
                    FIGURE.PANEL_MARGINS["left"],
                    FIGURE.PANEL_MARGINS["bottom"],
                    FIGURE.PANEL_MARGINS["right"]
                    - FIGURE.PANEL_MARGINS["left"],
                    FIGURE.PANEL_MARGINS["top"]
                    - FIGURE.PANEL_MARGINS["bottom"],
                ),
            )
            self.assertEqual(len(axis.containers), 2)
            expected_styles = ((FIGURE.BLUE, ""), (FIGURE.ORANGE, "///"))
            for observed, target, (color, hatch) in zip(
                axis.containers, expected, expected_styles
            ):
                self.assertEqual(len(observed), 5)
                for bar, value in zip(observed, target):
                    self.assertTrue(math.isclose(bar.get_height(), value))
                    self.assertTrue(
                        math.isclose(bar.get_width(), FIGURE.BAR_WIDTH)
                    )
                    self.assertEqual(
                        bar.get_facecolor(), FIGURE.mpl.colors.to_rgba(color)
                    )
                    self.assertEqual(bar.get_hatch(), hatch)
            self.assertEqual(len(axis.texts), 0)
            self.assertTrue(
                all(spine.get_visible() for spine in axis.spines.values())
            )
            for tick in axis.xaxis.get_major_ticks():
                self.assertTrue(tick.tick1line.get_visible())
                self.assertFalse(tick.tick2line.get_visible())
                self.assertEqual(tick._tickdir, "in")
            for tick in axis.yaxis.get_major_ticks():
                self.assertTrue(tick.tick1line.get_visible())
                self.assertFalse(tick.tick2line.get_visible())
                self.assertEqual(tick._tickdir, "in")
        finally:
            FIGURE.plt.close(figure)


if __name__ == "__main__":
    unittest.main()
