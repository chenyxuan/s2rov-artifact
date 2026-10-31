from __future__ import annotations

import csv
import importlib.util
import sys
import unittest
from collections import Counter
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "analyze_handoff_fig2.py"
SPEC = importlib.util.spec_from_file_location("analyze_handoff_fig2", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
FIGURE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = FIGURE
SPEC.loader.exec_module(FIGURE)


def _read_csv(name: str) -> list[dict[str, str]]:
    path = SCRIPT.parent.parent / "figures" / "source_data" / name
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


class DualStackFigureSourceTests(unittest.TestCase):
    def test_dual_stack_source_tables_retain_the_complete_design(self) -> None:
        trials = _read_csv("handoff_latency_trials.csv")
        stages = _read_csv("handoff_latency_stages.csv")
        rounds = _read_csv("handoff_endpoint_rounds_recomputed.csv")
        contrasts = _read_csv("handoff_latency_contrasts.csv")

        self.assertEqual(
            Counter(row["address_family"] for row in trials),
            {"IPv4": 120, "IPv6": 120},
        )
        self.assertEqual(
            Counter(row["address_family"] for row in stages),
            {"IPv4": 15, "IPv6": 15},
        )
        self.assertEqual(
            Counter(row["address_family"] for row in rounds),
            {"IPv4": 30, "IPv6": 30},
        )
        self.assertEqual(
            Counter(row["address_family"] for row in contrasts),
            {"IPv4": 2, "IPv6": 2},
        )

    def test_each_family_has_ten_complete_rounds_and_exact_stage_sums(self) -> None:
        trials = _read_csv("handoff_latency_trials.csv")
        cells: Counter[tuple[str, int, str]] = Counter()
        for row in trials:
            cells[(row["address_family"], int(row["round"]), row["arm"])] += 1
            self.assertAlmostEqual(
                float(row["stage_sum_ms"]),
                float(row["observed_to_probe_ms"]),
                places=6,
            )
            if row["arm"] != "reactive_exact":
                self.assertEqual(float(row["online_roa_update_ms"]), 0.0)

        expected = {
            (family, round_id, arm)
            for family in ("IPv4", "IPv6")
            for round_id in range(1, 11)
            for arm in FIGURE.ARMS
        }
        self.assertEqual(set(cells), expected)
        self.assertEqual(set(cells.values()), {4})

    def test_plotted_contrasts_match_the_two_independent_audits(self) -> None:
        rows = {
            (row["address_family"], row["contrast"]): row
            for row in _read_csv("handoff_latency_contrasts.csv")
        }
        expected = {
            ("IPv4", "reactive_exact_minus_open_dynamic"): (
                1375.250,
                1343.303,
                1417.390,
            ),
            ("IPv4", "open_dynamic_minus_prepublished_exact"): (
                5.490,
                -0.902,
                12.978,
            ),
            ("IPv6", "reactive_exact_minus_open_dynamic"): (
                1376.771,
                1334.178,
                1438.862,
            ),
            ("IPv6", "open_dynamic_minus_prepublished_exact"): (
                4.714,
                -3.622,
                13.422,
            ),
        }
        self.assertEqual(set(rows), set(expected))
        for key, values in expected.items():
            row = rows[key]
            actual = tuple(
                float(row[field])
                for field in ("estimate_ms", "ci95_lower_ms", "ci95_upper_ms")
            )
            for observed, target in zip(actual, values):
                self.assertAlmostEqual(observed, target, places=3)
            self.assertEqual(int(row["n_complete_rounds"]), 10)


if __name__ == "__main__":
    unittest.main()
