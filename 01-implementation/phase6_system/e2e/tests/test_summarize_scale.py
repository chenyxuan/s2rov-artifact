import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


TESTS_DIR = Path(__file__).parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from scale_fixture import LEVELS, build_scale_run, corrupt_sample_matrix


MODULE_PATH = Path(__file__).parents[1] / "src" / "summarize_scale.py"
SPEC = importlib.util.spec_from_file_location("summarize_scale", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def run_summary(run_dir: Path, address_family: str, target_prefix: str) -> int:
    argv = [
        str(MODULE_PATH),
        "--run-dir",
        str(run_dir),
        "--output",
        str(run_dir / "summary.json"),
        "--address-family",
        address_family,
        "--target-prefix",
        target_prefix,
    ]
    with patch.object(sys, "argv", argv):
        return MODULE.main()


class ScaleSummaryTests(unittest.TestCase):
    def test_dual_stack_complete_80_sample_matrix(self) -> None:
        for address_family in ("ipv4", "ipv6"):
            with (
                self.subTest(address_family=address_family),
                tempfile.TemporaryDirectory() as tmp,
            ):
                run_dir, target_prefix = build_scale_run(
                    Path(tmp), address_family=address_family
                )
                self.assertEqual(
                    run_summary(run_dir, address_family, target_prefix), 0
                )
                summary = json.loads(
                    (run_dir / "summary.json").read_text(encoding="utf-8")
                )
                self.assertTrue(summary["passed"])
                self.assertEqual(summary["address_family"], address_family)
                self.assertEqual(summary["target_prefix"], target_prefix)
                self.assertEqual(summary["levels"], list(LEVELS))
                self.assertEqual(summary["trials_per_transition"], 10)
                self.assertEqual(summary["transition_samples"], 80)
                self.assertEqual(summary["enforcement_snapshots"], 80)
                self.assertEqual(summary["route_outcome_checks"], 80)
                self.assertEqual(summary["route_checks_per_transition"], 1)
                self.assertTrue(
                    summary["checks"]["one_route_check_per_transition"]
                )
                self.assertEqual(len(summary["timing"]), 8)
                self.assertTrue(all(item["n"] == 10 for item in summary["timing"]))
                report = (run_dir / "REPORT.md").read_text(encoding="utf-8")
                self.assertIn(f"Address family: **{address_family}**", report)
                self.assertIn("1 route(s) per transition", report)

    def test_malformed_80_row_matrix_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir, target_prefix = build_scale_run(
                Path(tmp), address_family="ipv4"
            )
            corrupt_sample_matrix(run_dir / "policy-scale-samples.csv")
            self.assertEqual(run_summary(run_dir, "ipv4", target_prefix), 1)
            summary = json.loads(
                (run_dir / "summary.json").read_text(encoding="utf-8")
            )
            self.assertFalse(summary["passed"])
            self.assertFalse(summary["checks"]["equal_trial_counts"])

    def test_more_than_one_route_check_per_transition_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir, target_prefix = build_scale_run(
                Path(tmp),
                address_family="ipv6",
                route_checks_per_transition=2,
            )
            self.assertEqual(run_summary(run_dir, "ipv6", target_prefix), 1)
            summary = json.loads(
                (run_dir / "summary.json").read_text(encoding="utf-8")
            )
            self.assertFalse(summary["passed"])
            self.assertEqual(summary["route_checks_per_transition"], 2)
            self.assertFalse(
                summary["checks"]["one_route_check_per_transition"]
            )


if __name__ == "__main__":
    unittest.main()
