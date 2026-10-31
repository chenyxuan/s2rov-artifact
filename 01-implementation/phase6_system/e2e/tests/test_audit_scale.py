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

from scale_fixture import build_scale_run, corrupt_sample_matrix


SRC_DIR = Path(__file__).parents[1] / "src"


def load_module(name: str):
    path = SRC_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUMMARY = load_module("summarize_scale")
AUDIT = load_module("audit_scale")


def run_summary(run_dir: Path, address_family: str, target_prefix: str) -> int:
    argv = [
        str(SRC_DIR / "summarize_scale.py"),
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
        return SUMMARY.main()


def run_audit(run_dir: Path, address_family: str) -> tuple[int, dict]:
    output_path = run_dir / "independent_audit.json"
    argv = [
        str(SRC_DIR / "audit_scale.py"),
        "--run-dir",
        str(run_dir),
        "--output",
        str(output_path),
        "--address-family",
        address_family,
    ]
    with patch.object(sys, "argv", argv):
        status = AUDIT.main()
    return status, json.loads(output_path.read_text(encoding="utf-8"))


class ScaleAuditTests(unittest.TestCase):
    def test_dual_stack_single_route_runs_pass(self) -> None:
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
                status, audit = run_audit(run_dir, address_family)
                self.assertEqual(status, 0)
                self.assertTrue(audit["passed"])
                self.assertEqual(audit["address_family"], address_family)
                self.assertEqual(audit["counts"]["samples"], 80)
                self.assertEqual(audit["counts"]["enforcement_snapshots"], 80)
                self.assertEqual(audit["counts"]["route_outcome_checks"], 80)
                self.assertTrue(audit["checks"]["exact_80_sample_matrix"])
                self.assertTrue(
                    audit["checks"]["one_route_check_per_transition"]
                )

    def test_corrupted_80_row_matrix_fails_independent_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir, target_prefix = build_scale_run(
                Path(tmp), address_family="ipv4"
            )
            self.assertEqual(run_summary(run_dir, "ipv4", target_prefix), 0)
            corrupt_sample_matrix(run_dir / "policy-scale-samples.csv")
            status, audit = run_audit(run_dir, "ipv4")
            self.assertEqual(status, 1)
            self.assertFalse(audit["passed"])
            self.assertFalse(audit["checks"]["exact_80_sample_matrix"])

    def test_two_route_checks_per_transition_fail_independent_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir, target_prefix = build_scale_run(
                Path(tmp), address_family="ipv6"
            )
            self.assertEqual(run_summary(run_dir, "ipv6", target_prefix), 0)

            for path in run_dir.glob(
                "background-*/trial-*/*/enforcement.json"
            ):
                checks = json.loads(path.read_text(encoding="utf-8"))
                checks.append(dict(checks[0], name="unexpected-second-route"))
                path.write_text(json.dumps(checks) + "\n", encoding="utf-8")
            summary = json.loads(
                (run_dir / "summary.json").read_text(encoding="utf-8")
            )
            summary["route_outcome_checks"] = 160
            (run_dir / "summary.json").write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            status, audit = run_audit(run_dir, "ipv6")
            self.assertEqual(status, 1)
            self.assertFalse(audit["passed"])
            self.assertEqual(audit["counts"]["route_outcome_checks"], 160)
            self.assertFalse(
                audit["checks"]["one_route_check_per_transition"]
            )


if __name__ == "__main__":
    unittest.main()
