import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "src" / "summarize_churn.py"
SPEC = importlib.util.spec_from_file_location("summarize_churn", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def row(lane, trial, block, invalid, updates, changes, state, preference, digest):
    return {
        "global_order": trial if lane == "exact" else trial + 2,
        "lane": lane,
        "lane_trial": trial,
        "block": block,
        "block_trial": trial,
        "from_origin": 8075 if trial % 2 else 18403,
        "to_origin": 18403 if trial % 2 else 8075,
        "signed_update_transactions": updates,
        "authorization_entry_changes": changes,
        "invalid_exposure_ms": invalid,
        "unavailable_ms": 100.0 + invalid,
        "end_to_end_ms": 120.0 + invalid,
        "bgp_observation_ms": 10.0,
        "authorization_to_completion_ms": invalid if lane == "exact" else 0.0,
        "signed_request_to_routinator_ms": invalid * 0.7 if lane == "exact" else 0.0,
        "routinator_to_rtr_ms": invalid * 0.2 if lane == "exact" else 0.0,
        "rtr_to_enforcement_ms": invalid * 0.1 if lane == "exact" else 0.0,
        "final_state": state,
        "final_action": "accept",
        "final_local_preference": preference,
        "final_origin": 18403 if trial % 2 else 8075,
        "policy_digest": digest,
        "passed": True,
    }


class ChurnSummaryTests(unittest.TestCase):
    def test_nearest_rank(self):
        self.assertEqual(MODULE.nearest_rank(range(1, 31), 0.95), 29)

    def test_passing_two_lane_summary(self):
        rows = [
            row("exact", 1, 1, 400.0, 1, 2, "Valid", 300, "e1"),
            row("exact", 2, 3, 500.0, 1, 2, "Valid", 300, "e2"),
            row("da", 1, 2, 0.0, 0, 0, "Delegated", 200, "open"),
            row("da", 2, 2, 0.0, 0, 0, "Delegated", 200, "open"),
        ]
        summary = MODULE.summarize_rows(rows, 2)
        self.assertTrue(summary["passed"])
        self.assertEqual(
            summary["lanes"]["exact"]["signed_update_transactions_total"],
            2,
        )
        self.assertEqual(
            summary["lanes"]["da"]["invalid_exposure"]["median_ms"], 0.0
        )

    def test_changed_da_digest_fails(self):
        rows = [
            row("exact", 1, 1, 400.0, 1, 2, "Valid", 300, "e1"),
            row("da", 1, 2, 0.0, 0, 0, "Delegated", 200, "open-a"),
        ]
        rows.append(row("exact", 2, 3, 500.0, 1, 2, "Valid", 300, "e2"))
        rows.append(row("da", 2, 2, 0.0, 0, 0, "Delegated", 200, "open-b"))
        summary = MODULE.summarize_rows(rows, 2)
        self.assertFalse(summary["passed"])
        self.assertFalse(summary["checks"]["da_policy_unchanged_during_churn"])


if __name__ == "__main__":
    unittest.main()
