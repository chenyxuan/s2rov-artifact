import importlib.util
import sys
import unittest
from pathlib import Path


SRC_DIR = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))
MODULE_PATH = SRC_DIR / "summarize_churn_controls.py"
SPEC = importlib.util.spec_from_file_location(
    "summarize_churn_controls", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def row(lane, trial, block, digest="stable"):
    state, preference = MODULE.FINAL[lane]
    exact = lane == "exact"
    return {
        "global_order": block,
        "lane": lane,
        "lane_trial": trial,
        "block": block,
        "block_trial": 1,
        "from_origin": 8075,
        "to_origin": 18403,
        "signed_update_transactions": 1 if exact else 0,
        "authorization_entry_changes": 2 if exact else 0,
        "invalid_exposure_ms": 400.0 if exact else 0.0,
        "unavailable_ms": 500.0 if exact else 100.0,
        "end_to_end_ms": 520.0 if exact else 120.0,
        "bgp_observation_ms": 20.0,
        "authorization_to_completion_ms": 400.0 if exact else 0.0,
        "signed_request_to_routinator_ms": 300.0 if exact else 0.0,
        "routinator_to_rtr_ms": 50.0 if exact else 0.0,
        "rtr_to_enforcement_ms": 50.0 if exact else 0.0,
        "final_state": state,
        "final_action": "accept",
        "final_local_preference": preference,
        "final_origin": 18403,
        "policy_digest": f"exact-{trial}" if exact else digest,
        "passed": True,
    }


class ControlSummaryTests(unittest.TestCase):
    def setUp(self):
        self.schedule = [
            {"round": 1, "lane": lane} for lane in MODULE.ARMS
        ]
        self.rows = [
            row(lane, 1, block)
            for block, lane in enumerate(MODULE.ARMS, start=1)
        ]

    def test_passing_four_arm_summary(self):
        summary = MODULE.summarize_rows(
            self.rows, 1, 1, 1, self.schedule
        )
        self.assertTrue(summary["passed"])
        self.assertEqual(summary["total_trials"], 4)
        self.assertEqual(
            summary["lanes"]["prepublished_exact"]
            ["signed_update_transactions_total"],
            0,
        )

    def test_changed_static_digest_fails(self):
        rows = []
        schedule = []
        block = 0
        for round_id in (1, 2):
            for lane in MODULE.ARMS:
                block += 1
                schedule.append({"round": round_id, "lane": lane})
                digest = (
                    f"changed-{round_id}"
                    if lane == "prepublished_exact"
                    else "stable"
                )
                rows.append(row(lane, round_id, block, digest))
        summary = MODULE.summarize_rows(rows, 2, 1, 2, schedule)
        self.assertFalse(summary["passed"])
        self.assertFalse(
            summary["checks"]["static_policy_digests_unchanged"]
        )

    def test_incomplete_round_fails(self):
        summary = MODULE.summarize_rows(
            self.rows[:-1], 1, 1, 1, self.schedule[:-1]
        )
        self.assertFalse(summary["passed"])
        self.assertFalse(
            summary["checks"]["randomized_complete_block_schedule"]
        )


if __name__ == "__main__":
    unittest.main()
