import importlib.util
import sys
import unittest
from pathlib import Path


SRC_DIR = Path(__file__).parents[1] / "src"
MODULE_PATH = SRC_DIR / "summarize_handoff_benefit.py"
SPEC = importlib.util.spec_from_file_location(
    "summarize_handoff_benefit", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def trial_row(lane, trial, round_id, action_ms, probe_ms, passed=True):
    exact = lane == "reactive_exact"
    state = "OpenScope" if lane == "open_dynamic" else "Valid"
    lp = 200 if lane == "open_dynamic" else 300
    return {
        "global_order": trial,
        "round": round_id,
        "block": round_id,
        "block_trial": 1,
        "lane": lane,
        "trial": trial,
        "from_origin": 8075,
        "to_origin": 18403,
        "direction": "a_to_b",
        "signed_update_transactions": 1 if exact else 0,
        "roa_entry_changes": 2 if exact else 0,
        "observed_to_action_ms": action_ms,
        "observed_to_probe_ms": probe_ms,
        "switch_to_action_ms": None if action_ms is None else action_ms + 20,
        "switch_to_probe_ms": None if probe_ms is None else probe_ms + 20,
        "completion": "completed" if passed else "timeout",
        "completion_success": passed,
        "deadline_miss": not passed,
        "status": "ok" if passed else "failed",
        "failure_category": "" if passed else "deadline",
        "final_state": state,
        "final_state_raw": "Delegated" if lane == "open_dynamic" else state,
        "final_action": "accept" if passed else "",
        "final_lp": lp if passed else None,
        "final_origin": 18403 if passed else None,
        "policy_digest": f"{lane}-policy",
        "passed": passed,
    }


def two_round_rows():
    values = {
        "reactive_exact": ((100.0, 110.0), (110.0, 120.0)),
        "open_dynamic": ((40.0, 50.0), (50.0, 60.0)),
        "prepublished_exact": ((42.0, 52.0), (52.0, 62.0)),
    }
    rows = []
    for round_id in (1, 2):
        for lane in MODULE.ARMS:
            action, probe = values[lane][round_id - 1]
            rows.append(trial_row(lane, round_id, round_id, action, probe))
    return rows


class HandoffBenefitSummaryTests(unittest.TestCase):
    def test_complete_round_contrast_is_deterministic(self):
        first = MODULE.summarize_rows(
            two_round_rows(),
            expected_trials_per_lane=2,
            expected_rounds=2,
            bootstrap_replicates=200,
            bootstrap_seed=7,
        )
        second = MODULE.summarize_rows(
            two_round_rows(),
            expected_trials_per_lane=2,
            expected_rounds=2,
            bootstrap_replicates=200,
            bootstrap_seed=7,
        )
        self.assertTrue(first["passed"])
        self.assertEqual(first, second)
        primary = first["inference"]["contrasts"][
            "reactive_exact_minus_open_dynamic"
        ]["metrics"]["observed_to_action_ms"]
        self.assertEqual(primary["estimate_ms"], 60.0)
        self.assertEqual(primary["ci95_nearest_rank_ms"], [60.0, 60.0])
        self.assertEqual(primary["inferential_n_complete_rounds"], 2)

    def test_failed_trial_is_retained_and_missing_round_is_explicit(self):
        rows = two_round_rows()
        failed = next(
            row
            for row in rows
            if row["lane"] == "open_dynamic" and row["round"] == 2
        )
        failed.update(
            {
                "observed_to_action_ms": None,
                "observed_to_probe_ms": None,
                "switch_to_action_ms": None,
                "switch_to_probe_ms": None,
                "completion": "timeout",
                "completion_success": False,
                "deadline_miss": True,
                "status": "failed",
                "failure_category": "deadline",
                "passed": False,
            }
        )
        result = MODULE.summarize_rows(
            rows,
            expected_trials_per_lane=2,
            expected_rounds=2,
            bootstrap_replicates=100,
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["design"]["total_trial_rows"], 6)
        self.assertEqual(len(result["all_trial_records"]), 6)
        self.assertEqual(len(result["failed_trials"]), 1)
        primary = result["inference"]["contrasts"][
            "reactive_exact_minus_open_dynamic"
        ]["metrics"]["observed_to_action_ms"]
        self.assertEqual(primary["included_rounds"], [1])
        self.assertEqual(primary["excluded_rounds_missing_metric"], [2])

    def test_normalize_row_accepts_legacy_aliases_and_blanks(self):
        raw = {
            "round": "1",
            "lane": "open_dynamic",
            "lane_trial": "1",
            "authorization_entry_changes": "0",
            "signed_update_transactions": "0",
            "observed_to_action_ms": "",
            "observed_to_probe_ms": "",
            "completion": "timeout",
            "deadline_miss": "true",
            "passed": "false",
            "final_state": "OpenScope",
            "final_lp": "200",
        }
        row = MODULE.normalize_row(raw)
        self.assertEqual(row["trial"], 1)
        self.assertEqual(row["roa_entry_changes"], 0)
        self.assertIsNone(row["observed_to_action_ms"])
        self.assertFalse(row["passed"])


if __name__ == "__main__":
    unittest.main()
