import csv
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path


SRC_DIR = Path(__file__).parents[1] / "src"
MODULE_PATH = SRC_DIR / "audit_churn_controls.py"
SPEC = importlib.util.spec_from_file_location(
    "audit_churn_controls", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


TRIAL_FIELDS = (
    "global_order",
    "lane",
    "lane_trial",
    "block",
    "block_trial",
    "from_origin",
    "to_origin",
    "signed_update_transactions",
    "authorization_entry_changes",
    "invalid_exposure_ms",
    "unavailable_ms",
    "end_to_end_ms",
    "bgp_observation_ms",
    "authorization_to_completion_ms",
    "signed_request_to_routinator_ms",
    "routinator_to_rtr_ms",
    "rtr_to_enforcement_ms",
    "final_state",
    "final_action",
    "final_local_preference",
    "final_origin",
    "policy_digest",
    "passed",
)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def policy_document(lane, origin):
    keepalive = {
        "asn": "AS64501",
        "prefix": "10.255.255.0/24",
        "minLength": 24,
        "maxLength": 24,
        "inclusivity": None,
        "ta": "krill",
    }
    if lane == "exact":
        relevant = [
            {
                "asn": f"AS{origin}",
                "prefix": "10.0.10.0/24",
                "minLength": 24,
                "maxLength": 24,
                "inclusivity": None,
                "ta": "krill",
            }
        ]
    elif lane == "da":
        relevant = [
            {
                "asn": "AS64501",
                "prefix": "10.0.0.0/16",
                "minLength": 16,
                "maxLength": 24,
                "inclusivity": "inclusive",
                "ta": "krill",
            }
        ]
    elif lane == "prepublished_exact":
        relevant = [
            {
                "asn": f"AS{candidate}",
                "prefix": "10.0.10.0/24",
                "minLength": 24,
                "maxLength": 24,
                "inclusivity": None,
                "ta": "krill",
            }
            for candidate in (8075, 18403)
        ]
    else:
        relevant = []
    return {"metadata": {"generated": 1}, "roas": relevant + [keepalive]}


def rib(origin, preference, community, native_state):
    path = {
        "aspath": {
            "string": str(origin),
            "segments": [{"type": "as-sequence", "list": [origin]}],
        },
        "rpkiValidationState": native_state,
    }
    if preference != 100:
        path["locPrf"] = preference
    if community is not None:
        path["community"] = {
            "string": community,
            "list": [community],
        }
    return {"defaultLocPrf": 100, "paths": [path]}


def build_synthetic_run(source_root):
    rounds = 2
    block_size = 1
    seed = 20260823
    schedule = MODULE._expected_schedule(rounds, seed)
    run_dir = source_root / "outputs" / "controls-synthetic"
    run_dir.mkdir(parents=True)
    setup_transactions, setup_changes = MODULE._setup_update_counts(schedule)
    protocol = {
        "arms": list(MODULE.ARMS),
        "trials_per_lane": rounds * block_size,
        "randomized_complete_block_rounds": rounds,
        "trials_per_block": block_size,
        "random_seed": seed,
        "setup_signed_update_transactions": setup_transactions,
        "setup_authorization_entry_changes": setup_changes,
        "repository_keepalive": "10.255.255.0/24 => AS64501",
    }
    write_json(run_dir / "protocol.json", protocol)
    with (run_dir / "block-order.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(("round", "lane"))
        writer.writerows(schedule)

    fixture_source = source_root / "fixture-source.txt"
    fixture_source.write_text("immutable synthetic source\n", encoding="utf-8")
    digest = hashlib.sha256(fixture_source.read_bytes()).hexdigest()
    (run_dir / "source.sha256").write_text(
        f"{digest}  fixture-source.txt\n", encoding="utf-8"
    )

    # Deliberately invalid derived outputs prove that the audit never reads them.
    (run_dir / "summary.json").write_text("not-json\n", encoding="utf-8")
    (run_dir / "summary.csv").write_text("not,a,summary\n", encoding="utf-8")
    (run_dir / "REPORT.md").write_text("do not read\n", encoding="utf-8")

    events = []
    trial_rows = []
    lane_trial = Counter()
    current_origin = 8075
    base_ns = 1_000_000_000
    global_order = 0
    for block, (round_id, lane) in enumerate(schedule, start=1):
        lane_trial[lane] += 1
        trial = lane_trial[lane]
        global_order += 1
        old_origin = current_origin
        new_origin = 18403 if old_origin == 8075 else 8075
        exact = lane == "exact"
        event_offsets_ms = (
            (
                ("switch_requested", 0),
                ("old_route_absent", 10),
                ("new_route_in_adj_rib_in", 20),
                ("signed_authorization_requested", 30),
                ("routinator_validated", 60),
                ("frr_rtr_table_updated", 70),
                ("valid_route_accepted", 100),
            )
            if exact
            else (
                ("switch_requested", 0),
                ("old_route_absent", 10),
                ("new_route_in_adj_rib_in", 20),
                (
                    "delegated_route_accepted"
                    if lane == "da"
                    else "route_accepted",
                    40,
                ),
            )
        )
        for event, offset_ms in event_offsets_ms:
            events.append(
                {
                    "lane": lane,
                    "trial": trial,
                    "event": event,
                    "monotonic_ns": base_ns + offset_ms * 1_000_000,
                }
            )
        base_ns += (event_offsets_ms[-1][1] + 10) * 1_000_000

        before_policy = policy_document(lane, old_origin)
        final_policy = policy_document(lane, new_origin)
        policy_digest = MODULE._policy_digest(final_policy)
        state, preference, community = MODULE.FINAL_METADATA[lane]
        decision_state = MODULE.FINAL_DECISION[lane]
        native_state = {
            "exact": "valid",
            "da": "invalid",
            "bgp_only": "not found",
            "prepublished_exact": "valid",
        }[lane]
        durations = {
            "invalid_exposure_ms": 80.0 if exact else 0.0,
            "unavailable_ms": 90.0 if exact else 30.0,
            "end_to_end_ms": 100.0 if exact else 40.0,
            "authorization_to_completion_ms": 70.0 if exact else 0.0,
            "signed_request_to_routinator_ms": 30.0 if exact else 0.0,
            "routinator_to_rtr_ms": 10.0 if exact else 0.0,
            "rtr_to_enforcement_ms": 30.0 if exact else 0.0,
        }
        directory = run_dir / "raw" / lane / f"trial-{trial:02d}"
        directory.mkdir(parents=True)
        metadata = {
            "lane": lane,
            "trial": trial,
            "block": block,
            "prefix": "10.0.10.0/24",
            "from_origin": old_origin,
            "to_origin": new_origin,
            "signed_update_transactions": 1 if exact else 0,
            "authorization_entry_changes": 2 if exact else 0,
            **{
                field: durations[field]
                for field in MODULE.METADATA_DURATION_FIELDS
            },
            "final_state": state,
            "final_action": "accept",
            "final_local_preference": preference,
            "policy_digest": policy_digest,
            "passed": True,
        }
        write_json(directory / "metadata.json", metadata)
        write_json(
            directory / "before-rib.json",
            rib(old_origin, preference, community, native_state),
        )
        write_json(directory / "after-withdraw-rib.json", {})
        write_json(
            directory / "new-origin-received.json",
            {
                "receivedRoutes": {
                    "10.0.10.0/24": {"path": str(new_origin)}
                }
            },
        )
        write_json(
            directory / "final-rib.json",
            rib(new_origin, preference, community, native_state),
        )
        write_json(
            directory / "final-decision.json",
            [{"state": decision_state, "pass": True}],
        )
        write_json(directory / "before-routinator.json", before_policy)
        write_json(directory / "final-routinator.json", final_policy)
        if exact:
            write_json(
                directory / "preauthorization-decision.json",
                [{"state": "Invalid", "pass": True}],
            )
            write_json(directory / "preauthorization-rib.json", {})

        trial_rows.append(
            {
                "global_order": global_order,
                "lane": lane,
                "lane_trial": trial,
                "block": block,
                "block_trial": 1,
                "from_origin": old_origin,
                "to_origin": new_origin,
                "signed_update_transactions": 1 if exact else 0,
                "authorization_entry_changes": 2 if exact else 0,
                **durations,
                "bgp_observation_ms": 10.0,
                "final_state": state,
                "final_action": "accept",
                "final_local_preference": preference,
                "final_origin": new_origin,
                "policy_digest": policy_digest,
                "passed": "true",
            }
        )
        current_origin = new_origin

    with (run_dir / "events.jsonl").open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    with (run_dir / "trials.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=TRIAL_FIELDS)
        writer.writeheader()
        writer.writerows(trial_rows)
    return run_dir, fixture_source


class IndependentControlAuditTests(unittest.TestCase):
    def test_nearest_rank_is_explicit(self):
        self.assertEqual(MODULE.nearest_rank(range(1, 31), 0.95), 29)
        summary = MODULE.sample_stats(range(1, 31))
        self.assertEqual(summary["p95_nearest_rank_ms"], 29.0)
        self.assertEqual(summary["median_ms"], 15.5)

    def test_passes_from_raw_data_and_ignores_bogus_summaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary) / "e2e"
            run_dir, _ = build_synthetic_run(source_root)
            first = MODULE.audit_run(
                run_dir,
                source_root=source_root,
                bootstrap_replicates=200,
            )
            second = MODULE.audit_run(
                run_dir,
                source_root=source_root,
                bootstrap_replicates=200,
            )
        self.assertTrue(first["passed"])
        self.assertEqual(first, second)
        self.assertEqual(first["design"]["trial_n_per_arm"], 2)
        self.assertEqual(first["design"]["inferential_n_complete_rounds"], 2)
        self.assertEqual(
            first["descriptive_trial_level"]["exact"]
            ["end_to_end_completion"]["median_ms"],
            100.0,
        )
        self.assertEqual(
            first["inference"]["contrasts"]
            ["exact_minus_prepublished_exact"]["metrics"]
            ["end_to_end_ms"]["estimate_ms"],
            60.0,
        )
        self.assertIn("summary.json", first["inputs"]["intentionally_not_read"])

    def test_detects_state_and_update_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary) / "e2e"
            run_dir, _ = build_synthetic_run(source_root)
            decision_path = run_dir / "raw" / "da" / "trial-01" / "final-decision.json"
            write_json(decision_path, [{"state": "Invalid", "pass": True}])
            metadata_path = run_dir / "raw" / "exact" / "trial-01" / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["signed_update_transactions"] = 0
            write_json(metadata_path, metadata)
            result = MODULE.audit_run(
                run_dir,
                source_root=source_root,
                bootstrap_replicates=50,
            )
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["custom_decision_matches_arm"])
        self.assertFalse(result["checks"]["exact_updates_each_handoff"])

    def test_detects_source_hash_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary) / "e2e"
            run_dir, fixture_source = build_synthetic_run(source_root)
            fixture_source.write_text("changed after run\n", encoding="utf-8")
            result = MODULE.audit_run(
                run_dir,
                source_root=source_root,
                bootstrap_replicates=50,
            )
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["source_hashes_match"])
        self.assertIn("source_hashes_match", result["failures"])


if __name__ == "__main__":
    unittest.main()
