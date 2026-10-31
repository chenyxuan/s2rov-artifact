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
MODULE_PATH = SRC_DIR / "audit_handoff_benefit.py"
SPEC = importlib.util.spec_from_file_location(
    "audit_handoff_benefit", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


TRIAL_FIELDS = (
    "global_order",
    "round",
    "block",
    "block_trial",
    "lane",
    "trial",
    "from_origin",
    "to_origin",
    "direction",
    "signed_update_transactions",
    "roa_entry_changes",
    "observed_to_action_ms",
    "observed_to_probe_ms",
    "switch_to_action_ms",
    "switch_to_probe_ms",
    "completion",
    "deadline_miss",
    "status",
    "failure_category",
    "final_state_raw",
    "final_state_paper",
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
    }
    if lane == "reactive_exact":
        relevant = [
            {
                "asn": f"AS{origin}",
                "prefix": "10.0.10.0/24",
                "minLength": 24,
                "maxLength": 24,
                "inclusivity": None,
            }
        ]
    elif lane == "open_dynamic":
        relevant = [
            {
                "asn": "AS64501",
                "prefix": "10.0.0.0/16",
                "minLength": 16,
                "maxLength": 24,
                "inclusivity": "inclusive",
            }
        ]
    else:
        relevant = [
            {
                "asn": f"AS{candidate}",
                "prefix": "10.0.10.0/24",
                "minLength": 24,
                "maxLength": 24,
                "inclusivity": None,
            }
            for candidate in (8075, 18403)
        ]
    return {"metadata": {"generated": 1}, "roas": relevant + [keepalive]}


def final_rib(origin):
    return {
        "defaultLocPrf": 100,
        "paths": [
            {
                "aspath": {
                    "string": str(origin),
                    "segments": [
                        {"type": "as-sequence", "list": [origin]}
                    ],
                }
            }
        ],
    }


def build_synthetic_run(source_root):
    rounds = 2
    block_size = 1
    seed = 20260828
    schedule = MODULE._expected_schedule(rounds, seed)
    run_dir = source_root / "outputs" / "handoff-benefit-synthetic"
    run_dir.mkdir(parents=True)
    protocol = {
        "arms": list(MODULE.ARMS),
        "trials_per_lane": rounds * block_size,
        "randomized_complete_block_rounds": rounds,
        "trials_per_block": block_size,
        "random_seed": seed,
    }
    write_json(run_dir / "protocol.json", protocol)
    with (run_dir / "block-order.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(("round", "lane"))
        writer.writerows(schedule)

    source = source_root / "fixture-source.txt"
    source.write_text("immutable handoff fixture\n", encoding="utf-8")
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    (run_dir / "source.sha256").write_text(
        f"{source_digest}  fixture-source.txt\n", encoding="utf-8"
    )

    # Invalid derived outputs demonstrate that the independent audit ignores them.
    (run_dir / "summary.json").write_text("not-json\n", encoding="utf-8")
    (run_dir / "summary.csv").write_text("not,a,summary\n", encoding="utf-8")
    (run_dir / "REPORT.md").write_text("do not read\n", encoding="utf-8")

    lane_trials = Counter()
    events = []
    rows = []
    current_origin = 8075
    base_ns = 1_000_000_000
    for block, (round_id, lane) in enumerate(schedule, start=1):
        lane_trials[lane] += 1
        trial = lane_trials[lane]
        from_origin = current_origin
        to_origin = 18403 if from_origin == 8075 else 8075
        exact = lane == "reactive_exact"
        offsets = [
            ("switch_requested", 0),
            ("old_route_absent", 10),
            ("new_route_in_adj_rib_in", 20),
        ]
        if exact:
            offsets.append(("signed_roa_requested", 30))
        action_offset = {
            "reactive_exact": 100,
            "open_dynamic": 50,
            "prepublished_exact": 52,
        }[lane]
        offsets.extend(
            [
                ("rp_policy_available", 35 if exact else 25),
                ("compiler_started", 40 if exact else 30),
                ("compiler_completed", action_offset - 5),
                ("action_installed", action_offset),
                ("probe_succeeded", action_offset + 5),
            ]
        )
        for name, offset in offsets:
            event = {
                "round": round_id,
                "lane": lane,
                "trial": trial,
                "event": name,
                "monotonic_ns": base_ns + offset * 1_000_000,
            }
            if name == "signed_roa_requested":
                event["roa_entry_changes"] = 2
            events.append(event)
        base_ns += (offsets[-1][1] + 10) * 1_000_000

        pre_policy = policy_document(lane, from_origin)
        final_policy = policy_document(lane, to_origin)
        trial_dir = run_dir / "raw" / lane / f"trial-{trial:02d}"
        trial_dir.mkdir(parents=True)
        write_json(trial_dir / "pre-policy.json", pre_policy)
        write_json(trial_dir / "final-policy.json", final_policy)
        write_json(
            trial_dir / "decisions.json",
            [
                {
                    "prefix": "10.0.10.0/24",
                    "origin": to_origin,
                    "state": "OpenScope" if lane == "open_dynamic" else "Valid",
                    "action": "accept",
                }
            ],
        )
        write_json(trial_dir / "final-rib.json", final_rib(to_origin))
        (trial_dir / "ping.txt").write_text(
            "4 packets transmitted, 4 received, 0% packet loss\n",
            encoding="utf-8",
        )
        (trial_dir / "frr-policy.vty").write_text(
            "route-map TEST permit 10\n", encoding="utf-8"
        )
        write_json(trial_dir / "received-a.json", {})
        write_json(trial_dir / "received-b.json", {})

        timings = {
            "observed_to_action_ms": action_offset - 20.0,
            "observed_to_probe_ms": action_offset - 15.0,
            "switch_to_action_ms": float(action_offset),
            "switch_to_probe_ms": action_offset + 5.0,
        }
        raw_state = "Delegated" if lane == "open_dynamic" else "Valid"
        paper_state = "OpenScope" if lane == "open_dynamic" else "Valid"
        local_preference = 200 if lane == "open_dynamic" else 300
        final_policy_path = trial_dir / "final-policy.json"
        policy_digest = hashlib.sha256(final_policy_path.read_bytes()).hexdigest()
        metadata = {
            "round": round_id,
            "lane": lane,
            "trial": trial,
            "prefix": "10.0.10.0/24",
            "from_origin": from_origin,
            "to_origin": to_origin,
            "direction": "a_to_b" if to_origin == 18403 else "b_to_a",
            "signed_update_transactions": 1 if exact else 0,
            "roa_entry_changes": 2 if exact else 0,
            **timings,
            "completion": "completed",
            "deadline_miss": False,
            "status": "ok",
            "failure_category": "",
            "final_state_raw": raw_state,
            "final_state_paper": paper_state,
            "final_action": "accept",
            "final_local_preference": local_preference,
            "final_origin": to_origin,
            "policy_digest": policy_digest,
            "passed": True,
        }
        write_json(trial_dir / "metadata.json", metadata)
        rows.append(
            {
                "global_order": block,
                "round": round_id,
                "block": block,
                "block_trial": 1,
                "lane": lane,
                "trial": trial,
                "from_origin": from_origin,
                "to_origin": to_origin,
                "direction": metadata["direction"],
                "signed_update_transactions": 1 if exact else 0,
                "roa_entry_changes": 2 if exact else 0,
                **timings,
                "completion": "completed",
                "deadline_miss": "false",
                "status": "ok",
                "failure_category": "",
                "final_state_raw": raw_state,
                "final_state_paper": paper_state,
                "final_action": "accept",
                "final_local_preference": local_preference,
                "final_origin": to_origin,
                "policy_digest": policy_digest,
                "passed": "true",
            }
        )
        current_origin = to_origin

    with (run_dir / "events.jsonl").open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    with (run_dir / "trials.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=TRIAL_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return run_dir, source


class IndependentHandoffBenefitAuditTests(unittest.TestCase):
    def test_passes_from_raw_data_and_ignores_bogus_summaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary) / "e2e"
            run_dir, _ = build_synthetic_run(source_root)
            first = MODULE.audit_run(
                run_dir,
                source_root=source_root,
                bootstrap_replicates=200,
                bootstrap_seed=11,
            )
            second = MODULE.audit_run(
                run_dir,
                source_root=source_root,
                bootstrap_replicates=200,
                bootstrap_seed=11,
            )
        self.assertTrue(first["passed"], first["failures"])
        self.assertEqual(first, second)
        self.assertEqual(first["design"]["trial_n_per_arm"], 2)
        self.assertEqual(
            first["descriptive_trial_level"]["reactive_exact"]
            ["roa_entry_changes_total"],
            4,
        )
        primary = first["inference"]["contrasts"][
            "reactive_exact_minus_open_dynamic"
        ]["metrics"]["observed_to_action_ms"]
        self.assertEqual(primary["estimate_ms"], 50.0)
        self.assertIn("summary.json", first["inputs"]["intentionally_not_read"])

    def test_detects_multiple_dynamic_origins_and_endpoint_in_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary) / "e2e"
            run_dir, _ = build_synthetic_run(source_root)
            trial_dir = run_dir / "raw" / "open_dynamic" / "trial-01"
            metadata = json.loads(
                (trial_dir / "metadata.json").read_text(encoding="utf-8")
            )
            target = metadata["to_origin"]
            decisions = json.loads(
                (trial_dir / "decisions.json").read_text(encoding="utf-8")
            )
            decisions.append({"origin": 64496, "state": "OpenScope"})
            write_json(trial_dir / "decisions.json", decisions)
            for name in ("pre-policy.json", "final-policy.json"):
                path = trial_dir / name
                policy = json.loads(path.read_text(encoding="utf-8"))
                policy["roas"].append(
                    {
                        "asn": f"AS{target}",
                        "prefix": "10.0.10.0/24",
                        "minLength": 24,
                        "maxLength": 24,
                        "inclusivity": None,
                    }
                )
                write_json(path, policy)
            result = MODULE.audit_run(
                run_dir,
                source_root=source_root,
                bootstrap_replicates=50,
            )
        self.assertFalse(result["passed"])
        self.assertFalse(
            result["checks"]["open_dynamic_has_one_observed_origin_decision"]
        )
        self.assertFalse(
            result["checks"]["open_signed_policy_omits_endpoint_origins"]
        )

    def test_detects_event_order_and_source_hash_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary) / "e2e"
            run_dir, source = build_synthetic_run(source_root)
            events_path = run_dir / "events.jsonl"
            events = [
                json.loads(line)
                for line in events_path.read_text(encoding="utf-8").splitlines()
            ]
            open_indices = [
                index
                for index, event in enumerate(events)
                if event["lane"] == "open_dynamic"
                and event["trial"] == 1
                and event["event"] in {"compiler_started", "compiler_completed"}
            ]
            first, second = open_indices
            events[first]["event"], events[second]["event"] = (
                events[second]["event"],
                events[first]["event"],
            )
            events_path.write_text(
                "".join(
                    json.dumps(event, separators=(",", ":")) + "\n"
                    for event in events
                ),
                encoding="utf-8",
            )
            source.write_text("modified source\n", encoding="utf-8")
            result = MODULE.audit_run(
                run_dir,
                source_root=source_root,
                bootstrap_replicates=50,
            )
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["per_trial_event_sequences_match"])
        self.assertFalse(result["checks"]["source_hashes_match"])


if __name__ == "__main__":
    unittest.main()
