#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


BENCHMARK_DIR = Path(__file__).resolve().parent
RUNNER_PATH = BENCHMARK_DIR / "run_policy_update_benchmark.py"
AUDITOR_PATH = BENCHMARK_DIR / "audit_policy_update_benchmark.py"
SOURCE_RUN = (
    BENCHMARK_DIR
    / "outputs"
    / "controlled-processing-20260830T-marker-final-v1"
)


def import_path(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RUNNER = import_path("policy_update_benchmark", RUNNER_PATH)
AUDITOR = import_path("policy_update_benchmark_auditor", AUDITOR_PATH)


class PolicyUpdateBenchmarkTests(unittest.TestCase):
    def make_synthetic_formal_run(self, root: Path) -> Path:
        run_dir = root / "synthetic-policy-update"
        (run_dir / "raw").mkdir(parents=True)
        inputs = RUNNER.prepare_inputs(run_dir, SOURCE_RUN)
        schedule = RUNNER.build_schedule(
            run_dir,
            repetitions=RUNNER.DEFAULT_REPETITIONS,
            seed=RUNNER.DEFAULT_SEED,
            cpu=RUNNER.DEFAULT_CPU,
        )
        RUNNER.build_run_config(
            run_dir,
            SOURCE_RUN,
            repetitions=RUNNER.DEFAULT_REPETITIONS,
            cpu=RUNNER.DEFAULT_CPU,
            seed=RUNNER.DEFAULT_SEED,
        )

        parent_pid = 900_000
        for condition in schedule:
            ip_version = int(condition["ip_version"])
            rules = int(condition["rules"])
            family = inputs["families"][str(ip_version)]
            policy = family["policies"][str(rules)]
            query = family["query"]
            update_ns = 100_000 + ip_version * 1_000 + rules * 10 + int(
                condition["repetition"]
            )
            raw = {
                "schema_version": RUNNER.SCHEMA_VERSION,
                "worker": "same-size-policy-update",
                "schedule_index": condition["schedule_index"],
                "nonce": condition["nonce"],
                "ip_version": ip_version,
                "rules": rules,
                "repetition": condition["repetition"],
                "requested_cpu": RUNNER.DEFAULT_CPU,
                "cpu_affinity": [RUNNER.DEFAULT_CPU],
                "worker_pid": parent_pid + 1 + int(condition["schedule_index"]),
                "parent_pid": parent_pid,
                "probe_index": query["probe_index"],
                "probe_prefix": query["probe_prefix"],
                "probe_origin": query["probe_origin"],
                "closed_state": "Invalid",
                "updated_state": "Delegated",
                "manuscript_state": "OpenScope",
                "open_payload_sha256": policy["frozen_open_sha256"],
                "open_serialized_bytes": policy["open_serialized_bytes"],
                "closed_payload_sha256": policy["frozen_closed_sha256"],
                "closed_serialized_bytes": policy["closed_serialized_bytes"],
                "query_sha256": query["frozen_sha256"],
                "closed_roundtrip_identical": True,
                "open_roundtrip_identical": True,
                "active_pointer_is_updated_policy": True,
                "update_ns": update_ns,
                "update_ms": update_ns / 1_000_000,
                "file_reads_excluded": True,
                "closed_policy_preload_excluded": True,
                "probe_precheck_excluded": True,
                "gc_collection_excluded": True,
            }
            RUNNER.write_json(run_dir / condition["raw_json"], raw)

        RUNNER.summarize(
            run_dir,
            schedule,
            expected_repetitions=RUNNER.DEFAULT_REPETITIONS,
            expected_cpu=RUNNER.DEFAULT_CPU,
        )
        (run_dir / "RUN_REPORT.md").write_text(
            "# Synthetic unit-test fixture\n", encoding="utf-8"
        )
        RUNNER.write_artifact_manifest(run_dir)
        return run_dir

    def test_unmarked_counterpart_changes_only_base_marker_bit(self):
        source = RUNNER.source_policy_path(SOURCE_RUN, 4, 64)
        open_payload = source.read_bytes()
        closed_payload, spec = RUNNER.build_unmarked_counterpart(open_payload)
        open_policy = RUNNER.DAROA.deserialize(open_payload)
        closed_policy = RUNNER.DAROA.deserialize(closed_payload)

        self.assertEqual(len(open_policy.stripes), 64)
        self.assertEqual(len(closed_policy.stripes), 64)
        self.assertTrue(spec["same_entry_count"])
        self.assertTrue(spec["only_base_marker_bit_changed"])
        self.assertTrue(spec["only_base_open_bit_changed"])
        self.assertEqual(
            spec["compatibility_aliases"],
            {"open": "marked", "closed": "unmarked"},
        )
        self.assertEqual(len(spec["semantic_delta"]), 1)
        self.assertTrue(spec["semantic_delta"][0]["before"]["open"])
        self.assertFalse(spec["semantic_delta"][0]["after"]["open"])

    def test_schedule_is_seeded_random_complete_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            schedule = RUNNER.build_schedule(run_dir)
        self.assertEqual(len(schedule), 200)
        self.assertEqual(schedule, AUDITOR.expected_schedule(RUNNER.DEFAULT_SEED))
        cells = {}
        for item in schedule:
            cells.setdefault((item["ip_version"], item["rules"]), set()).add(
                item["repetition"]
            )
        self.assertEqual(len(cells), 10)
        self.assertTrue(all(repetitions == set(range(1, 21)) for repetitions in cells.values()))

    def test_independent_audit_passes_complete_raw_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.make_synthetic_formal_run(Path(temporary))
            result = AUDITOR.audit(run_dir)
        self.assertTrue(result["checks"]["all_checks_pass"])
        self.assertTrue(result["checks"]["exact_2_by_5_matrix"])
        self.assertTrue(result["checks"]["twenty_observations_per_cell"])
        self.assertTrue(result["checks"]["all_summary_statistics_recomputed"])

    def test_independent_audit_rejects_raw_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.make_synthetic_formal_run(Path(temporary))
            schedule = json.loads(
                (run_dir / "schedule.json").read_text(encoding="utf-8")
            )
            raw_path = run_dir / schedule[0]["raw_json"]
            raw = json.loads(raw_path.read_text(encoding="utf-8"))
            raw["updated_state"] = "Invalid"
            RUNNER.write_json(raw_path, raw)

            result = AUDITOR.audit(run_dir)
        self.assertFalse(result["checks"]["all_checks_pass"])
        self.assertFalse(result["checks"]["raw_states_match_protocol"])
        self.assertFalse(result["checks"]["artifact_input_output_hashes_match"])


if __name__ == "__main__":
    unittest.main()
