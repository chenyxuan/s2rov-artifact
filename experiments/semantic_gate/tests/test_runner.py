from __future__ import annotations

import itertools
import unittest

from experiments.semantic_gate.run_e1a import (
    BOUNDARY_VECTOR_COUNT,
    BOUNDED_VECTOR_COUNT,
    INVALID_FAMILIES,
    artifact_allowlist_diff,
    boundary_vectors,
    evaluate_invalid_object,
    evaluate_vector,
    exhaustive_vectors,
    generated_invalid_objects,
    generated_vectors,
    execution_source_paths,
    planned_artifact_paths,
    run_baseline_matrix,
    run_composition_census,
    run_mutation_census,
    run_projection_negative_controls,
)


class RunnerComponentTests(unittest.TestCase):
    def test_frozen_generator_is_deterministic(self) -> None:
        left = list(generated_vectors(20260826, 20))
        right = list(generated_vectors(20260826, 20))
        self.assertEqual(left, right)
        self.assertEqual(len(left), 20)

    def test_sampled_vectors_match_all_differential_paths(self) -> None:
        vectors = itertools.chain(
            itertools.islice(exhaustive_vectors(), 500),
            generated_vectors(20260826, 500),
        )
        for vector in vectors:
            result = evaluate_vector(vector)
            self.assertFalse(result["semantic_mismatch"], vector["id"])
            self.assertFalse(result["order_dependent"], vector["id"])
            self.assertEqual(result["forbidden_state_upgrade_count"], 0, vector["id"])
            self.assertFalse(result["metadata_mismatch"], vector["id"])

    def test_frozen_bounded_and_boundary_counts(self) -> None:
        self.assertEqual(sum(1 for _ in exhaustive_vectors()), BOUNDED_VECTOR_COUNT)
        self.assertEqual(sum(1 for _ in boundary_vectors()), BOUNDARY_VECTOR_COUNT)

    def test_generated_invalid_families_fail_for_targeted_reason(self) -> None:
        cases = list(generated_invalid_objects(120260826, len(INVALID_FAMILIES) * 2))
        self.assertEqual({case["family"] for case in cases}, set(INVALID_FAMILIES))
        for case in cases:
            result = evaluate_invalid_object(case)
            self.assertTrue(result["rejected"], case["id"])
            self.assertTrue(result["target_matched"], (case["id"], result["message"]))

    def test_fixed_censuses_pass(self) -> None:
        self.assertEqual(run_mutation_census()["unexpected_accept_count"], 0)
        self.assertEqual(run_composition_census()["failure_count"], 0)
        self.assertEqual(run_baseline_matrix()["failure_count"], 0)
        self.assertEqual(run_projection_negative_controls()["failure_count"], 0)

    def test_execution_source_closure_and_prefrozen_allowlist(self) -> None:
        source_paths = {str(path) for path in execution_source_paths()}
        self.assertTrue(
            any(path.endswith("experiments/semantic_gate/frozen_v3/__init__.py") for path in source_paths)
        )
        source_hashes = {
            "experiments/semantic_gate/run_e1a.py": "a",
            "experiments/semantic_gate/frozen_v3/__init__.py": "b",
        }
        planned = planned_artifact_paths(source_hashes)
        self.assertIn(
            "source_bundle/experiments/semantic_gate/frozen_v3/__init__.py", planned
        )
        missing, extra = artifact_allowlist_diff(planned, [*planned, "unexpected.txt"])
        self.assertEqual(missing, [])
        self.assertEqual(extra, ["unexpected.txt"])


if __name__ == "__main__":
    unittest.main()
