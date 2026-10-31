import importlib.util
import sys
import unittest
from pathlib import Path


E2E_ROOT = Path(__file__).parents[1]
MODULE_PATH = E2E_ROOT / "src" / "audit_selected_fixture_run.py"
SPEC = importlib.util.spec_from_file_location(
    "audit_selected_fixture_run", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class IndependentClassifierTests(unittest.TestCase):
    def test_self_checks(self):
        MODULE.run_self_checks()

    def test_removal_policy_reclassifies_listed_customer(self):
        policy = MODULE.parse_policy(
            {
                "roas": [
                    {
                        "asn": "AS64501",
                        "prefix": "10.0.0.0/16",
                        "minLength": 16,
                        "maxLength": 24,
                        "inclusivity": "inclusive",
                        "ta": "test",
                    }
                ]
            }
        )
        result = MODULE.classify_da(policy, "10.0.1.0/24", 8075)
        self.assertEqual(result.state, "Delegated")
        self.assertEqual(str(result.evidence.network), "10.0.0.0/16")

    def test_unmarked_exact_entry_does_not_shadow_marker(self):
        policy = MODULE.parse_policy(
            {
                "roas": [
                    {
                        "asn": "AS64501",
                        "prefix": "10.0.0.0/16",
                        "minLength": 16,
                        "maxLength": 24,
                        "inclusivity": "inclusive",
                    },
                    {
                        "asn": "AS8075",
                        "prefix": "10.0.1.0/24",
                        "minLength": 24,
                        "maxLength": 24,
                    },
                ]
            }
        )
        explicit = MODULE.classify_da(policy, "10.0.1.0/24", 8075)
        delegated = MODULE.classify_da(policy, "10.0.1.0/24", 18403)
        self.assertEqual(explicit.state, "Explicit")
        self.assertEqual(str(explicit.evidence.network), "10.0.1.0/24")
        self.assertEqual(delegated.state, "Delegated")
        self.assertEqual(str(delegated.evidence.network), "10.0.0.0/16")

    def test_overlapping_markers_are_rejected(self):
        with self.assertRaisesRegex(MODULE.AuditError, "pairwise prefix-disjoint"):
            MODULE.parse_policy(
                {
                    "roas": [
                        {
                            "asn": "AS64501",
                            "prefix": "10.0.0.0/16",
                            "maxLength": 24,
                            "inclusivity": "inclusive",
                        },
                        {
                            "asn": "AS64502",
                            "prefix": "10.0.1.0/24",
                            "maxLength": 25,
                            "inclusivity": "inclusive",
                        },
                    ]
                }
            )

    def test_invalid_marker_length_intervals_are_rejected(self):
        for min_length, max_length in ((20, 24), (16, 16)):
            with self.subTest(min_length=min_length, max_length=max_length):
                with self.assertRaisesRegex(
                    MODULE.AuditError, "OpenScope marker requires minLength"
                ):
                    MODULE.parse_policy(
                        {
                            "roas": [
                                {
                                    "asn": "AS64501",
                                    "prefix": "10.0.0.0/16",
                                    "minLength": min_length,
                                    "maxLength": max_length,
                                    "inclusivity": "inclusive",
                                }
                            ]
                        }
                    )

    def test_exclusive_compatibility_alias_is_unmarked(self):
        policy = MODULE.parse_policy(
            {
                "roas": [
                    {
                        "asn": "AS64501",
                        "prefix": "10.0.0.0/16",
                        "minLength": 16,
                        "maxLength": 24,
                        "inclusivity": "exclusive",
                    }
                ]
            }
        )
        self.assertEqual(
            MODULE.classify_da(policy, "10.0.1.0/24", 64501).state,
            "Explicit",
        )
        self.assertEqual(
            MODULE.classify_da(policy, "10.0.1.0/24", 18403).state,
            "Invalid",
        )


class SelectedFixtureIntegrationTests(unittest.TestCase):
    def test_accepted_fixture_requires_rerun_after_classifier_change(self):
        run_dir = E2E_ROOT / "outputs" / "run-20260823T024129Z"
        if not run_dir.is_dir():
            self.skipTest("archived container fixture is not included in a clean clone")
        with self.assertRaisesRegex(
            MODULE.AuditError,
            "source-manifest hashes do not match",
        ):
            MODULE.audit_run(run_dir)


if __name__ == "__main__":
    unittest.main()
