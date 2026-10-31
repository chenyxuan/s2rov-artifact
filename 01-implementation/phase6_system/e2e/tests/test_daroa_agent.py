#!/usr/bin/env python3
import importlib.util
import ipaddress
import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "daroa_agent", ROOT / "src" / "daroa_agent.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.policy = MODULE.Policy.from_routinator(
            {
                "roas": [
                    {
                        "asn": "AS64501",
                        "prefix": "10.0.0.0/16",
                        "minLength": 16,
                        "maxLength": 24,
                        "inclusivity": "inclusive",
                        "ta": "lab",
                    },
                    {
                        "asn": "AS8075",
                        "prefix": "10.0.1.0/24",
                        "minLength": 24,
                        "maxLength": 24,
                        "inclusivity": None,
                        "ta": "lab",
                    },
                ]
            }
        )
        self.cases = json.loads((ROOT / "config" / "cases.json").read_text())

    def test_reference_cases(self):
        results = MODULE.evaluate_cases(self.policy, self.cases)
        self.assertTrue(all(item["pass"] for item in results), results)

    def test_open_policy_is_not_origin_authentication(self):
        state, _ = self.policy.validate("10.0.3.0/24", 15169)
        self.assertEqual(state, "Delegated")

    def test_exact_aggregate_is_not_open(self):
        state, _ = self.policy.validate("10.0.0.0/16", 13335)
        self.assertEqual(state, "Invalid")

    def test_unmarked_exact_entry_does_not_shadow_marker(self):
        state, stripe = self.policy.validate("10.0.1.0/24", 15169)
        self.assertEqual(state, "Delegated")
        self.assertEqual(str(stripe.network), "10.0.0.0/16")

        state, stripe = self.policy.validate("10.0.1.0/24", 8075)
        self.assertEqual(state, "Explicit")
        self.assertEqual(str(stripe.network), "10.0.1.0/24")

        state, stripe = self.policy.validate("10.0.1.0/24", 64501)
        self.assertEqual(state, "Explicit")
        self.assertEqual(str(stripe.network), "10.0.0.0/16")

    def test_private_origin_gate(self):
        self.assertFalse(MODULE.eligible_delegated_origin(64513))
        self.assertFalse(MODULE.eligible_delegated_origin(65552))
        self.assertFalse(MODULE.eligible_delegated_origin(131071))
        self.assertTrue(MODULE.eligible_delegated_origin(18403))
        self.assertTrue(MODULE.eligible_delegated_origin(131072))

    def test_overlength_route_is_invalid(self):
        state, stripe = self.policy.validate("10.0.2.0/25", 18403)
        self.assertEqual(state, "Invalid")
        self.assertIsNone(stripe)

    def test_overlength_explicit_origin_is_invalid(self):
        state, stripe = self.policy.validate("10.0.2.0/25", 64501)
        self.assertEqual(state, "Invalid")
        self.assertIsNone(stripe)

    def test_overlapping_markers_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "pairwise prefix-disjoint"):
            MODULE.Policy.from_routinator(
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
                            "asn": "AS64502",
                            "prefix": "10.0.1.0/24",
                            "minLength": 24,
                            "maxLength": 25,
                            "inclusivity": "inclusive",
                        },
                    ]
                }
            )

    def test_invalid_ipv4_marker_length_intervals_are_rejected(self):
        for min_length, max_length in ((20, 24), (16, 16)):
            with self.subTest(min_length=min_length, max_length=max_length):
                with self.assertRaisesRegex(
                    ValueError, "OpenScope marker requires minLength"
                ):
                    MODULE.Policy.from_routinator(
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
        policy = MODULE.Policy.from_routinator(
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
        self.assertEqual(policy.validate("10.0.1.0/24", 64501)[0], "Explicit")
        self.assertEqual(policy.validate("10.0.1.0/24", 18403)[0], "Invalid")

    def test_rfc6811_covering_ignores_max_length(self):
        baseline = MODULE.Policy.from_routinator(
            {
                "roas": [
                    {
                        "asn": "AS64501",
                        "prefix": "10.0.0.0/16",
                        "minLength": 16,
                        "maxLength": 16,
                        "inclusivity": None,
                    }
                ]
            }
        )
        state, _ = baseline.validate_baseline("10.0.1.0/24", 8075)
        self.assertEqual(state, "Invalid")

    def test_length_admissible_baseline_rejects_unnamed_origin(self):
        baseline = MODULE.Policy.from_routinator(
            {
                "roas": [
                    {
                        "asn": "AS64501",
                        "prefix": "10.0.0.0/16",
                        "minLength": 16,
                        "maxLength": 24,
                        "inclusivity": None,
                    }
                ]
            }
        )
        state, _ = baseline.validate_baseline("10.0.1.0/24", 8075)
        self.assertEqual(state, "Invalid")

    def test_indexed_lookup_with_1024_unrelated_stripes(self):
        document = {
            "roas": [
                {
                    "asn": "AS64501",
                    "prefix": "10.0.0.0/16",
                    "minLength": 16,
                    "maxLength": 24,
                    "inclusivity": "inclusive",
                }
            ]
        }
        benchmark_space = ipaddress.ip_network("198.18.0.0/15")
        for prefix in list(benchmark_space.subnets(new_prefix=26))[:1024]:
            document["roas"].append(
                {
                    "asn": "AS65010",
                    "prefix": str(prefix),
                    "minLength": 26,
                    "maxLength": 26,
                    "inclusivity": None,
                }
            )
        policy = MODULE.Policy.from_routinator(document)
        state, stripe = policy.validate("10.0.2.0/24", 18403)
        self.assertEqual(state, "Delegated")
        self.assertEqual(str(stripe.network), "10.0.0.0/16")
        self.assertEqual(len(policy._by_prefix), 1025)

    def test_compiler_keeps_two_prefixes_from_one_neighbor(self):
        results = [
            {
                "peer": "172.31.0.11",
                "prefix": "10.0.1.0/24",
                "origin": 8075,
                "state": "Explicit",
            },
            {
                "peer": "172.31.0.11",
                "prefix": "10.0.2.0/24",
                "origin": 18403,
                "state": "Delegated",
            },
        ]
        commands = MODULE.policy_commands(results)
        route_map = "DA-IN-172-31-0-11"
        self.assertEqual(
            commands.count(
                f"neighbor 172.31.0.11 route-map {route_map} in"
            ),
            1,
        )
        self.assertIn(f"route-map {route_map} permit 10", commands)
        self.assertIn(f"route-map {route_map} permit 20", commands)
        self.assertIn("permit 10.0.1.0/24", commands)
        self.assertIn("permit 10.0.2.0/24", commands)
        self.assertLess(
            commands.index(
                "no neighbor 172.31.0.11 route-map DA-IN-1 in"
            ),
            commands.index(
                f"neighbor 172.31.0.11 route-map {route_map} in"
            ),
        )

    def test_origin_change_does_not_leave_old_origin_permitted(self):
        previous = [
            {
                "peer": "172.31.0.11",
                "prefix": "10.0.1.0/24",
                "origin": 8075,
                "state": "Explicit",
            }
        ]
        current = [
            {
                "peer": "172.31.0.11",
                "prefix": "10.0.1.0/24",
                "origin": 18403,
                "state": "Explicit",
            }
        ]
        commands = MODULE.policy_commands(current, previous)
        self.assertIn("permit _18403$", commands)
        self.assertNotIn("permit _8075$", commands)
        self.assertIn("route-map DA-IN-172-31-0-11 deny 9990", commands)
        self.assertIn(
            "no bgp as-path access-list DA-A-172-31-0-11-1", commands
        )

    def test_removed_peer_route_map_is_detached_and_deleted(self):
        previous = [
            {
                "peer": "172.31.0.11",
                "prefix": "10.0.1.0/24",
                "origin": 8075,
                "state": "Explicit",
            }
        ]
        commands = MODULE.policy_commands([], previous)
        self.assertIn(
            "no neighbor 172.31.0.11 route-map DA-IN-172-31-0-11 in",
            commands,
        )
        self.assertIn(
            "neighbor 172.31.0.11 route-map RPKI-IN in", commands
        )
        self.assertIn("no route-map DA-IN-172-31-0-11", commands)
        self.assertIn("no route-map DA-IN-1", commands)


if __name__ == "__main__":
    unittest.main()
