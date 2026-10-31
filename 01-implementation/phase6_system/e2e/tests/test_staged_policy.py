import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
SPEC = importlib.util.spec_from_file_location(
    "staged_policy", ROOT / "src" / "staged_policy.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

SUMMARY_SPEC = importlib.util.spec_from_file_location(
    "summarize_staged", ROOT / "src" / "summarize_staged.py"
)
SUMMARY = importlib.util.module_from_spec(SUMMARY_SPEC)
assert SUMMARY_SPEC.loader is not None
SUMMARY_SPEC.loader.exec_module(SUMMARY)


class StagedPolicyTest(unittest.TestCase):
    def test_staged_nearest_rank(self):
        self.assertEqual(SUMMARY.nearest_rank(list(range(1, 31)), 0.95), 29)

    def test_received_routes_and_origin(self):
        document = {
            "receivedRoutes": {
                "10.0.2.0/24": {"path": "65001 18403"},
                "192.0.2.0/24": {"path": "65001 64496"},
            }
        }
        records = MODULE.received_records(document, "172.30.0.11")
        self.assertEqual(
            {(item["prefix"], item["origin"]) for item in records},
            {("10.0.2.0/24", 18403), ("192.0.2.0/24", 64496)},
        )

    def test_compiler_matches_prefix_and_origin(self):
        results = [
            {
                "peer": "172.30.0.21",
                "prefix": "10.0.0.0/16",
                "origin": 64501,
                "state": "Explicit",
            },
            {
                "peer": "172.30.0.21",
                "prefix": "10.0.0.0/16",
                "origin": 13335,
                "state": "Invalid",
            },
        ]
        commands = MODULE.policy_commands(results, 65001)
        self.assertIn("router bgp 65001", commands)
        self.assertIn("permit _64501$", commands)
        self.assertIn("permit _13335$", commands)
        self.assertIn("route-map STG-IN-172-30-0-21 deny 20", commands)
        self.assertIn("neighbor 172.30.0.21 route-map STG-IN-172-30-0-21 in", commands)

    def test_empty_managed_peer_replaces_stale_map_with_default_deny(self):
        commands = MODULE.policy_commands([], 65001, ["172.30.0.21"])
        self.assertIn("no route-map STG-IN-172-30-0-21", commands)
        self.assertIn("route-map STG-IN-172-30-0-21 deny 9990", commands)
        self.assertIn(
            "neighbor 172.30.0.21 route-map STG-IN-172-30-0-21 in",
            commands,
        )

    def test_ipv6_compiler_uses_ipv6_address_family(self):
        results = [
            {
                "peer": "fd30:61::11",
                "prefix": "2001:db8:10::/48",
                "origin": 18403,
                "state": "Delegated",
            }
        ]
        commands = MODULE.policy_commands(
            results,
            65000,
            ["fd30:61::11"],
            "ipv6",
        )
        self.assertIn(
            "ipv6 prefix-list STG-P-fd30-61--11-1 seq 5 permit "
            "2001:db8:10::/48",
            commands,
        )
        self.assertIn(
            "match ipv6 address prefix-list STG-P-fd30-61--11-1", commands
        )
        self.assertIn("address-family ipv6 unicast", commands)
        self.assertIn(
            "neighbor fd30:61::11 route-map STG-IN-fd30-61--11 in", commands
        )

    def test_ipv6_received_route_is_preserved(self):
        document = {
            "receivedRoutes": {
                "2001:db8:10::/48": {"path": "65001 18403"},
            }
        }
        records = MODULE.received_records(document, "fd30:61::11")
        self.assertEqual(
            [(item["prefix"], item["origin"]) for item in records],
            [("2001:db8:10::/48", 18403)],
        )

    def test_three_hop_expected_boundary(self):
        cases = [
            {
                "prefix": "10.0.2.0/24",
                "origin": 18403,
                "expected_baseline": "Invalid",
                "expected_da": "Delegated",
            },
            {
                "prefix": "10.0.0.0/16",
                "origin": 64501,
                "expected_baseline": "Valid",
                "expected_da": "Explicit",
            },
        ]
        mixed, _ = SUMMARY.expected_sets(cases, "DLD")
        full, _ = SUMMARY.expected_sets(cases, "DDD")
        self.assertNotIn(("10.0.2.0/24", 18403), mixed["sink"])
        self.assertIn(("10.0.2.0/24", 18403), full["sink"])
        self.assertIn(("10.0.0.0/16", 64501), mixed["sink"])


if __name__ == "__main__":
    unittest.main()
