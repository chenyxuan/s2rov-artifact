import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from daroa_policy_dualstack import Policy  # noqa: E402


class DualStackPolicyTest(unittest.TestCase):
    def test_ipv6_marker_and_unmarked_exact_entry(self):
        policy = Policy.from_routinator(
            {
                "roas": [
                    {
                        "asn": "AS64501",
                        "prefix": "2001:db8::/32",
                        "minLength": 32,
                        "maxLength": 48,
                        "inclusivity": "inclusive",
                        "ta": "lab",
                    },
                    {
                        "asn": "AS8075",
                        "prefix": "2001:db8:1::/48",
                        "minLength": 48,
                        "maxLength": 48,
                        "inclusivity": None,
                        "ta": "lab",
                    },
                ]
            }
        )
        state, stripe = policy.validate("2001:db8:10::/48", 18403)
        self.assertEqual(state, "Delegated")
        self.assertEqual(str(stripe.network), "2001:db8::/32")
        state, stripe = policy.validate("2001:db8:1::/48", 18403)
        self.assertEqual(state, "Delegated")
        self.assertEqual(str(stripe.network), "2001:db8::/32")
        state, stripe = policy.validate("2001:db8:1::/48", 8075)
        self.assertEqual(state, "Explicit")
        self.assertEqual(str(stripe.network), "2001:db8:1::/48")
        state, stripe = policy.validate("2001:db8:1::/48", 64501)
        self.assertEqual(state, "Explicit")
        self.assertEqual(str(stripe.network), "2001:db8::/32")

    def test_ipv6_overlapping_markers_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "pairwise prefix-disjoint"):
            Policy.from_routinator(
                {
                    "roas": [
                        {
                            "asn": "AS64501",
                            "prefix": "2001:db8::/32",
                            "minLength": 32,
                            "maxLength": 48,
                            "inclusivity": "inclusive",
                        },
                        {
                            "asn": "AS64502",
                            "prefix": "2001:db8:1::/48",
                            "minLength": 48,
                            "maxLength": 49,
                            "inclusivity": "inclusive",
                        },
                    ]
                }
            )

    def test_invalid_ipv6_marker_length_intervals_are_rejected(self):
        for min_length, max_length in ((40, 48), (32, 32)):
            with self.subTest(min_length=min_length, max_length=max_length):
                with self.assertRaisesRegex(
                    ValueError, "OpenScope marker requires minLength"
                ):
                    Policy.from_routinator(
                        {
                            "roas": [
                                {
                                    "asn": "AS64501",
                                    "prefix": "2001:db8::/32",
                                    "minLength": min_length,
                                    "maxLength": max_length,
                                    "inclusivity": "inclusive",
                                }
                            ]
                        }
                    )

    def test_exclusive_compatibility_alias_is_unmarked(self):
        policy = Policy.from_routinator(
            {
                "roas": [
                    {
                        "asn": "AS64501",
                        "prefix": "2001:db8::/32",
                        "minLength": 32,
                        "maxLength": 48,
                        "inclusivity": "exclusive",
                    }
                ]
            }
        )
        self.assertEqual(
            policy.validate("2001:db8:1::/48", 64501)[0], "Explicit"
        )
        self.assertEqual(
            policy.validate("2001:db8:1::/48", 18403)[0], "Invalid"
        )

    def test_mixed_address_families_do_not_cross_cover(self):
        policy = Policy.from_routinator(
            {
                "roas": [
                    {
                        "asn": "AS64501",
                        "prefix": "10.0.0.0/16",
                        "minLength": 16,
                        "maxLength": 24,
                        "inclusivity": None,
                    },
                    {
                        "asn": "AS64501",
                        "prefix": "2001:db8::/32",
                        "minLength": 32,
                        "maxLength": 48,
                        "inclusivity": None,
                    },
                ]
            }
        )
        self.assertEqual(
            policy.validate_baseline("10.0.1.0/24", 8075)[0], "Invalid"
        )
        self.assertEqual(
            policy.validate_baseline("2001:db8:10::/48", 18403)[0],
            "Invalid",
        )


if __name__ == "__main__":
    unittest.main()
