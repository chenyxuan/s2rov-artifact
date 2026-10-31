from __future__ import annotations

from dataclasses import FrozenInstanceError
import sys
import unittest
from pathlib import Path


HERE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE_DIR / "scripts"))

from utils.as_set import AsSetType, decode, encode  # noqa: E402
from utils.daroa import (  # noqa: E402
    DAROA,
    Stripe,
    ValidationState,
    is_eligible_delegated_origin,
)
from utils.flatten import flatten_to_vrps, flattening_validation  # noqa: E402
from utils.merge import merge_stripes  # noqa: E402


def example_policy() -> DAROA:
    return DAROA(
        "10.0.0.0/16",
        24,
        64501,
        [
            Stripe("10.0.0.0/16", {64501}, True),
            Stripe("10.0.1.0/24", {64502}),
        ],
    )


def example_ipv6_policy() -> DAROA:
    return DAROA(
        "2001:db8::/32",
        128,
        15169,
        [
            Stripe("2001:db8::/32", {15169}, True),
            Stripe("2001:db8:1::/48", {18403}),
            Stripe("2001:db8:2::/48", {16509}),
            Stripe("2001:db8:2:1::/64", {13335}),
            Stripe("2001:db8:2:1::1/128", {8075}),
        ],
    )


class SemanticsTests(unittest.TestCase):
    def test_delegation_eligibility_boundaries(self) -> None:
        for asn in (
            0,
            23456,
            64496,
            64513,
            65535,
            65536,
            131071,
            4200000000,
            4294967295,
            0x100000000,
        ):
            self.assertFalse(is_eligible_delegated_origin(asn), asn)
        for asn in (1, 15169, 131072, 4199999999):
            self.assertTrue(is_eligible_delegated_origin(asn), asn)

    def test_four_state_cases(self) -> None:
        policy = example_policy()
        cases = [
            ("10.0.0.0/16", 64501, ValidationState.EXPLICIT),
            ("10.0.0.0/16", 64502, ValidationState.INVALID),
            ("10.0.1.0/24", 64502, ValidationState.EXPLICIT),
            ("10.0.1.0/24", 15169, ValidationState.OPEN_SCOPE),
            ("10.0.2.0/24", 18403, ValidationState.OPEN_SCOPE),
            ("10.0.2.0/24", 15169, ValidationState.OPEN_SCOPE),
            ("10.0.2.0/24", 64501, ValidationState.EXPLICIT),
            ("10.0.2.0/24", 64513, ValidationState.INVALID),
            ("192.0.2.0/24", 64501, ValidationState.NOT_FOUND),
        ]
        decoded = DAROA.deserialize(policy.serialize())
        for prefix, asn, expected in cases:
            self.assertEqual(policy.validate_route(prefix, asn), expected)
            self.assertEqual(decoded.validate_route(prefix, asn), expected)

    def test_too_specific_is_invalid(self) -> None:
        policy = example_policy()
        for origin in (64501, 15169):
            self.assertEqual(
                policy.validate_route("10.0.2.0/25", origin),
                ValidationState.INVALID,
            )

    def test_unmarked_empty_record_does_not_cancel_marker(self) -> None:
        policy = DAROA(
            "10.0.0.0/16",
            24,
            64501,
            [
                Stripe("10.0.0.0/16", {64501}, True),
                Stripe("10.0.2.0/24", set()),
            ],
        )
        self.assertEqual(
            policy.validate_route("10.0.2.0/24", 15169),
            ValidationState.OPEN_SCOPE,
        )
        self.assertEqual(
            policy.validate_route("10.0.2.0/24", 64501),
            ValidationState.EXPLICIT,
        )

    def test_base_max_length_and_nonbase_exact_match(self) -> None:
        policy = DAROA(
            "10.0.0.0/16",
            24,
            15169,
            [
                Stripe("10.0.0.0/16", {15169}, True),
                Stripe("10.0.16.0/20", {18403}),
                Stripe("10.0.17.0/24", {16509}),
            ],
        )
        decoded = DAROA.deserialize(policy.serialize())
        cases = [
            ("10.0.16.0/20", 18403, ValidationState.EXPLICIT),
            ("10.0.16.0/20", 16509, ValidationState.OPEN_SCOPE),
            ("10.0.17.0/24", 15169, ValidationState.EXPLICIT),
            # The non-base /20 is an exact ROA and does not authorize /24s.
            ("10.0.17.0/24", 18403, ValidationState.OPEN_SCOPE),
            ("10.0.17.0/24", 16509, ValidationState.EXPLICIT),
            ("10.0.17.0/24", 13335, ValidationState.OPEN_SCOPE),
        ]
        for prefix, asn, expected in cases:
            self.assertEqual(policy.validate_route(prefix, asn), expected)
            self.assertEqual(decoded.validate_route(prefix, asn), expected)

    def test_ipv6_records_and_address_family_scope(self) -> None:
        policy = example_ipv6_policy()
        decoded = DAROA.deserialize(policy.serialize())
        cases = [
            ("2001:db8::/32", 15169, ValidationState.EXPLICIT),
            ("2001:db8::/32", 16509, ValidationState.INVALID),
            ("2001:db8:3::/48", 16509, ValidationState.OPEN_SCOPE),
            ("2001:db8:1::/48", 18403, ValidationState.EXPLICIT),
            # A non-base /48 record is exact and cannot match a /64.
            ("2001:db8:1:1::/64", 18403, ValidationState.OPEN_SCOPE),
            ("2001:db8:1:1::/64", 16509, ValidationState.OPEN_SCOPE),
            ("2001:db8:2::/48", 13335, ValidationState.OPEN_SCOPE),
            ("2001:db8:2:2::/64", 13335, ValidationState.OPEN_SCOPE),
            ("2001:db8:2:1::/64", 13335, ValidationState.EXPLICIT),
            ("2001:db8:2:1::2/128", 16509, ValidationState.OPEN_SCOPE),
            ("2001:db8:2:1::1/128", 8075, ValidationState.EXPLICIT),
            # The base origin is carried through the policy maxLength.
            ("2001:db8:2:1::1/128", 15169, ValidationState.EXPLICIT),
            ("2001:db9::/32", 15169, ValidationState.NOT_FOUND),
            ("192.0.2.0/24", 15169, ValidationState.NOT_FOUND),
        ]
        for prefix, asn, expected in cases:
            self.assertEqual(policy.validate_route(prefix, asn), expected)
            self.assertEqual(decoded.validate_route(prefix, asn), expected)


class StructureTests(unittest.TestCase):
    def test_boolean_length_and_malformed_route_inputs_are_rejected(self) -> None:
        with self.assertRaisesRegex(TypeError, "max_length"):
            DAROA(
                "0.0.0.0/0",
                True,
                15169,
                [Stripe("0.0.0.0/0", {15169}, True)],
            )
        policy = example_policy()
        for origin in (True, 0, 0x100000000):
            with self.assertRaises((TypeError, ValueError)):
                policy.validate_route("10.0.2.0/24", origin)
        with self.assertRaises(ValueError):
            policy.validate_route("10.0.2.7/24", 15169)

    def test_as_set_decoder_rejects_noncanonical_order(self) -> None:
        payload = b"\x02\x00\x00\x00\x02\x00\x00\x00\x01"
        with self.assertRaisesRegex(ValueError, "increasing"):
            decode(AsSetType.LIST, payload)

    def test_constructor_serialization_is_order_independent(self) -> None:
        base = Stripe("10.0.0.0/16", {64501}, True)
        child = Stripe("10.0.1.0/24", {64502})
        self.assertFalse(child.has_openscope_marker)
        forward = DAROA("10.0.0.0/16", 24, 64501, [base, child])
        reverse = DAROA("10.0.0.0/16", 24, 64501, [child, base])
        self.assertEqual(forward.serialize(), reverse.serialize())

    def test_classification_is_independent_of_record_order_and_lpm(self) -> None:
        records = [
            Stripe("10.0.0.0/16", {15169}, True),
            Stripe("10.0.16.0/20", {18403}, False),
            Stripe("10.0.17.0/24", {16509}, False),
        ]
        forward = DAROA("10.0.0.0/16", 24, 15169, records)
        reverse = DAROA("10.0.0.0/16", 24, 15169, reversed(records))
        cases = (
            (18403, ValidationState.OPEN_SCOPE),
            (16509, ValidationState.EXPLICIT),
            (13335, ValidationState.OPEN_SCOPE),
        )
        for origin, expected in cases:
            self.assertEqual(
                forward.validate_route("10.0.17.0/24", origin), expected
            )
            self.assertEqual(
                reverse.validate_route("10.0.17.0/24", origin), expected
            )

    def test_overlapping_openscope_markers_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "prefix-disjoint"):
            DAROA(
                "10.0.0.0/16",
                24,
                15169,
                [
                    Stripe("10.0.0.0/16", {15169}, True),
                    Stripe("10.0.16.0/20", set(), True),
                ],
            )

        policy = DAROA(
            "10.0.0.0/16",
            24,
            15169,
            [
                Stripe("10.0.0.0/16", {15169}, False),
                Stripe("10.0.16.0/20", set(), True),
                Stripe("10.0.32.0/20", set(), True),
            ],
        )
        self.assertEqual(
            policy.validate_route("10.0.16.0/20", 16509),
            ValidationState.INVALID,
        )
        self.assertEqual(
            policy.validate_route("10.0.17.0/24", 16509),
            ValidationState.OPEN_SCOPE,
        )

    def test_openscope_marker_at_max_length_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "proper descendants"):
            DAROA(
                "10.0.0.0/16",
                24,
                15169,
                [
                    Stripe("10.0.0.0/16", {15169}),
                    Stripe("10.0.1.0/24", set(), True),
                ],
            )

    def test_ipv4_wire_version_one_is_byte_compatible(self) -> None:
        self.assertEqual(
            example_policy().serialize().hex(),
            "0a00000010180000fbf501000200180a000102010000fbf6"
            "100a0003010000fbf5",
        )

    def test_dual_stack_prefix_length_boundaries_round_trip(self) -> None:
        ipv4 = DAROA(
            "0.0.0.0/0",
            32,
            15169,
            [
                Stripe("0.0.0.0/0", {15169}, True),
                Stripe("255.255.255.255/32", {16509}, False),
            ],
        )
        ipv6 = DAROA(
            "::/0",
            128,
            15169,
            [
                Stripe("::/0", {15169}, True),
                Stripe("2001:db8::/32", {16509}, False),
                Stripe("2001:db8:1::/48", {18403}, False),
                Stripe("2001:db8:1:2::/64", {13335}, False),
                Stripe("2001:db8:1:2::1/128", {8075}, False),
            ],
        )

        self.assertEqual(ipv4.serialize()[10], 1)
        self.assertEqual(ipv6.serialize()[0:4], b"IPv6")
        self.assertEqual(ipv6.serialize()[10], 2)
        self.assertEqual(
            [stripe.prefix_length for stripe in ipv6.stripes],
            [128, 64, 48, 32, 0],
        )
        for policy in (ipv4, ipv6):
            payload = policy.serialize()
            decoded = DAROA.deserialize(payload)
            self.assertEqual(decoded, policy)
            self.assertEqual(decoded.serialize(), payload)

    def test_ipv6_constructor_canonicalizes_host_bits_and_text(self) -> None:
        policy = DAROA(
            "2001:0DB8:ffff::1/32",
            64,
            15169,
            [
                Stripe("2001:0DB8:ffff::1/32", {15169}, True),
                Stripe("2001:0DB8:0001:0002::abcd/64", {16509}, False),
            ],
        )
        self.assertEqual(policy.base_prefix, "2001:db8::/32")
        self.assertEqual(
            [stripe.prefix for stripe in policy.stripes],
            ["2001:db8:1:2::/64", "2001:db8::/32"],
        )
        self.assertEqual(DAROA.deserialize(policy.serialize()), policy)

    def test_ipv6_max_length_boundaries(self) -> None:
        policy = DAROA(
            "2001:db8::/32",
            64,
            15169,
            [Stripe("2001:db8::/32", {15169}, True)],
        )
        self.assertEqual(
            policy.validate_route("2001:db8:1::/64", 16509),
            ValidationState.OPEN_SCOPE,
        )
        self.assertEqual(
            policy.validate_route("2001:db8:1::/65", 16509),
            ValidationState.INVALID,
        )
        for max_length in (31, 129):
            with self.assertRaisesRegex(ValueError, "max_length"):
                DAROA(
                    "2001:db8::/32",
                    max_length,
                    15169,
                    [Stripe("2001:db8::/32", {15169}, True)],
                )
        with self.assertRaisesRegex(ValueError, "exceeds"):
            DAROA(
                "2001:db8::/32",
                64,
                15169,
                [
                    Stripe("2001:db8::/32", {15169}, True),
                    Stripe("2001:db8::/65", {16509}, False),
                ],
            )

    def test_mixed_address_families_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "address families"):
            DAROA(
                "0.0.0.0/0",
                32,
                15169,
                [
                    Stripe("0.0.0.0/0", {15169}, True),
                    Stripe("::/0", {16509}, False),
                ],
            )

    def test_policy_is_immutable_and_defensively_copies_inputs(self) -> None:
        origins = {64501}
        stripes = [
            Stripe("10.0.0.0/16", origins, True),
            Stripe("10.0.1.0/24", {64502}, False),
        ]
        policy = DAROA("10.0.0.0/16", 24, 64501, stripes)
        canonical = policy.serialize()

        origins.add(64503)
        stripes.reverse()
        self.assertEqual(policy.serialize(), canonical)
        self.assertEqual(DAROA.deserialize(canonical).serialize(), canonical)

        with self.assertRaises(FrozenInstanceError):
            policy.max_length = 32
        with self.assertRaises(FrozenInstanceError):
            policy.stripes[0].is_open = True
        with self.assertRaises(AttributeError):
            policy.stripes.reverse()
        with self.assertRaises(AttributeError):
            policy.stripes[0].as_set.add(64503)

        extended = policy.add_stripe(Stripe("10.0.2.0/24", {64503}, False))
        self.assertEqual(len(policy.stripes), 2)
        self.assertEqual(len(extended.stripes), 3)
        self.assertEqual(DAROA.deserialize(extended.serialize()), extended)

    def test_deserializer_rejects_noncanonical_stripe_order(self) -> None:
        policy = example_policy()
        canonical = policy.serialize()
        header = canonical[:14]
        child = policy.stripes[0].serialize()
        base = policy.stripes[1].serialize()
        self.assertEqual(
            [stripe.prefix for stripe in policy.stripes],
            ["10.0.1.0/24", "10.0.0.0/16"],
        )
        with self.assertRaisesRegex(ValueError, "order"):
            DAROA.deserialize(header + base + child)

    def test_missing_base_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "base Stripe"):
            DAROA("10.0.0.0/16", 24, 64501, [])

    def test_duplicate_prefix_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate"):
            DAROA(
                "10.0.0.0/16",
                24,
                64501,
                [
                    Stripe("10.0.0.0/16", {64501}, True),
                    Stripe("10.0.0.0/16", {64502}, False),
                ],
            )

    def test_outside_and_overlong_stripes_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside"):
            DAROA(
                "10.0.0.0/16",
                24,
                64501,
                [
                    Stripe("10.0.0.0/16", {64501}, True),
                    Stripe("10.1.0.0/24", {64502}, False),
                ],
            )
        with self.assertRaisesRegex(ValueError, "exceeds"):
            DAROA(
                "10.0.0.0/16",
                23,
                64501,
                [
                    Stripe("10.0.0.0/16", {64501}, True),
                    Stripe("10.0.1.0/24", {64502}, False),
                ],
            )

    def test_explicit_set_count_bound(self) -> None:
        with self.assertRaisesRegex(ValueError, "maximum"):
            encode(set(range(1, 257)))

    def test_deserializer_rejects_header_corruption(self) -> None:
        payload = bytearray(example_policy().serialize())
        for index, value, message in (
            (10, 2, "version"),
            (13, 1, "flags"),
            (2, 1, "non-canonical"),
        ):
            corrupted = bytearray(payload)
            corrupted[index] = value
            with self.assertRaisesRegex(ValueError, message):
                DAROA.deserialize(bytes(corrupted))

    def test_ipv6_deserializer_rejects_noncanonical_and_malformed_wire(self) -> None:
        policy = DAROA(
            "2001:db8::/32",
            64,
            15169,
            [
                Stripe("2001:db8::/32", {15169}, True),
                Stripe("2001:db8:8000::/49", {16509}, False),
            ],
        )
        payload = bytearray(policy.serialize())

        noncanonical_base = bytearray(payload)
        noncanonical_base[18] = 1
        with self.assertRaisesRegex(ValueError, "non-canonical base"):
            DAROA.deserialize(bytes(noncanonical_base))

        # The /49 child is first. Its seventh prefix byte has one network bit,
        # so setting the low bit produces a noncanonical wire prefix.
        noncanonical_stripe = bytearray(payload)
        noncanonical_stripe[37] |= 0x01
        with self.assertRaisesRegex(ValueError, "non-canonical Stripe"):
            DAROA.deserialize(bytes(noncanonical_stripe))

        bad_tag = bytearray(payload)
        bad_tag[0] ^= 0x01
        with self.assertRaisesRegex(ValueError, "version or header tag"):
            DAROA.deserialize(bytes(bad_tag))

        with self.assertRaisesRegex(ValueError, "truncated IPv6"):
            DAROA.deserialize(bytes(payload[:29]))

        header = bytes(payload[:30])
        child = policy.stripes[0].serialize()
        base = policy.stripes[1].serialize()
        with self.assertRaisesRegex(ValueError, "order"):
            DAROA.deserialize(header + base + child)

        overlong_prefix = bytearray(payload)
        overlong_prefix[30] = 129
        with self.assertRaisesRegex(ValueError, "IPv6 Stripe prefix length"):
            DAROA.deserialize(bytes(overlong_prefix))

    def test_deserializer_rejects_truncation_and_trailing_bytes(self) -> None:
        payload = example_policy().serialize()
        for cut in (0, 13, len(payload) - 1):
            with self.assertRaises(ValueError):
                DAROA.deserialize(payload[:cut])
        with self.assertRaisesRegex(ValueError, "trailing"):
            DAROA.deserialize(payload + b"\x00")


class LookupBoundTests(unittest.TestCase):
    def test_probe_bound_is_independent_of_stripe_count(self) -> None:
        class CountingIndex(dict[tuple[int, int], Stripe]):
            def __init__(self, entries: dict[tuple[int, int], Stripe]) -> None:
                super().__init__(entries)
                self.probes = 0

            def get(  # type: ignore[override]
                self,
                key: tuple[int, int],
                default: Stripe | None = None,
            ) -> Stripe | None:
                self.probes += 1
                return super().get(key, default)

        customer_stripes = [
            Stripe(
                f"10.{index // 256}.{index % 256}.0/24",
                {100_000 + index},
                False,
            )
            for index in range(4_096)
        ]
        policies = (
            DAROA(
                "0.0.0.0/0",
                32,
                64_501,
                [Stripe("0.0.0.0/0", {64_501}, True)],
            ),
            DAROA(
                "0.0.0.0/0",
                32,
                64_501,
                [Stripe("0.0.0.0/0", {64_501}, True), *customer_stripes],
            ),
        )

        self.assertEqual([len(policy.stripes) for policy in policies], [1, 4_097])
        for policy in policies:
            index = CountingIndex(policy._stripe_index)
            object.__setattr__(policy, "_stripe_index", index)
            self.assertEqual(
                policy.validate_route("203.0.113.1/32", 15_169),
                ValidationState.OPEN_SCOPE,
            )
            self.assertEqual(index.probes, 33)

    def test_ipv6_probe_bound_is_independent_of_stripe_count(self) -> None:
        class CountingIndex(dict[tuple[int, int], Stripe]):
            def __init__(self, entries: dict[tuple[int, int], Stripe]) -> None:
                super().__init__(entries)
                self.probes = 0

            def get(  # type: ignore[override]
                self,
                key: tuple[int, int],
                default: Stripe | None = None,
            ) -> Stripe | None:
                self.probes += 1
                return super().get(key, default)

        customer_stripes = [
            Stripe(f"2001:db8:{index:x}::/48", {100_000 + index}, False)
            for index in range(4_096)
        ]
        policies = (
            DAROA(
                "::/0",
                128,
                15169,
                [Stripe("::/0", {15169}, True)],
            ),
            DAROA(
                "::/0",
                128,
                15169,
                [Stripe("::/0", {15169}, True), *customer_stripes],
            ),
        )

        self.assertEqual([len(policy.stripes) for policy in policies], [1, 4_097])
        for policy in policies:
            index = CountingIndex(policy._stripe_index)
            object.__setattr__(policy, "_stripe_index", index)
            self.assertEqual(
                policy.validate_route("2001:db9::1/128", 16509),
                ValidationState.OPEN_SCOPE,
            )
            self.assertEqual(index.probes, 129)


class ProjectionAndMergeTests(unittest.TestCase):
    def test_all_base_origins_use_policy_max_length(self) -> None:
        policy = DAROA(
            "10.0.0.0/16",
            24,
            15169,
            [Stripe("10.0.0.0/16", {15169, 16509}, True)],
        )
        self.assertEqual(
            flatten_to_vrps(policy),
            [
                ("10.0.0.0/16", 15169, 24),
                ("10.0.0.0/16", 16509, 24),
            ],
        )
        self.assertTrue(flattening_validation(policy))
        self.assertEqual(
            policy.validate_route("10.0.255.0/24", 16509),
            ValidationState.EXPLICIT,
        )

    def test_projection_contains_only_explicit_outcomes(self) -> None:
        policy = example_policy()
        self.assertTrue(flattening_validation(policy))
        self.assertEqual(
            flatten_to_vrps(policy),
            [
                ("10.0.0.0/16", 64501, 24),
                ("10.0.1.0/24", 64502, 24),
            ],
        )

    def test_ipv6_projection_contains_only_explicit_outcomes(self) -> None:
        policy = example_ipv6_policy()
        self.assertTrue(flattening_validation(policy))
        self.assertEqual(
            flatten_to_vrps(policy),
            [
                ("2001:db8::/32", 15169, 128),
                ("2001:db8:2:1::1/128", 8075, 128),
                ("2001:db8:2:1::/64", 13335, 64),
                ("2001:db8:1::/48", 18403, 48),
                ("2001:db8:2::/48", 16509, 48),
            ],
        )

    def test_merge_preserves_exact_record_prefixes(self) -> None:
        stripes = [
            Stripe(f"10.0.{index}.0/24", {64501}, False)
            for index in range(4)
        ]
        stripes += [
            Stripe(f"10.0.{index}.0/24", {64501}, True)
            for index in range(4, 8)
        ]
        merged = merge_stripes(stripes)
        self.assertEqual(
            [(stripe.prefix, stripe.is_open) for stripe in merged],
            [
                ("10.0.0.0/24", False),
                ("10.0.1.0/24", False),
                ("10.0.2.0/24", False),
                ("10.0.3.0/24", False),
                ("10.0.4.0/24", True),
                ("10.0.5.0/24", True),
                ("10.0.6.0/24", True),
                ("10.0.7.0/24", True),
            ],
        )

    def test_merge_keeps_ipv4_and_ipv6_exact_records(self) -> None:
        merged = merge_stripes(
            [
                Stripe("192.0.2.0/25", {15169}, False),
                Stripe("192.0.2.128/25", {15169}, False),
                Stripe("2001:db8::/65", {15169}, False),
                Stripe("2001:db8:0:0:8000::/65", {15169}, False),
            ]
        )
        self.assertEqual(
            [stripe.prefix for stripe in merged],
            [
                "192.0.2.0/25",
                "192.0.2.128/25",
                "2001:db8::/65",
                "2001:db8:0:0:8000::/65",
            ],
        )

    def test_merge_uses_policy_canonical_prefix_order(self) -> None:
        merged = merge_stripes(
            [
                Stripe("10.0.0.0/16", {15169}),
                Stripe("10.0.1.0/24", {16509}),
                Stripe("10.0.0.0/20", {18403}),
            ]
        )
        self.assertEqual(
            [stripe.prefix for stripe in merged],
            ["10.0.1.0/24", "10.0.0.0/20", "10.0.0.0/16"],
        )


if __name__ == "__main__":
    unittest.main()
