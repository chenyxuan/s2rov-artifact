from __future__ import annotations

from dataclasses import FrozenInstanceError
import sys
import unittest
from pathlib import Path


HERE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE_DIR / "scripts"))

from utils.s2rov import S2ROV, Stripe, ValidationState  # noqa: E402
from utils.snapshot import (  # noqa: E402
    PolicyEnvelope,
    PolicySnapshot,
    SnapshotError,
    SnapshotStore,
)


NOW = 2_000_000_000


def policy(base: str, max_length: int, holder: int, base_marker: bool) -> S2ROV:
    return S2ROV(
        base,
        max_length,
        holder,
        [Stripe(base, {holder}, base_marker)],
    )


def envelope(
    object_id: str,
    value: S2ROV,
    *,
    issuer: str = "ta.example",
    serial: int = 1,
    not_before: int = NOW - 100,
    not_after: int = NOW + 100,
    revoked: bool = False,
) -> PolicyEnvelope:
    return PolicyEnvelope(
        issuer=issuer,
        object_id=object_id,
        profile_version=2,
        object_serial=serial,
        not_before=not_before,
        not_after=not_after,
        revoked=revoked,
        policy=value,
    )


class SnapshotCompositionTests(unittest.TestCase):
    def test_order_independent_bytes_and_decisions(self) -> None:
        broad = envelope("broad", policy("10.0.0.0/8", 24, 15169, True))
        nested = envelope("nested", policy("10.1.0.0/16", 24, 16509, False))
        first = PolicySnapshot(7, NOW, [broad, nested])
        second = PolicySnapshot(7, NOW, [nested, broad])
        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())
        self.assertEqual(
            first.validate_route("10.2.0.0/24", 13335),
            ValidationState.DELEGATED,
        )
        self.assertEqual(
            first.validate_route("10.1.1.0/24", 13335),
            ValidationState.INVALID,
        )

    def test_same_base_conflict_is_rejected(self) -> None:
        left = envelope("left", policy("10.0.0.0/8", 24, 15169, True))
        right = envelope("right", policy("10.0.0.0/8", 24, 16509, False))
        with self.assertRaisesRegex(SnapshotError, "share base"):
            PolicySnapshot(1, NOW, [left, right])

    def test_identical_duplicate_envelope_is_deduplicated(self) -> None:
        item = envelope("one", policy("10.0.0.0/8", 24, 15169, True))
        snapshot = PolicySnapshot(1, NOW, [item, item])
        self.assertEqual(len(snapshot.envelopes), 1)

    def test_dual_stack_composition_selects_only_the_matching_family(self) -> None:
        ipv4 = envelope("ipv4", policy("10.0.0.0/8", 24, 15169, True))
        ipv6_broad = envelope(
            "ipv6-broad",
            policy("2001:db8::/32", 64, 16509, True),
        )
        ipv6_nested = envelope(
            "ipv6-nested",
            policy("2001:db8:1::/48", 64, 18403, False),
        )
        first = PolicySnapshot(7, NOW, [ipv4, ipv6_broad, ipv6_nested])
        second = PolicySnapshot(7, NOW, [ipv6_nested, ipv4, ipv6_broad])

        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())
        cases = [
            ("10.2.0.0/24", 13335, ValidationState.DELEGATED),
            ("2001:db8:2::/48", 13335, ValidationState.DELEGATED),
            ("2001:db8:1:1::/64", 13335, ValidationState.INVALID),
            ("2001:db9::/32", 13335, ValidationState.NOT_FOUND),
        ]
        for prefix, asn, expected in cases:
            self.assertEqual(first.validate_route(prefix, asn), expected)


class SnapshotLifecycleTests(unittest.TestCase):
    def test_applied_policy_cannot_change_without_a_new_snapshot(self) -> None:
        value = policy("10.0.0.0/8", 24, 15169, True)
        snapshot = PolicySnapshot(1, NOW, [envelope("one", value)])
        digest = snapshot.sha256()
        store = SnapshotStore()
        store.apply(snapshot)

        with self.assertRaises(FrozenInstanceError):
            value.stripes[0].is_open = False
        with self.assertRaises(AttributeError):
            value.stripes[0].as_set.add(13335)
        with self.assertRaises(AttributeError):
            value.stripes.reverse()

        self.assertEqual(snapshot.sha256(), digest)
        self.assertEqual(
            store.validate_route("10.2.0.0/24", 13335),
            ValidationState.DELEGATED,
        )

    def test_expired_future_and_revoked_objects_cannot_upgrade(self) -> None:
        value = policy("10.0.0.0/8", 24, 15169, True)
        inactive = (
            envelope("expired", value, not_before=NOW - 200, not_after=NOW - 1),
            envelope("future", value, not_before=NOW + 1, not_after=NOW + 200),
            envelope("revoked", value, revoked=True),
        )
        for item in inactive:
            snapshot = PolicySnapshot(1, NOW, [item])
            self.assertEqual(
                snapshot.validate_route("10.2.0.0/24", 13335),
                ValidationState.NOT_FOUND,
            )

    def test_monotone_store_withdrawal_and_replay_rules(self) -> None:
        active = envelope("one", policy("10.0.0.0/8", 24, 15169, True))
        initial = PolicySnapshot(10, NOW, [active])
        withdrawn = PolicySnapshot(11, NOW + 1, [])
        store = SnapshotStore()
        self.assertTrue(store.apply(initial))
        self.assertFalse(store.apply(initial))
        self.assertEqual(
            store.validate_route("10.2.0.0/24", 13335),
            ValidationState.DELEGATED,
        )
        self.assertTrue(store.apply(withdrawn))
        self.assertEqual(
            store.validate_route("10.2.0.0/24", 13335),
            ValidationState.NOT_FOUND,
        )
        with self.assertRaisesRegex(SnapshotError, "rollback"):
            store.apply(initial)

    def test_same_serial_content_collision_is_rejected(self) -> None:
        left = PolicySnapshot(
            5,
            NOW,
            [envelope("left", policy("10.0.0.0/8", 24, 15169, True))],
        )
        right = PolicySnapshot(
            5,
            NOW,
            [envelope("right", policy("10.0.0.0/8", 24, 16509, True))],
        )
        store = SnapshotStore()
        store.apply(left)
        with self.assertRaisesRegex(SnapshotError, "different content"):
            store.apply(right)

    def test_unsupported_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(SnapshotError, "unsupported"):
            PolicyEnvelope(
                issuer="ta.example",
                object_id="one",
                profile_version=1,
                object_serial=1,
                not_before=NOW - 1,
                not_after=NOW + 1,
                revoked=False,
                policy=policy("10.0.0.0/8", 24, 15169, True),
            )


if __name__ == "__main__":
    unittest.main()
