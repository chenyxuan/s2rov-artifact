from __future__ import annotations

import ast
from pathlib import Path
import unittest

from phase10_semantic_gate.frozen_v3.daroa import DAROA, Stripe, ValidationState
from phase10_semantic_gate.frozen_v3.snapshot import (
    PolicyEnvelope,
    PolicySnapshot,
    SnapshotError,
    SnapshotStore,
)
from phase10_semantic_gate import snapshot_oracle
from phase10_semantic_gate.snapshot_oracle import (
    SnapshotOracle,
    SnapshotOracleEnvelope,
    SnapshotOracleError,
    SnapshotOracleRule,
    SnapshotOracleState,
    SnapshotOracleStore,
)


NOW = 2_000_000_000
IMPLEMENTATION_STATE = {
    ValidationState.EXPLICIT: SnapshotOracleState.EXPLICIT,
    ValidationState.DELEGATED: SnapshotOracleState.OPEN_SCOPE,
    ValidationState.INVALID: SnapshotOracleState.INVALID,
    ValidationState.NOT_FOUND: SnapshotOracleState.NOT_FOUND,
}


def oracle_envelope(
    object_id: str,
    base_prefix: str,
    max_length: int,
    holder_asn: int,
    is_open: bool,
    *,
    issuer: str = "ta.example",
    profile_version: int = 1,
    object_serial: int = 1,
    not_before: int = NOW - 100,
    not_after: int = NOW + 100,
    revoked: bool = False,
) -> SnapshotOracleEnvelope:
    return SnapshotOracleEnvelope(
        issuer=issuer,
        object_id=object_id,
        profile_version=profile_version,
        object_serial=object_serial,
        not_before=not_before,
        not_after=not_after,
        revoked=revoked,
        base_prefix=base_prefix,
        max_length=max_length,
        holder_asn=holder_asn,
        rules=(SnapshotOracleRule(base_prefix, {holder_asn}, is_open),),
    )


def implementation_policy(
    base_prefix: str,
    max_length: int,
    holder_asn: int,
    is_open: bool,
) -> DAROA:
    return DAROA(
        base_prefix,
        max_length,
        holder_asn,
        [Stripe(base_prefix, {holder_asn}, is_open)],
    )


def implementation_envelope(
    object_id: str,
    base_prefix: str,
    max_length: int,
    holder_asn: int,
    is_open: bool,
    *,
    issuer: str = "ta.example",
    profile_version: int = 1,
    object_serial: int = 1,
    not_before: int = NOW - 100,
    not_after: int = NOW + 100,
    revoked: bool = False,
) -> PolicyEnvelope:
    return PolicyEnvelope(
        issuer=issuer,
        object_id=object_id,
        profile_version=profile_version,
        object_serial=object_serial,
        not_before=not_before,
        not_after=not_after,
        revoked=revoked,
        policy=implementation_policy(
            base_prefix,
            max_length,
            holder_asn,
            is_open,
        ),
    )


class SnapshotOracleIndependenceTests(unittest.TestCase):
    def test_oracle_imports_no_snapshot_or_daroa_implementation(self) -> None:
        source_path = Path(snapshot_oracle.__file__).resolve()
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported_modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.append(node.module)
        forbidden = {
            module
            for module in imported_modules
            if module == "snapshot"
            or module == "daroa"
            or module.endswith(".snapshot")
            or module.endswith(".daroa")
            or module.startswith("phase10_semantic_gate.frozen_v3")
        }
        self.assertEqual(forbidden, set())


class SnapshotOracleCompositionTests(unittest.TestCase):
    def test_most_specific_base_and_order_match_implementation(self) -> None:
        oracle_broad = oracle_envelope(
            "broad", "10.0.0.0/8", 24, 15169, True
        )
        oracle_nested = oracle_envelope(
            "nested", "10.1.0.0/16", 24, 16509, False
        )
        oracle_first = SnapshotOracle(7, NOW, [oracle_broad, oracle_nested])
        oracle_second = SnapshotOracle(7, NOW, [oracle_nested, oracle_broad])
        self.assertEqual(
            oracle_first.canonical_bytes(), oracle_second.canonical_bytes()
        )

        implementation = PolicySnapshot(
            7,
            NOW,
            [
                implementation_envelope(
                    "broad", "10.0.0.0/8", 24, 15169, True
                ),
                implementation_envelope(
                    "nested", "10.1.0.0/16", 24, 16509, False
                ),
            ],
        )
        for prefix, expected in (
            ("10.1.1.0/24", SnapshotOracleState.INVALID),
            ("10.2.0.0/24", SnapshotOracleState.OPEN_SCOPE),
        ):
            self.assertEqual(
                oracle_first.validate_route(prefix, 13335),
                expected,
            )
            self.assertEqual(
                IMPLEMENTATION_STATE[
                    implementation.validate_route(prefix, 13335)
                ],
                expected,
            )

    def test_same_base_conflict_is_rejected_by_both_paths(self) -> None:
        with self.assertRaisesRegex(SnapshotOracleError, "share base"):
            SnapshotOracle(
                8,
                NOW,
                [
                    oracle_envelope(
                        "left", "10.0.0.0/8", 24, 15169, True
                    ),
                    oracle_envelope(
                        "right", "10.0.0.0/8", 24, 16509, False
                    ),
                ],
            )
        with self.assertRaisesRegex(SnapshotError, "share base"):
            PolicySnapshot(
                8,
                NOW,
                [
                    implementation_envelope(
                        "left", "10.0.0.0/8", 24, 15169, True
                    ),
                    implementation_envelope(
                        "right", "10.0.0.0/8", 24, 16509, False
                    ),
                ],
            )

    def test_identity_duplicate_deduplicates_but_collision_rejects(self) -> None:
        oracle_item = oracle_envelope(
            "one", "10.0.0.0/8", 24, 15169, True
        )
        implementation_item = implementation_envelope(
            "one", "10.0.0.0/8", 24, 15169, True
        )
        self.assertEqual(
            len(SnapshotOracle(1, NOW, [oracle_item, oracle_item]).envelopes),
            1,
        )
        self.assertEqual(
            len(
                PolicySnapshot(
                    1, NOW, [implementation_item, implementation_item]
                ).envelopes
            ),
            1,
        )

        with self.assertRaisesRegex(SnapshotOracleError, "identity"):
            SnapshotOracle(
                1,
                NOW,
                [
                    oracle_item,
                    oracle_envelope(
                        "one",
                        "10.0.0.0/8",
                        24,
                        15169,
                        True,
                        object_serial=2,
                    ),
                ],
            )
        with self.assertRaisesRegex(SnapshotError, "identity"):
            PolicySnapshot(
                1,
                NOW,
                [
                    implementation_item,
                    implementation_envelope(
                        "one",
                        "10.0.0.0/8",
                        24,
                        15169,
                        True,
                        object_serial=2,
                    ),
                ],
            )


class SnapshotOracleLifecycleTests(unittest.TestCase):
    def test_expired_future_and_revoked_are_inactive_in_both_paths(self) -> None:
        variants = (
            {
                "object_id": "expired",
                "not_before": NOW - 200,
                "not_after": NOW,
            },
            {
                "object_id": "future",
                "not_before": NOW + 1,
                "not_after": NOW + 200,
            },
            {"object_id": "revoked", "revoked": True},
        )
        for variant in variants:
            object_id = str(variant["object_id"])
            kwargs = {
                key: value
                for key, value in variant.items()
                if key != "object_id"
            }
            oracle = SnapshotOracle(
                2,
                NOW,
                [
                    oracle_envelope(
                        object_id,
                        "10.0.0.0/8",
                        24,
                        15169,
                        True,
                        **kwargs,
                    )
                ],
            )
            implementation = PolicySnapshot(
                2,
                NOW,
                [
                    implementation_envelope(
                        object_id,
                        "10.0.0.0/8",
                        24,
                        15169,
                        True,
                        **kwargs,
                    )
                ],
            )
            self.assertEqual(
                oracle.validate_route("10.2.0.0/24", 13335),
                SnapshotOracleState.NOT_FOUND,
                object_id,
            )
            self.assertEqual(
                IMPLEMENTATION_STATE[
                    implementation.validate_route("10.2.0.0/24", 13335)
                ],
                SnapshotOracleState.NOT_FOUND,
                object_id,
            )

    def test_monotonic_serial_idempotence_collision_and_withdrawal(self) -> None:
        oracle_active = oracle_envelope(
            "one", "10.0.0.0/8", 24, 15169, True
        )
        implementation_active = implementation_envelope(
            "one", "10.0.0.0/8", 24, 15169, True
        )
        oracle_initial = SnapshotOracle(10, NOW, [oracle_active])
        implementation_initial = PolicySnapshot(
            10, NOW, [implementation_active]
        )
        oracle_replay = SnapshotOracle(
            10,
            NOW,
            [oracle_envelope("one", "10.0.0.0/8", 24, 15169, True)],
        )
        implementation_replay = PolicySnapshot(
            10,
            NOW,
            [
                implementation_envelope(
                    "one", "10.0.0.0/8", 24, 15169, True
                )
            ],
        )
        oracle_store = SnapshotOracleStore()
        implementation_store = SnapshotStore()

        self.assertTrue(oracle_store.apply(oracle_initial))
        self.assertTrue(implementation_store.apply(implementation_initial))
        self.assertFalse(oracle_store.apply(oracle_replay))
        self.assertFalse(implementation_store.apply(implementation_replay))

        oracle_collision = SnapshotOracle(
            10,
            NOW,
            [oracle_envelope("other", "10.0.0.0/8", 24, 16509, True)],
        )
        implementation_collision = PolicySnapshot(
            10,
            NOW,
            [
                implementation_envelope(
                    "other", "10.0.0.0/8", 24, 16509, True
                )
            ],
        )
        with self.assertRaisesRegex(SnapshotOracleError, "different content"):
            oracle_store.apply(oracle_collision)
        with self.assertRaisesRegex(SnapshotError, "different content"):
            implementation_store.apply(implementation_collision)
        self.assertEqual(
            oracle_store.validate_route("10.2.0.0/24", 13335),
            SnapshotOracleState.OPEN_SCOPE,
        )
        self.assertEqual(
            IMPLEMENTATION_STATE[
                implementation_store.validate_route("10.2.0.0/24", 13335)
            ],
            SnapshotOracleState.OPEN_SCOPE,
        )

        oracle_withdrawn = SnapshotOracle(11, NOW + 1, [])
        implementation_withdrawn = PolicySnapshot(11, NOW + 1, [])
        self.assertTrue(oracle_store.apply(oracle_withdrawn))
        self.assertTrue(implementation_store.apply(implementation_withdrawn))
        self.assertEqual(
            oracle_store.validate_route("10.2.0.0/24", 13335),
            SnapshotOracleState.NOT_FOUND,
        )
        self.assertEqual(
            IMPLEMENTATION_STATE[
                implementation_store.validate_route("10.2.0.0/24", 13335)
            ],
            SnapshotOracleState.NOT_FOUND,
        )

        with self.assertRaisesRegex(SnapshotOracleError, "rollback"):
            oracle_store.apply(oracle_initial)
        with self.assertRaisesRegex(SnapshotError, "rollback"):
            implementation_store.apply(implementation_initial)

    def test_unsupported_profile_is_rejected_by_both_paths(self) -> None:
        with self.assertRaisesRegex(SnapshotOracleError, "unsupported"):
            oracle_envelope(
                "unsupported",
                "10.0.0.0/8",
                24,
                15169,
                True,
                profile_version=2,
            )
        with self.assertRaisesRegex(SnapshotError, "unsupported"):
            implementation_envelope(
                "unsupported",
                "10.0.0.0/8",
                24,
                15169,
                True,
                profile_version=2,
            )


if __name__ == "__main__":
    unittest.main()
