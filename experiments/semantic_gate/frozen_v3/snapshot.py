"""Deterministic pure-policy composition and lifecycle model.

This module is an executable *semantic* contract for E1a.  It is deliberately
not an RPKI object profile, signature validator, repository implementation, or
RTR payload.  The later E2 carrier must preserve these decisions through the
real signed-object pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress as ip
import json
import re
from typing import Iterable

from .s2rov import S2ROV, ValidationState


SUPPORTED_PROFILE_VERSION = 1
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class SnapshotError(ValueError):
    """Raised when a policy snapshot is ambiguous, malformed, or replayed."""


@dataclass(frozen=True)
class PolicyEnvelope:
    """Lifecycle metadata around one pure S2-ROV policy.

    ``revoked`` is an auditable tombstone: the envelope remains in the
    canonical snapshot but cannot enter the active-policy index.
    """

    issuer: str
    object_id: str
    profile_version: int
    object_serial: int
    not_before: int
    not_after: int
    revoked: bool
    policy: S2ROV

    def __post_init__(self) -> None:
        if not _IDENTIFIER_RE.fullmatch(self.issuer):
            raise SnapshotError("issuer must be a canonical nonempty identifier")
        if not _IDENTIFIER_RE.fullmatch(self.object_id):
            raise SnapshotError("object_id must be a canonical nonempty identifier")
        if self.profile_version != SUPPORTED_PROFILE_VERSION:
            raise SnapshotError(
                f"unsupported policy profile version: {self.profile_version}"
            )
        if isinstance(self.object_serial, bool) or not isinstance(self.object_serial, int):
            raise SnapshotError("object_serial must be an integer")
        if self.object_serial < 0:
            raise SnapshotError("object_serial must be nonnegative")
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in (self.not_before, self.not_after)
        ):
            raise SnapshotError("validity bounds must be integer epoch seconds")
        if self.not_before >= self.not_after:
            raise SnapshotError("not_before must precede not_after")
        if not isinstance(self.revoked, bool):
            raise SnapshotError("revoked must be bool")
        if not isinstance(self.policy, S2ROV):
            raise SnapshotError("policy must be a S2ROV")

    @property
    def identity(self) -> tuple[str, str]:
        return self.issuer, self.object_id

    def is_active_at(self, validation_time: int) -> bool:
        return (
            not self.revoked
            and self.not_before <= validation_time < self.not_after
        )

    def canonical_bytes(self) -> bytes:
        document = {
            "issuer": self.issuer,
            "not_after": self.not_after,
            "not_before": self.not_before,
            "object_id": self.object_id,
            "object_serial": self.object_serial,
            "policy_hex": self.policy.serialize().hex(),
            "profile_version": self.profile_version,
            "revoked": self.revoked,
        }
        return json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True)
class PolicySnapshot:
    """One complete, canonical policy snapshot.

    Active objects may have nested base prefixes; the most-specific covering
    base is selected.  Two different active objects at the same base are
    rejected rather than resolved by input order.  Byte-identical duplicate
    envelopes are deduplicated.
    """

    snapshot_serial: int
    validation_time: int
    envelopes: tuple[PolicyEnvelope, ...]

    def __init__(
        self,
        snapshot_serial: int,
        validation_time: int,
        envelopes: Iterable[PolicyEnvelope],
    ) -> None:
        object.__setattr__(self, "snapshot_serial", snapshot_serial)
        object.__setattr__(self, "validation_time", validation_time)
        object.__setattr__(self, "envelopes", tuple(envelopes))
        self.__post_init__()

    def __post_init__(self) -> None:
        if (
            isinstance(self.snapshot_serial, bool)
            or not isinstance(self.snapshot_serial, int)
            or self.snapshot_serial < 0
        ):
            raise SnapshotError("snapshot_serial must be a nonnegative integer")
        if isinstance(self.validation_time, bool) or not isinstance(
            self.validation_time, int
        ):
            raise SnapshotError("validation_time must be an integer epoch second")

        by_identity: dict[tuple[str, str], PolicyEnvelope] = {}
        for envelope in self.envelopes:
            if not isinstance(envelope, PolicyEnvelope):
                raise SnapshotError("snapshot contains a non-envelope value")
            existing = by_identity.get(envelope.identity)
            if existing is not None and existing.canonical_bytes() != envelope.canonical_bytes():
                raise SnapshotError(
                    "conflicting envelopes share issuer/object_id identity"
                )
            by_identity[envelope.identity] = envelope

        canonical = tuple(
            sorted(
                by_identity.values(),
                key=lambda envelope: (
                    envelope.issuer,
                    envelope.object_id,
                    envelope.object_serial,
                    envelope.sha256(),
                ),
            )
        )
        object.__setattr__(self, "envelopes", canonical)

        active_by_base: dict[str, PolicyEnvelope] = {}
        for envelope in canonical:
            if not envelope.is_active_at(self.validation_time):
                continue
            base = envelope.policy.base_prefix
            existing = active_by_base.get(base)
            if existing is not None and existing.identity != envelope.identity:
                raise SnapshotError(f"conflicting active policies share base {base}")
            active_by_base[base] = envelope
        object.__setattr__(self, "_active_by_base", active_by_base)

    @property
    def active_envelopes(self) -> tuple[PolicyEnvelope, ...]:
        return tuple(
            sorted(
                self._active_by_base.values(),
                key=lambda envelope: (
                    -envelope.policy.base_prefix_length,
                    int(envelope.policy.base_network.network_address),
                ),
            )
        )

    def canonical_bytes(self) -> bytes:
        document = {
            "envelopes": [
                json.loads(envelope.canonical_bytes().decode("ascii"))
                for envelope in self.envelopes
            ],
            "snapshot_serial": self.snapshot_serial,
            "validation_time": self.validation_time,
        }
        return json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def validate_route(self, target_prefix: str, origin_asn: int) -> ValidationState:
        target = ip.IPv4Network(target_prefix, strict=True)
        for envelope in self.active_envelopes:
            if target.subnet_of(envelope.policy.base_network):
                return envelope.policy.validate_route(str(target), origin_asn)
        return ValidationState.NOT_FOUND


class SnapshotStore:
    """Fail-closed monotone application of complete snapshots."""

    def __init__(self) -> None:
        self.current: PolicySnapshot | None = None

    def apply(self, snapshot: PolicySnapshot) -> bool:
        """Apply a snapshot and return whether state changed.

        A byte-identical replay at the current serial is an idempotent no-op.
        Older serials and same-serial content collisions are rejected.
        """

        if not isinstance(snapshot, PolicySnapshot):
            raise SnapshotError("store accepts PolicySnapshot values only")
        if self.current is None:
            self.current = snapshot
            return True
        if snapshot.snapshot_serial < self.current.snapshot_serial:
            raise SnapshotError("snapshot rollback/replay rejected")
        if snapshot.snapshot_serial == self.current.snapshot_serial:
            if snapshot.canonical_bytes() == self.current.canonical_bytes():
                return False
            raise SnapshotError("same snapshot serial has different content")
        self.current = snapshot
        return True

    def validate_route(self, target_prefix: str, origin_asn: int) -> ValidationState:
        if self.current is None:
            return ValidationState.NOT_FOUND
        return self.current.validate_route(target_prefix, origin_asn)
