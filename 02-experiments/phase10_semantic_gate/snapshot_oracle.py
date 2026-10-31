"""Independent pure oracle for policy-snapshot composition and lifecycle.

This module intentionally shares no policy or snapshot data structures with
the Phase 4 implementation.  It models the frozen E1a contract directly from
primitive fields so the implementation can be checked by a genuinely separate
decision path.  It is not a signed-object, repository, RP, RTR, or router model.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import ipaddress as ip
import json
import re
from typing import Iterable


SUPPORTED_PROFILE_VERSION = 1
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_MAX_ASN = 0xFFFFFFFF
_MAX_EXPLICIT_ORIGINS = 255


class SnapshotOracleError(ValueError):
    """Raised when an oracle policy, snapshot, or transition is ambiguous."""


class SnapshotOracleState(str, Enum):
    """Manuscript-facing validation states returned by the oracle."""

    EXPLICIT = "Explicit"
    OPEN_SCOPE = "OpenScope"
    INVALID = "Invalid"
    NOT_FOUND = "NotFound"


def _integer(value: object, field: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SnapshotOracleError(f"{field} must be an integer")
    if minimum is not None and value < minimum:
        raise SnapshotOracleError(f"{field} must be at least {minimum}")
    return value


def _network(value: object, field: str) -> ip.IPv4Network:
    if not isinstance(value, str):
        raise SnapshotOracleError(f"{field} must be an IPv4 prefix string")
    try:
        return ip.IPv4Network(value, strict=True)
    except (ip.AddressValueError, ip.NetmaskValueError, ValueError) as exc:
        raise SnapshotOracleError(
            f"{field} must be a canonical IPv4 prefix"
        ) from exc


def _public_origin_eligible(asn: int) -> bool:
    """Return the frozen E1 eligibility decision without implementation code."""

    if asn <= 0 or asn > _MAX_ASN or asn == 23456:
        return False
    if 64496 <= asn <= 65535:
        return False
    if 65536 <= asn <= 131071:
        return False
    if 4200000000 <= asn <= 4294967295:
        return False
    return True


@dataclass(frozen=True)
class SnapshotOracleRule:
    """One independently represented prefix-scope rule."""

    prefix: str
    origins: frozenset[int]
    is_open: bool

    def __init__(
        self,
        prefix: str,
        origins: Iterable[int],
        is_open: bool,
    ) -> None:
        network = _network(prefix, "rule prefix")
        try:
            origin_set = frozenset(origins)
        except TypeError as exc:
            raise SnapshotOracleError("rule origins must be iterable") from exc
        if len(origin_set) > _MAX_EXPLICIT_ORIGINS:
            raise SnapshotOracleError(
                f"rule origins exceed {_MAX_EXPLICIT_ORIGINS} entries"
            )
        for asn in origin_set:
            _integer(asn, "rule origin ASN", minimum=1)
            if asn > _MAX_ASN:
                raise SnapshotOracleError("rule origin ASN exceeds 32-bit range")
        if not isinstance(is_open, bool):
            raise SnapshotOracleError("rule is_open must be bool")
        object.__setattr__(self, "prefix", str(network))
        object.__setattr__(self, "origins", origin_set)
        object.__setattr__(self, "is_open", is_open)

    @property
    def network(self) -> ip.IPv4Network:
        return ip.IPv4Network(self.prefix, strict=True)

    def canonical_document(self) -> dict[str, object]:
        return {
            "is_open": self.is_open,
            "origins": sorted(self.origins),
            "prefix": self.prefix,
        }


@dataclass(frozen=True)
class SnapshotOracleEnvelope:
    """Lifecycle metadata plus an independent policy representation."""

    issuer: str
    object_id: str
    profile_version: int
    object_serial: int
    not_before: int
    not_after: int
    revoked: bool
    base_prefix: str
    max_length: int
    holder_asn: int
    rules: tuple[SnapshotOracleRule, ...]

    def __init__(
        self,
        *,
        issuer: str,
        object_id: str,
        profile_version: int,
        object_serial: int,
        not_before: int,
        not_after: int,
        revoked: bool,
        base_prefix: str,
        max_length: int,
        holder_asn: int,
        rules: Iterable[SnapshotOracleRule],
    ) -> None:
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "object_id", object_id)
        object.__setattr__(self, "profile_version", profile_version)
        object.__setattr__(self, "object_serial", object_serial)
        object.__setattr__(self, "not_before", not_before)
        object.__setattr__(self, "not_after", not_after)
        object.__setattr__(self, "revoked", revoked)
        object.__setattr__(self, "base_prefix", base_prefix)
        object.__setattr__(self, "max_length", max_length)
        object.__setattr__(self, "holder_asn", holder_asn)
        try:
            rule_values = tuple(rules)
        except TypeError as exc:
            raise SnapshotOracleError("rules must be iterable") from exc
        object.__setattr__(self, "rules", rule_values)
        self.__post_init__()

    def __post_init__(self) -> None:
        if not isinstance(self.issuer, str) or not _IDENTIFIER_RE.fullmatch(
            self.issuer
        ):
            raise SnapshotOracleError(
                "issuer must be a canonical nonempty identifier"
            )
        if not isinstance(self.object_id, str) or not _IDENTIFIER_RE.fullmatch(
            self.object_id
        ):
            raise SnapshotOracleError(
                "object_id must be a canonical nonempty identifier"
            )
        profile_version = _integer(
            self.profile_version, "profile_version", minimum=0
        )
        if profile_version != SUPPORTED_PROFILE_VERSION:
            raise SnapshotOracleError(
                f"unsupported policy profile version: {profile_version}"
            )
        _integer(self.object_serial, "object_serial", minimum=0)
        not_before = _integer(self.not_before, "not_before")
        not_after = _integer(self.not_after, "not_after")
        if not_before >= not_after:
            raise SnapshotOracleError("not_before must precede not_after")
        if not isinstance(self.revoked, bool):
            raise SnapshotOracleError("revoked must be bool")

        base = _network(self.base_prefix, "base_prefix")
        max_length = _integer(self.max_length, "max_length", minimum=0)
        if not base.prefixlen <= max_length <= 32:
            raise SnapshotOracleError(
                f"max_length {max_length} outside [{base.prefixlen}, 32]"
            )
        holder_asn = _integer(self.holder_asn, "holder_asn", minimum=1)
        if holder_asn > _MAX_ASN:
            raise SnapshotOracleError("holder_asn exceeds 32-bit range")

        by_prefix: dict[str, SnapshotOracleRule] = {}
        for rule in self.rules:
            if not isinstance(rule, SnapshotOracleRule):
                raise SnapshotOracleError(
                    "rules must contain SnapshotOracleRule values"
                )
            if not rule.network.subnet_of(base):
                raise SnapshotOracleError(
                    f"rule {rule.prefix} lies outside base {base}"
                )
            if rule.network.prefixlen > max_length:
                raise SnapshotOracleError(
                    f"rule {rule.prefix} exceeds max_length {max_length}"
                )
            if rule.prefix in by_prefix:
                raise SnapshotOracleError(f"duplicate rule prefix: {rule.prefix}")
            by_prefix[rule.prefix] = rule

        base_rule = by_prefix.get(str(base))
        if base_rule is None:
            raise SnapshotOracleError("policy must contain exactly one base rule")
        if holder_asn not in base_rule.origins:
            raise SnapshotOracleError("base rule must explicitly name holder_asn")

        canonical_rules = tuple(
            sorted(
                by_prefix.values(),
                key=lambda rule: (
                    -rule.network.prefixlen,
                    int(rule.network.network_address),
                ),
            )
        )
        object.__setattr__(self, "base_prefix", str(base))
        object.__setattr__(self, "rules", canonical_rules)

    @property
    def identity(self) -> tuple[str, str]:
        return self.issuer, self.object_id

    @property
    def base_network(self) -> ip.IPv4Network:
        return ip.IPv4Network(self.base_prefix, strict=True)

    @property
    def base_prefix_length(self) -> int:
        return self.base_network.prefixlen

    def is_active_at(self, validation_time: int) -> bool:
        return (
            not self.revoked
            and self.not_before <= validation_time < self.not_after
        )

    def canonical_document(self) -> dict[str, object]:
        return {
            "base_prefix": self.base_prefix,
            "holder_asn": self.holder_asn,
            "issuer": self.issuer,
            "max_length": self.max_length,
            "not_after": self.not_after,
            "not_before": self.not_before,
            "object_id": self.object_id,
            "object_serial": self.object_serial,
            "profile_version": self.profile_version,
            "revoked": self.revoked,
            "rules": [rule.canonical_document() for rule in self.rules],
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.canonical_document(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def classify_route(
        self,
        target_prefix: str,
        origin_asn: int,
    ) -> SnapshotOracleState:
        target = _network(target_prefix, "target_prefix")
        origin = _integer(origin_asn, "origin_asn", minimum=1)
        if origin > _MAX_ASN:
            raise SnapshotOracleError("origin_asn exceeds 32-bit range")
        if not target.subnet_of(self.base_network):
            return SnapshotOracleState.NOT_FOUND
        if target.prefixlen > self.max_length:
            return SnapshotOracleState.INVALID

        covering = [rule for rule in self.rules if target.subnet_of(rule.network)]
        if not covering:
            return SnapshotOracleState.INVALID
        selected = min(
            covering,
            key=lambda rule: (
                -rule.network.prefixlen,
                int(rule.network.network_address),
            ),
        )
        if origin in selected.origins:
            return SnapshotOracleState.EXPLICIT
        if (
            selected.is_open
            and target.prefixlen > selected.network.prefixlen
            and _public_origin_eligible(origin)
        ):
            return SnapshotOracleState.OPEN_SCOPE
        return SnapshotOracleState.INVALID


@dataclass(frozen=True)
class SnapshotOracle:
    """One complete oracle snapshot with deterministic active composition."""

    snapshot_serial: int
    validation_time: int
    envelopes: tuple[SnapshotOracleEnvelope, ...]

    def __init__(
        self,
        snapshot_serial: int,
        validation_time: int,
        envelopes: Iterable[SnapshotOracleEnvelope],
    ) -> None:
        object.__setattr__(self, "snapshot_serial", snapshot_serial)
        object.__setattr__(self, "validation_time", validation_time)
        try:
            envelope_values = tuple(envelopes)
        except TypeError as exc:
            raise SnapshotOracleError("envelopes must be iterable") from exc
        object.__setattr__(self, "envelopes", envelope_values)
        self.__post_init__()

    def __post_init__(self) -> None:
        _integer(self.snapshot_serial, "snapshot_serial", minimum=0)
        validation_time = _integer(self.validation_time, "validation_time")

        by_identity: dict[tuple[str, str], SnapshotOracleEnvelope] = {}
        for envelope in self.envelopes:
            if not isinstance(envelope, SnapshotOracleEnvelope):
                raise SnapshotOracleError(
                    "snapshot must contain SnapshotOracleEnvelope values"
                )
            previous = by_identity.get(envelope.identity)
            if (
                previous is not None
                and previous.canonical_bytes() != envelope.canonical_bytes()
            ):
                raise SnapshotOracleError(
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

        active_by_base: dict[str, SnapshotOracleEnvelope] = {}
        for envelope in canonical:
            if not envelope.is_active_at(validation_time):
                continue
            previous = active_by_base.get(envelope.base_prefix)
            if previous is not None and previous.identity != envelope.identity:
                raise SnapshotOracleError(
                    f"conflicting active policies share base {envelope.base_prefix}"
                )
            active_by_base[envelope.base_prefix] = envelope
        object.__setattr__(self, "_active_by_base", active_by_base)

    @property
    def active_envelopes(self) -> tuple[SnapshotOracleEnvelope, ...]:
        return tuple(
            sorted(
                self._active_by_base.values(),
                key=lambda envelope: (
                    -envelope.base_prefix_length,
                    int(envelope.base_network.network_address),
                    envelope.issuer,
                    envelope.object_id,
                ),
            )
        )

    def canonical_document(self) -> dict[str, object]:
        return {
            "envelopes": [
                envelope.canonical_document() for envelope in self.envelopes
            ],
            "snapshot_serial": self.snapshot_serial,
            "validation_time": self.validation_time,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.canonical_document(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def classify_route(
        self,
        target_prefix: str,
        origin_asn: int,
    ) -> SnapshotOracleState:
        target = _network(target_prefix, "target_prefix")
        for envelope in self.active_envelopes:
            if target.subnet_of(envelope.base_network):
                return envelope.classify_route(str(target), origin_asn)
        return SnapshotOracleState.NOT_FOUND

    def validate_route(
        self,
        target_prefix: str,
        origin_asn: int,
    ) -> SnapshotOracleState:
        """Alias matching the implementation-facing runner vocabulary."""

        return self.classify_route(target_prefix, origin_asn)


class SnapshotOracleStore:
    """Independent fail-closed store for complete snapshot transitions."""

    def __init__(self) -> None:
        self.current: SnapshotOracle | None = None

    def apply(self, snapshot: SnapshotOracle) -> bool:
        if not isinstance(snapshot, SnapshotOracle):
            raise SnapshotOracleError("store accepts SnapshotOracle values only")
        if self.current is None:
            self.current = snapshot
            return True
        if snapshot.snapshot_serial < self.current.snapshot_serial:
            raise SnapshotOracleError("snapshot rollback/replay rejected")
        if snapshot.snapshot_serial == self.current.snapshot_serial:
            if snapshot.canonical_bytes() == self.current.canonical_bytes():
                return False
            raise SnapshotOracleError("same snapshot serial has different content")
        self.current = snapshot
        return True

    def classify_route(
        self,
        target_prefix: str,
        origin_asn: int,
    ) -> SnapshotOracleState:
        if self.current is None:
            return SnapshotOracleState.NOT_FOUND
        return self.current.classify_route(target_prefix, origin_asn)

    def validate_route(
        self,
        target_prefix: str,
        origin_asn: int,
    ) -> SnapshotOracleState:
        return self.classify_route(target_prefix, origin_asn)


__all__ = [
    "SUPPORTED_PROFILE_VERSION",
    "SnapshotOracle",
    "SnapshotOracleEnvelope",
    "SnapshotOracleError",
    "SnapshotOracleRule",
    "SnapshotOracleState",
    "SnapshotOracleStore",
]
