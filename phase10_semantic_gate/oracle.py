"""Independent pure oracle and faithful baseline semantics for E1a."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import ipaddress as ip
from typing import Iterable


class OracleState(str, Enum):
    EXPLICIT = "Explicit"
    OPEN_SCOPE = "OpenScope"
    INVALID = "Invalid"
    NOT_FOUND = "NotFound"


class ROVState(str, Enum):
    VALID = "Valid"
    INVALID = "Invalid"
    NOT_FOUND = "NotFound"


class WildcardState(str, Enum):
    REGULAR_VALID = "RegularValid"
    WILDCARD_VALID = "WildcardValid"
    INVALID = "Invalid"
    NOT_FOUND = "NotFound"


@dataclass(frozen=True)
class OracleRule:
    prefix: str
    origins: frozenset[int]
    is_open: bool

    @property
    def network(self) -> ip.IPv4Network:
        return ip.IPv4Network(self.prefix, strict=True)


@dataclass(frozen=True)
class OraclePolicy:
    base_prefix: str
    max_length: int
    holder_asn: int
    rules: tuple[OracleRule, ...]

    @property
    def base_network(self) -> ip.IPv4Network:
        return ip.IPv4Network(self.base_prefix, strict=True)


@dataclass(frozen=True)
class VRP:
    prefix: str
    origin_asn: int
    max_length: int

    @property
    def network(self) -> ip.IPv4Network:
        return ip.IPv4Network(self.prefix, strict=True)


def eligible_public_origin(asn: int) -> bool:
    """Independent copy of the E1 public-origin eligibility contract."""

    if isinstance(asn, bool) or not isinstance(asn, int):
        return False
    if asn <= 0 or asn > 0xFFFFFFFF or asn == 23456:
        return False
    if 64496 <= asn <= 65535:
        return False
    if 65536 <= asn <= 131071:
        return False
    if 4200000000 <= asn <= 4294967295:
        return False
    return True


def selected_rule(
    policy: OraclePolicy,
    target_prefix: str,
) -> OracleRule | None:
    target = ip.IPv4Network(target_prefix, strict=True)
    covering = [rule for rule in policy.rules if target.subnet_of(rule.network)]
    if not covering:
        return None
    return min(
        covering,
        key=lambda rule: (-rule.network.prefixlen, int(rule.network.network_address)),
    )


def classify(
    policy: OraclePolicy,
    target_prefix: str,
    origin_asn: int,
) -> OracleState:
    target = ip.IPv4Network(target_prefix, strict=True)
    base = policy.base_network
    if not target.subnet_of(base):
        return OracleState.NOT_FOUND
    if target.prefixlen > policy.max_length:
        return OracleState.INVALID
    rule = selected_rule(policy, target_prefix)
    if rule is None:
        return OracleState.INVALID
    if origin_asn in rule.origins:
        return OracleState.EXPLICIT
    if (
        rule.is_open
        and target.prefixlen > rule.network.prefixlen
        and eligible_public_origin(origin_asn)
    ):
        return OracleState.OPEN_SCOPE
    return OracleState.INVALID


def conventional_rov(
    target_prefix: str,
    origin_asn: int,
    vrps: Iterable[VRP],
) -> ROVState:
    target = ip.IPv4Network(target_prefix, strict=True)
    covering = [vrp for vrp in vrps if target.subnet_of(vrp.network)]
    if not covering:
        return ROVState.NOT_FOUND
    if any(
        vrp.origin_asn == origin_asn and target.prefixlen <= vrp.max_length
        for vrp in covering
    ):
        return ROVState.VALID
    return ROVState.INVALID


def wildcard_exact(
    wildcard_prefix: str,
    target_prefix: str,
    origin_asn: int,
    same_prefix_regular_vrps: Iterable[VRP] = (),
) -> WildcardState:
    """B4-exact: exact target only, regular ROAs at that prefix prevail."""

    wildcard = ip.IPv4Network(wildcard_prefix, strict=True)
    target = ip.IPv4Network(target_prefix, strict=True)
    if target != wildcard:
        return WildcardState.NOT_FOUND
    regular = [vrp for vrp in same_prefix_regular_vrps if vrp.network == wildcard]
    if regular:
        if any(
            vrp.origin_asn == origin_asn and target.prefixlen <= vrp.max_length
            for vrp in regular
        ):
            return WildcardState.REGULAR_VALID
        return WildcardState.INVALID
    return WildcardState.WILDCARD_VALID


def action_for_state(state: str, treatment: str) -> tuple[str, int | None]:
    """Frozen state-to-action oracle used by the E1 boundary matrix."""

    if state == "Explicit":
        return "accept", 300
    if state == "Invalid":
        return "reject", None
    if state == "NotFound":
        return "accept", 100
    if state != "OpenScope":
        raise ValueError(f"unknown S2 state: {state}")
    if treatment == "T1-accept":
        return "accept", 300
    if treatment == "T2-deprefer":
        return "accept", 200
    if treatment == "T3-reject":
        return "reject", None
    raise ValueError(f"unknown treatment: {treatment}")
