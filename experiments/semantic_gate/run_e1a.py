"""Execute the frozen E1a semantic differential corpus."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import ipaddress as ip
from itertools import chain, permutations
import json
import os
from pathlib import Path
import platform
import random
import resource
import shutil
import subprocess
import sys
import time
from typing import Any, Iterable, Iterator

from experiments.semantic_gate.frozen_v3.daroa import (
    DAROA,
    Stripe,
    ValidationState,
)
from experiments.semantic_gate.frozen_v3.flatten import flatten_to_vrps
from experiments.semantic_gate.frozen_v3.snapshot import (
    PolicyEnvelope,
    PolicySnapshot,
    SnapshotError,
    SnapshotStore,
)
from experiments.semantic_gate.oracle import (
    OraclePolicy,
    OracleRule,
    OracleState,
    VRP,
    action_for_state,
    classify,
    conventional_rov,
    eligible_public_origin,
    selected_rule,
    wildcard_exact,
)
from experiments.semantic_gate.snapshot_oracle import (
    SnapshotOracle,
    SnapshotOracleEnvelope,
    SnapshotOracleError,
    SnapshotOracleRule,
    SnapshotOracleStore,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SEED = 20260826
DEFAULT_GENERATED = 100_000
DEFAULT_INVALID_SEED = 120260826
DEFAULT_INVALID_GENERATED = 100_000
BOUNDED_VECTOR_COUNT = 6_080
BOUNDARY_VECTOR_COUNT = 138
SCHEMA_VERSION = "e1a-result-v3"
OPEN_SCOPE_MAP = {
    ValidationState.EXPLICIT: OracleState.EXPLICIT.value,
    ValidationState.DELEGATED: OracleState.OPEN_SCOPE.value,
    ValidationState.INVALID: OracleState.INVALID.value,
    ValidationState.NOT_FOUND: OracleState.NOT_FOUND.value,
}
ELIGIBLE_ORIGINS = (15169, 16509, 13335, 8075, 18403, 20940)
INELIGIBLE_ORIGINS = (23456, 64513, 65536, 4200000000)


class GateFailure(RuntimeError):
    """Raised for a fail-closed execution or integrity error."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_text(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def normalize_output_path(raw: str) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        path = REPOSITORY_ROOT / path
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(REPOSITORY_ROOT.resolve())
    except ValueError as exc:
        raise GateFailure("output directory must remain inside the repository") from exc
    if path.is_symlink() or resolved.is_symlink():
        raise GateFailure("output directory must not be a symbolic link")
    if resolved.exists() and any(resolved.iterdir()):
        raise GateFailure("output directory must be empty")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def oracle_policy(vector: dict[str, Any]) -> OraclePolicy:
    policy = vector["policy"]
    return OraclePolicy(
        base_prefix=policy["base_prefix"],
        max_length=policy["max_length"],
        holder_asn=policy["holder_asn"],
        rules=tuple(
            OracleRule(
                prefix=rule["prefix"],
                origins=frozenset(rule["origins"]),
                is_open=rule["is_open"],
            )
            for rule in policy["rules"]
        ),
    )


def reference_policy(
    vector: dict[str, Any],
    order: Iterable[int] | None = None,
) -> DAROA:
    policy = vector["policy"]
    rules = list(policy["rules"])
    if order is not None:
        rules = [rules[index] for index in order]
    return DAROA(
        policy["base_prefix"],
        policy["max_length"],
        policy["holder_asn"],
        [
            Stripe(rule["prefix"], set(rule["origins"]), rule["is_open"])
            for rule in rules
        ],
    )


def rule_orders(vector: dict[str, Any]) -> tuple[tuple[int, ...], ...]:
    count = len(vector["policy"]["rules"])
    identity = tuple(range(count))
    if vector["source"] == "bounded-exhaustive":
        return tuple(permutations(identity))
    candidates = [
        identity,
        tuple(reversed(identity)),
        identity[1:] + identity[:1],
        identity[::2] + identity[1::2],
    ]
    shuffled = list(identity)
    seeded = random.Random(int(hashlib.sha256(vector["id"].encode("ascii")).hexdigest()[:16], 16))
    seeded.shuffle(shuffled)
    candidates.append(tuple(shuffled))
    return tuple(dict.fromkeys(candidates))


def subnet_at(parent: ip.IPv4Network, prefix_length: int, index: int) -> ip.IPv4Network:
    if not parent.prefixlen <= prefix_length <= 32:
        raise ValueError("subnet prefix length outside parent bounds")
    count = 1 << (prefix_length - parent.prefixlen)
    if not 0 <= index < count:
        raise ValueError("subnet index outside parent bounds")
    address = int(parent.network_address) + (index << (32 - prefix_length))
    return ip.IPv4Network((address, prefix_length))


def outside_peer(base: ip.IPv4Network) -> ip.IPv4Network:
    if base.prefixlen == 0:
        raise ValueError("a /0 has no outside peer")
    toggled = int(base.network_address) ^ (1 << (32 - base.prefixlen))
    return ip.IPv4Network((toggled, base.prefixlen))


def derive_route_mode(
    base: ip.IPv4Network,
    max_length: int,
    rules: Iterable[tuple[ip.IPv4Network, Iterable[int], bool]],
    route: ip.IPv4Network,
) -> str:
    """Derive, rather than trust, the mutually exclusive route relation label."""

    materialized = list(rules)
    if not route.subnet_of(base):
        return "outside"
    if route == base:
        return "exact_base"
    if route.prefixlen > max_length:
        return "overlength"
    nested = [prefix for prefix, _, _ in materialized if prefix != base]
    if any(route == prefix for prefix in nested):
        return "exact_nested_rule"
    if any(route.subnet_of(prefix) and route.prefixlen > prefix.prefixlen for prefix in nested):
        return "descendant_of_nested_rule"
    return "proper_descendant"


def derive_origin_mode(
    rules: Iterable[tuple[ip.IPv4Network, Iterable[int], bool]],
    route: ip.IPv4Network,
    origin: int,
) -> str:
    covering = [
        (prefix, set(origins))
        for prefix, origins, _ in rules
        if route.subnet_of(prefix)
    ]
    if covering:
        _, origins = max(
            covering,
            key=lambda item: (item[0].prefixlen, -int(item[0].network_address)),
        )
        if origin in origins:
            return "explicit"
    return "eligible_unlisted" if eligible_public_origin(origin) else "ineligible"


def make_vector(
    vector_id: str,
    source: str,
    base: ip.IPv4Network,
    max_length: int,
    holder: int,
    rules: Iterable[tuple[ip.IPv4Network, Iterable[int], bool]],
    route: ip.IPv4Network,
    origin: int,
    route_mode: str,
    origin_mode: str,
) -> dict[str, Any]:
    materialized_rules = [
        (prefix, sorted(set(origins)), is_open)
        for prefix, origins, is_open in rules
    ]
    actual_route_mode = derive_route_mode(base, max_length, materialized_rules, route)
    actual_origin_mode = derive_origin_mode(materialized_rules, route, origin)
    target_length = min(32, base.prefixlen + 1) if max_length > base.prefixlen else base.prefixlen
    baseline_target = (
        subnet_at(base, target_length, 0) if target_length > base.prefixlen else base
    )
    intended_origin = next(asn for asn in ELIGIBLE_ORIGINS if asn != holder)
    regular_present = bool(hashlib.sha256(vector_id.encode("ascii")).digest()[0] & 1)
    return {
        "id": vector_id,
        "source": source,
        "policy": {
            "base_prefix": str(base),
            "max_length": max_length,
            "holder_asn": holder,
            "rules": [
                {
                    "prefix": str(prefix),
                    "origins": origins,
                    "is_open": is_open,
                }
                for prefix, origins, is_open in materialized_rules
            ],
        },
        "baseline_policy": {
            "target_prefix": str(baseline_target),
            "intended_origin_asn": intended_origin,
            "regular_exact_present": regular_present,
        },
        "route_prefix": str(route),
        "origin_asn": origin,
        "route_mode": actual_route_mode,
        "origin_mode": actual_origin_mode,
        "generator_route_mode": route_mode,
        "generator_origin_mode": origin_mode,
    }


def exhaustive_vectors() -> Iterator[dict[str, Any]]:
    base = ip.IPv4Network("192.0.2.0/30")
    holder = 15169
    other = 16509
    rule_options = (
        (frozenset(), False),
        (frozenset(), True),
        (frozenset({holder}), False),
        (frozenset({other}), False),
        (frozenset({other}), True),
    )
    routes = (
        (outside_peer(base), "outside"),
        (base, "exact_base"),
        (subnet_at(base, 31, 0), "proper_descendant"),
        (subnet_at(base, 31, 1), "proper_descendant"),
        (subnet_at(base, 32, 0), "proper_descendant"),
        (subnet_at(base, 32, 1), "proper_descendant"),
        (subnet_at(base, 32, 2), "proper_descendant"),
        (subnet_at(base, 32, 3), "proper_descendant"),
    )
    origins = (
        (holder, "holder"),
        (other, "other_explicit_or_unlisted"),
        (13335, "eligible_unlisted"),
        (64513, "private_ineligible"),
        (23456, "reserved_ineligible"),
    )
    counter = 0
    for max_length in (30, 31, 32):
        for base_open in (False, True):
            for include_other in (False, True):
                base_origins = {holder, *({other} if include_other else set())}
                variants: list[list[tuple[ip.IPv4Network, Iterable[int], bool]]] = [
                    [(base, base_origins, base_open)]
                ]
                if max_length >= 31:
                    child = subnet_at(base, 31, 0)
                    for origins_set, mode in rule_options:
                        variants.append(
                            [(base, base_origins, base_open), (child, origins_set, mode)]
                        )
                if max_length == 32:
                    child = subnet_at(base, 31, 0)
                    grandchild = subnet_at(child, 32, 1)
                    for child_origins, child_mode in rule_options:
                        for grand_origins, grand_mode in rule_options:
                            variants.append(
                                [
                                    (base, base_origins, base_open),
                                    (child, child_origins, child_mode),
                                    (grandchild, grand_origins, grand_mode),
                                ]
                            )
                for rules in variants:
                    nested = {str(prefix): prefix.prefixlen for prefix, _, _ in rules[1:]}
                    for route, broad_mode in routes:
                        if str(route) in nested:
                            route_mode = "exact_nested_rule"
                        elif any(
                            route.subnet_of(prefix) and route.prefixlen > prefix.prefixlen
                            for prefix, _, _ in rules[1:]
                        ):
                            route_mode = "descendant_of_nested_rule"
                        elif route.subnet_of(base) and route.prefixlen > max_length:
                            route_mode = "overlength"
                        else:
                            route_mode = broad_mode
                        for origin, origin_mode in origins:
                            yield make_vector(
                                f"bounded-{counter:07d}",
                                "bounded-exhaustive",
                                base,
                                max_length,
                                holder,
                                rules,
                                route,
                                origin,
                                route_mode,
                                origin_mode,
                            )
                            counter += 1


def boundary_vectors() -> Iterator[dict[str, Any]]:
    """Freeze IPv4 extremes and a 33-rule alternating deep chain."""

    holder = 15169
    other = 16509
    target = ip.IPv4Address("10.1.2.3")
    deep_base = ip.IPv4Network("0.0.0.0/0")
    deep_rules: list[tuple[ip.IPv4Network, set[int], bool]] = []
    for prefix_length in range(33):
        prefix = ip.IPv4Network((int(target), prefix_length), strict=False)
        origins = {holder} if prefix_length == 0 or prefix_length % 2 == 0 else {other}
        deep_rules.append((prefix, origins, bool(prefix_length % 2)))

    counter = 0
    for route_length in range(33):
        route = ip.IPv4Network((int(target), route_length), strict=False)
        for origin, label in (
            (holder, "holder"),
            (13335, "eligible_unlisted"),
            (64513, "private_ineligible"),
        ):
            yield make_vector(
                f"boundary-{counter:04d}",
                "deterministic-boundary",
                deep_base,
                32,
                holder,
                deep_rules,
                route,
                origin,
                "derived",
                label,
            )
            counter += 1

    extreme_specs = (
        (
            ip.IPv4Network("0.0.0.0/0"),
            0,
            [(ip.IPv4Network("0.0.0.0/0"), {holder}, False)],
            (ip.IPv4Network("0.0.0.0/0"),),
        ),
        (
            ip.IPv4Network("0.0.0.0/1"),
            32,
            [(ip.IPv4Network("0.0.0.0/1"), {holder}, True)],
            (
                ip.IPv4Network("0.0.0.0/1"),
                ip.IPv4Network("0.0.0.0/32"),
                ip.IPv4Network("128.0.0.0/1"),
            ),
        ),
        (
            ip.IPv4Network("128.0.0.0/1"),
            32,
            [(ip.IPv4Network("128.0.0.0/1"), {holder}, True)],
            (
                ip.IPv4Network("128.0.0.0/1"),
                ip.IPv4Network("255.255.255.255/32"),
                ip.IPv4Network("0.0.0.0/1"),
            ),
        ),
        (
            ip.IPv4Network("192.0.2.0/31"),
            32,
            [
                (ip.IPv4Network("192.0.2.0/31"), {holder}, True),
                (ip.IPv4Network("192.0.2.0/32"), {other}, False),
            ],
            (
                ip.IPv4Network("192.0.2.0/31"),
                ip.IPv4Network("192.0.2.0/32"),
                ip.IPv4Network("192.0.2.1/32"),
                ip.IPv4Network("192.0.2.2/31"),
            ),
        ),
        (
            ip.IPv4Network("192.0.2.1/32"),
            32,
            [(ip.IPv4Network("192.0.2.1/32"), {holder}, False)],
            (
                ip.IPv4Network("192.0.2.1/32"),
                ip.IPv4Network("192.0.2.0/32"),
            ),
        ),
    )
    for base, max_length, rules, routes in extreme_specs:
        for route in routes:
            for origin, label in (
                (holder, "holder"),
                (13335, "eligible_unlisted"),
                (64513, "private_ineligible"),
            ):
                yield make_vector(
                    f"boundary-{counter:04d}",
                    "deterministic-boundary",
                    base,
                    max_length,
                    holder,
                    rules,
                    route,
                    origin,
                    "derived",
                    label,
                )
                counter += 1

    if counter != BOUNDARY_VECTOR_COUNT:
        raise GateFailure(
            f"boundary corpus count {counter} != frozen {BOUNDARY_VECTOR_COUNT}"
        )


def random_subnet(
    rng: random.Random,
    parent: ip.IPv4Network,
    prefix_length: int,
) -> ip.IPv4Network:
    count = 1 << (prefix_length - parent.prefixlen)
    return subnet_at(parent, prefix_length, rng.randrange(count))


def generated_vectors(seed: int, count: int) -> Iterator[dict[str, Any]]:
    rng = random.Random(seed)
    for index in range(count):
        base_length = rng.randint(8, 28)
        base = ip.IPv4Network((rng.getrandbits(32), base_length), strict=False)
        holder = rng.choice(ELIGIBLE_ORIGINS)
        max_length = rng.randint(base_length, min(32, base_length + 8))
        base_origins = {holder}
        if rng.random() < 0.35:
            base_origins.add(rng.choice([asn for asn in ELIGIBLE_ORIGINS if asn != holder]))
        rules: list[tuple[ip.IPv4Network, set[int], bool]] = [
            (base, base_origins, bool(rng.getrandbits(1)))
        ]
        desired_nested = rng.randrange(4)
        used = {str(base)}
        attempts = 0
        while len(rules) - 1 < desired_nested and attempts < 30:
            attempts += 1
            if max_length <= base_length:
                break
            length = rng.randint(base_length + 1, max_length)
            prefix = random_subnet(rng, base, length)
            if str(prefix) in used:
                continue
            used.add(str(prefix))
            mode = rng.randrange(4)
            if mode == 0:
                origins: set[int] = set()
            elif mode == 1:
                origins = {holder}
            elif mode == 2:
                origins = {rng.choice(ELIGIBLE_ORIGINS)}
            else:
                origins = set(rng.sample(ELIGIBLE_ORIGINS, 2))
            rules.append((prefix, origins, bool(rng.getrandbits(1))))

        route_mode = rng.choice(
            (
                "outside",
                "exact_base",
                "proper_descendant",
                "exact_nested_rule",
                "descendant_of_nested_rule",
                "overlength",
            )
        )
        nested_rules = rules[1:]
        if route_mode == "outside":
            route = outside_peer(base)
        elif route_mode == "exact_base":
            route = base
        elif route_mode == "exact_nested_rule" and nested_rules:
            route = rng.choice(nested_rules)[0]
        elif route_mode == "descendant_of_nested_rule" and any(
            prefix.prefixlen < max_length for prefix, _, _ in nested_rules
        ):
            parent = rng.choice(
                [prefix for prefix, _, _ in nested_rules if prefix.prefixlen < max_length]
            )
            route = random_subnet(
                rng,
                parent,
                rng.randint(parent.prefixlen + 1, max_length),
            )
        elif route_mode == "overlength" and max_length < 32:
            route = random_subnet(rng, base, rng.randint(max_length + 1, 32))
        elif base_length < max_length:
            route_mode = "proper_descendant"
            route = random_subnet(rng, base, rng.randint(base_length + 1, max_length))
        else:
            route_mode = "exact_base"
            route = base

        provisional = make_vector(
            f"generated-{index:07d}",
            "property-generated",
            base,
            max_length,
            holder,
            rules,
            route,
            holder,
            route_mode,
            "provisional",
        )
        selected = selected_rule(oracle_policy(provisional), str(route))
        origin_mode = rng.choice(("explicit", "eligible_unlisted", "ineligible"))
        selected_origins = set(selected.origins) if selected is not None else set()
        if origin_mode == "explicit" and selected_origins:
            origin = rng.choice(sorted(selected_origins))
        elif origin_mode == "ineligible":
            origin = rng.choice(INELIGIBLE_ORIGINS)
        else:
            origin_mode = "eligible_unlisted"
            candidates = [asn for asn in ELIGIBLE_ORIGINS if asn not in selected_origins]
            origin = rng.choice(candidates)

        yield make_vector(
            f"generated-{index:07d}",
            "property-generated",
            base,
            max_length,
            holder,
            rules,
            route,
            origin,
            route_mode,
            origin_mode,
        )


INVALID_FAMILIES = (
    "unsupported-version",
    "nonzero-header-flags",
    "noncanonical-base",
    "base-prefix-overflow",
    "max-length-underflow",
    "max-length-overflow",
    "holder-zero-wire",
    "holder-mismatch-wire",
    "zero-stripe-count",
    "stripe-prefix-overflow",
    "nonzero-stripe-flags",
    "unknown-as-set-type",
    "trailing-byte",
    "random-truncation",
    "noncanonical-stripe-order",
    "duplicate-stripe-wire",
    "asn-zero-wire",
    "noncanonical-asn-order-wire",
    "zero-list-count-wire",
    "missing-base-constructor",
    "missing-holder-constructor",
    "duplicate-prefix-constructor",
    "outside-rule-constructor",
    "overlong-rule-constructor",
    "boolean-max-length-constructor",
    "boolean-holder-constructor",
    "zero-holder-constructor",
    "boolean-open-constructor",
    "zero-asn-constructor",
)


def _wire_case(
    case_id: str,
    family: str,
    payload: bytes,
    expected_message: str,
) -> dict[str, Any]:
    return {
        "id": case_id,
        "source": "property-generated-invalid",
        "family": family,
        "input_kind": "wire",
        "payload_hex": payload.hex(),
        "expected_message_substring": expected_message,
    }


def _constructor_case(
    case_id: str,
    family: str,
    spec: dict[str, Any],
    expected_message: str,
) -> dict[str, Any]:
    return {
        "id": case_id,
        "source": "property-generated-invalid",
        "family": family,
        "input_kind": "constructor",
        "spec": spec,
        "expected_message_substring": expected_message,
    }


def _constructor_spec(vector: dict[str, Any]) -> dict[str, Any]:
    return {
        "base_prefix": vector["policy"]["base_prefix"],
        "max_length": vector["policy"]["max_length"],
        "holder_asn": vector["policy"]["holder_asn"],
        "rules": [dict(rule) for rule in vector["policy"]["rules"]],
    }


def _fixed_multi_asn_policy() -> DAROA:
    return DAROA(
        "10.0.0.0/8",
        24,
        15169,
        [
            Stripe("10.1.0.0/16", {13335, 16509}, False),
            Stripe("10.0.0.0/8", {15169, 18403}, True),
        ],
    )


def generated_invalid_objects(seed: int, count: int) -> Iterator[dict[str, Any]]:
    """Generate a frozen diverse stream of objects that must fail closed."""

    rng = random.Random(seed)
    legal_stream = generated_vectors(seed ^ DEFAULT_SEED, count)
    for index, vector in enumerate(legal_stream):
        case_id = f"invalid-{index:07d}"
        family = INVALID_FAMILIES[index % len(INVALID_FAMILIES)]
        reference = reference_policy(vector)
        payload = reference.serialize()
        header = payload[:14]
        chunks = [stripe.serialize() for stripe in reference.stripes]
        first = chunks[0]
        first_prefix_bytes = (first[0] + 7) // 8
        first_flags_offset = 14 + 1 + first_prefix_bytes

        if family == "unsupported-version":
            changed = bytearray(payload)
            changed[10] = 2
            yield _wire_case(case_id, family, bytes(changed), "unsupported DA-ROA version")
        elif family == "nonzero-header-flags":
            changed = bytearray(payload)
            changed[13] = 1
            yield _wire_case(case_id, family, bytes(changed), "reserved DA-ROA flags")
        elif family == "noncanonical-base":
            changed = bytearray(payload)
            changed[3] |= 1
            yield _wire_case(case_id, family, bytes(changed), "non-canonical base prefix")
        elif family == "base-prefix-overflow":
            changed = bytearray(payload)
            changed[4] = 33
            yield _wire_case(case_id, family, bytes(changed), "invalid IPv4 base prefix length")
        elif family == "max-length-underflow":
            changed = bytearray(payload)
            changed[5] = reference.base_prefix_length - 1
            yield _wire_case(case_id, family, bytes(changed), "max_length")
        elif family == "max-length-overflow":
            changed = bytearray(payload)
            changed[5] = 33
            yield _wire_case(case_id, family, bytes(changed), "max_length")
        elif family == "holder-zero-wire":
            changed = bytearray(payload)
            changed[6:10] = b"\x00\x00\x00\x00"
            yield _wire_case(case_id, family, bytes(changed), "holder ASN out of range")
        elif family == "holder-mismatch-wire":
            changed = bytearray(payload)
            changed[6:10] = (1).to_bytes(4, "big")
            yield _wire_case(case_id, family, bytes(changed), "base Stripe must explicitly name holder_asn")
        elif family == "zero-stripe-count":
            changed = bytearray(header)
            changed[11:13] = b"\x00\x00"
            yield _wire_case(case_id, family, bytes(changed), "policy must contain exactly one base Stripe")
        elif family == "stripe-prefix-overflow":
            changed = bytearray(payload)
            changed[14] = 33
            yield _wire_case(case_id, family, bytes(changed), "invalid IPv4 Stripe prefix length")
        elif family == "nonzero-stripe-flags":
            changed = bytearray(payload)
            changed[first_flags_offset] |= 0x80
            yield _wire_case(case_id, family, bytes(changed), "reserved Stripe flag bits")
        elif family == "unknown-as-set-type":
            changed = bytearray(payload)
            changed[first_flags_offset] = (changed[first_flags_offset] & 0x01) | 0x04
            yield _wire_case(case_id, family, bytes(changed), "unknown AS-set type")
        elif family == "trailing-byte":
            yield _wire_case(case_id, family, payload + bytes([rng.randrange(256)]), "trailing bytes")
        elif family == "random-truncation":
            cut = rng.randrange(len(payload))
            yield _wire_case(case_id, family, payload[:cut], "truncated")
        elif family in {"noncanonical-stripe-order", "duplicate-stripe-wire"}:
            multi = reference if len(reference.stripes) > 1 else _fixed_multi_asn_policy()
            multi_header = bytearray(multi.serialize()[:14])
            multi_chunks = [stripe.serialize() for stripe in multi.stripes]
            if family == "noncanonical-stripe-order":
                changed_payload = bytes(multi_header) + b"".join(reversed(multi_chunks))
                yield _wire_case(case_id, family, changed_payload, "non-canonical Stripe order")
            else:
                multi_header[11:13] = (len(multi_chunks) + 1).to_bytes(2, "big")
                changed_payload = bytes(multi_header) + multi_chunks[0] + b"".join(multi_chunks)
                yield _wire_case(case_id, family, changed_payload, "duplicate Stripe prefix")
        elif family in {"asn-zero-wire", "noncanonical-asn-order-wire", "zero-list-count-wire"}:
            multi = _fixed_multi_asn_policy()
            multi_header = multi.serialize()[:14]
            multi_chunks = [stripe.serialize() for stripe in multi.stripes]
            chosen = bytearray(multi_chunks[0])
            prefix_bytes = (chosen[0] + 7) // 8
            count_offset = 1 + prefix_bytes + 1
            asn_offset = count_offset + 1
            if family == "asn-zero-wire":
                chosen[asn_offset : asn_offset + 4] = b"\x00\x00\x00\x00"
                expected_message = "ASN 0"
            elif family == "noncanonical-asn-order-wire":
                first_asn = bytes(chosen[asn_offset : asn_offset + 4])
                second_asn = bytes(chosen[asn_offset + 4 : asn_offset + 8])
                chosen[asn_offset : asn_offset + 8] = second_asn + first_asn
                expected_message = "strictly increasing order"
            else:
                chosen[count_offset] = 0
                expected_message = "at least one ASN"
            changed_payload = multi_header + bytes(chosen) + b"".join(multi_chunks[1:])
            yield _wire_case(case_id, family, changed_payload, expected_message)
        else:
            spec = _constructor_spec(vector)
            base = ip.IPv4Network(spec["base_prefix"])
            child = subnet_at(base, base.prefixlen + 1, 0)
            holder = spec["holder_asn"]
            other = next(asn for asn in ELIGIBLE_ORIGINS if asn != holder)
            if family == "missing-base-constructor":
                spec["max_length"] = max(spec["max_length"], child.prefixlen)
                spec["rules"] = [{"prefix": str(child), "origins": [other], "is_open": True}]
                expected_message = "policy must contain exactly one base Stripe"
            elif family == "missing-holder-constructor":
                spec["rules"] = [{"prefix": str(base), "origins": [other], "is_open": True}]
                expected_message = "base Stripe must explicitly name holder_asn"
            elif family == "duplicate-prefix-constructor":
                spec["rules"] = [dict(spec["rules"][-1]), dict(spec["rules"][-1])]
                expected_message = "duplicate Stripe prefix"
            elif family == "outside-rule-constructor":
                spec["rules"].append(
                    {"prefix": str(outside_peer(base)), "origins": [other], "is_open": False}
                )
                expected_message = "lies outside base"
            elif family == "overlong-rule-constructor":
                spec["max_length"] = base.prefixlen
                spec["rules"].append(
                    {"prefix": str(child), "origins": [other], "is_open": False}
                )
                expected_message = "exceeds max_length"
            elif family == "boolean-max-length-constructor":
                spec["max_length"] = True
                expected_message = "max_length must be int"
            elif family == "boolean-holder-constructor":
                spec["holder_asn"] = True
                expected_message = "holder_asn must be int"
            elif family == "zero-holder-constructor":
                spec["holder_asn"] = 0
                expected_message = "holder ASN out of range"
            elif family == "boolean-open-constructor":
                spec["rules"][0] = {**spec["rules"][0], "is_open": 1}
                expected_message = "is_open must be bool"
            elif family == "zero-asn-constructor":
                spec["rules"][0] = {**spec["rules"][0], "origins": [0]}
                expected_message = "ASN out of range: 0"
            else:  # pragma: no cover - INVALID_FAMILIES is frozen above.
                raise AssertionError(f"unhandled invalid family: {family}")
            yield _constructor_case(case_id, family, spec, expected_message)


def evaluate_invalid_object(case: dict[str, Any]) -> dict[str, Any]:
    try:
        if case["input_kind"] == "wire":
            DAROA.deserialize(bytes.fromhex(case["payload_hex"]))
        elif case["input_kind"] == "constructor":
            spec = case["spec"]
            DAROA(
                spec["base_prefix"],
                spec["max_length"],
                spec["holder_asn"],
                [
                    Stripe(rule["prefix"], set(rule["origins"]), rule["is_open"])
                    for rule in spec["rules"]
                ],
            )
        else:
            raise GateFailure(f"unknown invalid input kind: {case['input_kind']}")
    except Exception as exc:
        message = str(exc)
        target_matched = case["expected_message_substring"] in message
        return {
            "schema_version": "e1a-invalid-result-v3",
            "id": case["id"],
            "family": case["family"],
            "rejected": True,
            "target_matched": target_matched,
            "exception": type(exc).__name__,
            "message": message,
        }
    return {
        "schema_version": "e1a-invalid-result-v3",
        "id": case["id"],
        "family": case["family"],
        "rejected": False,
        "target_matched": False,
        "exception": None,
        "message": "invalid object unexpectedly accepted",
    }


def projection_check_rows(
    policy: OraclePolicy,
    projected: Iterable[VRP],
) -> list[dict[str, Any]]:
    """Fail closed unless every projected authorization is exact and Explicit."""

    rows: list[dict[str, Any]] = []
    for vrp in projected:
        prefix_length = vrp.network.prefixlen
        exact_length = vrp.max_length == prefix_length
        oracle_state = classify(policy, vrp.prefix, vrp.origin_asn).value
        conventional_state = conventional_rov(vrp.prefix, vrp.origin_asn, [vrp]).value
        rows.append(
            {
                "prefix": vrp.prefix,
                "origin_asn": vrp.origin_asn,
                "max_length": vrp.max_length,
                "exact_length": exact_length,
                "oracle_state": oracle_state,
                "conventional_state": conventional_state,
                "unsafe": (
                    not exact_length
                    or conventional_state != "Valid"
                    or oracle_state != "Explicit"
                ),
            }
        )
    return rows


def run_projection_negative_controls() -> dict[str, Any]:
    policy = OraclePolicy(
        "10.0.0.0/8",
        24,
        15169,
        (
            OracleRule("10.0.0.0/8", frozenset({15169}), True),
            OracleRule("10.1.0.0/16", frozenset({16509}), False),
        ),
    )
    bad = VRP("10.0.0.0/8", 15169, 24)
    checks = projection_check_rows(policy, [bad])
    descendant_conventional = conventional_rov(
        "10.1.0.0/24", 15169, [bad]
    ).value
    descendant_native = classify(policy, "10.1.0.0/24", 15169).value
    detected = (
        len(checks) == 1
        and checks[0]["unsafe"]
        and not checks[0]["exact_length"]
        and descendant_conventional == "Valid"
        and descendant_native == "Invalid"
    )
    return {
        "schema_version": "e1a-projection-negative-control-v3",
        "check_count": 1,
        "failure_count": int(not detected),
        "rows": [
            {
                "name": "broad-maxLength-crosses-nested-closed-rule",
                "detected": detected,
                "projection_check": checks[0],
                "critical_descendant": "10.1.0.0/24",
                "critical_descendant_conventional": descendant_conventional,
                "critical_descendant_native": descendant_native,
            }
        ],
    }


def evaluate_vector(vector: dict[str, Any]) -> dict[str, Any]:
    pure = oracle_policy(vector)
    expected = classify(pure, vector["route_prefix"], vector["origin_asn"]).value
    reference = reference_policy(vector)
    encoded = reference.serialize()
    decoded = DAROA.deserialize(encoded)
    reference_state = OPEN_SCOPE_MAP[
        reference.validate_route(vector["route_prefix"], vector["origin_asn"])
    ]
    decoded_state = OPEN_SCOPE_MAP[
        decoded.validate_route(vector["route_prefix"], vector["origin_asn"])
    ]
    orders = rule_orders(vector)
    permutation_payloads = [reference_policy(vector, order=order).serialize() for order in orders]
    order_dependent = any(payload != encoded for payload in permutation_payloads)

    projected = [VRP(prefix, asn, max_length) for prefix, asn, max_length in flatten_to_vrps(reference)]
    projection_checks = projection_check_rows(pure, projected)
    projection_failures = [row for row in projection_checks if row["unsafe"]]
    projection_state = conventional_rov(
        vector["route_prefix"],
        vector["origin_asn"],
        projected,
    ).value

    base = pure.base_network
    aggregate_vrp = [VRP(str(base), pure.holder_asn, pure.max_length)]
    baseline = vector["baseline_policy"]
    exact_vrp = [
        VRP(
            baseline["target_prefix"],
            baseline["intended_origin_asn"],
            ip.IPv4Network(baseline["target_prefix"]).prefixlen,
        )
    ]
    b4_regular = exact_vrp if baseline["regular_exact_present"] else []
    selected = selected_rule(pure, vector["route_prefix"])
    mismatch = not (expected == reference_state == decoded_state)
    derived_route = derive_route_mode(
        pure.base_network,
        pure.max_length,
        [
            (rule.network, rule.origins, rule.is_open)
            for rule in pure.rules
        ],
        ip.IPv4Network(vector["route_prefix"], strict=True),
    )
    derived_origin = derive_origin_mode(
        [(rule.network, rule.origins, rule.is_open) for rule in pure.rules],
        ip.IPv4Network(vector["route_prefix"], strict=True),
        vector["origin_asn"],
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "id": vector["id"],
        "source": vector["source"],
        "expected": expected,
        "reference": reference_state,
        "roundtrip": decoded_state,
        "semantic_mismatch": mismatch,
        "order_dependent": order_dependent,
        "permutation_check_count": len(orders),
        "forbidden_state_upgrade_count": len(projection_failures),
        "projection_vrp_count": len(projection_checks),
        "projection_census_sha256": hashlib.sha256(
            canonical_json(projection_checks).encode("ascii")
        ).hexdigest(),
        "projection_failures": projection_failures,
        "canonical_payload_sha256": hashlib.sha256(encoded).hexdigest(),
        "selected_rule_prefix": selected.prefix if selected else None,
        "selected_rule_mode": (
            "open" if selected and selected.is_open else "closed" if selected else "none"
        ),
        "baseline_b1_aggregate": conventional_rov(
            vector["route_prefix"], vector["origin_asn"], aggregate_vrp
        ).value,
        "baseline_b3_exact": conventional_rov(
            vector["route_prefix"], vector["origin_asn"], [*aggregate_vrp, *exact_vrp]
        ).value,
        "baseline_b4_exact": wildcard_exact(
            baseline["target_prefix"],
            vector["route_prefix"],
            vector["origin_asn"],
            b4_regular,
        ).value,
        "legacy_projection": projection_state,
        "route_mode": derived_route,
        "origin_mode": derived_origin,
        "metadata_mismatch": (
            vector["route_mode"] != derived_route or vector["origin_mode"] != derived_origin
        ),
    }


def mutation_payloads() -> list[tuple[str, bytes]]:
    policy = DAROA(
        "10.0.0.0/16",
        25,
        15169,
        [
            Stripe("10.0.0.0/16", {15169}, True),
            Stripe("10.0.1.0/25", {16509}, False),
        ],
    )
    payload = policy.serialize()
    chunks = [stripe.serialize() for stripe in policy.stripes]
    child_start = 14
    child = chunks[0]
    base = chunks[1]
    prefix_bytes = (child[0] + 7) // 8
    flags_offset = child_start + 1 + prefix_bytes
    count_offset = flags_offset + 1
    asn_offset = count_offset + 1
    mutations: list[tuple[str, bytes]] = []

    for index in range(len(payload)):
        mutations.append((f"truncation-{index:03d}", payload[:index]))

    def changed(name: str, offset: int, value: int) -> None:
        document = bytearray(payload)
        document[offset] = value
        mutations.append((name, bytes(document)))

    changed("unsupported-version", 10, 2)
    changed("nonzero-header-flags", 13, 1)
    changed("noncanonical-base", 3, 1)
    changed("invalid-stripe-prefix-length", child_start, 33)
    changed("noncanonical-stripe-prefix", child_start + 1 + prefix_bytes - 1, 1)
    changed("nonzero-stripe-flags", flags_offset, payload[flags_offset] | 0x80)
    changed("unknown-as-set-type", flags_offset, 0x04)
    changed("zero-list-count", count_offset, 0)
    zero_asn = bytearray(payload)
    zero_asn[asn_offset : asn_offset + 4] = b"\x00\x00\x00\x00"
    mutations.append(("asn-zero", bytes(zero_asn)))

    duplicate_asn_child = (
        child[: 1 + prefix_bytes + 1]
        + b"\x02"
        + child[1 + prefix_bytes + 2 : 1 + prefix_bytes + 6] * 2
    )
    mutations.append(("duplicate-asn", payload[:14] + duplicate_asn_child + base))

    duplicate_prefix = bytearray(payload[:14])
    duplicate_prefix[11:13] = (3).to_bytes(2, "big")
    mutations.append(("duplicate-stripe-prefix", bytes(duplicate_prefix) + child + child + base))
    mutations.append(("noncanonical-stripe-order", payload[:14] + base + child))
    mutations.append(("trailing-byte", payload + b"\x00"))

    multi_policy = DAROA(
        "10.0.0.0/16",
        25,
        15169,
        [
            Stripe("10.0.0.0/16", {15169}, True),
            Stripe("10.0.1.0/25", {13335, 16509}, False),
        ],
    )
    multi_payload = multi_policy.serialize()
    multi_child = multi_policy.stripes[0].serialize()
    multi_base = multi_policy.stripes[1].serialize()
    multi_prefix_bytes = (multi_child[0] + 7) // 8
    multi_asn_start = 1 + multi_prefix_bytes + 2
    reversed_multi_child = (
        multi_child[:multi_asn_start]
        + multi_child[multi_asn_start + 4 : multi_asn_start + 8]
        + multi_child[multi_asn_start : multi_asn_start + 4]
    )
    mutations.append(
        (
            "noncanonical-asn-order",
            multi_payload[:14] + reversed_multi_child + multi_base,
        )
    )
    return mutations


def run_mutation_census() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    accepted = 0
    for name, payload in mutation_payloads():
        try:
            DAROA.deserialize(payload)
        except Exception as exc:  # Expected rejection is part of this census.
            rows.append(
                {
                    "name": name,
                    "rejected": True,
                    "exception": type(exc).__name__,
                    "message": str(exc),
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
        else:
            accepted += 1
            rows.append(
                {
                    "name": name,
                    "rejected": False,
                    "exception": None,
                    "message": "mutation unexpectedly accepted",
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                }
            )

    constructors = (
        (
            "missing-base-rule",
            lambda: DAROA("10.0.0.0/16", 24, 15169, []),
        ),
        (
            "missing-holder-at-base",
            lambda: DAROA(
                "10.0.0.0/16",
                24,
                15169,
                [Stripe("10.0.0.0/16", {16509}, True)],
            ),
        ),
        (
            "duplicate-prefix-constructor",
            lambda: DAROA(
                "10.0.0.0/16",
                24,
                15169,
                [
                    Stripe("10.0.0.0/16", {15169}, True),
                    Stripe("10.0.0.0/16", {15169}, False),
                ],
            ),
        ),
        (
            "outside-rule",
            lambda: DAROA(
                "10.0.0.0/16",
                24,
                15169,
                [
                    Stripe("10.0.0.0/16", {15169}, True),
                    Stripe("10.1.0.0/24", {16509}, False),
                ],
            ),
        ),
        (
            "overlong-rule",
            lambda: DAROA(
                "10.0.0.0/16",
                23,
                15169,
                [
                    Stripe("10.0.0.0/16", {15169}, True),
                    Stripe("10.0.1.0/24", {16509}, False),
                ],
            ),
        ),
        (
            "boolean-max-length",
            lambda: DAROA(
                "0.0.0.0/0",
                True,
                15169,
                [Stripe("0.0.0.0/0", {15169}, True)],
            ),
        ),
    )
    for name, constructor in constructors:
        try:
            constructor()
        except Exception as exc:
            rows.append(
                {
                    "name": name,
                    "rejected": True,
                    "exception": type(exc).__name__,
                    "message": str(exc),
                    "payload_sha256": None,
                }
            )
        else:
            accepted += 1
            rows.append(
                {
                    "name": name,
                    "rejected": False,
                    "exception": None,
                    "message": "malformed constructor unexpectedly accepted",
                    "payload_sha256": None,
                }
            )

    valid_route_policy = one_rule_policy("10.0.0.0/8", 24, 15169, True)
    route_calls = (
        ("boolean-route-origin", lambda: valid_route_policy.validate_route("10.1.0.0/16", True)),
        ("zero-route-origin", lambda: valid_route_policy.validate_route("10.1.0.0/16", 0)),
        (
            "overflow-route-origin",
            lambda: valid_route_policy.validate_route("10.1.0.0/16", 0x100000000),
        ),
        (
            "noncanonical-route-prefix",
            lambda: valid_route_policy.validate_route("10.1.2.3/16", 13335),
        ),
    )
    for name, route_call in route_calls:
        try:
            route_call()
        except Exception as exc:
            rows.append(
                {
                    "name": name,
                    "rejected": True,
                    "exception": type(exc).__name__,
                    "message": str(exc),
                    "payload_sha256": None,
                }
            )
        else:
            accepted += 1
            rows.append(
                {
                    "name": name,
                    "rejected": False,
                    "exception": None,
                    "message": "malformed route unexpectedly accepted",
                    "payload_sha256": None,
                }
            )
    return {
        "mutation_count": len(rows),
        "rejected_count": len(rows) - accepted,
        "unexpected_accept_count": accepted,
        "rows": rows,
    }


def envelope(
    object_id: str,
    policy: DAROA,
    *,
    serial: int = 1,
    revoked: bool = False,
    not_before: int = 1_999_999_900,
    not_after: int = 2_000_000_100,
) -> PolicyEnvelope:
    return PolicyEnvelope(
        issuer="ta.example",
        object_id=object_id,
        profile_version=1,
        object_serial=serial,
        not_before=not_before,
        not_after=not_after,
        revoked=revoked,
        policy=policy,
    )


def one_rule_policy(base: str, max_length: int, holder: int, is_open: bool) -> DAROA:
    return DAROA(base, max_length, holder, [Stripe(base, {holder}, is_open)])


def run_composition_census() -> dict[str, Any]:
    """Differentially check implementation snapshots against an independent oracle."""

    now = 2_000_000_000
    rows: list[dict[str, Any]] = []

    def check(name: str, condition: bool, detail: Any) -> None:
        rows.append({"name": name, "pass": bool(condition), "detail": detail})

    def oracle_item(
        object_id: str,
        base: str,
        max_length: int,
        holder: int,
        is_open: bool,
        *,
        issuer: str = "ta.example",
        profile_version: int = 1,
        serial: int = 1,
        revoked: bool = False,
        not_before: int = now - 100,
        not_after: int = now + 100,
    ) -> SnapshotOracleEnvelope:
        return SnapshotOracleEnvelope(
            issuer=issuer,
            object_id=object_id,
            profile_version=profile_version,
            object_serial=serial,
            not_before=not_before,
            not_after=not_after,
            revoked=revoked,
            base_prefix=base,
            max_length=max_length,
            holder_asn=holder,
            rules=(SnapshotOracleRule(base, {holder}, is_open),),
        )

    impl_broad = envelope("broad", one_rule_policy("10.0.0.0/8", 24, 15169, True))
    impl_nested = envelope("nested", one_rule_policy("10.1.0.0/16", 24, 16509, False))
    oracle_broad = oracle_item("broad", "10.0.0.0/8", 24, 15169, True)
    oracle_nested = oracle_item("nested", "10.1.0.0/16", 24, 16509, False)
    impl_first = PolicySnapshot(7, now, [impl_broad, impl_nested])
    impl_second = PolicySnapshot(7, now, [impl_nested, impl_broad])
    oracle_first = SnapshotOracle(7, now, [oracle_broad, oracle_nested])
    oracle_second = SnapshotOracle(7, now, [oracle_nested, oracle_broad])
    check(
        "composition-order-independent",
        impl_first.canonical_bytes() == impl_second.canonical_bytes()
        and oracle_first.canonical_bytes() == oracle_second.canonical_bytes(),
        {"implementation": impl_first.sha256(), "oracle": oracle_first.sha256()},
    )

    for name, prefix, origin, expected in (
        ("most-specific-base-selected", "10.1.1.0/24", 13335, "Invalid"),
        ("broader-open-remains-active-outside-nested", "10.2.0.0/24", 13335, "OpenScope"),
    ):
        impl_state = OPEN_SCOPE_MAP[impl_first.validate_route(prefix, origin)]
        oracle_state = oracle_first.validate_route(prefix, origin).value
        check(
            name,
            impl_state == oracle_state == expected,
            {"implementation": impl_state, "oracle": oracle_state, "expected": expected},
        )

    def differential_rejection(
        name: str,
        implementation_call: Any,
        oracle_call: Any,
    ) -> None:
        outcomes: dict[str, dict[str, str] | None] = {"implementation": None, "oracle": None}
        for label, call, expected_error in (
            ("implementation", implementation_call, SnapshotError),
            ("oracle", oracle_call, SnapshotOracleError),
        ):
            try:
                call()
            except expected_error as exc:
                outcomes[label] = {"exception": type(exc).__name__, "message": str(exc)}
        check(name, all(outcomes.values()), outcomes)

    differential_rejection(
        "same-base-conflict-rejected",
        lambda: PolicySnapshot(
            8,
            now,
            [impl_broad, envelope("conflict", one_rule_policy("10.0.0.0/8", 24, 16509, False))],
        ),
        lambda: SnapshotOracle(
            8,
            now,
            [oracle_broad, oracle_item("conflict", "10.0.0.0/8", 24, 16509, False)],
        ),
    )
    check(
        "identity-duplicate-deduplicated",
        len(PolicySnapshot(8, now, [impl_broad, impl_broad]).envelopes) == 1
        and len(SnapshotOracle(8, now, [oracle_broad, oracle_broad]).envelopes) == 1,
        "one canonical envelope on both paths",
    )
    differential_rejection(
        "identity-content-collision-rejected",
        lambda: PolicySnapshot(
            8,
            now,
            [impl_broad, envelope("broad", impl_broad.policy, serial=2)],
        ),
        lambda: SnapshotOracle(
            8,
            now,
            [oracle_broad, oracle_item("broad", "10.0.0.0/8", 24, 15169, True, serial=2)],
        ),
    )

    lifecycle_variants = (
        (
            "expired-object-inactive",
            {"not_before": now - 200, "not_after": now},
        ),
        (
            "future-object-inactive",
            {"not_before": now + 1, "not_after": now + 200},
        ),
        ("revoked-object-inactive", {"revoked": True}),
    )
    for name, kwargs in lifecycle_variants:
        impl = envelope(
            name,
            impl_broad.policy,
            not_before=kwargs.get("not_before", now - 100),
            not_after=kwargs.get("not_after", now + 100),
            revoked=kwargs.get("revoked", False),
        )
        oracle = oracle_item(
            name,
            "10.0.0.0/8",
            24,
            15169,
            True,
            **kwargs,
        )
        impl_state = OPEN_SCOPE_MAP[
            PolicySnapshot(9, now, [impl]).validate_route("10.2.0.0/24", 13335)
        ]
        oracle_state = SnapshotOracle(9, now, [oracle]).validate_route(
            "10.2.0.0/24", 13335
        ).value
        check(
            name,
            impl_state == oracle_state == "NotFound",
            {"implementation": impl_state, "oracle": oracle_state},
        )

    differential_rejection(
        "unsupported-profile-rejected",
        lambda: envelope("unsupported", impl_broad.policy, serial=1).__class__(
            issuer="ta.example",
            object_id="unsupported",
            profile_version=2,
            object_serial=1,
            not_before=now - 100,
            not_after=now + 100,
            revoked=False,
            policy=impl_broad.policy,
        ),
        lambda: oracle_item(
            "unsupported", "10.0.0.0/8", 24, 15169, True, profile_version=2
        ),
    )

    impl_store = SnapshotStore()
    oracle_store = SnapshotOracleStore()
    impl_initial = PolicySnapshot(10, now, [impl_broad])
    oracle_initial = SnapshotOracle(10, now, [oracle_broad])
    check(
        "initial-snapshot-applied",
        impl_store.apply(impl_initial) and oracle_store.apply(oracle_initial),
        "both stores changed",
    )
    impl_replay = PolicySnapshot(10, now, [envelope("broad", impl_broad.policy)])
    oracle_replay = SnapshotOracle(
        10,
        now,
        [oracle_item("broad", "10.0.0.0/8", 24, 15169, True)],
    )
    check(
        "independent-identical-replay-idempotent",
        not impl_store.apply(impl_replay) and not oracle_store.apply(oracle_replay),
        "both stores returned false",
    )
    differential_rejection(
        "same-serial-content-collision-rejected",
        lambda: impl_store.apply(
            PolicySnapshot(
                10,
                now,
                [envelope("other", one_rule_policy("10.0.0.0/8", 24, 16509, True))],
            )
        ),
        lambda: oracle_store.apply(
            SnapshotOracle(
                10,
                now,
                [oracle_item("other", "10.0.0.0/8", 24, 16509, True)],
            )
        ),
    )
    impl_withdrawn = PolicySnapshot(11, now + 1, [])
    oracle_withdrawn = SnapshotOracle(11, now + 1, [])
    check(
        "higher-serial-withdrawal-applied",
        impl_store.apply(impl_withdrawn) and oracle_store.apply(oracle_withdrawn),
        "both stores changed",
    )
    impl_state = OPEN_SCOPE_MAP[impl_store.validate_route("10.2.0.0/24", 13335)]
    oracle_state = oracle_store.validate_route("10.2.0.0/24", 13335).value
    check(
        "withdrawal-removes-policy",
        impl_state == oracle_state == "NotFound",
        {"implementation": impl_state, "oracle": oracle_state},
    )
    differential_rejection(
        "rollback-rejected",
        lambda: impl_store.apply(impl_initial),
        lambda: oracle_store.apply(oracle_initial),
    )

    return {
        "schema_version": "e1a-snapshot-differential-v2",
        "oracle": "experiments.semantic_gate.snapshot_oracle",
        "check_count": len(rows),
        "failure_count": sum(not row["pass"] for row in rows),
        "rows": rows,
    }


def run_baseline_matrix() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []

    def add(name: str, actual: str, expected: str) -> None:
        rows.append(
            {"name": name, "actual": actual, "expected": expected, "pass": actual == expected}
        )

    aggregate = VRP("10.0.0.0/16", 15169, 24)
    exact = VRP("10.0.1.0/24", 16509, 24)
    add("B1 aggregate holder", conventional_rov("10.0.0.0/16", 15169, [aggregate]).value, "Valid")
    add("B1 unnamed child", conventional_rov("10.0.2.0/24", 16509, [aggregate]).value, "Invalid")
    add("B3 exact intended", conventional_rov("10.0.1.0/24", 16509, [aggregate, exact]).value, "Valid")
    add("B3 exact competitor", conventional_rov("10.0.1.0/24", 13335, [aggregate, exact]).value, "Invalid")
    add("B4 exact wildcard", wildcard_exact("10.0.1.0/24", "10.0.1.0/24", 13335).value, "WildcardValid")
    add("B4 does not cover descendant", wildcard_exact("10.0.1.0/24", "10.0.1.0/25", 13335).value, "NotFound")
    add("B4 regular priority match", wildcard_exact("10.0.1.0/24", "10.0.1.0/24", 16509, [exact]).value, "RegularValid")
    add("B4 regular priority reject", wildcard_exact("10.0.1.0/24", "10.0.1.0/24", 13335, [exact]).value, "Invalid")

    policy = OraclePolicy(
        "10.0.0.0/16",
        24,
        15169,
        (
            OracleRule("10.0.0.0/16", frozenset({15169}), True),
            OracleRule("10.0.1.0/24", frozenset({16509}), False),
            OracleRule("10.0.0.0/20", frozenset({18403}), True),
        ),
    )
    add("S2 aggregate explicit", classify(policy, "10.0.0.0/16", 15169).value, "Explicit")
    add("S2 exact unlisted invalid", classify(policy, "10.0.0.0/16", 13335).value, "Invalid")
    add("S2 closed child explicit", classify(policy, "10.0.1.0/24", 16509).value, "Explicit")
    add("S2 closed child unlisted invalid", classify(policy, "10.0.1.0/24", 13335).value, "Invalid")
    add("W2 intended open scope", classify(policy, "10.0.3.0/24", 8075).value, "OpenScope")
    add("W2 impostor observation equivalent", classify(policy, "10.0.3.0/24", 13335).value, "OpenScope")
    add("W5 unshadowed holder descendant explicit", classify(policy, "10.0.32.0/24", 15169).value, "Explicit")
    add("W5 shadowed holder at nested exact invalid", classify(policy, "10.0.0.0/20", 15169).value, "Invalid")
    add("W5 shadowed holder below nested open", classify(policy, "10.0.3.0/24", 15169).value, "OpenScope")
    add("T1 OpenScope action", str(action_for_state("OpenScope", "T1-accept")), "('accept', 300)")
    add("T2 OpenScope action", str(action_for_state("OpenScope", "T2-deprefer")), "('accept', 200)")
    add("T3 OpenScope action", str(action_for_state("OpenScope", "T3-reject")), "('reject', None)")
    return {
        "case_count": len(rows),
        "failure_count": sum(not row["pass"] for row in rows),
        "rows": rows,
    }


def execution_source_paths() -> tuple[Path, ...]:
    static_paths = {
        Path(__file__).resolve(),
        REPOSITORY_ROOT / "experiments" / "semantic_gate" / "__init__.py",
        REPOSITORY_ROOT / "experiments" / "semantic_gate" / "oracle.py",
        REPOSITORY_ROOT / "experiments" / "semantic_gate" / "snapshot_oracle.py",
        REPOSITORY_ROOT / "experiments" / "semantic_gate" / "compare_runs.py",
        REPOSITORY_ROOT / "experiments" / "semantic_gate" / "EXPERIMENT_CONTRACT.md",
        REPOSITORY_ROOT / "experiments" / "semantic_gate" / "frozen_v3" / "__init__.py",
        REPOSITORY_ROOT / "experiments" / "semantic_gate" / "frozen_v3" / "daroa.py",
        REPOSITORY_ROOT / "experiments" / "semantic_gate" / "frozen_v3" / "as_set.py",
        REPOSITORY_ROOT / "experiments" / "semantic_gate" / "frozen_v3" / "snapshot.py",
        REPOSITORY_ROOT / "experiments" / "semantic_gate" / "frozen_v3" / "flatten.py",
        REPOSITORY_ROOT / "experiments" / "semantic_gate" / "frozen_v3" / "DESIGN.md",
        REPOSITORY_ROOT
        / "."
        / "experiment_redesign"
        / "EXPERIMENT_REDESIGN.md",
    }
    loaded_paths: set[Path] = set()
    repository_root = REPOSITORY_ROOT.resolve()
    for module in tuple(sys.modules.values()):
        raw_path = getattr(module, "__file__", None)
        if not raw_path:
            continue
        path = Path(raw_path).resolve()
        if path.suffix == ".pyc" and path.with_suffix(".py").exists():
            path = path.with_suffix(".py")
        try:
            path.relative_to(repository_root)
        except ValueError:
            continue
        if path.is_file():
            loaded_paths.add(path)
    return tuple(sorted(static_paths | loaded_paths))


def planned_artifact_paths(source_hashes: dict[str, str]) -> list[str]:
    fixed = {
        "REPORT.md",
        "baseline_matrix.json",
        "composition_results.json",
        "coverage.json",
        "differential_results.jsonl",
        "invalid_objects.jsonl",
        "invalid_results.jsonl",
        "manifest.initial.json",
        "manifest.json",
        "mutation_results.json",
        "projection_census.json",
        "reproducer.py",
        "semantic_vectors.jsonl",
        "source_bundle_manifest.json",
        "summary.json",
    }
    fixed.update(f"source_bundle/{relative}" for relative in source_hashes)
    return sorted(fixed)


def artifact_allowlist_diff(
    planned: Iterable[str],
    actual: Iterable[str],
) -> tuple[list[str], list[str]]:
    planned_set = set(planned)
    actual_set = set(actual)
    return sorted(planned_set - actual_set), sorted(actual_set - planned_set)


def environment_document() -> dict[str, Any]:
    source_paths = execution_source_paths()
    status = git_text("status", "--porcelain=v1")
    return {
        "git_commit": git_text("rev-parse", "HEAD"),
        "git_status": status.splitlines(),
        "git_diff_sha256": hashlib.sha256(
            git_text("diff", "--binary").encode("utf-8")
        ).hexdigest(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "cpu_count": os.cpu_count(),
        "source_sha256": {
            str(path.relative_to(REPOSITORY_ROOT)): sha256_file(path) for path in source_paths
        },
    }


def archive_source_bundle(output: Path, source_hashes: dict[str, str]) -> dict[str, Any]:
    bundle = output / "source_bundle"
    bundle.mkdir()
    digest = hashlib.sha256()
    for relative, expected_hash in sorted(source_hashes.items()):
        source = REPOSITORY_ROOT / relative
        destination = bundle / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        actual_hash = sha256_file(destination)
        if actual_hash != expected_hash:
            raise GateFailure(f"source bundle hash mismatch for {relative}")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(source.read_bytes())
        digest.update(b"\x00")
    document = {
        "schema_version": "e1a-source-bundle-v3",
        "files": source_hashes,
        "bundle_content_sha256": digest.hexdigest(),
        "restore_note": "Copy files over the recorded git commit, then verify every hash before execution.",
    }
    write_json(output / "source_bundle_manifest.json", document)
    return document


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_reproducer(
    path: Path,
    source_hashes: dict[str, str],
    expected_outputs: dict[str, str],
) -> None:
    script = f'''#!/usr/bin/env python3
"""Verify E1a V3 sources, rerun, and compare deterministic outputs."""
from __future__ import annotations
import hashlib
from pathlib import Path
import subprocess
import sys

SOURCE_HASHES = {source_hashes!r}
EXPECTED_OUTPUTS = {expected_outputs!r}

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

root = Path(subprocess.check_output(
    ["git", "rev-parse", "--show-toplevel"], text=True
).strip())
for relative, expected in SOURCE_HASHES.items():
    actual = sha256(root / relative)
    if actual != expected:
        raise SystemExit(
            f"source mismatch: {{relative}} {{actual}} != {{expected}}; "
            "restore the bundled source first"
        )
output = Path(sys.argv[1] if len(sys.argv) > 1 else "runs/e1a-v3-reproduction")
if not output.is_absolute():
    output = root / output
subprocess.run(
    [
        sys.executable,
        "-m",
        "experiments.semantic_gate.run_e1a",
        "--output-dir",
        str(output),
        "--seed",
        "{DEFAULT_SEED}",
        "--generated-vectors",
        "{DEFAULT_GENERATED}",
        "--invalid-seed",
        "{DEFAULT_INVALID_SEED}",
        "--invalid-objects",
        "{DEFAULT_INVALID_GENERATED}",
    ],
    cwd=root,
    check=True,
)
for relative, expected in EXPECTED_OUTPUTS.items():
    actual = sha256(output / relative)
    if actual != expected:
        raise SystemExit(f"output mismatch: {{relative}} {{actual}} != {{expected}}")
print("E1a V3 deterministic outputs match")
'''
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def recursive_file_hashes(output: Path, *, exclude: set[str] | None = None) -> dict[str, str]:
    excluded = exclude or set()
    return {
        str(path.relative_to(output)): sha256_file(path)
        for path in sorted(output.rglob("*"))
        if path.is_file() and str(path.relative_to(output)) not in excluded
    }


def _main_v1_obsolete() -> int:
    """Retained only to document the superseded V1 execution path."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--generated-vectors", type=int, default=DEFAULT_GENERATED)
    parser.add_argument("--hard-timeout-seconds", type=float, default=1800.0)
    args = parser.parse_args()
    if args.seed != DEFAULT_SEED:
        raise GateFailure(f"production contract requires seed {DEFAULT_SEED}")
    if args.generated_vectors != DEFAULT_GENERATED:
        raise GateFailure(
            f"production contract requires {DEFAULT_GENERATED} generated vectors"
        )
    if args.hard_timeout_seconds <= 0:
        raise GateFailure("hard timeout must be positive")

    output = normalize_output_path(args.output_dir)
    failure_dir = output / "fuzz_failures"
    failure_dir.mkdir()
    start_wall = time.monotonic()
    start_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    environment = environment_document()
    initial_manifest = {
        "schema_version": "e1a-manifest-v1",
        "status": "RUNNING",
        "started_at_utc": start_utc,
        "seed": args.seed,
        "generated_vectors_planned": args.generated_vectors,
        "hard_timeout_seconds": args.hard_timeout_seconds,
        "environment": environment,
        "contract_sha256": environment["source_sha256"][
            "experiments/semantic_gate/EXPERIMENT_CONTRACT.md"
        ],
    }
    write_json(output / "manifest.running.json", initial_manifest)

    vectors_path = output / "semantic_vectors.jsonl"
    results_path = output / "differential_results.jsonl"
    coverage: dict[str, Counter[str]] = {
        "source": Counter(),
        "expected_state": Counter(),
        "route_mode": Counter(),
        "origin_mode": Counter(),
        "selected_rule_mode": Counter(),
        "state_route_pair": Counter(),
    }
    counts = Counter()
    scientific_digest = hashlib.sha256()
    generated_seen = 0
    bounded_seen = 0

    with vectors_path.open("x", encoding="utf-8") as vector_handle, results_path.open(
        "x", encoding="utf-8"
    ) as result_handle:
        for vector in chain(
            exhaustive_vectors(),
            generated_vectors(args.seed, args.generated_vectors),
        ):
            if time.monotonic() - start_wall > args.hard_timeout_seconds:
                raise GateFailure("hard timeout reached; partial outputs retained")
            result = evaluate_vector(vector)
            vector_line = canonical_json(vector)
            result_line = canonical_json(result)
            vector_handle.write(vector_line + "\n")
            result_handle.write(result_line + "\n")
            scientific_digest.update(result_line.encode("ascii"))
            scientific_digest.update(b"\n")

            counts["total_vectors"] += 1
            counts["semantic_mismatch_count"] += int(result["semantic_mismatch"])
            counts["order_dependent_count"] += int(result["order_dependent"])
            counts["forbidden_state_upgrade_count"] += int(
                result["forbidden_state_upgrade"]
            )
            if vector["source"] == "property-generated":
                generated_seen += 1
            else:
                bounded_seen += 1
            coverage["source"][vector["source"]] += 1
            coverage["expected_state"][result["expected"]] += 1
            coverage["route_mode"][vector["route_mode"]] += 1
            coverage["origin_mode"][vector["origin_mode"]] += 1
            coverage["selected_rule_mode"][result["selected_rule_mode"]] += 1
            coverage["state_route_pair"][
                f"{result['expected']}|{vector['route_mode']}"
            ] += 1

            if (
                result["semantic_mismatch"]
                or result["order_dependent"]
                or result["forbidden_state_upgrade"]
            ):
                failure_path = failure_dir / f"{vector['id']}.json"
                write_json(failure_path, {"vector": vector, "result": result})

            if counts["total_vectors"] % 4096 == 0:
                vector_handle.flush()
                result_handle.flush()
                os.fsync(vector_handle.fileno())
                os.fsync(result_handle.fileno())

    mutation = run_mutation_census()
    composition = run_composition_census()
    baseline = run_baseline_matrix()
    write_json(output / "mutation_results.json", mutation)
    write_json(output / "composition_results.json", composition)
    write_json(output / "baseline_matrix.json", baseline)

    required_states = {state.value for state in OracleState}
    required_routes = {
        "outside",
        "exact_base",
        "proper_descendant",
        "exact_nested_rule",
        "descendant_of_nested_rule",
        "overlength",
    }
    coverage_failures = []
    missing_states = sorted(required_states - set(coverage["expected_state"]))
    missing_routes = sorted(required_routes - set(coverage["route_mode"]))
    if missing_states:
        coverage_failures.append(f"missing states: {missing_states}")
    if missing_routes:
        coverage_failures.append(f"missing route modes: {missing_routes}")
    if generated_seen != args.generated_vectors:
        coverage_failures.append(
            f"generated count {generated_seen} != planned {args.generated_vectors}"
        )
    if bounded_seen == 0:
        coverage_failures.append("bounded exhaustive corpus is empty")

    coverage_document = {
        key: dict(sorted(counter.items())) for key, counter in coverage.items()
    }
    coverage_document["bounded_vectors"] = bounded_seen
    coverage_document["generated_vectors"] = generated_seen
    coverage_document["coverage_failures"] = coverage_failures
    write_json(output / "coverage.json", coverage_document)

    counts["parser_unexpected_accept_count"] = mutation["unexpected_accept_count"]
    counts["composition_failure_count"] = composition["failure_count"]
    counts["baseline_failure_count"] = baseline["failure_count"]
    counts["coverage_failure_count"] = len(coverage_failures)
    passed = all(
        counts[key] == 0
        for key in (
            "semantic_mismatch_count",
            "order_dependent_count",
            "forbidden_state_upgrade_count",
            "parser_unexpected_accept_count",
            "composition_failure_count",
            "baseline_failure_count",
            "coverage_failure_count",
        )
    )
    elapsed = time.monotonic() - start_wall
    peak_rss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    summary = {
        "schema_version": "e1a-summary-v1",
        "status": "PASS" if passed else "FAIL",
        "counts": dict(counts),
        "bounded_vectors": bounded_seen,
        "generated_vectors": generated_seen,
        "scientific_results_sha256": scientific_digest.hexdigest(),
        "vectors_file_sha256": sha256_file(vectors_path),
        "results_file_sha256": sha256_file(results_path),
        "elapsed_seconds": elapsed,
        "peak_rss_kib": peak_rss_kib,
        "failure_artifacts": len(list(failure_dir.glob("*.json"))),
    }
    write_json(output / "summary.json", summary)
    report = f"""# E1a Semantic Differential Result

## Material Passport

- Origin skills: `ts-paper-experiment`, `academic-research-suite/experiment-agent`
- Origin mode: run
- Experiment ID: E1a
- Status: {'PASS' if passed else 'FAIL'}
- Command seed: {args.seed}
- Generated vectors: {generated_seen:,}
- Bounded exhaustive vectors: {bounded_seen:,}
- Verification status: {'VERIFIED BY COMPLETE LOCAL RERUN' if passed else 'FAILED; SEE REPRODUCERS'}

## Hard endpoints

| Endpoint | Count | Criterion |
|---|---:|---:|
| Semantic mismatches | {counts['semantic_mismatch_count']} | 0 |
| Order-dependent encodings | {counts['order_dependent_count']} | 0 |
| Forbidden legacy upgrades | {counts['forbidden_state_upgrade_count']} | 0 |
| Unexpected parser accepts | {counts['parser_unexpected_accept_count']} | 0 |
| Composition/lifecycle failures | {counts['composition_failure_count']} | 0 |
| Baseline-oracle failures | {counts['baseline_failure_count']} | 0 |
| Coverage failures | {counts['coverage_failure_count']} | 0 |

Elapsed wall time: {elapsed:.3f} s. Peak process RSS: {peak_rss_kib / 1024:.2f} MiB.

Scientific result digest: `{scientific_digest.hexdigest()}`.

## Boundary

This result closes E1a only. The snapshot layer is a pure executable contract,
not a CMS/RPKI object or RP/router carrier. E1b and E2 remain mandatory before
the redesigned E3–E6 production experiments can support system or deployment
claims.
"""
    (output / "REPORT.md").write_text(report, encoding="utf-8")
    reproducer = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "cd \"$(git rev-parse --show-toplevel)\"\n"
        "python3 -m experiments.semantic_gate.run_e1a "
        "--output-dir runs/e1a-reproduction "
        f"--seed {args.seed} --generated-vectors {args.generated_vectors}\n"
    )
    reproducer_path = output / "reproducer.sh"
    reproducer_path.write_text(reproducer, encoding="utf-8")
    reproducer_path.chmod(0o755)

    final_manifest = {
        **initial_manifest,
        "status": "COMPLETE_PASS" if passed else "COMPLETE_FAIL",
        "completed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary_sha256": sha256_file(output / "summary.json"),
        "output_sha256": {
            path.name: sha256_file(path)
            for path in sorted(output.iterdir())
            if path.is_file() and path.name != "manifest.running.json"
        },
    }
    write_json(output / "manifest.json", final_manifest)

    print(canonical_json(summary))
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--generated-vectors", type=int, default=DEFAULT_GENERATED)
    parser.add_argument("--invalid-seed", type=int, default=DEFAULT_INVALID_SEED)
    parser.add_argument("--invalid-objects", type=int, default=DEFAULT_INVALID_GENERATED)
    parser.add_argument("--hard-timeout-seconds", type=float, default=1800.0)
    args = parser.parse_args()
    frozen_arguments = {
        "seed": (args.seed, DEFAULT_SEED),
        "generated-vectors": (args.generated_vectors, DEFAULT_GENERATED),
        "invalid-seed": (args.invalid_seed, DEFAULT_INVALID_SEED),
        "invalid-objects": (args.invalid_objects, DEFAULT_INVALID_GENERATED),
    }
    for name, (actual, expected) in frozen_arguments.items():
        if actual != expected:
            raise GateFailure(f"production contract requires {name}={expected}")
    if args.hard_timeout_seconds <= 0:
        raise GateFailure("hard timeout must be positive")

    output = normalize_output_path(args.output_dir)
    failure_dir = output / "fuzz_failures"
    failure_dir.mkdir()
    start_wall = time.monotonic()
    start_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    environment = environment_document()
    source_bundle = archive_source_bundle(output, environment["source_sha256"])
    planned_allowed_artifacts = planned_artifact_paths(environment["source_sha256"])
    initial_manifest = {
        "schema_version": "e1a-manifest-v3",
        "status": "RUNNING",
        "verification_status": "UNVERIFIED_LOCAL_RUN",
        "started_at_utc": start_utc,
        "legal_seed": args.seed,
        "invalid_seed": args.invalid_seed,
        "bounded_vectors_planned": BOUNDED_VECTOR_COUNT,
        "boundary_vectors_planned": BOUNDARY_VECTOR_COUNT,
        "generated_legal_vectors_planned": args.generated_vectors,
        "generated_invalid_objects_planned": args.invalid_objects,
        "hard_timeout_seconds": args.hard_timeout_seconds,
        "environment": environment,
        "source_bundle_content_sha256": source_bundle["bundle_content_sha256"],
        "planned_allowed_artifacts": planned_allowed_artifacts,
        "contract_sha256": environment["source_sha256"][
            "experiments/semantic_gate/EXPERIMENT_CONTRACT.md"
        ],
    }
    write_json(output / "manifest.initial.json", initial_manifest)

    vectors_path = output / "semantic_vectors.jsonl"
    results_path = output / "differential_results.jsonl"
    invalid_objects_path = output / "invalid_objects.jsonl"
    invalid_results_path = output / "invalid_results.jsonl"
    coverage: dict[str, Counter[str]] = {
        "source": Counter(),
        "expected_state": Counter(),
        "route_mode": Counter(),
        "origin_mode": Counter(),
        "selected_rule_mode": Counter(),
        "state_route_pair": Counter(),
        "baseline_b1_state": Counter(),
        "baseline_b3_state": Counter(),
        "baseline_b4_state": Counter(),
        "invalid_family": Counter(),
    }
    counts: Counter[str] = Counter()
    scientific_line_digest = hashlib.sha256()
    projection_digest = hashlib.sha256()
    seen_policy_digests: set[str] = set()

    legal_stream = chain(
        exhaustive_vectors(),
        boundary_vectors(),
        generated_vectors(args.seed, args.generated_vectors),
    )
    with vectors_path.open("x", encoding="utf-8") as vector_handle, results_path.open(
        "x", encoding="utf-8"
    ) as result_handle:
        for vector in legal_stream:
            if time.monotonic() - start_wall > args.hard_timeout_seconds:
                raise GateFailure("hard timeout reached; partial outputs retained")
            result = evaluate_vector(vector)
            vector_line = canonical_json(vector)
            result_line = canonical_json(result)
            vector_handle.write(vector_line + "\n")
            result_handle.write(result_line + "\n")
            scientific_line_digest.update(b"legal\x00")
            scientific_line_digest.update(result_line.encode("ascii"))
            scientific_line_digest.update(b"\n")

            counts["legal_vector_count"] += 1
            counts["semantic_mismatch_count"] += int(result["semantic_mismatch"])
            counts["order_dependent_count"] += int(result["order_dependent"])
            counts["permutation_check_count"] += result["permutation_check_count"]
            counts["metadata_mismatch_count"] += int(result["metadata_mismatch"])
            policy_digest = result["canonical_payload_sha256"]
            if policy_digest not in seen_policy_digests:
                seen_policy_digests.add(policy_digest)
                counts["unique_policy_count"] += 1
                counts["projected_vrp_check_count"] += result["projection_vrp_count"]
                counts["forbidden_state_upgrade_count"] += result[
                    "forbidden_state_upgrade_count"
                ]
                projection_row = {
                    "policy_sha256": policy_digest,
                    "projection_vrp_count": result["projection_vrp_count"],
                    "projection_census_sha256": result["projection_census_sha256"],
                }
                projection_digest.update(canonical_json(projection_row).encode("ascii"))
                projection_digest.update(b"\n")

            source = vector["source"]
            coverage["source"][source] += 1
            coverage["expected_state"][result["expected"]] += 1
            coverage["route_mode"][result["route_mode"]] += 1
            coverage["origin_mode"][result["origin_mode"]] += 1
            coverage["selected_rule_mode"][result["selected_rule_mode"]] += 1
            coverage["state_route_pair"][
                f"{result['expected']}|{result['route_mode']}"
            ] += 1
            for coverage_key, result_key in (
                ("baseline_b1_state", "baseline_b1_aggregate"),
                ("baseline_b3_state", "baseline_b3_exact"),
                ("baseline_b4_state", "baseline_b4_exact"),
            ):
                coverage[coverage_key][result[result_key]] += 1

            if (
                result["semantic_mismatch"]
                or result["order_dependent"]
                or result["forbidden_state_upgrade_count"]
                or result["metadata_mismatch"]
            ):
                write_json(
                    failure_dir / f"{vector['id']}.json",
                    {"vector": vector, "result": result},
                )

            if counts["legal_vector_count"] % 4096 == 0:
                vector_handle.flush()
                result_handle.flush()
                os.fsync(vector_handle.fileno())
                os.fsync(result_handle.fileno())

    with invalid_objects_path.open("x", encoding="utf-8") as object_handle, invalid_results_path.open(
        "x", encoding="utf-8"
    ) as invalid_result_handle:
        for case in generated_invalid_objects(args.invalid_seed, args.invalid_objects):
            if time.monotonic() - start_wall > args.hard_timeout_seconds:
                raise GateFailure("hard timeout reached during invalid stream; partial outputs retained")
            result = evaluate_invalid_object(case)
            case_line = canonical_json(case)
            result_line = canonical_json(result)
            object_handle.write(case_line + "\n")
            invalid_result_handle.write(result_line + "\n")
            scientific_line_digest.update(b"invalid\x00")
            scientific_line_digest.update(result_line.encode("ascii"))
            scientific_line_digest.update(b"\n")
            counts["invalid_object_count"] += 1
            counts["invalid_unexpected_accept_count"] += int(not result["rejected"])
            counts["invalid_wrong_reason_count"] += int(
                result["rejected"] and not result["target_matched"]
            )
            coverage["invalid_family"][case["family"]] += 1
            if not result["rejected"] or not result["target_matched"]:
                write_json(
                    failure_dir / f"{case['id']}.json",
                    {"case": case, "result": result},
                )
            if counts["invalid_object_count"] % 4096 == 0:
                object_handle.flush()
                invalid_result_handle.flush()
                os.fsync(object_handle.fileno())
                os.fsync(invalid_result_handle.fileno())

    projection_negative = run_projection_negative_controls()
    counts["projection_negative_control_failure_count"] = projection_negative[
        "failure_count"
    ]
    projection = {
        "schema_version": "e1a-projection-census-v3",
        "unique_policy_count": counts["unique_policy_count"],
        "projected_vrp_check_count": counts["projected_vrp_check_count"],
        "unsafe_projected_vrp_count": counts["forbidden_state_upgrade_count"],
        "ordered_policy_census_sha256": projection_digest.hexdigest(),
        "negative_control": projection_negative,
    }
    write_json(output / "projection_census.json", projection)

    mutation = run_mutation_census()
    composition = run_composition_census()
    baseline = run_baseline_matrix()
    write_json(output / "mutation_results.json", mutation)
    write_json(output / "composition_results.json", composition)
    write_json(output / "baseline_matrix.json", baseline)

    coverage_failures: list[str] = []

    def require_exact(label: str, actual: int, expected: int) -> None:
        if actual != expected:
            coverage_failures.append(f"{label} {actual} != frozen {expected}")

    required_sets = {
        "expected_state": {state.value for state in OracleState},
        "route_mode": {
            "outside",
            "exact_base",
            "proper_descendant",
            "exact_nested_rule",
            "descendant_of_nested_rule",
            "overlength",
        },
        "origin_mode": {"explicit", "eligible_unlisted", "ineligible"},
        "selected_rule_mode": {"open", "closed", "none"},
        "state_route_pair": {
            "Explicit|exact_base",
            "Explicit|proper_descendant",
            "Explicit|exact_nested_rule",
            "Explicit|descendant_of_nested_rule",
            "OpenScope|proper_descendant",
            "OpenScope|descendant_of_nested_rule",
            "Invalid|exact_base",
            "Invalid|proper_descendant",
            "Invalid|exact_nested_rule",
            "Invalid|descendant_of_nested_rule",
            "Invalid|overlength",
            "NotFound|outside",
        },
        "baseline_b1_state": {"Valid", "Invalid", "NotFound"},
        "baseline_b3_state": {"Valid", "Invalid", "NotFound"},
        "baseline_b4_state": {"RegularValid", "WildcardValid", "Invalid", "NotFound"},
        "invalid_family": set(INVALID_FAMILIES),
    }
    for key, required in required_sets.items():
        missing = sorted(required - set(coverage[key]))
        if missing:
            coverage_failures.append(f"{key} missing: {missing}")

    require_exact(
        "bounded exhaustive count",
        coverage["source"]["bounded-exhaustive"],
        BOUNDED_VECTOR_COUNT,
    )
    require_exact(
        "deterministic boundary count",
        coverage["source"]["deterministic-boundary"],
        BOUNDARY_VECTOR_COUNT,
    )
    require_exact(
        "generated legal count",
        coverage["source"]["property-generated"],
        args.generated_vectors,
    )
    require_exact("generated invalid count", counts["invalid_object_count"], args.invalid_objects)
    require_exact(
        "legal total",
        counts["legal_vector_count"],
        BOUNDED_VECTOR_COUNT + BOUNDARY_VECTOR_COUNT + args.generated_vectors,
    )

    coverage_document: dict[str, Any] = {
        key: dict(sorted(counter.items())) for key, counter in coverage.items()
    }
    coverage_document.update(
        {
            "schema_version": "e1a-coverage-v3",
            "coverage_failures": coverage_failures,
            "bounded_vectors": coverage["source"]["bounded-exhaustive"],
            "boundary_vectors": coverage["source"]["deterministic-boundary"],
            "generated_legal_vectors": coverage["source"]["property-generated"],
            "generated_invalid_objects": counts["invalid_object_count"],
        }
    )
    write_json(output / "coverage.json", coverage_document)

    counts["fixed_parser_unexpected_accept_count"] = mutation["unexpected_accept_count"]
    counts["invalid_object_failure_count"] = (
        counts["invalid_unexpected_accept_count"] + counts["invalid_wrong_reason_count"]
    )
    counts["composition_failure_count"] = composition["failure_count"]
    counts["baseline_failure_count"] = baseline["failure_count"]
    counts["coverage_failure_count"] = len(coverage_failures)
    hard_zero_keys = (
        "semantic_mismatch_count",
        "order_dependent_count",
        "forbidden_state_upgrade_count",
        "projection_negative_control_failure_count",
        "metadata_mismatch_count",
        "fixed_parser_unexpected_accept_count",
        "invalid_object_failure_count",
        "composition_failure_count",
        "baseline_failure_count",
        "coverage_failure_count",
    )
    passed = all(counts[key] == 0 for key in hard_zero_keys)
    elapsed = time.monotonic() - start_wall
    peak_rss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    deterministic_names = (
        "semantic_vectors.jsonl",
        "differential_results.jsonl",
        "invalid_objects.jsonl",
        "invalid_results.jsonl",
        "projection_census.json",
        "mutation_results.json",
        "composition_results.json",
        "baseline_matrix.json",
        "coverage.json",
    )
    deterministic_outputs = {
        name: sha256_file(output / name) for name in deterministic_names
    }
    scientific_results_sha256 = hashlib.sha256(
        canonical_json(deterministic_outputs).encode("ascii")
    ).hexdigest()
    summary = {
        "schema_version": "e1a-summary-v3",
        "status": "PASS" if passed else "FAIL",
        "verification_status": "UNVERIFIED_LOCAL_RUN",
        "counts": dict(sorted(counts.items())),
        "scientific_line_digest_sha256": scientific_line_digest.hexdigest(),
        "scientific_results_sha256": scientific_results_sha256,
        "deterministic_output_sha256": deterministic_outputs,
        "elapsed_seconds": elapsed,
        "peak_rss_kib": peak_rss_kib,
        "failure_artifacts": len(list(failure_dir.glob("*.json"))),
    }
    write_json(output / "summary.json", summary)

    report = f"""# E1a V3 Semantic Differential Result

## Material Passport

- Origin skills: `ts-paper-experiment`, `academic-research-suite/experiment-agent`
- Origin mode: run
- Contract: `e1a-v3-audit-repair`
- Status: {'PASS' if passed else 'FAIL'}
- Verification status: UNVERIFIED LOCAL RUN; a separate complete-run comparison is required
- Legal seed / generated vectors: {args.seed} / {args.generated_vectors:,}
- Invalid seed / generated objects: {args.invalid_seed} / {args.invalid_objects:,}
- Bounded / deterministic-boundary vectors: {BOUNDED_VECTOR_COUNT:,} / {BOUNDARY_VECTOR_COUNT:,}

## Hard endpoints

| Endpoint | Count | Criterion |
|---|---:|---:|
| Semantic mismatches | {counts['semantic_mismatch_count']} | 0 |
| Order-dependent encodings | {counts['order_dependent_count']} | 0 |
| Unsafe projected VRPs | {counts['forbidden_state_upgrade_count']} | 0 |
| Projection negative-control failures | {counts['projection_negative_control_failure_count']} | 0 |
| Generated-invalid failures | {counts['invalid_object_failure_count']} | 0 |
| Fixed parser unexpected accepts | {counts['fixed_parser_unexpected_accept_count']} | 0 |
| Snapshot differential failures | {counts['composition_failure_count']} | 0 |
| Baseline-oracle failures | {counts['baseline_failure_count']} | 0 |
| Coverage/metadata failures | {counts['coverage_failure_count'] + counts['metadata_mismatch_count']} | 0 |

The projection census checked {counts['projected_vrp_check_count']:,} VRPs from
{counts['unique_policy_count']:,} unique policies. Rule-order testing executed
{counts['permutation_check_count']:,} canonicalization checks. Elapsed wall time
was {elapsed:.3f} s; peak process RSS was {peak_rss_kib / 1024:.2f} MiB.

Scientific output digest: `{scientific_results_sha256}`.

## Boundary

This local run can close E1a only after a separate, complete reproduction
matches every deterministic output. Even then, the snapshot layer is a pure
executable contract, not a CMS/RPKI object or RP/router carrier. E1b and E2
remain mandatory before redesigned E3--E6 can support system or deployment
claims.
"""
    (output / "REPORT.md").write_text(report, encoding="utf-8")
    write_reproducer(
        output / "reproducer.py",
        environment["source_sha256"],
        deterministic_outputs,
    )

    artifact_hashes = recursive_file_hashes(output, exclude={"manifest.json"})
    actual_allowed_artifacts = set(artifact_hashes) | {"manifest.json"}
    missing_artifacts, extra_artifacts = artifact_allowlist_diff(
        planned_allowed_artifacts, actual_allowed_artifacts
    )
    if passed and (missing_artifacts or extra_artifacts):
        raise GateFailure(
            "artifact allowlist mismatch: "
            f"missing={missing_artifacts}, extra={extra_artifacts}"
        )
    final_manifest = {
        **initial_manifest,
        "status": "COMPLETE_PASS" if passed else "COMPLETE_FAIL",
        "verification_status": "UNVERIFIED_LOCAL_RUN",
        "completed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary_sha256": sha256_file(output / "summary.json"),
        "scientific_results_sha256": scientific_results_sha256,
        "artifact_sha256": artifact_hashes,
        "allowed_artifacts": planned_allowed_artifacts,
        "failure_artifacts": sorted(
            str(path.relative_to(output)) for path in failure_dir.glob("*.json")
        ),
    }
    write_json(output / "manifest.json", final_manifest)

    print(canonical_json(summary))
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateFailure as exc:
        print(f"E1a gate failure: {exc}", file=sys.stderr)
        raise SystemExit(2)
