"""VRP flattening and standard ROA derivation.

Implements DESIGN.md §4 (Standard VRP Derivation) and §5 (VRP Flattening).
"""
from __future__ import annotations
from typing import List, Set, Tuple

from .s2rov import S2ROV, ValidationState


def derive_standard_roa(s2rov: S2ROV) -> Tuple[str, int, int]:
    """Derive a backward-compatible standard ROA from a S2-ROV.

    Returns (prefix, origin_asn, max_length) per DESIGN.md §4.1.

    The conservative projection protects only the exact aggregate.  Using the
    DA policy's descendant max_length here could make holder-origin
    descendants Valid on a legacy router even where a more-specific Stripe
    excludes the holder.
    """
    return (s2rov.base_prefix, s2rov.holder_asn, s2rov.base_prefix_length)


def flatten_to_vrps(s2rov: S2ROV) -> List[Tuple[str, int, int]]:
    """Flatten a S2-ROV to a set of standard (prefix, origin_as, maxLength) VRPs.

    Implements DESIGN.md §5.1 algorithm.

    Returns deduplicated VRP list (most-specific-first order).
    """
    vrps: List[Tuple[str, int, int]] = []
    seen_vrps: Set[Tuple[str, int, int]] = set()

    # 1. Self-authorization VRP (base prefix)
    base_prefix = s2rov.base_prefix
    base_vrp = derive_standard_roa(s2rov)
    vrps.append(base_vrp)
    seen_vrps.add(base_vrp)

    # 2. Every explicitly named origin gets an exact-prefix VRP.  Open intent
    # itself produces no VRP, but an open Stripe may also name explicit origins.
    for stripe in s2rov.stripes:
        for asn in sorted(stripe.as_set):
            if stripe.prefix == base_prefix and asn == s2rov.holder_asn:
                continue
            vrp = (stripe.prefix, asn, stripe.prefix_length)
            if vrp not in seen_vrps:
                vrps.append(vrp)
                seen_vrps.add(vrp)

    # 3. Deduplicate exact VRP tuples. Multiple ASNs for the same prefix are
    # legitimate and must not be collapsed.

    return vrps


def flattening_validation(s2rov: S2ROV) -> bool:
    """Validate that flattening is safe:
    Every route Valid under RFC 6811 with flattened VRPs
    is also Valid under S2-ROV with the original S2-ROV.
    """
    for prefix, origin_as, max_length in flatten_to_vrps(s2rov):
        if max_length != int(prefix.split("/")[1]):
            return False
        if s2rov.validate_route(prefix, origin_as) != ValidationState.EXPLICIT:
            return False
    return True
