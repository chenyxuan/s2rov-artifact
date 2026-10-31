"""VRP flattening and standard ROA derivation.

Implements DESIGN.md §4 (Standard VRP Derivation) and §5 (VRP Flattening).
"""
from __future__ import annotations
from typing import List, Set, Tuple

from .daroa import DAROA, ValidationState


def derive_standard_roa(daroa: DAROA) -> Tuple[str, int, int]:
    """Derive a backward-compatible standard ROA from a DA-ROA.

    Returns (prefix, origin_asn, max_length) per DESIGN.md §4.1.

    The conservative projection protects only the exact aggregate.  Using the
    DA policy's descendant max_length here could make holder-origin
    descendants Valid on a legacy router even where a more-specific Stripe
    excludes the holder.
    """
    return (daroa.base_prefix, daroa.holder_asn, daroa.base_prefix_length)


def flatten_to_vrps(daroa: DAROA) -> List[Tuple[str, int, int]]:
    """Flatten a DA-ROA to a set of standard (prefix, origin_as, maxLength) VRPs.

    Implements DESIGN.md §5.1 algorithm.

    Returns deduplicated VRP list (most-specific-first order).
    """
    vrps: List[Tuple[str, int, int]] = []
    seen_vrps: Set[Tuple[str, int, int]] = set()

    # 1. Self-authorization VRP (base prefix)
    base_prefix = daroa.base_prefix
    base_vrp = derive_standard_roa(daroa)
    vrps.append(base_vrp)
    seen_vrps.add(base_vrp)

    # 2. Every explicitly named origin gets an exact-prefix VRP.  Open intent
    # itself produces no VRP, but an open Stripe may also name explicit origins.
    for stripe in daroa.stripes:
        for asn in sorted(stripe.as_set):
            if stripe.prefix == base_prefix and asn == daroa.holder_asn:
                continue
            vrp = (stripe.prefix, asn, stripe.prefix_length)
            if vrp not in seen_vrps:
                vrps.append(vrp)
                seen_vrps.add(vrp)

    # 3. Deduplicate exact VRP tuples. Multiple ASNs for the same prefix are
    # legitimate and must not be collapsed.

    return vrps


def flattening_validation(daroa: DAROA) -> bool:
    """Validate that flattening is safe:
    Every route Valid under RFC 6811 with flattened VRPs
    is also Valid under DA-ROV with the original DA-ROA.
    """
    for prefix, origin_as, max_length in flatten_to_vrps(daroa):
        if max_length != int(prefix.split("/")[1]):
            return False
        if daroa.validate_route(prefix, origin_as) != ValidationState.EXPLICIT:
            return False
    return True
