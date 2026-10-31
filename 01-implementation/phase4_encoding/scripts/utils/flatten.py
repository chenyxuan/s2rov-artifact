"""VRP flattening and standard ROA derivation.

Implements DESIGN.md §4 (Standard VRP Derivation) and §5 (VRP Flattening).
"""
from __future__ import annotations

import ipaddress as ip
from typing import List, Set, Tuple

from .daroa import DAROA, ValidationState


def derive_standard_roa(daroa: DAROA) -> Tuple[str, int, int]:
    """Derive a backward-compatible standard ROA from a DA-ROA.

    Returns (prefix, origin_asn, max_length) per DESIGN.md §4.1.

    The base record is the policy's carried conventional ROA entry, so its
    explicit holder origin uses the policy-wide maxLength.
    """
    return (daroa.base_prefix, daroa.holder_asn, daroa.max_length)


def flatten_to_vrps(daroa: DAROA) -> List[Tuple[str, int, int]]:
    """Flatten a DA-ROA to a set of standard (prefix, origin_as, maxLength) VRPs.

    Implements DESIGN.md §5.1 algorithm.

    Returns a deduplicated VRP list in canonical record order.
    """
    vrps: List[Tuple[str, int, int]] = []
    seen_vrps: Set[Tuple[str, int, int]] = set()

    # 1. Self-authorization VRP (base prefix)
    base_prefix = daroa.base_prefix
    base_vrp = derive_standard_roa(daroa)
    vrps.append(base_vrp)
    seen_vrps.add(base_vrp)

    # 2. Explicit origins in the base record use the carried policy maxLength.
    # Every non-base record is exact because the wire format has no per-record
    # maxLength.  A marker itself produces no VRP.
    for stripe in daroa.stripes:
        for asn in sorted(stripe.as_set):
            if stripe.prefix == base_prefix:
                vrp = (stripe.prefix, asn, daroa.max_length)
            else:
                vrp = (stripe.prefix, asn, stripe.prefix_length)
            if vrp not in seen_vrps:
                vrps.append(vrp)
                seen_vrps.add(vrp)

    # 3. Deduplicate exact VRP tuples. Multiple ASNs for the same prefix are
    # legitimate and must not be collapsed.

    return vrps


def flattening_validation(daroa: DAROA) -> bool:
    """Validate representative routes at each projected ROA's boundaries.

    Exact projections are checked at their prefix.  A non-exact maxLength is
    checked at the ROA prefix and at the first and last maxLength subprefixes,
    which exercises both ends of the carried base entry without enumerating
    its address space.
    """
    for prefix, origin_as, max_length in flatten_to_vrps(daroa):
        network = ip.ip_network(prefix)
        if not network.prefixlen <= max_length <= network.max_prefixlen:
            return False
        relevant_routes = [network]
        if max_length > network.prefixlen:
            subnet_size = 1 << (network.max_prefixlen - max_length)
            first = ip.ip_network((int(network.network_address), max_length))
            last_start = int(network.broadcast_address) - subnet_size + 1
            last = ip.ip_network((last_start, max_length))
            relevant_routes.extend((first, last))
        for route in relevant_routes:
            if (
                daroa.validate_route(str(route), origin_as)
                != ValidationState.EXPLICIT
            ):
                return False
    return True
