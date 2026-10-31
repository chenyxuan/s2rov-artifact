"""Canonical ordering for records whose prefixes carry exact semantics."""
from __future__ import annotations

from typing import List

from .daroa import Stripe


def merge_stripes(stripes: List[Stripe]) -> List[Stripe]:
    """Return records in canonical order without changing their prefixes.

    Non-base explicit records represent exact ROAs, so CIDR aggregation would
    change authorization semantics.  Marker aggregation would likewise expand
    the marked region.  The historical function name is retained for callers.
    """
    result = list(stripes)
    result.sort(
        key=lambda stripe: (
            stripe.ip_version,
            -stripe.prefix_length,
            stripe.prefix_int,
        )
    )
    return result


def merge_ratio(stripes_before: List[Stripe], stripes_after: List[Stripe]) -> float:
    """Return before/after Stripe-count ratio."""
    if not stripes_after:
        return 1.0
    return len(stripes_before) / len(stripes_after)
