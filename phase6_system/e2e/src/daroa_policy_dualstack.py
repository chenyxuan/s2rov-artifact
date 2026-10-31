#!/usr/bin/env python3
"""Dual-stack OpenScope-marker model for the IPv6 handoff lane.

The accepted IPv4 fixture is source-hash-bound to ``daroa_agent.py``.  This
module applies the same classification rules to both IPv4 and IPv6 prefixes.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from daroa_agent import eligible_delegated_origin, parse_asn


IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Stripe:
    network: IpNetwork
    min_length: int
    max_length: int
    origins: frozenset[int]
    is_open: bool
    trust_anchors: frozenset[str]

    def covers(self, route: IpNetwork) -> bool:
        return (
            route.version == self.network.version
            and route.subnet_of(self.network)
        )


class Policy:
    def __init__(self, stripes: Iterable[Stripe]):
        self.stripes = tuple(
            sorted(
                stripes,
                key=lambda item: (
                    -item.network.prefixlen,
                    item.network.version,
                    int(item.network.network_address),
                    item.is_open,
                ),
            )
        )
        by_prefix: dict[IpNetwork, list[Stripe]] = defaultdict(list)
        for stripe in self.stripes:
            by_prefix[stripe.network].append(stripe)
        self._by_prefix = {
            prefix: tuple(entries) for prefix, entries in by_prefix.items()
        }
        markers = [stripe for stripe in self.stripes if stripe.is_open]
        for marker in markers:
            if (
                marker.min_length != marker.network.prefixlen
                or marker.max_length <= marker.network.prefixlen
            ):
                raise ValueError(
                    "OpenScope marker requires minLength equal to its prefix "
                    "length and maxLength greater than its prefix length: "
                    f"{marker.network}: {marker.min_length}-{marker.max_length}"
                )
        for index, marker in enumerate(markers):
            for other in markers[index + 1 :]:
                if (
                    marker.network.version == other.network.version
                    and marker.network.overlaps(other.network)
                ):
                    raise ValueError(
                        "OpenScope markers must be pairwise prefix-disjoint: "
                        f"{marker.network} and {other.network}"
                    )

    @classmethod
    def from_routinator(cls, document: dict[str, Any]) -> "Policy":
        grouped: dict[
            tuple[str, int, int, bool], dict[str, set[Any]]
        ] = defaultdict(lambda: {"origins": set(), "tas": set()})

        for roa in document.get("roas", []):
            network = ipaddress.ip_network(roa["prefix"], strict=False)
            mode = roa.get("inclusivity")
            if mode not in (None, "inclusive", "exclusive"):
                raise ValueError(f"unknown inclusivity value: {mode!r}")
            is_open = mode == "inclusive"
            key = (
                str(network),
                int(roa.get("minLength", network.prefixlen)),
                int(roa.get("maxLength", network.prefixlen)),
                is_open,
            )
            grouped[key]["origins"].add(parse_asn(roa["asn"]))
            grouped[key]["tas"].add(str(roa.get("ta", "unknown")))

        stripes = []
        for (prefix, min_len, max_len, is_open), values in grouped.items():
            network = ipaddress.ip_network(prefix)
            if not (
                network.prefixlen <= min_len <= max_len <= network.max_prefixlen
            ):
                raise ValueError(
                    f"invalid length interval {prefix}: {min_len}-{max_len}"
                )
            stripes.append(
                Stripe(
                    network=network,
                    min_length=min_len,
                    max_length=max_len,
                    origins=frozenset(values["origins"]),
                    is_open=is_open,
                    trust_anchors=frozenset(str(v) for v in values["tas"]),
                )
            )
        return cls(stripes)

    def _covering(self, prefix: str) -> tuple[IpNetwork, list[Stripe]]:
        route = ipaddress.ip_network(prefix, strict=False)
        covering = []
        for length in range(route.prefixlen, -1, -1):
            candidate_prefix = route.supernet(new_prefix=length)
            covering.extend(self._by_prefix.get(candidate_prefix, ()))
        return route, covering

    @staticmethod
    def _best_evidence(entries: Iterable[Stripe]) -> Stripe:
        """Choose deterministic evidence, not a rule controlling the state."""
        return max(
            entries,
            key=lambda item: (
                item.network.prefixlen,
                not item.is_open,
                item.min_length,
                item.max_length,
            ),
        )

    def validate(self, prefix: str, origin: int) -> tuple[str, Stripe | None]:
        route, covering = self._covering(prefix)
        if not covering:
            return "NotFound", None

        explicit = [
            stripe
            for stripe in covering
            if stripe.min_length <= route.prefixlen <= stripe.max_length
            and origin in stripe.origins
        ]
        if explicit:
            return "Explicit", self._best_evidence(explicit)

        if eligible_delegated_origin(origin):
            markers = [
                stripe
                for stripe in covering
                if stripe.is_open
                and stripe.min_length <= route.prefixlen <= stripe.max_length
                and route.prefixlen > stripe.network.prefixlen
            ]
            if markers:
                if len(markers) != 1:
                    raise ValueError(f"multiple OpenScope markers cover {route}")
                return "Delegated", markers[0]
        return "Invalid", None

    def validate_baseline(
        self, prefix: str, origin: int
    ) -> tuple[str, Stripe | None]:
        route = ipaddress.ip_network(prefix, strict=False)
        covering = [
            stripe
            for stripe in self.stripes
            if (
                stripe.network.version == route.version
                and route.subnet_of(stripe.network)
            )
        ]
        if not covering:
            return "NotFound", None
        matching = [
            stripe
            for stripe in covering
            if (
                stripe.min_length <= route.prefixlen <= stripe.max_length
                and origin in stripe.origins
            )
        ]
        if matching:
            return "Valid", max(
                matching, key=lambda item: item.network.prefixlen
            )
        return "Invalid", max(
            covering, key=lambda item: item.network.prefixlen
        )
