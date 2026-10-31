"""DA-ROA: Core data structures and binary serialization.

Implements the DA-ROA wire format specified in DESIGN.md §2.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import List, Mapping, Tuple, TypeAlias
import ipaddress as ip
import struct

from .as_set import AsSetType, decode, encode, validate_as_set


IPNetwork: TypeAlias = ip.IPv4Network | ip.IPv6Network

_COMMON_HEADER_SIZE = 14
_IPV6_HEADER_SIZE = 30
_IPV4_WIRE_VERSION = 0x01
_IPV6_WIRE_VERSION = 0x02
_IPV6_HEADER_TAG = b"IPv6"


class ValidationState(str, Enum):
    """S2-ROV result with authorization provenance kept explicit."""

    EXPLICIT = "Explicit"
    DELEGATED = "Delegated"
    # Compatibility alias.  Existing experiment outputs retain the historical
    # ``Delegated`` wire label while the policy semantics call this state
    # OpenScope.
    OPEN_SCOPE = "Delegated"
    INVALID = "Invalid"
    NOT_FOUND = "NotFound"


def is_eligible_delegated_origin(asn: int) -> bool:
    """Return whether an ASN is eligible for an OpenScope marker.

    OpenScope is deliberately not an origin-authentication mechanism. The
    gate only excludes values that cannot be treated as ordinary public
    origins: AS0, AS_TRANS, documentation/reserved ranges, and private-use
    ASNs from RFC 6996.
    """
    if asn <= 0 or asn > 0xFFFFFFFF or asn == 23456:
        return False
    if 64496 <= asn <= 65535:
        return False
    # Documentation ASNs followed by the currently reserved 32-bit block.
    if 65536 <= asn <= 131071:
        return False
    if 4200000000 <= asn <= 4294967295:
        return False
    return True


@dataclass(frozen=True)
class Stripe:
    """A prefix record with explicit origins and an optional OpenScope marker.

    Attributes:
        prefix: CIDR prefix string (e.g., "10.0.0.0/24")
        as_set: Explicitly named origin ASNs.  At the base they use the
            policy maxLength; at a non-base prefix they are exact.  Empty
            means none are named.
        is_open: Compatibility name for the serialized OpenScope marker bit.
            ``False`` means that the prefix has no marker.  It does not create
            a restrictive region or override markers on covering prefixes.
    """
    prefix: str
    as_set: frozenset[int]
    is_open: bool = False
    _net: IPNetwork = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        network = ip.ip_network(self.prefix, strict=False)
        object.__setattr__(self, "_net", network)
        object.__setattr__(self, "prefix", str(network))
        if not isinstance(self.is_open, bool):
            raise TypeError("is_open must be bool")
        try:
            canonical_as_set = frozenset(self.as_set)
        except TypeError as exc:
            raise TypeError("as_set must be an iterable of ASNs") from exc
        validate_as_set(canonical_as_set)
        object.__setattr__(self, "as_set", canonical_as_set)

    @property
    def network(self) -> IPNetwork:
        return self._net

    @property
    def ip_version(self) -> int:
        return self._net.version

    @property
    def prefix_length(self) -> int:
        return self._net.prefixlen

    @property
    def prefix_int(self) -> int:
        return int(self._net.network_address)

    @property
    def has_openscope_marker(self) -> bool:
        """Return whether this prefix carries the OpenScope marker."""
        return self.is_open

    def serialize(self) -> bytes:
        """Serialize this Stripe to binary (DESIGN.md §2.2)."""
        plen = self.prefix_length
        prefix_bytes = self._net.network_address.packed

        # Encode AS set
        as_type, as_data = encode(self.as_set)

        # Flags byte: bit 0 = OpenScope marker, bits 1-2 = AS-set type,
        # bits 3-7 reserved.
        flags = (1 if self.is_open else 0) | (int(as_type) << 1)

        # Prefix length (1) + prefix bytes (ceil(plen/8)) + flags (1) + AS data
        return struct.pack("!B", plen) + prefix_bytes[:((plen + 7) // 8)] + struct.pack("!B", flags) + as_data

    @classmethod
    def deserialize(
        cls,
        data: bytes,
        offset: int = 0,
        ip_version: int = 4,
    ) -> Tuple[Stripe, int]:
        """Deserialize a Stripe from bytes. Returns (stripe, next_offset)."""
        if isinstance(ip_version, bool) or ip_version not in (4, 6):
            raise ValueError(f"unsupported IP version for Stripe: {ip_version}")
        if offset < 0 or offset >= len(data):
            raise ValueError("truncated Stripe: missing prefix length")
        plen = data[offset]
        address_bits = 32 if ip_version == 4 else 128
        if plen > address_bits:
            raise ValueError(
                f"invalid IPv{ip_version} Stripe prefix length: {plen}"
            )
        prefix_byte_len = (plen + 7) // 8
        prefix_end = offset + 1 + prefix_byte_len
        if prefix_end >= len(data):
            raise ValueError("truncated Stripe prefix or flags")
        prefix_bytes = data[offset + 1:offset + 1 + prefix_byte_len]
        address_bytes = address_bits // 8
        prefix_padded = prefix_bytes + b'\x00' * (address_bytes - prefix_byte_len)
        address_type = ip.IPv4Address if ip_version == 4 else ip.IPv6Address
        network_type = ip.IPv4Network if ip_version == 4 else ip.IPv6Network
        address = address_type(int.from_bytes(prefix_padded, "big"))
        network = network_type(f"{address}/{plen}", strict=False)
        canonical_prefix_bytes = network.network_address.packed[:prefix_byte_len]
        if prefix_bytes != canonical_prefix_bytes:
            raise ValueError("non-canonical Stripe prefix has host bits set")
        prefix_str = str(network)

        offset2 = offset + 1 + prefix_byte_len
        flags = data[offset2]
        if flags & 0xF8:
            raise ValueError(f"reserved Stripe flag bits are nonzero: 0x{flags:02x}")
        is_open = bool(flags & 0x01)
        as_type_val = (flags >> 1) & 0x03
        try:
            as_type = AsSetType(as_type_val)
        except ValueError as exc:
            raise ValueError(f"unknown AS-set type: {as_type_val}") from exc

        offset3 = offset2 + 1
        # Determine AS data length based on type
        if as_type == AsSetType.EMPTY:
            as_data = b""
        elif as_type == AsSetType.LIST:
            if offset3 >= len(data):
                raise ValueError("truncated AS-set list: missing count")
            count = data[offset3]
            encoded_length = 1 + count * 4
            if offset3 + encoded_length > len(data):
                raise ValueError("truncated AS-set list payload")
            as_data = data[offset3:offset3 + encoded_length]
            offset3 += encoded_length
        else:
            raise ValueError(f"Unknown AS set type: {as_type}")

        as_set = decode(as_type, as_data)
        return Stripe(prefix_str, as_set, is_open), offset3


@dataclass(frozen=True)
class DAROA:
    """A Delegation-Aware Route Origin Authorization.

    Attributes:
        base_prefix: The allocation root prefix (e.g., "10.0.0.0/16").
        max_length: Maximum prefix length covered by this DA-ROA.
        holder_asn: The ASN of the address space holder.
        stripes: Ordered list of Stripes.
    """
    base_prefix: str
    max_length: int
    holder_asn: int
    stripes: tuple[Stripe, ...] = field(default_factory=tuple)
    _base_net: IPNetwork = field(init=False, repr=False, compare=False)
    _stripe_index: Mapping[tuple[int, int], Stripe] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self):
        base_network = ip.ip_network(self.base_prefix, strict=False)
        object.__setattr__(self, "_base_net", base_network)
        object.__setattr__(self, "base_prefix", str(base_network))
        try:
            stripes = tuple(self.stripes)
        except TypeError as exc:
            raise TypeError("stripes must be an iterable of Stripe values") from exc
        for stripe in stripes:
            if not isinstance(stripe, Stripe):
                raise TypeError(f"expected Stripe, got {type(stripe).__name__}")
        # The wire format is canonical: logically equivalent policies must not
        # depend on the caller's list order.
        canonical_stripes = tuple(
            sorted(
                stripes,
                key=lambda stripe: (-stripe.prefix_length, stripe.prefix_int),
            )
        )
        object.__setattr__(self, "stripes", canonical_stripes)
        self._validate()
        self._rebuild_index()

    def _validate(self) -> None:
        if isinstance(self.max_length, bool) or not isinstance(self.max_length, int):
            raise TypeError("max_length must be int")
        address_bits = self._base_net.max_prefixlen
        if not self.base_prefix_length <= self.max_length <= address_bits:
            raise ValueError(
                f"max_length {self.max_length} outside "
                f"[{self.base_prefix_length}, {address_bits}]"
            )
        if isinstance(self.holder_asn, bool) or not isinstance(self.holder_asn, int):
            raise TypeError("holder_asn must be int")
        if not 1 <= self.holder_asn <= 0xFFFFFFFF:
            raise ValueError(f"holder ASN out of range: {self.holder_asn}")
        if len(self.stripes) > 0xFFFF:
            raise ValueError("too many Stripes for 16-bit count")

        by_prefix: dict[str, Stripe] = {}
        markers: list[Stripe] = []
        for stripe in self.stripes:
            if not isinstance(stripe, Stripe):
                raise TypeError(f"expected Stripe, got {type(stripe).__name__}")
            if stripe.ip_version != self.ip_version:
                raise ValueError(
                    f"Stripe {stripe.prefix} and base {self.base_prefix} "
                    "use different address families"
                )
            if not stripe.network.subnet_of(self._base_net):
                raise ValueError(
                    f"Stripe {stripe.prefix} lies outside base {self.base_prefix}"
                )
            if stripe.prefix_length > self.max_length:
                raise ValueError(
                    f"Stripe {stripe.prefix} exceeds max_length {self.max_length}"
                )
            if (
                stripe.has_openscope_marker
                and stripe.prefix_length >= self.max_length
            ):
                raise ValueError(
                    "OpenScope marker must have proper descendants within "
                    f"max_length: {stripe.prefix}"
                )
            if stripe.prefix in by_prefix:
                raise ValueError(f"duplicate Stripe prefix: {stripe.prefix}")
            by_prefix[stripe.prefix] = stripe
            if stripe.has_openscope_marker:
                markers.append(stripe)

        # OpenScope regions need no selection or precedence rule.  CIDR
        # regions are intervals, so overlap can be detected from adjacent
        # markers after sorting by their first address.  Ordinary explicit
        # records are intentionally excluded: they may lie inside a marked
        # region and take precedence for their listed origins.
        ordered_markers = sorted(markers, key=lambda item: item.prefix_int)
        for left, right in zip(ordered_markers, ordered_markers[1:]):
            if right.prefix_int <= int(left.network.broadcast_address):
                raise ValueError(
                    "OpenScope markers must be prefix-disjoint: "
                    f"{left.prefix} overlaps {right.prefix}"
                )

        base = by_prefix.get(self.base_prefix)
        if base is None:
            raise ValueError("policy must contain exactly one base Stripe")
        if self.holder_asn not in base.as_set:
            raise ValueError("base Stripe must explicitly name holder_asn")

    def _rebuild_index(self) -> None:
        """Build an index for prefix-ancestor probes."""
        index: dict[tuple[int, int], Stripe] = {}
        for stripe in self.stripes:
            key = (stripe.prefix_length, stripe.prefix_int)
            index[key] = stripe
        object.__setattr__(self, "_stripe_index", MappingProxyType(index))

    @property
    def base_network(self) -> IPNetwork:
        return self._base_net

    @property
    def ip_version(self) -> int:
        return self._base_net.version

    @property
    def base_prefix_length(self) -> int:
        return self._base_net.prefixlen

    def serialize(self) -> bytes:
        """Serialize this DA-ROA to binary (DESIGN.md §2.1)."""
        base_bytes = self._base_net.network_address.packed
        plen = self.base_prefix_length
        n_stripes = len(self.stripes)

        if self.ip_version == 4:
            # Wire version 1 is retained byte-for-byte for compatibility with
            # the original IPv4-only reference format.
            header = struct.pack(
                "!4sBBIBHB",
                base_bytes,
                plen,
                self.max_length,
                self.holder_asn,
                _IPV4_WIRE_VERSION,
                n_stripes,
                0,
            )
        else:
            # Wire version 2 keeps the common field offsets, uses a fixed tag
            # in the legacy four-byte address slot, and appends the full IPv6
            # base address.  A version-1 parser therefore rejects it safely.
            header = struct.pack(
                "!4sBBIBHB16s",
                _IPV6_HEADER_TAG,
                plen,
                self.max_length,
                self.holder_asn,
                _IPV6_WIRE_VERSION,
                n_stripes,
                0,
                base_bytes,
            )

        stripe_data = b"".join(s.serialize() for s in self.stripes)
        return header + stripe_data

    @classmethod
    def deserialize(cls, data: bytes) -> DAROA:
        """Deserialize a DA-ROA from binary."""
        if len(data) < _COMMON_HEADER_SIZE:
            raise ValueError("truncated DA-ROA header")
        plen = data[4]
        max_len = data[5]
        holder_asn = struct.unpack("!I", data[6:10])[0]
        version = data[10]
        n_stripes = struct.unpack("!H", data[11:13])[0]
        flags = data[13]
        if flags:
            raise ValueError(f"reserved DA-ROA flags are nonzero: 0x{flags:02x}")

        if version == _IPV4_WIRE_VERSION:
            ip_version = 4
            header_size = _COMMON_HEADER_SIZE
            base_bytes = data[0:4]
            address_type = ip.IPv4Address
            network_type = ip.IPv4Network
            address_bits = 32
        elif version == _IPV6_WIRE_VERSION and data[0:4] == _IPV6_HEADER_TAG:
            if len(data) < _IPV6_HEADER_SIZE:
                raise ValueError("truncated IPv6 DA-ROA header")
            ip_version = 6
            header_size = _IPV6_HEADER_SIZE
            base_bytes = data[_COMMON_HEADER_SIZE:_IPV6_HEADER_SIZE]
            address_type = ip.IPv6Address
            network_type = ip.IPv6Network
            address_bits = 128
        else:
            raise ValueError(
                f"unsupported DA-ROA version or header tag: {version}"
            )

        if plen > address_bits:
            raise ValueError(f"invalid IPv{ip_version} base prefix length: {plen}")
        base_address = address_type(int.from_bytes(base_bytes, "big"))
        base_network = network_type(f"{base_address}/{plen}", strict=False)
        if base_bytes != base_network.network_address.packed:
            raise ValueError("non-canonical base prefix has host bits set")
        prefix_str = str(base_network)

        offset = header_size
        stripes = []
        for _ in range(n_stripes):
            stripe, offset = Stripe.deserialize(data, offset, ip_version)
            stripes.append(stripe)
        if offset != len(data):
            raise ValueError(f"trailing bytes after DA-ROA payload: {len(data)-offset}")

        canonical_prefix_order = sorted(
            (stripe.prefix for stripe in stripes),
            key=lambda prefix: (
                -ip.ip_network(prefix).prefixlen,
                int(ip.ip_network(prefix).network_address),
            ),
        )
        if [stripe.prefix for stripe in stripes] != canonical_prefix_order:
            raise ValueError("non-canonical Stripe order")

        return DAROA(prefix_str, max_len, holder_asn, stripes)

    def add_stripe(self, stripe: Stripe) -> DAROA:
        """Return a new policy containing the Stripe in canonical order."""
        return DAROA(
            self.base_prefix,
            self.max_length,
            self.holder_asn,
            (*self.stripes, stripe),
        )

    def _covering_stripes(self, target: IPNetwork) -> tuple[Stripe, ...]:
        """Return every record covering ``target`` without selecting one."""
        target_int = int(target.network_address)
        address_bits = target.max_prefixlen
        full_mask = (1 << address_bits) - 1
        covering: list[Stripe] = []

        for plen in range(target.prefixlen, -1, -1):
            mask = (
                (full_mask << (address_bits - plen)) & full_mask
                if plen
                else 0
            )
            candidate = self._stripe_index.get((plen, target_int & mask))
            if candidate is not None:
                covering.append(candidate)

        return tuple(covering)

    def validate_route(self, target_prefix: str, origin_asn: int) -> ValidationState:
        """Classify a route using conventional ROA matches and scope markers.

        The base record carries the conventional ``(base, origin,
        max_length)`` entries.  Every non-base explicit record is exact
        because the wire format has no per-record maxLength.  A covering
        record still supplies conventional coverage even when its origin does
        not match or the route is too specific.  OpenScope refines only such
        covered Invalid routes and is bounded by the policy maxLength.
        """
        target = ip.ip_network(target_prefix, strict=True)
        if isinstance(origin_asn, bool) or not isinstance(origin_asn, int):
            raise TypeError("route origin ASN must be an integer")
        if not 1 <= origin_asn <= 0xFFFFFFFF:
            raise ValueError(f"route origin ASN out of range: {origin_asn}")
        if target.version != self.ip_version:
            return ValidationState.NOT_FOUND
        if not target.subnet_of(self._base_net):
            return ValidationState.NOT_FOUND

        covering = self._covering_stripes(target)
        if not covering:
            return ValidationState.NOT_FOUND

        conventional_match = any(
            origin_asn in stripe.as_set
            and (
                (
                    stripe.prefix == self.base_prefix
                    and target.prefixlen <= self.max_length
                )
                or (
                    stripe.prefix != self.base_prefix
                    and target == stripe.network
                )
            )
            for stripe in covering
        )
        if conventional_match:
            return ValidationState.EXPLICIT
        if (
            target.prefixlen <= self.max_length
            and is_eligible_delegated_origin(origin_asn)
            and any(
                stripe.has_openscope_marker
                and target.prefixlen > stripe.prefix_length
                for stripe in covering
            )
        ):
            return ValidationState.OPEN_SCOPE
        return ValidationState.INVALID

    def size_bytes(self) -> int:
        """Return the total wire-format size in bytes."""
        return len(self.serialize())

    def vrp_count_rfc6811(self) -> int:
        """Return the number of standard VRPs this DA-ROA would produce when flattened."""
        return len(self.flatten_to_vrps())

    def flatten_to_vrps(self) -> List[Tuple[str, int, int]]:
        """Flatten to standard (prefix, origin_as, maxLength) VRPs.
        
        Implements DESIGN.md §5.1 algorithm.
        """
        from .flatten import flatten_to_vrps
        return flatten_to_vrps(self)

    def __repr__(self) -> str:
        return (f"DAROA({self.base_prefix}, ℓ={self.max_length}, "
                f"holder=AS{self.holder_asn}, {len(self.stripes)} stripes)")
