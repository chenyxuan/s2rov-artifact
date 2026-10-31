"""S2-ROV: Core data structures and binary serialization.

Implements the S2-ROV wire format specified in DESIGN.md §2.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import List, Mapping, Optional, Tuple
import ipaddress as ip
import struct

from .as_set import AsSetType, decode, encode, validate_as_set


class ValidationState(str, Enum):
    """S2-ROV result with authorization provenance kept explicit."""

    EXPLICIT = "Explicit"
    DELEGATED = "Delegated"
    INVALID = "Invalid"
    NOT_FOUND = "NotFound"


def is_eligible_delegated_origin(asn: int) -> bool:
    """Return whether an ASN is eligible for an open delegation policy.

    Open policy is deliberately not an origin-authentication mechanism. The
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
    """A single authorization Stripe.

    Attributes:
        prefix: CIDR prefix string (e.g., "10.0.0.0/24")
        as_set: Explicitly named origin ASNs.  Empty means none are named.
        is_open: If True, eligible unnamed origins are admitted only for
            proper descendants of this Stripe prefix.
    """
    prefix: str
    as_set: frozenset[int]
    is_open: bool
    _net: ip.IPv4Network = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        network = ip.IPv4Network(self.prefix, strict=False)
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
    def network(self) -> ip.IPv4Network:
        return self._net

    @property
    def prefix_length(self) -> int:
        return self._net.prefixlen

    @property
    def prefix_int(self) -> int:
        return int(self._net.network_address)

    def serialize(self) -> bytes:
        """Serialize this Stripe to binary (DESIGN.md §2.2)."""
        plen = self.prefix_length
        prefix_bytes = self._net.network_address.packed

        # Encode AS set
        as_type, as_data = encode(self.as_set)

        # Flags byte: bit 0 = t, bits 1-2 = AS set type, bits 3-7 reserved
        flags = (1 if self.is_open else 0) | (int(as_type) << 1)

        # Prefix length (1) + prefix bytes (ceil(plen/8)) + flags (1) + AS data
        return struct.pack("!B", plen) + prefix_bytes[:((plen + 7) // 8)] + struct.pack("!B", flags) + as_data

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> Tuple[Stripe, int]:
        """Deserialize a Stripe from bytes. Returns (stripe, next_offset)."""
        if offset < 0 or offset >= len(data):
            raise ValueError("truncated Stripe: missing prefix length")
        plen = data[offset]
        if plen > 32:
            raise ValueError(f"invalid IPv4 Stripe prefix length: {plen}")
        prefix_byte_len = (plen + 7) // 8
        prefix_end = offset + 1 + prefix_byte_len
        if prefix_end >= len(data):
            raise ValueError("truncated Stripe prefix or flags")
        prefix_bytes = data[offset + 1:offset + 1 + prefix_byte_len]
        # Pad to 4 bytes for ipaddress
        prefix_padded = prefix_bytes + b'\x00' * (4 - prefix_byte_len)
        network = ip.IPv4Network(
            f"{ip.IPv4Address(int.from_bytes(prefix_padded, 'big'))}/{plen}",
            strict=False,
        )
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
class S2ROV:
    """A Delegation-Aware Route Origin Authorization.

    Attributes:
        base_prefix: The allocation root prefix (e.g., "10.0.0.0/16").
        max_length: Maximum prefix length covered by this S2-ROV.
        holder_asn: The ASN of the address space holder.
        stripes: Ordered list of Stripes.
    """
    base_prefix: str
    max_length: int
    holder_asn: int
    stripes: tuple[Stripe, ...] = field(default_factory=tuple)
    _base_net: ip.IPv4Network = field(init=False, repr=False, compare=False)
    _stripe_index: Mapping[tuple[int, int], Stripe] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self):
        base_network = ip.IPv4Network(self.base_prefix, strict=False)
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
        if not self.base_prefix_length <= self.max_length <= 32:
            raise ValueError(
                f"max_length {self.max_length} outside "
                f"[{self.base_prefix_length}, 32]"
            )
        if isinstance(self.holder_asn, bool) or not isinstance(self.holder_asn, int):
            raise TypeError("holder_asn must be int")
        if not 1 <= self.holder_asn <= 0xFFFFFFFF:
            raise ValueError(f"holder ASN out of range: {self.holder_asn}")
        if len(self.stripes) > 0xFFFF:
            raise ValueError("too many Stripes for 16-bit count")

        by_prefix: dict[str, Stripe] = {}
        for stripe in self.stripes:
            if not isinstance(stripe, Stripe):
                raise TypeError(f"expected Stripe, got {type(stripe).__name__}")
            if not stripe.network.subnet_of(self._base_net):
                raise ValueError(
                    f"Stripe {stripe.prefix} lies outside base {self.base_prefix}"
                )
            if stripe.prefix_length > self.max_length:
                raise ValueError(
                    f"Stripe {stripe.prefix} exceeds max_length {self.max_length}"
                )
            if stripe.prefix in by_prefix:
                raise ValueError(f"duplicate Stripe prefix: {stripe.prefix}")
            by_prefix[stripe.prefix] = stripe

        base = by_prefix.get(self.base_prefix)
        if base is None:
            raise ValueError("policy must contain exactly one base Stripe")
        if self.holder_asn not in base.as_set:
            raise ValueError("base Stripe must explicitly name holder_asn")

    def _rebuild_index(self) -> None:
        """Build an IPv4 longest-prefix-match index for the Stripe set."""
        index: dict[tuple[int, int], Stripe] = {}
        for stripe in self.stripes:
            key = (stripe.prefix_length, stripe.prefix_int)
            index[key] = stripe
        object.__setattr__(self, "_stripe_index", MappingProxyType(index))

    @property
    def base_network(self) -> ip.IPv4Network:
        return self._base_net

    @property
    def base_prefix_length(self) -> int:
        return self._base_net.prefixlen

    def serialize(self) -> bytes:
        """Serialize this S2-ROV to binary (DESIGN.md §2.1)."""
        base_bytes = self._base_net.network_address.packed
        plen = self.base_prefix_length
        n_stripes = len(self.stripes)

        header = struct.pack("!4s B B I B H B",
                             base_bytes,       # base prefix (4 bytes)
                             plen,             # prefix length
                             self.max_length,  # max length
                             self.holder_asn,  # holder ASN
                             0x01,             # version
                             n_stripes,        # num stripes
                             0)                # flags (reserved)

        stripe_data = b"".join(s.serialize() for s in self.stripes)
        return header + stripe_data

    @classmethod
    def deserialize(cls, data: bytes) -> S2ROV:
        """Deserialize a S2-ROV from binary."""
        if len(data) < 14:
            raise ValueError("truncated S2-ROV header")
        base_bytes = data[0:4]
        plen = data[4]
        if plen > 32:
            raise ValueError(f"invalid IPv4 base prefix length: {plen}")
        max_len = data[5]
        holder_asn = struct.unpack("!I", data[6:10])[0]
        version = data[10]
        if version != 0x01:
            raise ValueError(f"unsupported S2-ROV version: {version}")
        n_stripes = struct.unpack("!H", data[11:13])[0]
        flags = data[13]
        if flags:
            raise ValueError(f"reserved S2-ROV flags are nonzero: 0x{flags:02x}")

        base_network = ip.IPv4Network(
            f"{ip.IPv4Address(int.from_bytes(base_bytes, 'big'))}/{plen}",
            strict=False,
        )
        if base_bytes != base_network.network_address.packed:
            raise ValueError("non-canonical base prefix has host bits set")
        prefix_str = str(base_network)

        offset = 14  # Skip header
        stripes = []
        for _ in range(n_stripes):
            stripe, offset = Stripe.deserialize(data, offset)
            stripes.append(stripe)
        if offset != len(data):
            raise ValueError(f"trailing bytes after S2-ROV payload: {len(data)-offset}")

        canonical_prefix_order = sorted(
            (stripe.prefix for stripe in stripes),
            key=lambda prefix: (
                -ip.IPv4Network(prefix).prefixlen,
                int(ip.IPv4Network(prefix).network_address),
            ),
        )
        if [stripe.prefix for stripe in stripes] != canonical_prefix_order:
            raise ValueError("non-canonical Stripe order")

        return S2ROV(prefix_str, max_len, holder_asn, stripes)

    def add_stripe(self, stripe: Stripe) -> S2ROV:
        """Return a new policy containing the Stripe in canonical order."""
        return S2ROV(
            self.base_prefix,
            self.max_length,
            self.holder_asn,
            (*self.stripes, stripe),
        )

    def find_best_stripe(self, target_prefix: str) -> Optional[Stripe]:
        """Find the most-specific Stripe covering the given prefix."""
        target = ip.IPv4Network(target_prefix, strict=True)
        target_int = int(target.network_address)

        for plen in range(target.prefixlen, -1, -1):
            mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0
            candidate = self._stripe_index.get((plen, target_int & mask))
            if candidate is None:
                continue
            return candidate

        return None

    def validate_route(self, target_prefix: str, origin_asn: int) -> ValidationState:
        """Validate a route while preserving how it was authorized.

        ``Explicit`` means the holder listed the origin ASN in the selected
        Stripe. ``Delegated`` means the selected open Stripe intentionally
        delegates origin choice but does not authenticate the business
        relationship.
        """
        target = ip.IPv4Network(target_prefix, strict=True)
        if isinstance(origin_asn, bool) or not isinstance(origin_asn, int):
            raise TypeError("route origin ASN must be an integer")
        if not 1 <= origin_asn <= 0xFFFFFFFF:
            raise ValueError(f"route origin ASN out of range: {origin_asn}")
        if not target.subnet_of(self._base_net):
            return ValidationState.NOT_FOUND
        if target.prefixlen > self.max_length:
            return ValidationState.INVALID

        stripe = self.find_best_stripe(target_prefix)
        if stripe is None:
            return ValidationState.INVALID
        if origin_asn in stripe.as_set:
            return ValidationState.EXPLICIT
        if (
            stripe.is_open
            and target.prefixlen > stripe.prefix_length
            and is_eligible_delegated_origin(origin_asn)
        ):
            return ValidationState.DELEGATED
        return ValidationState.INVALID

    def size_bytes(self) -> int:
        """Return the total wire-format size in bytes."""
        return len(self.serialize())

    def vrp_count_rfc6811(self) -> int:
        """Return the number of standard VRPs this S2-ROV would produce when flattened."""
        return len(self.flatten_to_vrps())

    def flatten_to_vrps(self) -> List[Tuple[str, int, int]]:
        """Flatten to standard (prefix, origin_as, maxLength) VRPs.
        
        Implements DESIGN.md §5.1 algorithm.
        """
        from .flatten import flatten_to_vrps
        return flatten_to_vrps(self)

    def __repr__(self) -> str:
        return (f"S2ROV({self.base_prefix}, ℓ={self.max_length}, "
                f"holder=AS{self.holder_asn}, {len(self.stripes)} stripes)")
