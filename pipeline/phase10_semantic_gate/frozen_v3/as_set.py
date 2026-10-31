"""Explicit-AS-set encoding: empty / list.

Design rationale: |A| = 1 is the most common case, but dedicating a
separate Single mode saves only 1 byte (5→4) per Stripe at the cost of
~1/3 more code.  The zero-payload mode encodes an empty explicit set; the
Stripe's independent ``is_open`` bit determines whether descendants may use
unnamed origins.  An empty set in a closed Stripe therefore means deny-all,
not "any AS".
"""
from __future__ import annotations
from enum import IntEnum
from typing import AbstractSet, Set, Tuple
import struct


class AsSetType(IntEnum):
    EMPTY = 0  # A = ∅ (0 bytes)
    LIST = 1  # |A| ≥ 1 (1 + 4k bytes)

    @classmethod
    def select(cls, ases: AbstractSet[int]) -> AsSetType:
        return cls.EMPTY if len(ases) == 0 else cls.LIST


MAX_LIST_COUNT = 255
MAX_ASN = 0xFFFFFFFF


def validate_as_set(ases: AbstractSet[int]) -> None:
    if len(ases) > MAX_LIST_COUNT:
        raise ValueError(
            f"explicit AS set has {len(ases)} entries; maximum is {MAX_LIST_COUNT}"
        )
    for asn in ases:
        if isinstance(asn, bool) or not isinstance(asn, int):
            raise TypeError(f"ASN must be an integer, got {asn!r}")
        if not 1 <= asn <= MAX_ASN:
            raise ValueError(f"ASN out of range: {asn}")


def encode(ases: AbstractSet[int]) -> Tuple[AsSetType, bytes]:
    """Encode an AS set to bytes."""
    validate_as_set(ases)
    typ = AsSetType.select(ases)

    if typ == AsSetType.EMPTY:
        return typ, b""

    # LIST: count (1) + ASNs (4 each)
    sorted_ases = sorted(ases)
    payload = struct.pack("!B", len(sorted_ases))
    for asn in sorted_ases:
        payload += struct.pack("!I", asn)
    return typ, payload


def decode(typ: AsSetType, data: bytes) -> Set[int]:
    """Decode bytes back to an AS set."""
    if typ == AsSetType.EMPTY:
        if data:
            raise ValueError("empty AS-set encoding must have zero payload bytes")
        return set()

    if not data:
        raise ValueError("truncated AS-set list: missing count")
    count = data[0]
    if count == 0:
        raise ValueError("list encoding must contain at least one ASN")
    expected = 1 + count * 4
    if len(data) != expected:
        raise ValueError(
            f"AS-set list length mismatch: expected {expected}, got {len(data)}"
        )
    ases = set()
    previous = 0
    for i in range(count):
        offset = 1 + i * 4
        (asn,) = struct.unpack("!I", data[offset:offset + 4])
        if asn == 0:
            raise ValueError("ASN 0 is not a valid explicit origin")
        if asn in ases:
            raise ValueError(f"duplicate ASN in encoded set: {asn}")
        if asn <= previous:
            raise ValueError("encoded AS-set list is not in strictly increasing order")
        ases.add(asn)
        previous = asn
    return ases


def encode_size(ases: AbstractSet[int]) -> Tuple[int, str]:
    """Return (byte_size, encoding_name)."""
    validate_as_set(ases)
    if len(ases) == 0:
        return 0, "empty"
    return 1 + 4 * len(ases), "list"
