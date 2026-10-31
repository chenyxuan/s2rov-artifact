#!/usr/bin/env python3
"""Measure registry-indirect RIPE allocation paths and origin divergence.

This script is deliberately conservative.  It constructs only the two policy
chains used by the paper:

* IPv4: ALLOCATED PA -> [SUB-ALLOCATED PA] -> ASSIGNED PA
* IPv6: ALLOCATED-BY-RIR -> [ALLOCATED-BY-LIR] -> ASSIGNED

For every endpoint it selects the smallest eligible containing root.  A path
is ``registry_indirect`` iff at least one eligible hop is strictly between the
selected root and endpoint.  Registry structure is observable; issuer
knowledge, permission, ROA state, and route legitimacy are not inferred.

If a BGP origin CSV or MRT RIB is supplied, a potential conflict additionally
requires non-empty, disjoint *exact-prefix* origin-AS sets at the root and
endpoint.  MOAS sets are preserved.  Records whose terminal AS_PATH segment is
an AS_SET or confederation segment are excluded rather than guessed.

The RIPE database is parsed as a stream and intermediate state is kept in a
temporary SQLite database, so the full dump need not fit in memory.
"""

from __future__ import annotations

import argparse
from bisect import bisect_left
import csv
import gzip
import hashlib
import heapq
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, TextIO


ROLE_BY_FAMILY_STATUS = {
    4: {
        "ALLOCATED PA": "root",
        "SUB-ALLOCATED PA": "hop",
        "ASSIGNED PA": "endpoint",
    },
    6: {
        "ALLOCATED-BY-RIR": "root",
        "ALLOCATED-BY-LIR": "hop",
        "ASSIGNED": "endpoint",
    },
}

FAMILY_NAME = {4: "IPv4", 6: "IPv6"}
STATUS_COMMENT_RE = re.compile(r"\s*#.*$")
SPACE_RE = re.compile(r"\s+")
AMBIGUOUS_AS_RE = re.compile(r"[{}()\[\],]")


@dataclass(frozen=True)
class Root:
    object_id: int
    family: int
    start: int
    end: int
    prefix: str
    status: str
    org_json: str
    single_org: str
    origins: frozenset[int] = frozenset()
    origin_ambiguous: bool = False


@dataclass(frozen=True)
class Hop:
    object_id: int
    start: int
    end: int
    range_text: str
    status: str
    org_json: str
    single_org: str


class HopDepthIndex:
    """Count containing hops and track their longest strict nesting chain.

    Rows are added in nondecreasing start-address order, with longer ranges
    first when starts tie.  Therefore, an already-added hop strictly contains
    a new hop (or an endpoint) exactly when its end address is at least the
    queried end address.  Two Fenwick trees over reverse-ranked end addresses
    provide the containing-object count and maximum chain depth.
    """

    def __init__(self, end_addresses: Iterable[int]) -> None:
        self._ends = tuple(sorted(set(end_addresses)))
        self._counts = [0] * (len(self._ends) + 1)
        self._max_chain = [0] * (len(self._ends) + 1)

    def _prefix_size(self, minimum_end: int) -> int:
        return len(self._ends) - bisect_left(self._ends, minimum_end)

    @staticmethod
    def _query(tree: list[int], index: int, use_max: bool = False) -> int:
        value = 0
        while index:
            value = max(value, tree[index]) if use_max else value + tree[index]
            index -= index & -index
        return value

    @staticmethod
    def _update(tree: list[int], index: int, value: int, use_max: bool = False) -> None:
        while index < len(tree):
            if use_max:
                tree[index] = max(tree[index], value)
            else:
                tree[index] += value
            index += index & -index

    def add_hop(self, end: int) -> int:
        """Add one clean hop and return its longest outer-to-self chain."""
        index = self._prefix_size(end)
        if index <= 0:
            raise RuntimeError(f"hop end address absent from depth index: {end}")
        chain = self._query(self._max_chain, index, use_max=True) + 1
        self._update(self._counts, index, 1)
        self._update(self._max_chain, index, chain, use_max=True)
        return chain

    def endpoint_depth(self, end: int) -> tuple[int, int]:
        """Return (containing clean-hop objects, longest nested-hop chain)."""
        index = self._prefix_size(end)
        return (
            self._query(self._counts, index),
            self._query(self._max_chain, index, use_max=True),
        )


def normalize_status(value: str) -> str:
    """Normalize spacing/case and remove RIPE inline comment suffixes."""
    return SPACE_RE.sub(" ", STATUS_COMMENT_RE.sub("", value).strip()).upper()


def canonical_prefix(start: int, end: int, family: int) -> str | None:
    """Return one canonical CIDR iff [start, end] is exactly one CIDR."""
    bits = 32 if family == 4 else 128
    if start < 0 or end < start or end >= (1 << bits):
        return None
    size = end - start + 1
    if size & (size - 1) or start & (size - 1):
        return None
    prefixlen = bits - (size.bit_length() - 1)
    address = (
        ipaddress.IPv4Address(start)
        if family == 4
        else ipaddress.IPv6Address(start)
    )
    return str(ipaddress.ip_network((address, prefixlen), strict=True))


def parse_registry_range(raw_value: str, family: int) -> tuple[int, int, str | None]:
    """Parse one inetnum/inet6num value into an inclusive integer range."""
    value = STATUS_COMMENT_RE.sub("", raw_value).strip()
    if family == 4 and "-" in value:
        left, right = (part.strip() for part in value.split("-", 1))
        start_address = ipaddress.IPv4Address(left)
        end_address = ipaddress.IPv4Address(right)
        start, end = int(start_address), int(end_address)
    else:
        network = ipaddress.ip_network(value, strict=False)
        if network.version != family:
            raise ValueError(f"wrong address family: {value}")
        start, end = int(network.network_address), int(network.broadcast_address)
    if end < start:
        raise ValueError(f"reversed range: {value}")
    return start, end, canonical_prefix(start, end, family)


def address_blob(value: int, family: int) -> bytes:
    return value.to_bytes(4 if family == 4 else 16, "big")


def blob_address(value: bytes) -> int:
    return int.from_bytes(value, "big")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def open_ripe(path: Path) -> TextIO:
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="latin-1", errors="replace")
    return path.open("r", encoding="latin-1", errors="replace")


def iter_ripe_objects(path: Path) -> Iterator[dict[str, list[str]]]:
    """Yield only the fields needed from each RIPE WHOIS object."""
    current: dict[str, list[str]] = defaultdict(list)
    with open_ripe(path) as handle:
        for line in handle:
            line = line.rstrip("\r\n")
            if not line.strip():
                if current:
                    yield dict(current)
                    current.clear()
                continue
            if line.startswith(("%", "#", "+")) or line[0].isspace():
                continue
            key, separator, value = line.partition(":")
            if not separator:
                continue
            key = key.strip().lower()
            if key in {"inetnum", "inet6num", "status", "org"}:
                current[key].append(value.strip())
    if current:
        yield dict(current)


def connect_work_db(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute("PRAGMA temp_store=FILE")
    connection.execute("PRAGMA cache_size=-131072")
    connection.executescript(
        """
        CREATE TABLE variants (
            family INTEGER NOT NULL,
            start_addr BLOB NOT NULL,
            end_addr BLOB NOT NULL,
            status TEXT NOT NULL,
            org_handles TEXT NOT NULL,
            single_org TEXT NOT NULL,
            role TEXT NOT NULL,
            range_text TEXT NOT NULL,
            canonical_prefix TEXT,
            occurrences INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (family, start_addr, end_addr, status, org_handles)
        ) WITHOUT ROWID;
        """
    )
    return connection


def ingest_registry(
    connection: sqlite3.Connection,
    ripe_path: Path,
    progress_every: int,
) -> dict[str, object]:
    """Stream RIPE objects into deduplicated range fingerprints."""
    audit: Counter[str] = Counter()
    status_counts: dict[str, Counter[str]] = {
        "IPv4": Counter(),
        "IPv6": Counter(),
    }
    batch: list[tuple[object, ...]] = []
    statement = """
        INSERT INTO variants (
            family, start_addr, end_addr, status, org_handles, single_org,
            role, range_text, canonical_prefix, occurrences
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT (family, start_addr, end_addr, status, org_handles)
        DO UPDATE SET occurrences = occurrences + 1
    """

    def flush_batch() -> None:
        if batch:
            connection.executemany(statement, batch)
            connection.commit()
            batch.clear()

    for object_number, fields in enumerate(iter_ripe_objects(ripe_path), 1):
        if "inetnum" in fields:
            family, key = 4, "inetnum"
        elif "inet6num" in fields:
            family, key = 6, "inet6num"
        else:
            continue
        family_label = FAMILY_NAME[family]
        audit["ip_objects_seen"] += 1
        audit[f"{family_label}.ip_objects_seen"] += 1
        raw_range = fields[key][0]
        try:
            start, end, prefix = parse_registry_range(raw_range, family)
        except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            audit["invalid_ranges"] += 1
            audit[f"{family_label}.invalid_ranges"] += 1
            continue

        raw_statuses = fields.get("status", [])
        for raw_status in raw_statuses:
            if STATUS_COMMENT_RE.search(raw_status):
                audit["status_comment_suffixes_normalized"] += 1
                audit[f"{family_label}.status_comment_suffixes_normalized"] += 1
        statuses = sorted({normalize_status(item) for item in raw_statuses})
        statuses = [item for item in statuses if item]
        if len(statuses) == 1:
            status = statuses[0]
        elif not statuses:
            status = "<MISSING>"
            audit["missing_status_objects"] += 1
        else:
            status = "<AMBIGUOUS:" + "|".join(statuses) + ">"
            audit["ambiguous_status_objects"] += 1
        status_counts[family_label][status] += 1

        raw_orgs = [item.strip() for item in fields.get("org", []) if item.strip()]
        if any(item != item.upper() for item in raw_orgs):
            audit["org_handle_case_normalizations"] += 1
            audit[f"{family_label}.org_handle_case_normalizations"] += 1
        orgs = sorted({item.upper() for item in raw_orgs})
        org_json = json.dumps(orgs, ensure_ascii=True, separators=(",", ":"))
        single_org = orgs[0] if len(orgs) == 1 else ""
        role = ROLE_BY_FAMILY_STATUS[family].get(status, "")
        if role:
            audit["eligible_objects_seen"] += 1
            audit[f"{family_label}.{role}_objects_seen"] += 1

        batch.append(
            (
                family,
                address_blob(start, family),
                address_blob(end, family),
                status,
                org_json,
                single_org,
                role,
                raw_range.strip(),
                prefix,
            )
        )
        if len(batch) >= 25_000:
            flush_batch()
        if progress_every and object_number % progress_every == 0:
            print(f"RIPE objects scanned: {object_number:,}", flush=True)
    flush_batch()

    audit["range_fingerprint_variants"] = connection.execute(
        "SELECT COUNT(*) FROM variants"
    ).fetchone()[0]
    audit["duplicate_object_occurrences_collapsed"] = connection.execute(
        "SELECT COALESCE(SUM(occurrences - 1), 0) FROM variants"
    ).fetchone()[0]
    return {
        "counts": dict(sorted(audit.items())),
        "status_counts": {
            family: dict(sorted(counts.items()))
            for family, counts in status_counts.items()
        },
    }


def resolve_ranges(connection: sqlite3.Connection) -> dict[str, object]:
    """Exclude same-range status/org conflicts and materialize clean roles."""
    connection.executescript(
        """
        CREATE TABLE conflicting_ranges (
            family INTEGER NOT NULL,
            start_addr BLOB NOT NULL,
            end_addr BLOB NOT NULL,
            variant_count INTEGER NOT NULL,
            raw_object_count INTEGER NOT NULL,
            PRIMARY KEY (family, start_addr, end_addr)
        ) WITHOUT ROWID;

        INSERT INTO conflicting_ranges
        SELECT family, start_addr, end_addr, COUNT(*), SUM(occurrences)
        FROM variants
        GROUP BY family, start_addr, end_addr
        HAVING COUNT(*) > 1;

        CREATE TABLE clean_objects (
            id INTEGER PRIMARY KEY,
            family INTEGER NOT NULL,
            start_addr BLOB NOT NULL,
            end_addr BLOB NOT NULL,
            status TEXT NOT NULL,
            org_handles TEXT NOT NULL,
            single_org TEXT NOT NULL,
            role TEXT NOT NULL,
            range_text TEXT NOT NULL,
            canonical_prefix TEXT
        );

        INSERT INTO clean_objects (
            family, start_addr, end_addr, status, org_handles, single_org,
            role, range_text, canonical_prefix
        )
        SELECT v.family, v.start_addr, v.end_addr, v.status, v.org_handles,
               v.single_org, v.role, v.range_text, v.canonical_prefix
        FROM variants AS v
        LEFT JOIN conflicting_ranges AS c
          ON c.family = v.family
         AND c.start_addr = v.start_addr
         AND c.end_addr = v.end_addr
        WHERE v.role <> '' AND c.family IS NULL;

        INSERT INTO clean_objects (
            family, start_addr, end_addr, status, org_handles, single_org,
            role, range_text, canonical_prefix
        )
        SELECT v.family, v.start_addr, v.end_addr,
               '<SAME-RANGE-CONFLICT>', '[]', '', 'root_conflict',
               MIN(v.range_text), MAX(v.canonical_prefix)
        FROM variants AS v
        JOIN conflicting_ranges AS c
          ON c.family = v.family
         AND c.start_addr = v.start_addr
         AND c.end_addr = v.end_addr
        GROUP BY v.family, v.start_addr, v.end_addr
        HAVING SUM(CASE WHEN v.role='root' THEN 1 ELSE 0 END) > 0;

        INSERT INTO clean_objects (
            family, start_addr, end_addr, status, org_handles, single_org,
            role, range_text, canonical_prefix
        )
        SELECT v.family, v.start_addr, v.end_addr,
               '<SAME-RANGE-CONFLICT>', '[]', '', 'hop_conflict',
               MIN(v.range_text), MAX(v.canonical_prefix)
        FROM variants AS v
        JOIN conflicting_ranges AS c
          ON c.family = v.family
         AND c.start_addr = v.start_addr
         AND c.end_addr = v.end_addr
        GROUP BY v.family, v.start_addr, v.end_addr
        HAVING SUM(CASE WHEN v.role='hop' THEN 1 ELSE 0 END) > 0;

        CREATE INDEX clean_scan
        ON clean_objects (family, start_addr, end_addr, role);
        CREATE INDEX clean_prefix
        ON clean_objects (family, canonical_prefix);
        """
    )
    connection.commit()
    audit: dict[str, object] = {
        "conflicting_ranges": connection.execute(
            "SELECT COUNT(*) FROM conflicting_ranges"
        ).fetchone()[0],
        "raw_objects_on_conflicting_ranges": connection.execute(
            "SELECT COALESCE(SUM(raw_object_count), 0) FROM conflicting_ranges"
        ).fetchone()[0],
        "eligible_variants_excluded_by_same_range_conflict": connection.execute(
            """
            SELECT COUNT(*) FROM variants AS v
            JOIN conflicting_ranges AS c
              ON c.family=v.family AND c.start_addr=v.start_addr
             AND c.end_addr=v.end_addr
            WHERE v.role <> ''
            """
        ).fetchone()[0],
        "root_conflict_barriers": connection.execute(
            "SELECT COUNT(*) FROM clean_objects WHERE role='root_conflict'"
        ).fetchone()[0],
        "hop_conflict_barriers": connection.execute(
            "SELECT COUNT(*) FROM clean_objects WHERE role='hop_conflict'"
        ).fetchone()[0],
        "families": {},
    }
    for family, label in FAMILY_NAME.items():
        family_counts: dict[str, int] = {}
        for role in ("root", "hop", "endpoint"):
            family_counts[f"clean_{role}_ranges"] = connection.execute(
                "SELECT COUNT(*) FROM clean_objects WHERE family=? AND role=?",
                (family, role),
            ).fetchone()[0]
            if role in {"root", "endpoint"}:
                family_counts[f"non_cidr_{role}_ranges_excluded"] = connection.execute(
                    """SELECT COUNT(*) FROM clean_objects
                       WHERE family=? AND role=? AND canonical_prefix IS NULL""",
                    (family, role),
                ).fetchone()[0]
        family_counts["non_cidr_hop_ranges_retained"] = connection.execute(
            """SELECT COUNT(*) FROM clean_objects
               WHERE family=? AND role='hop' AND canonical_prefix IS NULL""",
            (family,),
        ).fetchone()[0]
        audit["families"][label] = family_counts
    return audit


def strictly_contains(root_start: int, root_end: int, start: int, end: int) -> bool:
    return (
        root_start <= start
        and end <= root_end
        and (root_start != start or root_end != end)
    )


def build_containment_matches(
    connection: sqlite3.Connection,
    progress_every: int,
) -> dict[str, dict[str, int]]:
    """Assign each hop/endpoint to its nearest eligible containing root."""
    connection.executescript(
        """
        CREATE TABLE endpoint_matches (
            endpoint_id INTEGER PRIMARY KEY,
            root_id INTEGER NOT NULL
        );
        CREATE INDEX endpoint_root ON endpoint_matches(root_id, endpoint_id);
        CREATE TABLE hop_matches (
            hop_id INTEGER PRIMARY KEY,
            root_id INTEGER NOT NULL
        );
        CREATE INDEX hop_root ON hop_matches(root_id, hop_id);
        """
    )
    query = """
        SELECT id, family, start_addr, end_addr, role, canonical_prefix
        FROM clean_objects
        WHERE role IN ('hop','hop_conflict')
           OR role IN ('root','root_conflict')
           OR (role='endpoint' AND canonical_prefix IS NOT NULL)
        ORDER BY family, start_addr, end_addr DESC,
                 CASE
                   WHEN role IN ('root','root_conflict') THEN 0
                   WHEN role IN ('hop','hop_conflict') THEN 1
                   ELSE 2
                 END
    """
    audit: dict[str, Counter[str]] = {
        "IPv4": Counter(),
        "IPv6": Counter(),
    }
    endpoint_batch: list[tuple[int, int]] = []
    hop_batch: list[tuple[int, int]] = []
    root_stack: list[tuple[int, int, int, bool, bool]] = []
    previous_family: int | None = None

    for row_number, (
        object_id,
        family,
        start_blob,
        end_blob,
        role,
        canonical,
    ) in enumerate(
        connection.execute(query), 1
    ):
        label = FAMILY_NAME[family]
        start, end = blob_address(start_blob), blob_address(end_blob)
        if family != previous_family:
            root_stack.clear()
            previous_family = family
        while root_stack and root_stack[-1][2] < start:
            root_stack.pop()

        if role in {"root", "root_conflict"}:
            while root_stack and not strictly_contains(
                root_stack[-1][1], root_stack[-1][2], start, end
            ):
                audit[label]["partial_overlap_root_ranges"] += 1
                raise RuntimeError(
                    f"non-laminar {label} eligible roots overlap near object {object_id}"
                )
            root_stack.append(
                (
                    object_id,
                    start,
                    end,
                    canonical is not None,
                    role == "root_conflict",
                )
            )
            audit[label][
                "eligible_root_conflict_barriers"
                if role == "root_conflict"
                else (
                    "eligible_cidr_roots"
                    if canonical is not None
                    else "eligible_non_cidr_roots"
                )
            ] += 1
            continue

        selected_root: int | None = None
        selected_root_is_cidr = False
        selected_root_is_conflict = False
        for (
            root_id,
            root_start,
            root_end,
            root_is_cidr,
            root_is_conflict,
        ) in reversed(root_stack):
            if strictly_contains(root_start, root_end, start, end):
                selected_root = root_id
                selected_root_is_cidr = root_is_cidr
                selected_root_is_conflict = root_is_conflict
                break
        if selected_root is None:
            audit[label][f"{role}s_without_eligible_root"] += 1
        elif selected_root_is_conflict:
            audit[label][f"{role}s_nearest_root_conflict_excluded"] += 1
        elif not selected_root_is_cidr:
            audit[label][f"{role}s_nearest_root_non_cidr_excluded"] += 1
        elif role == "endpoint":
            endpoint_batch.append((object_id, selected_root))
            audit[label]["endpoints_matched_to_nearest_root"] += 1
        else:
            hop_batch.append((object_id, selected_root))
            audit[label]["hops_matched_to_nearest_root"] += 1

        if len(endpoint_batch) + len(hop_batch) >= 25_000:
            connection.executemany(
                "INSERT INTO endpoint_matches(endpoint_id,root_id) VALUES (?,?)",
                endpoint_batch,
            )
            connection.executemany(
                "INSERT INTO hop_matches(hop_id,root_id) VALUES (?,?)", hop_batch
            )
            connection.commit()
            endpoint_batch.clear()
            hop_batch.clear()
        if progress_every and row_number % progress_every == 0:
            print(f"Eligible ranges matched: {row_number:,}", flush=True)

    connection.executemany(
        "INSERT INTO endpoint_matches(endpoint_id,root_id) VALUES (?,?)",
        endpoint_batch,
    )
    connection.executemany(
        "INSERT INTO hop_matches(hop_id,root_id) VALUES (?,?)", hop_batch
    )
    connection.commit()
    return {family: dict(counts) for family, counts in audit.items()}


def parse_scalar_asn(raw: str) -> tuple[int | None, str]:
    value = raw.strip()
    if not value:
        return None, "missing"
    if AMBIGUOUS_AS_RE.search(value):
        return None, "ambiguous_terminal_segment"
    if value.upper().startswith("AS"):
        value = value[2:]
    if "." in value:
        pieces = value.split(".")
        if len(pieces) != 2 or not all(piece.isdigit() for piece in pieces):
            return None, "invalid"
        asn = int(pieces[0]) * 65536 + int(pieces[1])
    elif value.isdigit():
        asn = int(value)
    else:
        return None, "invalid"
    if not 0 <= asn <= 0xFFFFFFFF:
        return None, "invalid"
    return asn, "accepted"


def terminal_asn(as_path: str) -> tuple[int | None, str]:
    path = as_path.strip()
    if not path:
        return None, "missing"
    if path.endswith(("}", ")", "]")):
        return None, "ambiguous_terminal_segment"
    return parse_scalar_asn(path.split()[-1])


def canonical_bgp_prefix(raw: str) -> tuple[int, str] | None:
    try:
        network = ipaddress.ip_network(raw.strip(), strict=True)
    except ValueError:
        return None
    return network.version, str(network)


def iter_bgp_csv(
    path: Path, audit: Counter[str]
) -> Iterator[tuple[int, str, int | None, str]]:
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not {"prefix", "origin_as"}.issubset(reader.fieldnames):
            raise ValueError("BGP CSV must contain columns: prefix, origin_as")
        for row in reader:
            audit["records_seen"] += 1
            parsed_prefix = canonical_bgp_prefix(row.get("prefix", ""))
            if parsed_prefix is None:
                audit["invalid_prefix_records"] += 1
                continue
            asn, reason = parse_scalar_asn(row.get("origin_as", ""))
            if asn is None:
                audit[f"{reason}_records"] += 1
                family, prefix = parsed_prefix
                yield family, prefix, None, reason
                continue
            family, prefix = parsed_prefix
            audit["accepted_records"] += 1
            yield family, prefix, asn, "accepted"


def iter_bgp_mrt(
    path: Path, bgpdump: str, audit: Counter[str]
) -> Iterator[tuple[int, str, int | None, str]]:
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as error_log:
        process = subprocess.Popen(
            [bgpdump, "-m", "-O", "/dev/stdout", str(path)],
            stdout=subprocess.PIPE,
            stderr=error_log,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert process.stdout is not None
        for line in process.stdout:
            audit["records_seen"] += 1
            fields = line.rstrip("\n").split("|")
            if len(fields) < 7:
                audit["malformed_records"] += 1
                continue
            parsed_prefix = canonical_bgp_prefix(fields[5])
            if parsed_prefix is None:
                audit["invalid_prefix_records"] += 1
                continue
            asn, reason = terminal_asn(fields[6])
            if asn is None:
                audit[f"{reason}_records"] += 1
                family, prefix = parsed_prefix
                yield family, prefix, None, reason
                continue
            family, prefix = parsed_prefix
            audit["accepted_records"] += 1
            yield family, prefix, asn, "accepted"
        return_code = process.wait()
        if return_code:
            error_log.seek(0)
            stderr = error_log.read()
            raise RuntimeError(f"bgpdump exited {return_code}: {stderr[-2000:]}")


def ingest_bgp(
    connection: sqlite3.Connection,
    bgp_csv: Path | None,
    mrt: Path | None,
    bgpdump: str,
) -> dict[str, object]:
    connection.execute(
        """CREATE TABLE bgp_origins (
               family INTEGER NOT NULL,
               prefix TEXT NOT NULL,
               asn INTEGER NOT NULL,
               PRIMARY KEY(family,prefix,asn)
           ) WITHOUT ROWID"""
    )
    connection.execute(
        """CREATE TABLE bgp_ambiguous_prefixes (
               family INTEGER NOT NULL,
               prefix TEXT NOT NULL,
               PRIMARY KEY(family,prefix)
           ) WITHOUT ROWID"""
    )
    audit: Counter[str] = Counter()
    if bgp_csv is None and mrt is None:
        connection.commit()
        return {"provided": False, "counts": {}}
    iterator: Iterable[tuple[int, str, int | None, str]]
    source_kind: str
    if bgp_csv is not None:
        iterator = iter_bgp_csv(bgp_csv, audit)
        source_kind = "origin_csv"
    else:
        assert mrt is not None
        iterator = iter_bgp_mrt(mrt, bgpdump, audit)
        source_kind = "mrt_via_bgpdump"
    batch: list[tuple[int, str, int]] = []
    ambiguous_batch: list[tuple[int, str]] = []
    for family, prefix, asn, reason in iterator:
        if asn is None:
            ambiguous_batch.append((family, prefix))
        else:
            batch.append((family, prefix, asn))
        if len(batch) + len(ambiguous_batch) >= 50_000:
            connection.executemany(
                "INSERT OR IGNORE INTO bgp_origins VALUES (?,?,?)", batch
            )
            connection.executemany(
                "INSERT OR IGNORE INTO bgp_ambiguous_prefixes VALUES (?,?)",
                ambiguous_batch,
            )
            connection.commit()
            batch.clear()
            ambiguous_batch.clear()
    connection.executemany("INSERT OR IGNORE INTO bgp_origins VALUES (?,?,?)", batch)
    connection.executemany(
        "INSERT OR IGNORE INTO bgp_ambiguous_prefixes VALUES (?,?)",
        ambiguous_batch,
    )
    connection.commit()
    unique_records = connection.execute("SELECT COUNT(*) FROM bgp_origins").fetchone()[0]
    audit["unique_prefix_origin_pairs"] = unique_records
    audit["duplicate_prefix_origin_pairs_collapsed"] = (
        audit["accepted_records"] - unique_records
    )
    audit["unique_prefixes"] = connection.execute(
        "SELECT COUNT(*) FROM (SELECT 1 FROM bgp_origins GROUP BY family,prefix)"
    ).fetchone()[0]
    audit["moas_prefixes"] = connection.execute(
        """SELECT COUNT(*) FROM (
               SELECT 1 FROM bgp_origins
               GROUP BY family,prefix HAVING COUNT(*) > 1
           )"""
    ).fetchone()[0]
    audit["ambiguous_prefixes"] = connection.execute(
        "SELECT COUNT(*) FROM bgp_ambiguous_prefixes"
    ).fetchone()[0]
    return {"provided": True, "source_kind": source_kind, "counts": dict(audit)}


def attach_origin_sets(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE object_origin_sets (
            object_id INTEGER PRIMARY KEY,
            origins TEXT NOT NULL,
            origin_count INTEGER NOT NULL
        );
        INSERT INTO object_origin_sets(object_id,origins,origin_count)
        SELECT c.id, GROUP_CONCAT(b.asn), COUNT(*)
        FROM clean_objects AS c
        JOIN bgp_origins AS b
          ON b.family=c.family AND b.prefix=c.canonical_prefix
        WHERE c.role IN ('root','endpoint') AND c.canonical_prefix IS NOT NULL
        GROUP BY c.id;

        CREATE TABLE object_origin_ambiguity (
            object_id INTEGER PRIMARY KEY
        );
        INSERT INTO object_origin_ambiguity(object_id)
        SELECT c.id
        FROM clean_objects AS c
        JOIN bgp_ambiguous_prefixes AS a
          ON a.family=c.family AND a.prefix=c.canonical_prefix
        WHERE c.role IN ('root','endpoint') AND c.canonical_prefix IS NOT NULL;
        """
    )
    connection.commit()


def parse_origins(value: str | None) -> frozenset[int]:
    if not value:
        return frozenset()
    return frozenset(int(item) for item in value.split(",") if item)


def load_roots(connection: sqlite3.Connection) -> dict[int, Root]:
    roots: dict[int, Root] = {}
    query = """
        SELECT c.id,c.family,c.start_addr,c.end_addr,c.canonical_prefix,
               c.status,c.org_handles,c.single_org,o.origins,
               CASE WHEN a.object_id IS NULL THEN 0 ELSE 1 END
        FROM clean_objects AS c
        LEFT JOIN object_origin_sets AS o ON o.object_id=c.id
        LEFT JOIN object_origin_ambiguity AS a ON a.object_id=c.id
        WHERE c.role='root' AND c.canonical_prefix IS NOT NULL
    """
    for row in connection.execute(query):
        (
            object_id,
            family,
            start,
            end,
            prefix,
            status,
            org_json,
            single_org,
            origins,
            origin_ambiguous,
        ) = row
        roots[object_id] = Root(
            object_id,
            family,
            blob_address(start),
            blob_address(end),
            prefix,
            status,
            org_json,
            single_org,
            parse_origins(origins),
            bool(origin_ambiguous),
        )
    return roots


def one_org(org_json: str) -> str:
    values = json.loads(org_json)
    return values[0] if len(values) == 1 else ""


def serialize_origins(origins: frozenset[int]) -> str:
    return ";".join(str(asn) for asn in sorted(origins))


DEPTH_COHORTS = (
    "all_registry_indirect",
    "exact_observed_registry_indirect",
    "origin_disjoint_candidate",
)
DEPTH_METRICS = (
    "longest_strict_nested_chain",
    "containing_eligible_objects",
)


def process_paths(
    connection: sqlite3.Connection,
    candidate_path: Path,
    bgp_provided: bool,
) -> tuple[
    dict[str, dict[str, object]],
    dict[str, set[str]],
    dict[str, dict[str, object]],
]:
    """Classify paths and, when possible, emit disjoint-origin candidates."""
    connection.executescript(
        """
        CREATE TABLE members (
            root_id INTEGER NOT NULL,
            kind INTEGER NOT NULL,
            object_id INTEGER NOT NULL,
            start_addr BLOB NOT NULL,
            end_addr BLOB NOT NULL,
            PRIMARY KEY(root_id,kind,object_id)
        ) WITHOUT ROWID;
        INSERT INTO members
        SELECT m.root_id,0,c.id,c.start_addr,c.end_addr
        FROM hop_matches AS m JOIN clean_objects AS c ON c.id=m.hop_id;
        INSERT INTO members
        SELECT m.root_id,1,c.id,c.start_addr,c.end_addr
        FROM endpoint_matches AS m JOIN clean_objects AS c ON c.id=m.endpoint_id;
        CREATE INDEX member_order
        ON members(root_id,start_addr,kind,end_addr DESC);
        """
    )
    connection.commit()
    roots = load_roots(connection)
    hop_ends_by_root: dict[int, list[int]] = defaultdict(list)
    for root_id, end_blob in connection.execute(
        """SELECT m.root_id,c.end_addr
           FROM hop_matches AS m
           JOIN clean_objects AS c ON c.id=m.hop_id
           WHERE c.role='hop'"""
    ):
        hop_ends_by_root[root_id].append(blob_address(end_blob))
    results: dict[str, Counter[str]] = {"IPv4": Counter(), "IPv6": Counter()}
    candidate_roots: dict[str, set[str]] = {"IPv4": set(), "IPv6": set()}
    depth_distributions: dict[str, dict[str, object]] = {
        label: {
            "distributions": {
                cohort: {metric: Counter() for metric in DEPTH_METRICS}
                for cohort in DEPTH_COHORTS
            },
            "cohort_paths": Counter(),
            "non_laminar_paths": Counter(),
        }
        for label in ("IPv4", "IPv6")
    }

    def record_depth(
        label: str, cohort: str, object_count: int, chain_depth: int
    ) -> None:
        if not 1 <= chain_depth <= object_count:
            raise RuntimeError(
                "invalid eligible-hop depth for "
                f"{label}/{cohort}: objects={object_count}, chain={chain_depth}"
            )
        family_depth = depth_distributions[label]
        distributions = family_depth["distributions"]
        distributions[cohort]["longest_strict_nested_chain"][chain_depth] += 1
        distributions[cohort]["containing_eligible_objects"][object_count] += 1
        family_depth["cohort_paths"][cohort] += 1
        if object_count != chain_depth:
            family_depth["non_laminar_paths"][cohort] += 1

    fields = [
        "family",
        "root_prefix",
        "root_status",
        "root_org_handle",
        "endpoint_prefix",
        "endpoint_status",
        "endpoint_org_handle",
        "root_origins",
        "endpoint_origins",
        "path_classification",
        "confirming_hop_range",
        "confirming_hop_status",
        "confirming_hop_org_handle",
        "org_confirmed_abc",
    ]
    query = """
        SELECT m.root_id,m.kind,c.id,c.start_addr,c.end_addr,c.range_text,
               c.status,c.org_handles,c.single_org,c.canonical_prefix,o.origins,
               CASE WHEN a.object_id IS NULL THEN 0 ELSE 1 END
        FROM members AS m
        JOIN clean_objects AS c ON c.id=m.object_id
        LEFT JOIN object_origin_sets AS o ON o.object_id=c.id
        LEFT JOIN object_origin_ambiguity AS a ON a.object_id=c.id
        ORDER BY m.root_id,m.start_addr,m.kind,m.end_addr DESC
    """

    with candidate_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        current_root_id: int | None = None
        hop_heap: list[tuple[int, int, Hop]] = []
        conflict_hop_heap: list[tuple[int, int, Hop]] = []
        org_heap: list[tuple[int, str, int, Hop]] = []
        org_best: dict[str, tuple[int, int, Hop]] = {}
        depth_index = HopDepthIndex(())
        sequence = 0

        def reset_group(root_id: int) -> None:
            nonlocal current_root_id, depth_index, sequence
            current_root_id = root_id
            hop_heap.clear()
            conflict_hop_heap.clear()
            org_heap.clear()
            org_best.clear()
            depth_index = HopDepthIndex(hop_ends_by_root.get(root_id, ()))
            sequence = 0

        def add_hop(hop: Hop) -> None:
            nonlocal sequence
            sequence += 1
            heapq.heappush(hop_heap, (-hop.end, sequence, hop))
            if hop.single_org:
                previous = org_best.get(hop.single_org)
                if previous is None or hop.end > previous[0]:
                    org_best[hop.single_org] = (hop.end, sequence, hop)
                    heapq.heappush(
                        org_heap, (-hop.end, hop.single_org, sequence, hop)
                    )

        def abc_hop(
            root_org: str, endpoint_org: str, endpoint_start: int, endpoint_end: int
        ) -> Hop | None:
            if not root_org or not endpoint_org or root_org == endpoint_org:
                return None
            blocked = {root_org, endpoint_org}
            held: list[tuple[int, str, int, Hop]] = []
            selected: Hop | None = None
            while org_heap:
                item = heapq.heappop(org_heap)
                neg_end, org, version, hop = item
                current = org_best.get(org)
                if current is None or current[1] != version:
                    continue
                end = -neg_end
                if end < endpoint_start:
                    del org_best[org]
                    continue
                held.append(item)
                if org in blocked:
                    continue
                if end >= endpoint_end:
                    selected = hop
                break
            for item in held:
                heapq.heappush(org_heap, item)
            return selected

        for row in connection.execute(query):
            (
                root_id,
                kind,
                object_id,
                start_blob,
                end_blob,
                range_text,
                status,
                org_json,
                single_org,
                prefix,
                origins_text,
                endpoint_origin_ambiguous,
            ) = row
            if root_id != current_root_id:
                reset_group(root_id)
            root = roots[root_id]
            label = FAMILY_NAME[root.family]
            start, end = blob_address(start_blob), blob_address(end_blob)
            if kind == 0:
                hop = Hop(
                    object_id,
                    start,
                    end,
                    range_text,
                    status,
                    org_json,
                    single_org,
                )
                if status == "<SAME-RANGE-CONFLICT>":
                    sequence += 1
                    heapq.heappush(conflict_hop_heap, (-hop.end, sequence, hop))
                else:
                    depth_index.add_hop(end)
                    add_hop(hop)
                continue

            results[label]["matched_endpoints"] += 1
            if hop_heap and -hop_heap[0][0] < start:
                # The maximum hop end is already left of this endpoint, hence
                # every accumulated hop is irrelevant to all later endpoints.
                hop_heap.clear()
                org_heap.clear()
                org_best.clear()
            if conflict_hop_heap and -conflict_hop_heap[0][0] < start:
                conflict_hop_heap.clear()
            if conflict_hop_heap and -conflict_hop_heap[0][0] >= end:
                results[label]["ambiguous_hop_paths_excluded"] += 1
                continue
            confirming_hop = (
                hop_heap[0][2]
                if hop_heap and -hop_heap[0][0] >= end
                else None
            )
            containing_hop_objects, nested_hop_depth = depth_index.endpoint_depth(end)
            if (confirming_hop is None) != (containing_hop_objects == 0):
                raise RuntimeError(
                    "eligible-hop existence/depth mismatch for endpoint "
                    f"{prefix}: heap={confirming_hop is not None}, "
                    f"objects={containing_hop_objects}"
                )
            if confirming_hop is None:
                results[label]["direct_paths"] += 1
                path_kind = "direct"
            else:
                results[label]["registry_indirect_paths"] += 1
                path_kind = "registry_indirect"
                record_depth(
                    label,
                    "all_registry_indirect",
                    containing_hop_objects,
                    nested_hop_depth,
                )
            selected_abc_hop = (
                abc_hop(root.single_org, single_org, start, end)
                if confirming_hop is not None
                else None
            )
            if selected_abc_hop is not None:
                results[label]["org_confirmed_abc_paths"] += 1

            if not bgp_provided:
                continue
            if root.origin_ambiguous or endpoint_origin_ambiguous:
                results[label][f"origin_ambiguous_{path_kind}_paths"] += 1
                continue
            endpoint_origins = parse_origins(origins_text)
            if root.origins and endpoint_origins:
                results[label][f"exact_routed_{path_kind}_paths"] += 1
                if confirming_hop is not None:
                    record_depth(
                        label,
                        "exact_observed_registry_indirect",
                        containing_hop_objects,
                        nested_hop_depth,
                    )
            else:
                results[label][f"unrouted_{path_kind}_paths"] += 1
                continue
            if not root.origins.isdisjoint(endpoint_origins):
                results[label][f"overlapping_origin_{path_kind}_paths"] += 1
                continue
            results[label][f"disjoint_origin_{path_kind}_paths"] += 1
            if confirming_hop is None:
                continue
            results[label]["potential_conflicts"] += 1
            record_depth(
                label,
                "origin_disjoint_candidate",
                containing_hop_objects,
                nested_hop_depth,
            )
            candidate_roots[label].add(root.prefix)
            if selected_abc_hop is not None:
                results[label]["org_confirmed_abc_conflicts"] += 1
            reported_hop = selected_abc_hop or confirming_hop
            writer.writerow(
                {
                    "family": label,
                    "root_prefix": root.prefix,
                    "root_status": root.status,
                    "root_org_handle": root.single_org,
                    "endpoint_prefix": prefix,
                    "endpoint_status": status,
                    "endpoint_org_handle": single_org,
                    "root_origins": serialize_origins(root.origins),
                    "endpoint_origins": serialize_origins(endpoint_origins),
                    "path_classification": path_kind,
                    "confirming_hop_range": reported_hop.range_text,
                    "confirming_hop_status": reported_hop.status,
                    "confirming_hop_org_handle": reported_hop.single_org,
                    "org_confirmed_abc": "yes" if selected_abc_hop else "no",
                }
            )

    serialized: dict[str, dict[str, object]] = {}
    for label, counts in results.items():
        row: dict[str, object] = dict(counts)
        row["potential_conflict_root_prefixes"] = len(candidate_roots[label])
        if bgp_provided:
            denominator = counts["exact_routed_registry_indirect_paths"]
            row["potential_conflict_rate_pct"] = (
                100.0 * counts["potential_conflicts"] / denominator
                if denominator
                else 0.0
            )
        else:
            row["potential_conflict_rate_pct"] = None
        serialized[label] = row
    return serialized, candidate_roots, depth_distributions


COMPACT_FIELDS = [
    "family",
    "matched_endpoints",
    "direct_paths",
    "registry_indirect_paths",
    "org_confirmed_abc_paths",
    "exact_routed_registry_indirect_paths",
    "potential_conflicts",
    "potential_conflict_rate_pct",
    "org_confirmed_abc_conflicts",
    "potential_conflict_root_prefixes",
]


def compact_row(label: str, values: dict[str, object], bgp_provided: bool) -> dict[str, object]:
    row: dict[str, object] = {"family": label}
    for field in COMPACT_FIELDS[1:]:
        if not bgp_provided and field in {
            "exact_routed_registry_indirect_paths",
            "potential_conflicts",
            "potential_conflict_rate_pct",
            "org_confirmed_abc_conflicts",
            "potential_conflict_root_prefixes",
        }:
            row[field] = ""
        elif field == "potential_conflict_rate_pct":
            value = values.get(field)
            row[field] = "" if value is None else f"{float(value):.6f}"
        else:
            row[field] = values.get(field, 0)
    return row


def write_compact(
    path: Path, family_results: dict[str, dict[str, object]], bgp_provided: bool
) -> None:
    rows = [compact_row(label, family_results[label], bgp_provided) for label in ("IPv4", "IPv6")]
    total_values: dict[str, object] = {}
    for field in COMPACT_FIELDS[1:]:
        if field == "potential_conflict_rate_pct":
            continue
        total_values[field] = sum(int(row.get(field, 0) or 0) for row in family_results.values())
    if bgp_provided:
        denominator = int(total_values.get("exact_routed_registry_indirect_paths", 0))
        numerator = int(total_values.get("potential_conflicts", 0))
        total_values["potential_conflict_rate_pct"] = (
            100.0 * numerator / denominator if denominator else 0.0
        )
    else:
        total_values["potential_conflict_rate_pct"] = None
    rows.append(compact_row("Total", total_values, bgp_provided))
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COMPACT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


DEPTH_FIELDS = [
    "family",
    "cohort",
    "depth_metric",
    "depth",
    "paths_at_depth",
    "cohort_paths",
    "share_pct",
    "non_laminar_paths",
]


def write_depth_distribution(
    path: Path,
    depth_results: dict[str, dict[str, object]],
    family_results: dict[str, dict[str, object]],
) -> None:
    """Write AFI/cohort distributions without changing legacy outputs."""
    expected_result_field = {
        "all_registry_indirect": "registry_indirect_paths",
        "exact_observed_registry_indirect": "exact_routed_registry_indirect_paths",
        "origin_disjoint_candidate": "potential_conflicts",
    }
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=DEPTH_FIELDS)
        writer.writeheader()
        for label in ("IPv4", "IPv6"):
            family_depth = depth_results[label]
            distributions = family_depth["distributions"]
            cohort_totals = family_depth["cohort_paths"]
            non_laminar = family_depth["non_laminar_paths"]
            for cohort in DEPTH_COHORTS:
                total = int(cohort_totals[cohort])
                expected = int(
                    family_results[label].get(expected_result_field[cohort], 0)
                )
                if total != expected:
                    raise RuntimeError(
                        f"depth cohort/result mismatch for {label}/{cohort}: "
                        f"depth={total}, result={expected}"
                    )
                mismatch_paths = int(non_laminar[cohort])
                for metric in DEPTH_METRICS:
                    counts = distributions[cohort][metric]
                    if sum(counts.values()) != total:
                        raise RuntimeError(
                            f"depth distribution mismatch for {label}/{cohort}/{metric}"
                        )
                    depths = sorted(counts) if counts else [None]
                    for depth in depths:
                        paths_at_depth = int(counts[depth]) if depth is not None else 0
                        writer.writerow(
                            {
                                "family": label,
                                "cohort": cohort,
                                "depth_metric": metric,
                                "depth": "" if depth is None else depth,
                                "paths_at_depth": paths_at_depth,
                                "cohort_paths": total,
                                "share_pct": (
                                    f"{100.0 * paths_at_depth / total:.6f}"
                                    if total
                                    else ""
                                ),
                                "non_laminar_paths": mismatch_paths,
                            }
                        )


def flatten_metrics(prefix: str, value: object) -> Iterator[tuple[str, str]]:
    if isinstance(value, dict):
        for key in sorted(value):
            nested = f"{prefix}.{key}" if prefix else str(key)
            yield from flatten_metrics(nested, value[key])
    else:
        yield prefix, "" if value is None else str(value)


def write_audit(path: Path, sections: dict[str, object]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["metric", "value"])
        writer.writerows(flatten_metrics("", sections))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ripe", type=Path, required=True, help="Frozen ripe.db[.gz]")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--bgp-csv", type=Path, help="CSV with prefix,origin_as")
    source.add_argument("--mrt", type=Path, help="MRT RIB parsed with bgpdump")
    parser.add_argument("--bgpdump", default="bgpdump", help="bgpdump executable")
    parser.add_argument("--output", type=Path, required=True, help="Output directory")
    parser.add_argument(
        "--progress-every", type=int, default=500_000, help="Progress interval (0 disables)"
    )
    parser.add_argument(
        "--keep-work-db", action="store_true", help="Retain temporary SQLite DB for audit"
    )
    parser.add_argument(
        "--skip-input-hashes", action="store_true", help="Skip potentially slow SHA-256 input hashes"
    )
    return parser


def run(args: argparse.Namespace) -> dict[str, object]:
    ripe_path = args.ripe.resolve()
    bgp_csv = args.bgp_csv.resolve() if args.bgp_csv else None
    mrt = args.mrt.resolve() if args.mrt else None
    for path in (ripe_path, bgp_csv, mrt):
        if path is not None and not path.is_file():
            raise FileNotFoundError(path)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    descriptor, work_name = tempfile.mkstemp(
        prefix="visibility_work_", suffix=".sqlite3", dir=output
    )
    os.close(descriptor)
    work_path = Path(work_name)
    connection: sqlite3.Connection | None = None
    candidate_tmp = output / "potential_conflicts.csv.tmp"
    depth_tmp = output / "visibility_depth_by_afi.csv.tmp"
    candidate_path = output / "visibility_candidates.csv"
    depth_path = output / "visibility_depth_by_afi.csv"
    compact_path = output / "visibility_by_afi.csv"
    audit_path = output / "visibility_audit_metrics.csv"
    summary_path = output / "visibility_summary.json"
    try:
        connection = connect_work_db(work_path)
        registry_ingest = ingest_registry(connection, ripe_path, args.progress_every)
        ingest_counts = registry_ingest["counts"]
        unsafe_registry_counts = {
            "ambiguous_status_objects": int(
                ingest_counts.get("ambiguous_status_objects", 0)
            ),
            "invalid_ranges": int(ingest_counts.get("invalid_ranges", 0)),
        }
        if any(unsafe_registry_counts.values()):
            raise RuntimeError(
                "registry safety gate failed; an ambiguous status or malformed range "
                f"could hide an eligible root/hop: {unsafe_registry_counts}"
            )
        range_resolution = resolve_ranges(connection)
        containment = build_containment_matches(connection, args.progress_every)
        bgp_audit = ingest_bgp(connection, bgp_csv, mrt, args.bgpdump)
        attach_origin_sets(connection)
        family_results, _, depth_results = process_paths(
            connection, candidate_tmp, bool(bgp_audit["provided"])
        )
        write_depth_distribution(depth_tmp, depth_results, family_results)
        os.replace(candidate_tmp, candidate_path)
        os.replace(depth_tmp, depth_path)
        write_compact(compact_path, family_results, bool(bgp_audit["provided"]))

        input_paths = {"ripe": str(ripe_path)}
        if bgp_csv:
            input_paths["bgp_csv"] = str(bgp_csv)
        if mrt:
            input_paths["mrt"] = str(mrt)
        input_hashes = (
            {name: sha256_file(Path(path)) for name, path in input_paths.items()}
            if not args.skip_input_hashes
            else {}
        )
        audit_sections: dict[str, object] = {
            "registry_ingest": registry_ingest,
            "range_resolution": range_resolution,
            "containment": containment,
            "bgp": bgp_audit,
            "results": family_results,
        }
        write_audit(audit_path, audit_sections)
        summary: dict[str, object] = {
            "schema_version": 1,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "method": {
                "IPv4_chain": "ALLOCATED PA -> [SUB-ALLOCATED PA] -> ASSIGNED PA",
                "IPv6_chain": "ALLOCATED-BY-RIR -> [ALLOCATED-BY-LIR] -> ASSIGNED",
                "root_selection": "nearest strictly containing eligible root",
                "indirect_rule": "one or more eligible hops strictly between root and endpoint",
                "org_confirmed_abc_rule": (
                    "root, one containing hop, and endpoint each have one exact org handle; "
                    "the three handles are pairwise distinct"
                ),
                "potential_conflict_rule": (
                    "registry-indirect path with non-empty disjoint exact-prefix "
                    "root and endpoint origin-AS sets"
                ),
                "claim_boundary": (
                    "candidate only; registry/BGP data do not establish issuer knowledge, "
                    "permission, ROA state, or route legitimacy"
                ),
                "same_range_rule": (
                    "identical status/org fingerprints are deduplicated; any range with "
                    "different status or exact org-handle fingerprints is flagged; conflicting "
                    "roots and hops remain poison barriers so paths cannot fall through"
                ),
                "org_handle_rule": "strip whitespace and canonicalize exact org handles to uppercase",
                "status_comment_rule": (
                    "strip and audit inline # comment suffixes before exact status matching"
                ),
                "registry_safety_gate": (
                    "abort if any object has multiple status values or an unparseable range"
                ),
                "bgp_terminal_rule": (
                    "MOAS is preserved; ambiguous terminal AS_SET/confederation records are excluded"
                ),
            },
            "inputs": {"paths": input_paths, "sha256": input_hashes},
            **audit_sections,
            "outputs": {
                "compact_table": {
                    "path": str(compact_path),
                    "sha256": sha256_file(compact_path),
                },
                "potential_conflicts": {
                    "path": str(candidate_path),
                    "sha256": sha256_file(candidate_path),
                },
                "depth_distribution": {
                    "path": str(depth_path),
                    "sha256": sha256_file(depth_path),
                },
                "audit_metrics": {
                    "path": str(audit_path),
                    "sha256": sha256_file(audit_path),
                },
            },
        }
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        print(json.dumps(family_results, indent=2, sort_keys=True))
        print(f"Wrote {compact_path}")
        print(f"Wrote {candidate_path}")
        print(f"Wrote {depth_path}")
        print(f"Wrote {audit_path}")
        print(f"Wrote {summary_path}")
        return summary
    finally:
        if connection is not None:
            connection.close()
        if candidate_tmp.exists():
            candidate_tmp.unlink()
        if depth_tmp.exists():
            depth_tmp.unlink()
        if args.keep_work_db:
            print(f"Retained work database: {work_path}")
        elif work_path.exists():
            work_path.unlink()


def main() -> None:
    args = build_parser().parse_args()
    run(args)


if __name__ == "__main__":
    main()
