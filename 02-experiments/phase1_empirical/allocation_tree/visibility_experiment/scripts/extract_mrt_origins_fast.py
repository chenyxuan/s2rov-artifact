#!/usr/bin/env python3
"""Fast, deterministic MRT-to-origin extraction for visibility cross-checks.

The main visibility analysis can read this script's CSV output directly via
``--bgp-csv``.  The extractor deliberately does less work per RIB record than
the main analysis:

* ``bgpdump -m`` is trusted to emit canonical prefix text.  A cheap address
  family/prefix-length check replaces per-record ``ipaddress.ip_network``.
* Prefix state is aggregated in memory.  The common case stores one integer;
  a ``set`` is allocated only after a prefix becomes MOAS.
* Any terminal AS_SET, confederation segment, missing terminal, or otherwise
  unparseable terminal marks the whole prefix ambiguous.  Scalar origins seen
  for that prefix are still retained for audit, but the compatible CSV also
  emits ``{AMBIGUOUS}``, causing the conservative main analysis to exclude it.
* Output is sorted bytewise by prefix and numerically by ASN, and contains no
  timestamps, so repeated runs over the same bgpdump stream are byte-identical.

This is an independent extraction/check path; it does not modify the MRT or
the running visibility analysis.  A synthetic regression test and a parser
benchmark are embedded as the ``self-test`` and ``benchmark`` subcommands.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import resource
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Sequence


CSV_AMBIGUITY_MARKER = b"{AMBIGUOUS}"

TERMINAL_AS_SET = 1 << 0
TERMINAL_CONFED = 1 << 1
TERMINAL_MISSING = 1 << 2
TERMINAL_UNPARSEABLE = 1 << 3

AMBIGUITY_REASON_NAMES: tuple[tuple[int, str], ...] = (
    (TERMINAL_AS_SET, "terminal_as_set"),
    (TERMINAL_CONFED, "terminal_confed"),
    (TERMINAL_MISSING, "terminal_missing"),
    (TERMINAL_UNPARSEABLE, "terminal_unparseable"),
)

_MISSING = object()
OriginValue = int | set[int] | None
RIB_RECORD_TYPES = frozenset(
    (b"TABLE_DUMP", b"TABLE_DUMP2", b"TABLE_DUMP2_AP")
)


@dataclass(slots=True)
class ScanStats:
    records_seen: int = 0
    add_path_records: int = 0
    malformed_records: int = 0
    invalid_prefix_records: int = 0
    accepted_records: int = 0
    terminal_as_set_records: int = 0
    terminal_confed_records: int = 0
    terminal_missing_records: int = 0
    terminal_unparseable_records: int = 0


@dataclass(slots=True)
class OriginTable:
    """Compact prefix state: scalar fast path, sets only for actual MOAS."""

    origins: dict[bytes, OriginValue] = field(default_factory=dict)
    ambiguity: dict[bytes, int] = field(default_factory=dict)
    ipv4_prefixes: int = 0
    ipv6_prefixes: int = 0

    def counts(self, scan: ScanStats) -> dict[str, int]:
        unique_pairs = 0
        moas_prefixes = 0
        prefixes_with_origins = 0
        prefixes_without_origins = 0
        mixed_ambiguous_prefixes = 0
        for prefix, value in self.origins.items():
            if value is None:
                prefixes_without_origins += 1
                continue
            prefixes_with_origins += 1
            if isinstance(value, int):
                unique_pairs += 1
            else:
                unique_pairs += len(value)
                if len(value) > 1:
                    moas_prefixes += 1
            if prefix in self.ambiguity:
                mixed_ambiguous_prefixes += 1

        result = {
            "records_seen": scan.records_seen,
            "add_path_records": scan.add_path_records,
            "malformed_records": scan.malformed_records,
            "invalid_prefix_records": scan.invalid_prefix_records,
            "accepted_records": scan.accepted_records,
            "terminal_as_set_records": scan.terminal_as_set_records,
            "terminal_confed_records": scan.terminal_confed_records,
            "terminal_missing_records": scan.terminal_missing_records,
            "terminal_unparseable_records": scan.terminal_unparseable_records,
            "unique_prefixes": len(self.origins),
            "ipv4_prefixes": self.ipv4_prefixes,
            "ipv6_prefixes": self.ipv6_prefixes,
            "prefixes_with_scalar_origins": prefixes_with_origins,
            "prefixes_without_scalar_origins": prefixes_without_origins,
            "unique_prefix_origin_pairs": unique_pairs,
            "duplicate_prefix_origin_pairs_collapsed": (
                scan.accepted_records - unique_pairs
            ),
            "moas_prefixes": moas_prefixes,
            "ambiguous_prefixes": len(self.ambiguity),
            "mixed_scalar_and_ambiguous_prefixes": mixed_ambiguous_prefixes,
        }
        return result


def cheap_prefix_family(prefix: bytes) -> int:
    """Return 4/6 using only delimiters and prefix-length bounds.

    ``bgpdump`` owns address parsing and canonicalization.  This guard catches
    field shifts and obvious corruption without paying for ``ipaddress`` on
    every peer-prefix record.  It intentionally is not a second IP parser.
    """

    slash = prefix.rfind(b"/")
    if slash <= 0 or slash == len(prefix) - 1 or not prefix.isascii():
        return 0
    address = prefix[:slash]
    prefix_length = prefix[slash + 1 :]
    if b"/" in address or not prefix_length.isdigit():
        return 0
    # Whitespace implies a shifted/corrupt bgpdump field.  Normal canonical
    # prefixes contain none; these four checks stay in fast C byte searches.
    if any(mark in prefix for mark in (b" ", b"\t", b"\r", b"\n")):
        return 0
    length = int(prefix_length)
    if b":" in address:
        return 6 if length <= 128 else 0
    if b"." in address:
        return 4 if length <= 32 and address.count(b".") == 3 else 0
    return 0


def parse_terminal_asn(as_path: bytes) -> tuple[int | None, int]:
    """Return a scalar terminal ASN or an ambiguity reason bit."""

    path = as_path.strip()
    if not path:
        return None, TERMINAL_MISSING

    # Sets/sequences may contain spaces, so inspect the closing delimiter
    # before splitting off a scalar terminal token.
    if path.endswith(b"}"):
        return None, TERMINAL_AS_SET
    if path.endswith((b")", b"]")):
        return None, TERMINAL_CONFED

    token = path.rsplit(None, 1)[-1]
    if token[:2].upper() == b"AS":
        token = token[2:]
    if not token:
        return None, TERMINAL_UNPARSEABLE

    if b"." in token:
        pieces = token.split(b".")
        if len(pieces) != 2 or not pieces[0].isdigit() or not pieces[1].isdigit():
            return None, TERMINAL_UNPARSEABLE
        high, low = int(pieces[0]), int(pieces[1])
        if high > 0xFFFF or low > 0xFFFF:
            return None, TERMINAL_UNPARSEABLE
        asn = high * 65536 + low
    elif token.isdigit():
        asn = int(token)
    else:
        return None, TERMINAL_UNPARSEABLE
    if asn > 0xFFFFFFFF:
        return None, TERMINAL_UNPARSEABLE
    return asn, 0


def _mark_ambiguity(table: OriginTable, prefix: bytes, reason: int) -> None:
    table.ambiguity[prefix] = table.ambiguity.get(prefix, 0) | reason


def extract_bgpdump_lines(
    lines: Iterable[bytes],
    *,
    progress_every: int = 0,
    progress_stream: object = sys.stderr,
) -> tuple[OriginTable, ScanStats]:
    """Aggregate origins from binary ``bgpdump -m`` output lines."""

    table = OriginTable()
    scan = ScanStats()
    origins = table.origins
    origins_get = origins.get
    started = time.monotonic()

    for line in lines:
        scan.records_seen += 1
        # Only fields 0..7 matter (7 only for Add-Path).  Limiting splits
        # avoids parsing communities and other large trailing attributes.
        fields = line.rstrip(b"\r\n").split(b"|", 8)
        if len(fields) <= 5:
            scan.malformed_records += 1
            if progress_every and scan.records_seen % progress_every == 0:
                _print_progress(scan, len(origins), started, progress_stream)
            continue

        record_type = fields[0]
        if record_type not in RIB_RECORD_TYPES or fields[2] != b"B":
            raise ValueError(
                "expected a bgpdump RIB record, got "
                f"type={record_type!r} action={fields[2]!r} "
                f"at record {scan.records_seen:,}"
            )

        prefix = fields[5].strip()
        current = origins_get(prefix, _MISSING)
        if current is _MISSING:
            family = cheap_prefix_family(prefix)
            if family == 0:
                scan.invalid_prefix_records += 1
                if progress_every and scan.records_seen % progress_every == 0:
                    _print_progress(scan, len(origins), started, progress_stream)
                continue
            # Keep even an ambiguity-only prefix so it gets an exclusion row.
            origins[prefix] = None
            current = None
            if family == 4:
                table.ipv4_prefixes += 1
            else:
                table.ipv6_prefixes += 1

        # bgpdump inserts a 32-bit path ID between prefix and AS_PATH for
        # TABLE_DUMP2_AP/BGP4MP*_AP.  Treating field 6 uniformly as AS_PATH
        # would silently turn path IDs into origins.
        add_path = record_type.endswith(b"_AP")
        as_path_index = 7 if add_path else 6
        if add_path:
            scan.add_path_records += 1
        if len(fields) <= as_path_index:
            scan.malformed_records += 1
            scan.terminal_missing_records += 1
            _mark_ambiguity(table, prefix, TERMINAL_MISSING)
        else:
            asn, reason = parse_terminal_asn(fields[as_path_index])
            if reason:
                if reason == TERMINAL_AS_SET:
                    scan.terminal_as_set_records += 1
                elif reason == TERMINAL_CONFED:
                    scan.terminal_confed_records += 1
                elif reason == TERMINAL_MISSING:
                    scan.terminal_missing_records += 1
                else:
                    scan.terminal_unparseable_records += 1
                _mark_ambiguity(table, prefix, reason)
            else:
                assert asn is not None
                scan.accepted_records += 1
                if current is None:
                    origins[prefix] = asn
                elif isinstance(current, int):
                    if current != asn:
                        origins[prefix] = {current, asn}
                else:
                    current.add(asn)

        if progress_every and scan.records_seen % progress_every == 0:
            _print_progress(scan, len(origins), started, progress_stream)

    return table, scan


def _print_progress(
    scan: ScanStats, unique_prefixes: int, started: float, stream: object
) -> None:
    elapsed = max(time.monotonic() - started, 1e-9)
    print(
        f"records={scan.records_seen:,} prefixes={unique_prefixes:,} "
        f"rate={scan.records_seen / elapsed:,.0f}/s",
        file=stream,
        flush=True,
    )


def extract_mrt(
    mrt: Path,
    *,
    bgpdump: str,
    progress_every: int,
) -> tuple[OriginTable, ScanStats]:
    """Run bgpdump safely and aggregate its stdout without intermediate files."""

    if not mrt.is_file():
        raise FileNotFoundError(mrt)
    with tempfile.TemporaryFile(mode="w+b") as error_log:
        process = subprocess.Popen(
            [bgpdump, "-q", "-m", "-O", "/dev/stdout", str(mrt)],
            stdout=subprocess.PIPE,
            stderr=error_log,
        )
        assert process.stdout is not None
        try:
            table, scan = extract_bgpdump_lines(
                process.stdout,
                progress_every=progress_every,
                progress_stream=sys.stderr,
            )
        except BaseException:
            process.kill()
            process.wait()
            raise
        return_code = process.wait()
        if return_code:
            error_log.seek(0, os.SEEK_END)
            size = error_log.tell()
            error_log.seek(max(0, size - 4000))
            stderr_tail = error_log.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"bgpdump exited {return_code}; stderr tail: {stderr_tail}"
            )
    return table, scan


def iter_origins(value: OriginValue) -> Iterator[int]:
    if value is None:
        return
    if isinstance(value, int):
        yield value
    else:
        yield from sorted(value)


def ambiguity_reasons(mask: int) -> list[str]:
    return [name for bit, name in AMBIGUITY_REASON_NAMES if mask & bit]


def write_csv(path: Path, table: OriginTable) -> None:
    """Write a CSV accepted by analyze_visibility.py's --bgp-csv path."""

    with path.open("wb") as handle:
        handle.write(b"prefix,origin_as\n")
        for prefix in sorted(table.origins):
            for asn in iter_origins(table.origins[prefix]):
                handle.write(prefix)
                handle.write(b",")
                handle.write(str(asn).encode("ascii"))
                handle.write(b"\n")
            if prefix in table.ambiguity:
                handle.write(prefix)
                handle.write(b",")
                handle.write(CSV_AMBIGUITY_MARKER)
                handle.write(b"\n")


def write_json(
    path: Path,
    table: OriginTable,
    counts: Mapping[str, int],
) -> None:
    """Write one valid, compact JSON document with explicit ambiguity reasons."""

    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(
            '{"schema_version":1,"ambiguity_marker":"{AMBIGUOUS}","prefixes":['
        )
        first = True
        for prefix in sorted(table.origins):
            if not first:
                handle.write(",")
            first = False
            mask = table.ambiguity.get(prefix, 0)
            entry = {
                "prefix": prefix.decode("ascii"),
                "family": 6 if b":" in prefix else 4,
                "origins": list(iter_origins(table.origins[prefix])),
                "ambiguous": bool(mask),
                "ambiguity_reasons": ambiguity_reasons(mask),
            }
            json.dump(entry, handle, ensure_ascii=True, separators=(",", ":"))
        handle.write('],"counts":')
        json.dump(counts, handle, sort_keys=True, separators=(",", ":"))
        handle.write("}\n")


def write_output_atomic(
    destination: Path,
    *,
    output_format: str,
    table: OriginTable,
    counts: Mapping[str, int],
    force: bool,
) -> None:
    destination = destination.absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise FileExistsError(f"refusing symlink output: {destination}")
    if destination.exists() and not force:
        raise FileExistsError(
            f"output exists (pass --force to replace): {destination}"
        )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        if output_format == "csv":
            write_csv(temporary, table)
        else:
            write_json(temporary, table, counts)
        if force:
            os.replace(temporary, destination)
        else:
            # The hard-link publication is atomic and fails with EEXIST.  In
            # contrast, a check followed by os.replace could clobber a file
            # concurrently created while the large MRT was being scanned.
            try:
                os.link(temporary, destination)
            except FileExistsError as error:
                raise FileExistsError(
                    f"output appeared during extraction: {destination}"
                ) from error
            temporary.unlink()
    finally:
        temporary.unlink(missing_ok=True)


def resolve_output_format(requested: str, output: Path) -> str:
    if requested != "auto":
        return requested
    if output.suffix.lower() == ".json":
        return "json"
    if output.suffix.lower() == ".csv":
        return "csv"
    raise ValueError("--format auto requires an output ending in .csv or .json")


def _synthetic_line(
    prefix: str, as_path: str, *, add_path_id: int | None = None
) -> bytes:
    record_type = "TABLE_DUMP2_AP" if add_path_id is not None else "TABLE_DUMP2"
    path_id = f"{add_path_id}|" if add_path_id is not None else ""
    return (
        f"{record_type}|1700000000|B|192.0.2.1|64500|{prefix}|{path_id}{as_path}|"
        "IGP|192.0.2.1|0|0|||NAG||\n"
    ).encode("ascii")


def run_self_test() -> None:
    """Exercise MOAS, every ambiguity class, cheap AFI checks, and output."""

    lines = [
        _synthetic_line("10.0.0.0/24", "64500"),
        _synthetic_line("10.0.0.0/24", "64500"),  # duplicate
        _synthetic_line("10.0.0.0/24", "64501"),  # MOAS
        _synthetic_line("10.0.0.0/24", "64500 {64502,64503}"),
        _synthetic_line("10.0.1.0/24", "64500 (65000 65001)"),
        _synthetic_line("10.0.1.0/24", "64500 [65002,65003]"),
        _synthetic_line("10.0.2.0/24", ""),
        _synthetic_line("10.0.2.0/24", "not-an-asn"),
        _synthetic_line("10.0.2.0/24", "1.10"),
        _synthetic_line("10.0.3.0/24", "AS64511"),
        _synthetic_line("10.0.4.0/24", "{64500,64501} 64512"),
        _synthetic_line("2001:db8::/32", "64513"),
        _synthetic_line("2001:db8:1::/48", "64520", add_path_id=4_000_000_001),
        _synthetic_line(
            "2001:db8:1::/48", "{64521,64522}", add_path_id=4_000_000_002
        ),
        _synthetic_line("10.0.5.0/99", "64514"),
        _synthetic_line("not-a-prefix", "64515"),
        _synthetic_line("10.0.6.0/24", "4294967296"),
        _synthetic_line("10.0.7.0/24", "0.70000"),
        b"malformed\n",
        b"TABLE_DUMP2|1700000000|B|192.0.2.1|64500|10.0.8.0/24\n",
    ]
    table, scan = extract_bgpdump_lines(lines)
    counts = table.counts(scan)

    assert table.origins[b"10.0.0.0/24"] == {64500, 64501}
    assert table.ambiguity[b"10.0.0.0/24"] == TERMINAL_AS_SET
    assert table.origins[b"10.0.1.0/24"] is None
    assert table.ambiguity[b"10.0.1.0/24"] == TERMINAL_CONFED
    assert table.origins[b"10.0.2.0/24"] == 65546
    assert table.ambiguity[b"10.0.2.0/24"] == (
        TERMINAL_MISSING | TERMINAL_UNPARSEABLE
    )
    assert table.origins[b"10.0.3.0/24"] == 64511
    assert table.origins[b"10.0.4.0/24"] == 64512
    assert table.origins[b"2001:db8::/32"] == 64513
    assert table.origins[b"2001:db8:1::/48"] == 64520
    assert table.ambiguity[b"2001:db8:1::/48"] == TERMINAL_AS_SET
    assert b"10.0.5.0/99" not in table.origins
    assert counts["records_seen"] == len(lines)
    assert counts["invalid_prefix_records"] == 2
    assert counts["malformed_records"] == 2
    assert counts["add_path_records"] == 2
    assert counts["accepted_records"] == 8
    assert counts["unique_prefix_origin_pairs"] == 7
    assert counts["moas_prefixes"] == 1
    assert counts["ambiguous_prefixes"] == 7

    update = _synthetic_line("10.9.0.0/24", "64530").replace(
        b"TABLE_DUMP2|", b"BGP4MP|", 1
    )
    withdrawal = _synthetic_line("10.9.1.0/24", "").replace(
        b"|B|", b"|W|", 1
    )
    for non_rib in (update, withdrawal):
        try:
            extract_bgpdump_lines([non_rib])
        except ValueError as error:
            assert "expected a bgpdump RIB record" in str(error)
        else:
            raise AssertionError("update/withdrawal input was not rejected")

    with tempfile.TemporaryDirectory(prefix="mrt_origin_selftest_") as raw_temp:
        root = Path(raw_temp)
        csv_one, csv_two = root / "one.csv", root / "two.csv"
        json_one, json_two = root / "one.json", root / "two.json"
        write_csv(csv_one, table)
        write_csv(csv_two, table)
        write_json(json_one, table, counts)
        write_json(json_two, table, counts)
        assert csv_one.read_bytes() == csv_two.read_bytes()
        assert json_one.read_bytes() == json_two.read_bytes()
        rows = csv_one.read_text(encoding="ascii").splitlines()
        assert rows[:4] == [
            "prefix,origin_as",
            "10.0.0.0/24,64500",
            "10.0.0.0/24,64501",
            "10.0.0.0/24,{AMBIGUOUS}",
        ]
        document = json.loads(json_one.read_text(encoding="utf-8"))
        assert document["counts"] == counts
        indexed = {item["prefix"]: item for item in document["prefixes"]}
        assert indexed["10.0.2.0/24"]["ambiguity_reasons"] == [
            "terminal_missing",
            "terminal_unparseable",
        ]

    print("self-test: PASS")
    print(json.dumps(counts, sort_keys=True, separators=(",", ":")))


def build_benchmark_block(prefixes: int) -> list[bytes]:
    if not 1 <= prefixes <= (1 << 24):
        raise ValueError("--prefixes must be between 1 and 16,777,216")
    block: list[bytes] = []
    for index in range(prefixes):
        address = (
            f"10.{(index >> 16) & 255}.{(index >> 8) & 255}.{index & 255}/32"
        )
        block.append(_synthetic_line(address, str(64512 + index % 10000)))
        if index % 997 == 0:
            block.append(_synthetic_line(address, str(74512 + index % 10000)))
        if index % 4999 == 0:
            block.append(_synthetic_line(address, "{64500,64501}"))
    return block


def run_benchmark(records: int, prefixes: int) -> None:
    """Benchmark the parser/aggregator on a prebuilt repeatable line block."""

    if records <= 0:
        raise ValueError("--records must be positive")
    if not 1 <= prefixes <= (1 << 24):
        raise ValueError("--prefixes must be between 1 and 16,777,216")
    effective_prefixes = min(prefixes, records)
    block = build_benchmark_block(effective_prefixes)
    fixture_bytes = sum(len(line) for line in block)
    lines = itertools.islice(itertools.cycle(block), records)
    started = time.perf_counter()
    table, scan = extract_bgpdump_lines(lines)
    elapsed = time.perf_counter() - started
    counts = table.counts(scan)
    max_rss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    report: dict[str, int | float] = {
        "records": records,
        "synthetic_prefixes_requested": prefixes,
        "synthetic_prefixes_materialized": effective_prefixes,
        "elapsed_seconds": round(elapsed, 6),
        "records_per_second": round(records / elapsed, 2),
        "process_max_rss_mib": round(max_rss_kib / 1024, 2),
        "fixture_bytes": fixture_bytes,
        "unique_prefixes": counts["unique_prefixes"],
        "unique_prefix_origin_pairs": counts["unique_prefix_origin_pairs"],
        "moas_prefixes": counts["moas_prefixes"],
        "ambiguous_prefixes": counts["ambiguous_prefixes"],
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    extract = commands.add_parser(
        "extract", help="extract deterministic origins from an MRT RIB"
    )
    extract.add_argument("--mrt", type=Path, required=True)
    extract.add_argument("--output", type=Path, required=True)
    extract.add_argument(
        "--format", choices=("auto", "csv", "json"), default="auto"
    )
    extract.add_argument("--bgpdump", default="bgpdump")
    extract.add_argument("--progress-every", type=int, default=5_000_000)
    extract.add_argument(
        "--force", action="store_true", help="replace an existing output file"
    )

    commands.add_parser("self-test", help="run embedded synthetic regression tests")

    benchmark = commands.add_parser(
        "benchmark", help="benchmark the parser on synthetic bgpdump lines"
    )
    benchmark.add_argument("--records", type=int, default=2_000_000)
    benchmark.add_argument("--prefixes", type=int, default=100_000)
    return parser


def run_extract(args: argparse.Namespace) -> None:
    if args.progress_every < 0:
        raise ValueError("--progress-every must be non-negative")
    mrt = args.mrt.resolve()
    output = args.output.parent.resolve() / args.output.name
    if mrt == output:
        raise ValueError("--output must not name the input MRT")
    if output.is_symlink():
        raise FileExistsError(f"refusing symlink output: {output}")
    if output.exists() and not args.force:
        raise FileExistsError(f"output exists (pass --force to replace): {output}")
    output_format = resolve_output_format(args.format, output)
    started = time.perf_counter()
    table, scan = extract_mrt(
        mrt,
        bgpdump=args.bgpdump,
        progress_every=args.progress_every,
    )
    counts = table.counts(scan)
    write_output_atomic(
        output,
        output_format=output_format,
        table=table,
        counts=counts,
        force=args.force,
    )
    elapsed = time.perf_counter() - started
    report: dict[str, object] = {
        "output": str(output),
        "format": output_format,
        "elapsed_seconds": round(elapsed, 6),
        "records_per_second": round(scan.records_seen / max(elapsed, 1e-9), 2),
        "counts": counts,
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")), file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if args.command == "extract":
        run_extract(args)
    elif args.command == "self-test":
        run_self_test()
    else:
        run_benchmark(args.records, args.prefixes)


if __name__ == "__main__":
    main()
