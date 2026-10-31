#!/usr/bin/env python3
"""Small end-to-end regression test for the visibility experiment."""

from __future__ import annotations

import csv
import gzip
import json
import subprocess
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "analyze_visibility.py"
sys.path.insert(0, str(SCRIPT.parent))

from analyze_visibility import HopDepthIndex  # noqa: E402


OBJECTS = """\
inetnum: 10.0.0.0 - 10.0.0.255
status: ALLOCATED PA
org: ORG-A-TEST

inetnum: 10.0.0.0 - 10.0.0.127
status: SUB-ALLOCATED PA
org: ORG-B-TEST

inetnum: 10.0.0.0 - 10.0.0.63
status: ASSIGNED PA
org: ORG-C-TEST

inetnum: 10.0.0.128 - 10.0.0.191
status: ASSIGNED PA
org: ORG-D-TEST

inetnum: 10.0.0.192 - 10.0.0.255
status: ASSIGNED PA
org: ORG-E-TEST

inetnum: 10.0.0.192 - 10.0.0.255
status: ASSIGNED PA
org: ORG-F-TEST

inetnum: 10.1.0.0 - 10.1.255.255
status: ALLOCATED PA
org: ORG-OUTER-TEST

inetnum: 10.1.0.0 - 10.1.0.255
status: ALLOCATED PA
org: ORG-INNER1-TEST

inetnum: 10.1.0.0 - 10.1.0.255
status: ALLOCATED PA
org: ORG-INNER2-TEST

inetnum: 10.1.0.0 - 10.1.0.127
status: ASSIGNED PA
org: ORG-END-TEST

inetnum: 10.2.0.0 - 10.2.0.255
status: ALLOCATED PA
org: ORG-HROOT-TEST

inetnum: 10.2.0.0 - 10.2.0.127
status: SUB-ALLOCATED PA
org: ORG-HOP1-TEST

inetnum: 10.2.0.0 - 10.2.0.127
status: SUB-ALLOCATED PA
org: ORG-HOP2-TEST

inetnum: 10.2.0.0 - 10.2.0.63
status: ASSIGNED PA
org: ORG-HEND-TEST

inetnum: 10.3.0.0 - 10.3.0.255
status: ALLOCATED PA
org: ORG-X-TEST

inetnum: 10.3.0.0 - 10.3.0.127
status: SUB-ALLOCATED PA
org: org-y-test

inetnum: 10.3.0.0 - 10.3.0.63
status: ASSIGNED PA
org: ORG-Y-TEST

inetnum: 10.4.0.0 - 10.4.0.255
status: ALLOCATED PA

inetnum: 10.4.0.0 - 10.4.0.191
status: SUB-ALLOCATED PA

inetnum: 10.4.0.64 - 10.4.0.255
status: SUB-ALLOCATED PA

inetnum: 10.4.0.96 - 10.4.0.127
status: ASSIGNED PA

inetnum: 10.5.0.0 - 10.5.0.255
status: ALLOCATED PA

inetnum: 10.5.0.0 - 10.5.0.127
status: SUB-ALLOCATED PA

inetnum: 10.5.0.0 - 10.5.0.63
status: SUB-ALLOCATED PA

inetnum: 10.5.0.0 - 10.5.0.31
status: SUB-ALLOCATED PA

inetnum: 10.5.0.0 - 10.5.0.15
status: ASSIGNED PA

inetnum: 10.5.0.32 - 10.5.0.63
status: ASSIGNED PA

inet6num: 2001:db8::/32
status: ALLOCATED-BY-RIR # normalised by the parser
org: ORG-A6-TEST

inet6num: 2001:db8:1::/48
status: ALLOCATED-BY-LIR
org: ORG-B6-TEST

inet6num: 2001:db8:1::/64
status: ASSIGNED
org: ORG-C6-TEST

inet6num: 2001:db8:2::/64
status: ASSIGNED
org: ORG-D6-TEST

"""


ORIGINS = [
    ("10.0.0.0/24", "64500"),
    ("10.0.0.0/26", "64501"),
    ("10.0.0.0/26", "64502"),
    ("10.0.0.128/26", "64500"),
    ("10.0.0.128/26", "{64599,64600}"),
    ("10.4.0.0/24", "64520"),
    ("10.4.0.96/27", "64521"),
    ("10.5.0.0/24", "64530"),
    ("10.5.0.0/28", "64531"),
    ("10.5.0.32/27", "64532"),
    ("2001:db8::/32", "64510"),
    ("2001:db8:1::/64", "64511"),
    ("2001:db8:2::/64", "64510"),
]


def test_equal_end_strict_nesting() -> None:
    """Two later-starting hops with one end address form a strict chain."""
    index = HopDepthIndex([255, 255])
    # The caller's sweep supplies starts in increasing order.  These calls
    # model [0,255] followed by [128,255], which is strict containment even
    # though both intervals have the same end address.
    assert index.add_hop(255) == 1
    assert index.add_hop(255) == 2
    assert index.endpoint_depth(255) == (2, 2)


def main() -> None:
    test_equal_end_strict_nesting()
    with tempfile.TemporaryDirectory(prefix="visibility_test_") as temp:
        root = Path(temp)
        ripe = root / "ripe.db.gz"
        bgp = root / "origins.csv"
        output = root / "out"
        with gzip.open(ripe, "wt", encoding="latin-1") as handle:
            handle.write(OBJECTS)
        with bgp.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["prefix", "origin_as"])
            writer.writerows(ORIGINS)
        subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--ripe",
                str(ripe),
                "--bgp-csv",
                str(bgp),
                "--output",
                str(output),
                "--progress-every",
                "0",
                "--skip-input-hashes",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        summary = json.loads((output / "visibility_summary.json").read_text())
        ipv4 = summary["results"]["IPv4"]
        ipv6 = summary["results"]["IPv6"]
        assert ipv4["direct_paths"] == 1, ipv4
        assert ipv4["registry_indirect_paths"] == 5, ipv4
        assert ipv4["org_confirmed_abc_paths"] == 1, ipv4
        assert ipv4["potential_conflicts"] == 4, ipv4
        assert ipv4["org_confirmed_abc_conflicts"] == 1, ipv4
        assert ipv4["ambiguous_hop_paths_excluded"] == 1, ipv4
        assert ipv6["direct_paths"] == 1, ipv6
        assert ipv6["registry_indirect_paths"] == 1, ipv6
        assert ipv6["potential_conflicts"] == 1, ipv6
        assert ipv6["org_confirmed_abc_conflicts"] == 1, ipv6
        assert summary["range_resolution"]["conflicting_ranges"] == 3
        assert summary["range_resolution"]["root_conflict_barriers"] == 1
        assert summary["range_resolution"]["hop_conflict_barriers"] == 1
        containment4 = summary["containment"]["IPv4"]
        assert containment4["endpoints_nearest_root_conflict_excluded"] == 1
        assert summary["registry_ingest"]["counts"]["org_handle_case_normalizations"] == 1
        assert summary["bgp"]["counts"]["ambiguous_prefixes"] == 1
        assert ipv4["origin_ambiguous_direct_paths"] == 1
        candidates = list(
            csv.DictReader((output / "visibility_candidates.csv").open())
        )
        assert len(candidates) == 5
        assert {row["family"] for row in candidates} == {"IPv4", "IPv6"}

        depth_rows = list(
            csv.DictReader((output / "visibility_depth_by_afi.csv").open())
        )

        def distribution(family: str, cohort: str, metric: str) -> dict[int, int]:
            return {
                int(row["depth"]): int(row["paths_at_depth"])
                for row in depth_rows
                if row["family"] == family
                and row["cohort"] == cohort
                and row["depth_metric"] == metric
                and row["depth"]
            }

        for cohort, expected_chain, expected_objects, expected_total in (
            (
                "all_registry_indirect",
                {1: 3, 2: 1, 3: 1},
                {1: 2, 2: 2, 3: 1},
                5,
            ),
            (
                "exact_observed_registry_indirect",
                {1: 2, 2: 1, 3: 1},
                {1: 1, 2: 2, 3: 1},
                4,
            ),
            (
                "origin_disjoint_candidate",
                {1: 2, 2: 1, 3: 1},
                {1: 1, 2: 2, 3: 1},
                4,
            ),
        ):
            assert distribution(
                "IPv4", cohort, "longest_strict_nested_chain"
            ) == expected_chain
            assert distribution(
                "IPv4", cohort, "containing_eligible_objects"
            ) == expected_objects
            rows = [
                row
                for row in depth_rows
                if row["family"] == "IPv4" and row["cohort"] == cohort
            ]
            assert {int(row["cohort_paths"]) for row in rows} == {expected_total}
            assert {int(row["non_laminar_paths"]) for row in rows} == {1}

        for cohort in (
            "all_registry_indirect",
            "exact_observed_registry_indirect",
            "origin_disjoint_candidate",
        ):
            assert distribution(
                "IPv6", cohort, "longest_strict_nested_chain"
            ) == {1: 1}
            assert distribution(
                "IPv6", cohort, "containing_eligible_objects"
            ) == {1: 1}
            rows = [
                row
                for row in depth_rows
                if row["family"] == "IPv6" and row["cohort"] == cohort
            ]
            assert {int(row["non_laminar_paths"]) for row in rows} == {0}


if __name__ == "__main__":
    main()
