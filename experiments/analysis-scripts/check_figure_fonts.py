#!/usr/bin/env python3
"""Fail when an active manuscript figure falls back from Nimbus Roman."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


PAPER = Path(__file__).resolve().parents[1]
FIGURES = PAPER / "figures"
ACTIVE_STEMS = (
    "fig_motivation_overview",
    "fig_partial_policy_legend",
    "fig_partial_policy_potential",
    "fig_partial_policy_observed",
    "fig_openscope_placement",
    "fig_processing_cost_classify",
    "fig_processing_cost_update",
    "fig_deployment_outcomes_a",
    "fig_deployment_outcomes_b",
)
FORBIDDEN_FAMILIES = (
    "Arial",
    "Helvetica",
    "DejaVu",
    "Liberation",
)


def pdf_font_rows(path: Path) -> list[list[str]]:
    result = subprocess.run(
        ["pdffonts", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    if "Type 3" in result.stdout:
        raise AssertionError(f"Type 3 font in {path.name}")
    rows = result.stdout.splitlines()[2:]
    return [row.split() for row in rows if row.split()]


def check_pdf(path: Path) -> None:
    rows = pdf_font_rows(path)
    if not rows:
        raise AssertionError(f"no embedded font found in {path.name}")
    names = [row[0] for row in rows]
    unexpected = [
        name
        for name in names
        if re.search(r"(?:^|\+)NimbusRoman-", name) is None
    ]
    if unexpected:
        raise AssertionError(
            f"unexpected fonts in {path.name}: {', '.join(unexpected)}"
        )
    incomplete = [row[0] for row in rows if row[-5:-2] != ["yes", "yes", "yes"]]
    if incomplete:
        raise AssertionError(
            f"fonts are not embedded, subset, and Unicode-mapped in {path.name}: "
            f"{', '.join(incomplete)}"
        )


def check_svg(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    if "Nimbus Roman" not in source:
        raise AssertionError(f"Nimbus Roman is not declared in {path.name}")
    found = [family for family in FORBIDDEN_FAMILIES if family in source]
    if found:
        raise AssertionError(
            f"fallback font declarations in {path.name}: {', '.join(found)}"
        )
    if "<text" not in source:
        raise AssertionError(f"editable SVG text missing from {path.name}")
    if "<image" in source:
        raise AssertionError(f"embedded raster found in {path.name}")
    if 'id="NimbusRoman-' in source:
        raise AssertionError(f"outlined Nimbus Roman glyphs found in {path.name}")


def check_main_pdf(path: Path) -> None:
    rows = pdf_font_rows(path)
    names = [row[0] for row in rows]
    found = [
        name
        for name in names
        if any(family.lower() in name.lower() for family in FORBIDDEN_FAMILIES)
    ]
    if found:
        raise AssertionError(
            f"fallback figure fonts in {path.name}: {', '.join(found)}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--main-pdf",
        action="store_true",
        help="also reject fallback figure fonts in the assembled manuscript",
    )
    args = parser.parse_args()

    for stem in ACTIVE_STEMS:
        check_pdf(FIGURES / f"{stem}.pdf")
        check_svg(FIGURES / f"{stem}.svg")
    if args.main_pdf:
        check_main_pdf(PAPER / "main.pdf")
    print(f"active figure font checks passed: {len(ACTIVE_STEMS)}")


if __name__ == "__main__":
    main()
