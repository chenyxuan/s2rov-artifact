#!/usr/bin/env python3
"""Shared typography for figures embedded in the IEEE manuscript."""

from __future__ import annotations

from pathlib import Path

import matplotlib as mpl
from matplotlib import font_manager


BODY_FONT_FAMILY = "Nimbus Roman"
BODY_FONT_FILENAMES = (
    "NimbusRoman-Regular.otf",
    "NimbusRoman-Italic.otf",
    "NimbusRoman-Bold.otf",
    "NimbusRoman-BoldItalic.otf",
)


def register_body_fonts() -> tuple[Path, ...]:
    """Register the Times-compatible font used by the IEEEtran body."""
    discovered = {
        Path(path).name: Path(path)
        for path in font_manager.findSystemFonts(fontext="otf")
        if Path(path).name in BODY_FONT_FILENAMES
    }
    missing = [name for name in BODY_FONT_FILENAMES if name not in discovered]
    if missing:
        raise RuntimeError(
            "missing manuscript figure fonts: " + ", ".join(missing)
        )

    ordered = tuple(discovered[name] for name in BODY_FONT_FILENAMES)
    for path in ordered:
        font_manager.fontManager.addfont(str(path))

    font_manager.findfont(BODY_FONT_FAMILY, fallback_to_default=False)
    return ordered


def configure_body_font() -> None:
    """Use one embedded Nimbus Roman family for all figure text."""
    register_body_fonts()
    mpl.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": [BODY_FONT_FAMILY],
            "pdf.fonttype": 42,
            "svg.fonttype": "none",
        }
    )
