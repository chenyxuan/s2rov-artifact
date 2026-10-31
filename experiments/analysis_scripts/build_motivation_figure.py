#!/usr/bin/env python3
"""Export the native Figure 1 SVG without changing its geometry."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess

PAPER = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = PAPER / "figure-data" / "fig_motivation_overview.svg"


def export(source: Path) -> None:
    if not source.is_file():
        raise FileNotFoundError(f"missing native figure source: {source}")
    try:
        import cairosvg
    except ModuleNotFoundError:
        figure_python = PAPER / ".venv" / "bin" / "python"
        if not figure_python.is_file():
            raise RuntimeError(
                "CairoSVG is required to export Figure 1; install it in "
                "the active Python environment or the project .venv"
            ) from None
        subprocess.run(
            [
                str(figure_python),
                str(Path(__file__).resolve()),
                "--source",
                str(source),
            ],
            check=True,
        )
        return
    cairosvg.svg2pdf(
        url=str(source),
        write_to=str(source.with_suffix(".pdf")),
    )
    cairosvg.svg2png(
        url=str(source),
        write_to=str(source.with_suffix(".png")),
        output_width=1800,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    args = parser.parse_args()
    export(args.source.resolve())


if __name__ == "__main__":
    main()
