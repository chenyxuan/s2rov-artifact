#!/usr/bin/env python3
"""Build the implementation-path schematic used in Section IV.

The figure is a semantic schematic.  It contains no measured values and is
grounded in the selected-fixture handoff implementation rather than in the
experimental result tables.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

os.environ.setdefault("SOURCE_DATE_EPOCH", "1787875200")

import matplotlib

matplotlib.use("Agg")
import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


SCRIPT = Path(__file__).resolve()
PAPER = SCRIPT.parents[1]
REPO = PAPER.parent
FIGURES = PAPER / "figures"
STEM = FIGURES / "fig_prototype_path"
OUTPUTS = {fmt: STEM.with_suffix(f".{fmt}") for fmt in ("svg", "pdf", "png", "tiff")}
MANIFEST = FIGURES / "fig_prototype_path.manifest.json"
PROVENANCE = FIGURES / "FIG_PROTOTYPE_PATH_PROVENANCE.md"

EVIDENCE = (
    REPO / "phase6_system/e2e/src/staged_policy.py",
    REPO / "phase6_system/e2e/src/daroa_policy_dualstack.py",
    REPO / "phase6_system/e2e/scripts/run-handoff-benefit.sh",
)

BLUE = "#0F4D92"
BLUE_FILL = "#E6F0FA"
GREY = "#596168"
GREY_FILL = "#F0F2F3"
TEAL = "#25877D"
TEAL_FILL = "#E1F3F0"
AMBER = "#A96B16"
AMBER_FILL = "#FAEEDC"
NAVY = "#34495E"
NAVY_FILL = "#E9EEF3"
INK = "#252A2E"
WHITE = "#FFFFFF"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repo_path(path: Path) -> str:
    return path.relative_to(REPO).as_posix()


def configure_style() -> None:
    mpl.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": ["Arial", "DejaVu Sans", "Liberation Sans"],
            "font.size": 6.2,
            "pdf.fonttype": 42,
            "svg.fonttype": "none",
            "svg.hashsalt": "s2-rov-prototype-path-v1",
            "figure.facecolor": WHITE,
            "savefig.facecolor": WHITE,
        }
    )


def box(
    ax: plt.Axes,
    *,
    x: float,
    y: float,
    width: float,
    height: float,
    title: str,
    subtitle: str,
    edge: str,
    fill: str,
) -> None:
    patch = FancyBboxPatch(
        (x, y),
        width,
        height,
        boxstyle="round,pad=0.010,rounding_size=0.025",
        linewidth=1.05,
        edgecolor=edge,
        facecolor=fill,
        transform=ax.transAxes,
        clip_on=False,
    )
    ax.add_patch(patch)
    center = x + width / 2
    ax.text(
        center,
        y + height * 0.64,
        title,
        transform=ax.transAxes,
        ha="center",
        va="center",
        fontsize=6.35,
        fontweight="bold",
        color=INK,
    )
    ax.text(
        center,
        y + height * 0.30,
        subtitle,
        transform=ax.transAxes,
        ha="center",
        va="center",
        fontsize=5.35,
        color=INK,
    )


def arrow(
    ax: plt.Axes,
    start: tuple[float, float],
    end: tuple[float, float],
    *,
    color: str = GREY,
) -> None:
    ax.add_patch(
        FancyArrowPatch(
            start,
            end,
            transform=ax.transAxes,
            arrowstyle="-|>",
            mutation_scale=8.5,
            linewidth=1.05,
            color=color,
            shrinkA=1.5,
            shrinkB=1.5,
            connectionstyle="arc3,rad=0",
            clip_on=False,
        )
    )


def arrow_label(
    ax: plt.Axes,
    *,
    x: float,
    y: float,
    text: str,
    color: str,
) -> None:
    ax.text(
        x,
        y,
        text,
        transform=ax.transAxes,
        ha="center",
        va="center",
        fontsize=4.85,
        color=color,
        bbox={"boxstyle": "square,pad=0.08", "fc": WHITE, "ec": "none"},
    )


def draw() -> None:
    configure_style()
    fig, ax = plt.subplots(figsize=(3.48, 1.38))
    fig.subplots_adjust(left=0.012, right=0.988, bottom=0.015, top=0.985)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    box(
        ax,
        x=0.025,
        y=0.765,
        width=0.455,
        height=0.205,
        title="Modified Krill and Routinator",
        subtitle="signed fixture over RRDP",
        edge=BLUE,
        fill=BLUE_FILL,
    )
    box(
        ax,
        x=0.520,
        y=0.765,
        width=0.455,
        height=0.205,
        title="FRR origin  →  collector",
        subtitle="live Adj-RIB-In route",
        edge=GREY,
        fill=GREY_FILL,
    )

    box(
        ax,
        x=0.125,
        y=0.500,
        width=0.750,
        height=0.160,
        title="Selected-policy evaluator",
        subtitle="validated JSON + live route (p, o)  →  four-state result",
        edge=TEAL,
        fill=TEAL_FILL,
    )
    box(
        ax,
        x=0.125,
        y=0.265,
        width=0.750,
        height=0.145,
        title="Route-derived compiler",
        subtitle="prefix + origin match; state  →  local preference or reject",
        edge=AMBER,
        fill=AMBER_FILL,
    )
    box(
        ax,
        x=0.125,
        y=0.030,
        width=0.750,
        height=0.145,
        title="FRR enforcement",
        subtitle="per-neighbor route map  →  Loc-RIB action  →  ICMP probe",
        edge=NAVY,
        fill=NAVY_FILL,
    )

    arrow(ax, (0.253, 0.755), (0.390, 0.670), color=BLUE)
    arrow(ax, (0.747, 0.755), (0.610, 0.670), color=GREY)
    arrow_label(ax, x=0.285, y=0.692, text="local API", color=BLUE)
    arrow_label(ax, x=0.715, y=0.692, text="prefix, origin, peer", color=GREY)
    arrow(ax, (0.500, 0.490), (0.500, 0.420), color=TEAL)
    arrow(ax, (0.500, 0.255), (0.500, 0.185), color=AMBER)

    FIGURES.mkdir(parents=True, exist_ok=True)
    common = {"bbox_inches": None, "pad_inches": 0, "facecolor": WHITE}
    fig.savefig(
        OUTPUTS["pdf"],
        format="pdf",
        metadata={
            "Title": "Prototype path",
            "Subject": "Controlled selected-fixture implementation path",
            "Creator": "build_prototype_path_figure.py",
        },
        **common,
    )
    fig.savefig(
        OUTPUTS["svg"],
        format="svg",
        metadata={
            "Title": "Prototype path",
            "Description": "Controlled selected-fixture implementation path",
            "Creator": "build_prototype_path_figure.py",
        },
        **common,
    )
    fig.savefig(
        OUTPUTS["png"],
        format="png",
        dpi=600,
        metadata={
            "Title": "Prototype path",
            "Description": "Controlled selected-fixture implementation path",
            "Software": "build_prototype_path_figure.py",
        },
        **common,
    )
    fig.savefig(OUTPUTS["tiff"], format="tiff", dpi=600, **common)
    plt.close(fig)


def write_trace() -> None:
    evidence_hashes = {repo_path(path): sha256(path) for path in EVIDENCE}
    output_hashes = {repo_path(path): sha256(path) for path in OUTPUTS.values()}
    generator_hash = sha256(SCRIPT)
    supported_claim = (
        "Validated local policy output and a live Adj-RIB-In route enter "
        "the selected-policy evaluator and route-derived compiler before "
        "FRR installs the resulting route-map action."
    )
    limitations = [
        "Semantic schematic with no measured values.",
        "The conventional RTR precheck is outside the depicted handoff path.",
        "The path does not establish standardized transport, general "
        "multi-object composition, native FRR state, or IPv6 version-2 "
        "wire interoperability.",
    ]
    manifest: dict[str, Any] = {
        "schema": "prototype-path-figure-v1",
        "status": "active implementation schematic",
        "backend": "python-matplotlib",
        "no_measured_values": True,
        "dimensions_inches": {"width": 3.48, "height": 1.38},
        "claim": (
            "In the controlled selected-fixture prototype, validated local "
            "policy output and a live Adj-RIB-In route enter the selected-policy "
            "evaluator and route-derived compiler before FRR installs a "
            "per-neighbor route-map action."
        ),
        "boundary": (
            "The schematic does not establish standardized OpenScope "
            "transport, general multi-object composition, native FRR state, "
            "full-table relying-party operation, or IPv6 version-2 wire "
            "interoperability. The conventional RTR precheck is omitted "
            "because it is not the handoff policy path."
        ),
        "generator": {repo_path(SCRIPT): generator_hash},
        "evidence": evidence_hashes,
        "outputs": output_hashes,
        "figure_table_trace": [
            {
                "artifact_id": "fig:prototype-path",
                "source_data": {
                    "dataset_id": "selected-fixture-implementation",
                    "files": list(evidence_hashes),
                },
                "transformation": {
                    "script": repo_path(SCRIPT),
                    "sha256": generator_hash,
                },
                "caption_claim": "Prototype path.",
                "supported_manuscript_claims": [
                    {"claim": supported_claim, "locator": "Section IV"}
                ],
                "limitations": limitations,
            }
        ],
    }
    MANIFEST.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    evidence_lines = "\n".join(
        f"- `{path}`: `{digest}`" for path, digest in evidence_hashes.items()
    )
    output_lines = "\n".join(
        f"- `{path}`: `{digest}`" for path, digest in output_hashes.items()
    )
    PROVENANCE.write_text(
        """# Prototype path figure provenance

Status: **active implementation schematic**

The figure traces the controlled selected-fixture handoff path. Routinator's
validated local output and a route captured from live FRR Adj-RIB-In feed the
selected-policy evaluator. The route-derived compiler then emits one per-neighbor
FRR route map, whose installed action is checked in the Loc-RIB and by an
address-family-specific ICMP probe.

The diagram contains no measured values. It does not claim standardized
OpenScope transport, general multi-object composition, native FRR state,
full-table relying-party operation, or IPv6 version-2 wire interoperability.
The ordinary RTR view used by the conventional ROV precheck is intentionally
omitted because it is not the handoff policy path.

## Implementation evidence

"""
        + evidence_lines
        + "\n\n## Generator\n\n"
        + f"- `{repo_path(SCRIPT)}`: `{generator_hash}`\n"
        + "\n## Exports\n\n"
        + output_lines
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    missing = [repo_path(path) for path in EVIDENCE if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing implementation evidence: {missing}")
    draw()
    write_trace()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
