#!/usr/bin/env python3
"""Build the V.B classification and policy-update panels."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FixedFormatter, FixedLocator, StrMethodFormatter

from figure_typography import BODY_FONT_FAMILY, configure_body_font


SCRIPT = Path(__file__).resolve()
PAPER = SCRIPT.parents[2]
REPO = PAPER
FIGURES = PAPER / "figure-data"

RUN_DIR = (
    REPO
    / "experiments" / "cost"
    / "processing_benchmark"
    / "results"
    / "controlled-processing-20260830T-marker-final-v1"
)
SUMMARY = RUN_DIR / "summary.json"
INDEPENDENT_AUDIT = RUN_DIR / "independent_audit.json"
SOURCE_CSV = PAPER / "results" / "tables" / "processing_cost_dual_stack.csv"
UPDATE_RUN = (
    REPO
    / "experiments" / "cost"
    / "processing_benchmark"
    / "results"
    / "policy-update-20260830T-marker-final-v1"
)
UPDATE_SUMMARY = UPDATE_RUN / "summary.json"
UPDATE_AUDIT = UPDATE_RUN / "independent_audit.json"
UPDATE_INPUT_MANIFEST = UPDATE_RUN / "input_manifest.json"
UPDATE_RUN_CONFIG = UPDATE_RUN / "run_config.json"
UPDATE_ARTIFACT_MANIFEST = UPDATE_RUN / "artifact_manifest.json"
OUTAGE_DIR = (
    REPO
    / "implementation" / "prototype"
    / "e2e"
    / "results"
    / "run-20260823T024129Z"
    / "failures"
    / "routinator-outage"
)
OUTAGE_RESULT = OUTAGE_DIR / "result.json"
OUTAGE_ENFORCEMENT = OUTAGE_DIR / "enforcement.json"

EXPECTED_HASHES = {
    SUMMARY: "ebb77c5bf194de663b81aea82fc2a06abe5a8f878c571080accfc3ad146f0a6a",
    INDEPENDENT_AUDIT: "586c3a0f4efc4ea75c374f7f5c2ad258c66434e5888c5313f765a85f8a3c3a6f",
    SOURCE_CSV: "0b991a50082524e5e816c4aa174b284eee79f7036d8835e213fbce1b0a76f79e",
    UPDATE_SUMMARY: "0e900d7b4b9561fdb3c6db3c4d3c8596d8390a9e7dc0be625db51dec90e74e4b",
    UPDATE_AUDIT: "40d583d46e7678a442161153dafbc9176da57eacca07a9d2e19feb7de0523ab8",
    UPDATE_INPUT_MANIFEST: "8681d009b22b66541df46083ebd8519bdab6d3c74c45cbf130dd71cf10c646a7",
    UPDATE_RUN_CONFIG: "badb9b5ba9f7f255bb7f01b940eaa9f83794a50a7329fe7cab0c7dc12999e11b",
    UPDATE_ARTIFACT_MANIFEST: "f193d682dacecc43f0f4c193e172ff294e544cf35707e096b660bdf0af9c9357",
    OUTAGE_RESULT: "09f642a447d499e9ff4870baf8ad332c73acef18a2e544a253b340f8343a7a2e",
    OUTAGE_ENFORCEMENT: "e60624cdb0032b7ebd8263c33a7cec6ac74d96f99fc58eb92366afe9d8d0588c",
}

OUTPUT_STEMS = {
    "classify": FIGURES / "fig_processing_cost_classify",
    "update": FIGURES / "fig_processing_cost_update",
}
PROCESSING_PANELS = ("classify",)
OUTPUT_SUFFIXES = (".svg", ".pdf", ".png", ".tiff")
OUTPUTS = {
    f"{panel}_{suffix.removeprefix('.')}": stem.with_suffix(suffix)
    for panel, stem in OUTPUT_STEMS.items()
    for suffix in OUTPUT_SUFFIXES
}
REPORT = FIGURES / "FIG_PROCESSING_COST_PROVENANCE.md"
MANIFEST = FIGURES / "fig_processing_cost.manifest.json"

VERSIONS = ("IPv4", "IPv6")
POLICY_SIZES = (1, 64, 256, 1024, 4096)
UPDATE_SCHEMA = "same-size-policy-update-v1"
UPDATE_AUDIT_SCHEMA = "same-size-policy-update-independent-audit-v1"
BLUE = "#0F4D92"
ORANGE = "#D66B27"
EDGE = "#303438"
GRID = "#D9DDE0"
WHITE = "#FFFFFF"
BAR_WIDTH = 0.34
ACTIVE_PANEL_FIGSIZE = (3.50, 1.75)
ACTIVE_PANEL_MARGINS = {
    "left": 0.145,
    "right": 0.94,
    "bottom": 0.27,
    "top": 0.89,
}
ACTIVE_BASE_FONTSIZE = 8.4
ACTIVE_TICK_LABELSIZE = 7.56
ACTIVE_AXIS_LABELSIZE = 8.4
ACTIVE_LEGEND_FONTSIZE = 6.96
PANEL_FIGSIZE = ACTIVE_PANEL_FIGSIZE
PANEL_MARGINS = ACTIVE_PANEL_MARGINS


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repo_path(path: Path) -> str:
    return path.relative_to(REPO).as_posix()


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def verify_inputs() -> dict[str, str]:
    observed: dict[str, str] = {}
    for path, expected in EXPECTED_HASHES.items():
        if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise ValueError(f"invalid expected hash for {repo_path(path)}")
        if not path.is_file():
            raise FileNotFoundError(f"missing input: {repo_path(path)}")
        actual = sha256(path)
        if actual != expected:
            raise ValueError(f"input hash mismatch for {repo_path(path)}: {actual}")
        observed[repo_path(path)] = actual

    summary: dict[str, Any] = load_json(SUMMARY)
    audit: dict[str, Any] = load_json(INDEPENDENT_AUDIT)
    if not bool(summary.get("gates", {}).get("all_gates_pass")):
        raise ValueError("accepted processing run failed an internal gate")
    if not bool(audit.get("checks", {}).get("all_checks_pass")):
        raise ValueError("accepted processing run failed its independent audit")

    update_summary: dict[str, Any] = load_json(UPDATE_SUMMARY)
    update_audit: dict[str, Any] = load_json(UPDATE_AUDIT)
    update_config: dict[str, Any] = load_json(UPDATE_RUN_CONFIG)
    if (
        update_summary.get("schema_version") != UPDATE_SCHEMA
        or not bool(update_summary.get("gates", {}).get("all_gates_pass"))
    ):
        raise ValueError("accepted policy-update run failed an internal gate")
    if (
        update_audit.get("schema_version") != UPDATE_AUDIT_SCHEMA
        or not bool(update_audit.get("checks", {}).get("all_checks_pass"))
        or not all(
            value is True for value in update_audit.get("checks", {}).values()
        )
    ):
        raise ValueError("accepted policy-update run failed its independent audit")
    expected_timed_scope = [
        "S2ROV.deserialize(open_payload)",
        "active_policy_pointer_replacement",
        "first_validate_route",
    ]
    if (
        update_config.get("schema_version") != UPDATE_SCHEMA
        or update_config.get("ip_versions") != [4, 6]
        or update_config.get("rule_counts") != list(POLICY_SIZES)
        or int(update_config.get("repetitions_per_cell", -1)) != 20
        or int(update_config.get("expected_worker_records", -1)) != 200
        or update_config.get("worker_process_model")
        != "one fresh subprocess per observation"
        or update_config.get("timed_scope") != expected_timed_scope
    ):
        raise ValueError("accepted policy-update protocol changed")

    outage_result: dict[str, Any] = load_json(OUTAGE_RESULT)
    outage_enforcement: list[dict[str, Any]] = load_json(OUTAGE_ENFORCEMENT)
    if outage_result != {"hold_seconds": 15, "policy_retained": True}:
        raise ValueError("accepted relying-party outage result changed")
    if len(outage_enforcement) != 7 or not all(
        item.get("pass") is True for item in outage_enforcement
    ):
        raise ValueError("accepted relying-party outage enforcement did not pass")
    return observed


def load_rows() -> list[dict[str, Any]]:
    with SOURCE_CSV.open(newline="", encoding="utf-8") as handle:
        source_rows = list(csv.DictReader(handle))

    rows: list[dict[str, Any]] = []
    for source in source_rows:
        rows.append(
            {
                "ip_version": source["ip_version"],
                "subprefix_entries": int(source["subprefix_entries"]),
                "total_policy_entries": int(source["total_policy_entries"]),
                "classify_pairs_s_mean": 1000.0
                * float(source["classify_kpairs_s_mean"]),
                "classify_pairs_s_median": 1000.0
                * float(source["classify_kpairs_s_median"]),
                "classify_pairs_s_min": 1000.0
                * float(source["classify_kpairs_s_min"]),
                "classify_pairs_s_max": 1000.0
                * float(source["classify_kpairs_s_max"]),
            }
        )
    validate_rows(rows)
    return rows


def validate_rows(rows: list[dict[str, Any]]) -> None:
    expected = {
        (version, size) for version in VERSIONS for size in POLICY_SIZES
    }
    observed = {
        (str(row["ip_version"]), int(row["total_policy_entries"])) for row in rows
    }
    if len(rows) != 10 or observed != expected:
        raise ValueError("processing source is not the exact 2 x 5 matrix")

    for row in rows:
        if int(row["total_policy_entries"]) != int(row["subprefix_entries"]) + 1:
            raise ValueError("total policy count must include one base entry")
        values = [
            float(row["classify_pairs_s_mean"]),
            float(row["classify_pairs_s_median"]),
            float(row["classify_pairs_s_min"]),
            float(row["classify_pairs_s_max"]),
        ]
        if not all(math.isfinite(value) for value in values):
            raise ValueError("processing source contains a non-finite statistic")
        if not (
            float(row["classify_pairs_s_min"])
            <= float(row["classify_pairs_s_median"])
            <= float(row["classify_pairs_s_max"])
        ):
            raise ValueError("classification median lies outside its run range")


def keyed(rows: list[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    return {
        (str(row["ip_version"]), int(row["total_policy_entries"])): row
        for row in rows
    }


def load_update_rows() -> list[dict[str, Any]]:
    summary: dict[str, Any] = load_json(UPDATE_SUMMARY)
    audit: dict[str, Any] = load_json(UPDATE_AUDIT)
    inputs: dict[str, Any] = load_json(UPDATE_INPUT_MANIFEST)
    rows = [
        {
            "ip_version": str(source["label"]),
            "rules": int(source["rules"]),
            "repetitions": int(source["repetitions"]),
            "closed_serialized_bytes": int(source["closed_serialized_bytes"]),
            "open_serialized_bytes": int(source["open_serialized_bytes"]),
            "update_ms_mean": float(source["update_ms_mean"]),
            "update_ms_median": float(source["update_ms_median"]),
            "update_ms_q1": float(source["update_ms_q1"]),
            "update_ms_q3": float(source["update_ms_q3"]),
        }
        for source in summary.get("rows", [])
    ]
    validate_update_rows(rows, audit, inputs)
    return rows


def validate_update_rows(
    rows: list[dict[str, Any]],
    audit: dict[str, Any],
    inputs: dict[str, Any],
) -> None:
    expected_cells = {
        (version, rules) for version in VERSIONS for rules in POLICY_SIZES
    }
    observed_cells = {
        (str(row["ip_version"]), int(row["rules"])) for row in rows
    }
    if len(rows) != 10 or observed_cells != expected_cells:
        raise ValueError("policy-update source is not the exact 2 x 5 matrix")
    if (
        audit.get("schema_version") != UPDATE_AUDIT_SCHEMA
        or audit.get("checks", {}).get("all_checks_pass") is not True
        or audit.get("matrix", {}).get("raw_records") != 200
        or audit.get("matrix", {}).get("repetitions_per_cell") != 20
        or audit.get("matrix", {}).get("rule_counts") != list(POLICY_SIZES)
    ):
        raise ValueError("policy-update audit contract changed")

    recomputed = {
        (str(item["label"]), int(item["rules"])): item
        for item in audit.get("recomputed_rows", [])
    }
    if set(recomputed) != expected_cells:
        raise ValueError("policy-update audit lacks the exact recomputed matrix")

    family_inputs = inputs.get("families", {})
    if set(family_inputs) != {"4", "6"}:
        raise ValueError("policy-update input manifest lacks both IP versions")
    for row in rows:
        version = str(row["ip_version"])
        rules = int(row["rules"])
        if int(row["repetitions"]) != 20:
            raise ValueError("policy-update cell does not have twenty processes")
        if int(row["closed_serialized_bytes"]) != int(
            row["open_serialized_bytes"]
        ):
            raise ValueError("policy-update snapshots differ in serialized size")
        values = [
            float(row["update_ms_mean"]),
            float(row["update_ms_median"]),
            float(row["update_ms_q1"]),
            float(row["update_ms_q3"]),
        ]
        if not all(math.isfinite(value) and value > 0.0 for value in values):
            raise ValueError("policy-update source contains an invalid duration")
        if not values[2] <= values[1] <= values[3]:
            raise ValueError("policy-update median lies outside its interquartile range")

        audited = recomputed[(version, rules)]
        for field in (
            "update_ms_mean",
            "update_ms_median",
            "update_ms_q1",
            "update_ms_q3",
        ):
            if not math.isclose(
                float(row[field]),
                float(audited[field]),
                rel_tol=0.0,
                abs_tol=1e-12,
            ):
                raise ValueError("policy-update summary differs from the raw audit")

        family_key = "4" if version == "IPv4" else "6"
        policy = family_inputs[family_key].get("policies", {}).get(str(rules), {})
        if (
            policy.get("only_base_open_bit_changed") is not True
            or policy.get("same_entry_count") is not True
            or policy.get("same_serialized_size") is not True
            or int(policy.get("total_policy_entries", -1)) != rules
            or policy.get("probe_closed_state") != "Invalid"
            or policy.get("probe_open_state") != "Delegated"
            or policy.get("probe_manuscript_state") != "OpenScope"
        ):
            raise ValueError("policy-update snapshot semantics changed")


def load_outage_control() -> dict[str, Any]:
    result: dict[str, Any] = load_json(OUTAGE_RESULT)
    enforcement: list[dict[str, Any]] = load_json(OUTAGE_ENFORCEMENT)
    if result != {"hold_seconds": 15, "policy_retained": True}:
        raise ValueError("relying-party outage result changed")
    if len(enforcement) != 7 or not all(
        item.get("pass") is True for item in enforcement
    ):
        raise ValueError("relying-party outage route checks did not all pass")
    return {
        "episodes": 1,
        "hold_seconds": 15,
        "action_retained": True,
        "checks_passed": len(enforcement),
        "checks_total": len(enforcement),
    }


def configure_style() -> None:
    configure_body_font()
    mpl.rcParams.update(
        {
            "font.size": ACTIVE_BASE_FONTSIZE,
            "axes.labelsize": ACTIVE_AXIS_LABELSIZE,
            "xtick.labelsize": ACTIVE_TICK_LABELSIZE,
            "ytick.labelsize": ACTIVE_TICK_LABELSIZE,
            "legend.fontsize": ACTIVE_LEGEND_FONTSIZE,
            "axes.linewidth": 0.75,
            "axes.spines.top": True,
            "axes.spines.right": True,
            "xtick.direction": "in",
            "ytick.direction": "in",
            "xtick.top": False,
            "ytick.right": False,
            "legend.frameon": False,
            "pdf.fonttype": 42,
            "svg.fonttype": "none",
            "svg.hashsalt": "s2-rov-processing-cost-v2",
            "figure.facecolor": WHITE,
            "axes.facecolor": WHITE,
            "savefig.facecolor": WHITE,
        }
    )


def export_figure(fig: plt.Figure, panel: str, creator: str) -> None:
    common: dict[str, Any] = {"facecolor": WHITE}
    fig.savefig(
        OUTPUTS[f"{panel}_svg"],
        format="svg",
        metadata={"Date": None, "Creator": creator},
        **common,
    )
    fig.savefig(
        OUTPUTS[f"{panel}_pdf"],
        format="pdf",
        metadata={"Creator": creator, "CreationDate": None, "ModDate": None},
        **common,
    )
    fig.savefig(
        OUTPUTS[f"{panel}_png"],
        format="png",
        dpi=300,
        metadata={"Software": creator},
        **common,
    )
    fig.savefig(
        OUTPUTS[f"{panel}_tiff"],
        format="tiff",
        dpi=600,
        pil_kwargs={"compression": "tiff_lzw"},
        **common,
    )
    plt.close(fig)

    svg = OUTPUTS[f"{panel}_svg"]
    normalized = "\n".join(
        line.rstrip() for line in svg.read_text(encoding="utf-8").splitlines()
    )
    svg.write_text(normalized + "\n", encoding="utf-8")


def new_cost_panel() -> tuple[plt.Figure, plt.Axes]:
    fig, ax = plt.subplots(figsize=ACTIVE_PANEL_FIGSIZE)
    fig.subplots_adjust(**ACTIVE_PANEL_MARGINS)
    return fig, ax


def dual_stack_bar_styles() -> dict[str, tuple[str, str, float]]:
    return {
        "IPv4": (BLUE, "", -BAR_WIDTH / 2),
        "IPv6": (ORANGE, "///", BAR_WIDTH / 2),
    }


def make_update_latency_figure(
    rows: list[dict[str, Any]],
) -> plt.Figure:
    configure_style()
    observed = {
        (str(item["ip_version"]), int(item["rules"])) for item in rows
    }
    expected = {
        (version, size) for version in VERSIONS for size in POLICY_SIZES
    }
    if len(rows) != 10 or observed != expected:
        raise ValueError("update-latency panel lacks the ordered dual-stack matrix")

    by_cell = {
        (str(item["ip_version"]), int(item["rules"])): item for item in rows
    }
    x = np.arange(len(POLICY_SIZES), dtype=float)
    fig, ax = new_cost_panel()
    styles = dual_stack_bar_styles()
    for version in VERSIONS:
        selected = [by_cell[(version, size)] for size in POLICY_SIZES]
        color, hatch, offset = styles[version]
        ax.bar(
            x + offset,
            [float(item["update_ms_mean"]) for item in selected],
            BAR_WIDTH,
            label=version,
            color=color,
            hatch=hatch,
            edgecolor=EDGE,
            linewidth=0.5,
            zorder=3,
        )

    ax.xaxis.set_major_locator(FixedLocator(x))
    ax.xaxis.set_major_formatter(
        FixedFormatter([str(size) for size in POLICY_SIZES])
    )
    ax.set_xlabel("Policy size (records)")
    ax.set_ylabel("Latency (ms)")
    ax.set_ylim(0.0, 520.0)
    ax.yaxis.set_major_locator(FixedLocator([0.0, 150.0, 300.0, 450.0]))
    ax.yaxis.set_major_formatter(StrMethodFormatter("{x:.0f}"))
    ax.grid(axis="y", color=GRID, linewidth=0.45, linestyle=":", zorder=0)
    ax.set_axisbelow(True)
    ax.tick_params(
        axis="both",
        which="both",
        direction="in",
        top=False,
        right=False,
        length=2.5,
        width=0.7,
        pad=1.8,
    )
    for spine in ax.spines.values():
        spine.set_visible(True)
    return fig


def draw_update_latency_panel(rows: list[dict[str, Any]]) -> None:
    figure = make_update_latency_figure(rows)
    export_figure(
        figure,
        "update",
        "S2-ROV dual-stack policy-update latency panel",
    )


def draw_panel(rows: list[dict[str, Any]], panel: str) -> plt.Figure:
    if panel not in PROCESSING_PANELS:
        raise ValueError(f"unknown panel: {panel}")
    configure_style()
    by_cell = keyed(rows)
    x = np.arange(len(POLICY_SIZES), dtype=float)
    fig, ax = new_cost_panel()

    field = "classify_pairs_s_mean"
    ylabel = "Throughput (routes/s)"
    upper = 34_000.0
    yticks = [0.0, 10_000.0, 20_000.0, 30_000.0]
    styles = dual_stack_bar_styles()
    for version in VERSIONS:
        selected = [by_cell[(version, size)] for size in POLICY_SIZES]
        means = np.asarray([float(row[field]) for row in selected])
        color, hatch, offset = styles[version]
        ax.bar(
            x + offset,
            means,
            BAR_WIDTH,
            label=version,
            color=color,
            hatch=hatch,
            edgecolor=EDGE,
            linewidth=0.5,
            zorder=3,
        )

    ax.xaxis.set_major_locator(FixedLocator(x))
    ax.xaxis.set_major_formatter(
        FixedFormatter([f"{size:d}" for size in POLICY_SIZES])
    )
    ax.set_xlabel("Policy size (records)")
    ax.set_ylabel(ylabel)
    ax.set_ylim(0.0, upper)
    ax.yaxis.set_major_locator(FixedLocator(yticks))
    ax.yaxis.set_major_formatter(
        FixedFormatter(["0", "10000", "20000", "30000"])
    )
    ax.grid(axis="y", color=GRID, linewidth=0.45, linestyle=":", zorder=0)
    ax.set_axisbelow(True)
    ax.tick_params(
        axis="both",
        which="both",
        direction="in",
        top=False,
        right=False,
        length=2.5,
        width=0.7,
        pad=1.8,
    )
    for spine in ax.spines.values():
        spine.set_visible(True)
    ax.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, 1.01),
        ncol=2,
        handlelength=1.4,
        columnspacing=0.8,
        borderaxespad=0.0,
    )

    return fig


def write_report(
    rows: list[dict[str, Any]],
    update_rows: list[dict[str, Any]],
    outage: dict[str, Any],
    hashes: dict[str, str],
) -> None:
    by_cell = keyed(rows)
    anchor_lines = []
    for version in VERSIONS:
        for size in POLICY_SIZES:
            row = by_cell[(version, size)]
            anchor_lines.append(
                f"| {version} | {size} | "
                f"{row['classify_pairs_s_mean']:,.1f} |"
            )
    anchors = "\n".join(anchor_lines)
    update_lines = "\n".join(
        f"| {version} | {item['rules']:,} | "
        f"{item['update_ms_mean']:.1f} | 20 |"
        for version in VERSIONS
        for item in sorted(
            (row for row in update_rows if row["ip_version"] == version),
            key=lambda row: int(row["rules"]),
        )
    )
    input_lines = "\n".join(
        f"- `{path}`: `{digest}`" for path, digest in sorted(hashes.items())
    )
    report = f"""# System-cost figure provenance

Status: **active V.B performance evidence**

Both panels use the shared active-panel geometry: 3.50 x 1.75 inches, an
identical axes bounding box, 7.56 pt tick labels, 8.4 pt axis labels, and
6.96 pt legend text.

## Classification panel

The classification panel uses the accepted controlled dual-stack run. Policy
size is the total number of records, including one base record carrying the
OpenScope marker. The five sizes are 1, 64, 256, 1,024, and 4,096 records. Bars report arithmetic means over five
fresh classification workers; no interval is displayed. Every cell reuses its
version-specific 4,096-query set and produces the same OpenScope result sequence
as policy size grows.

| Version | Records | Mean throughput (routes/s) |
|---|---:|---:|
{anchors}

The values characterize one active-policy Python reference implementation on
one pinned Kunpeng 920 core. IPv4 and IPv6 use different fixed query sets, so
the grouped bars are descriptive version-specific results rather than a causal
estimate of an address-family effect. They do not measure a relying party, RTR,
FRR, forwarding, or line-rate throughput.

## Update-latency panel

The update panel uses the accepted dual-stack same-size policy-replacement run.
For every version and size, two immutable snapshots contain the same number of
records and differ only in the base record's OpenScope marker bit. The timer
starts with the unmarked policy already active. It covers deserialization of the
marked snapshot, including validation, canonicalization, and index construction,
one active-policy replacement, and the fixed route's first OpenScope result.
Each bar is the arithmetic mean of 20 fresh processes. No interval is displayed.

| Version | Total records | Mean update (ms) | Fresh processes |
|---|---:|---:|---:|
{update_lines}

The timed interval excludes file acquisition, ROA-repository and relying-party
refresh, RTR transfer, router installation, and forwarding. In the separate
15-s relying-party-outage control, the last installed action is retained and
all seven route checks pass.

## Scope and reproducibility boundary

These are descriptive results for pinned, accepted prototype runs and tested
controls. The grouped IPv4 and IPv6 bars do not establish a causal address-family
effect, and none of the artifacts supports production or Internet-wide generalization.

- Generator: `{repo_path(SCRIPT)}`
- Pinned inputs (SHA-256):
{input_lines}
"""
    REPORT.write_text(report, encoding="utf-8")


def write_manifest(
    rows: list[dict[str, Any]],
    update_rows: list[dict[str, Any]],
    outage: dict[str, Any],
    hashes: dict[str, str],
) -> None:
    manifest = {
        "schema_version": "s2-rov-system-cost-figure-v10-routes-s",
        "backend": "python-matplotlib",
        "generator": {"path": repo_path(SCRIPT), "sha256": sha256(SCRIPT)},
        "figure_contract": {
            "archetypes": {
                "classify": "grouped_mean_bar",
                "update": "grouped_mean_bar",
            },
            "latex_composition": (
                "subfig package; panel labels are not embedded in graphics"
            ),
            "panels": {
                "classify": "mean classification throughput",
                "update": "mean same-size policy-replacement latency",
            },
            "shared_panel_style": {
                "canvas_inches": list(ACTIVE_PANEL_FIGSIZE),
                "axes_fraction": {
                    "left": ACTIVE_PANEL_MARGINS["left"],
                    "bottom": ACTIVE_PANEL_MARGINS["bottom"],
                    "width": ACTIVE_PANEL_MARGINS["right"]
                    - ACTIVE_PANEL_MARGINS["left"],
                    "height": ACTIVE_PANEL_MARGINS["top"]
                    - ACTIVE_PANEL_MARGINS["bottom"],
                },
                "axis_label_pt": ACTIVE_AXIS_LABELSIZE,
                "tick_label_pt": ACTIVE_TICK_LABELSIZE,
                "legend_pt": ACTIVE_LEGEND_FONTSIZE,
            },
            "processing_groups": list(VERSIONS),
            "policy_sizes_total_records": list(POLICY_SIZES),
            "update_groups": list(VERSIONS),
            "update_versions": list(VERSIONS),
            "update_policy_sizes_total_records": list(POLICY_SIZES),
            "update_transition": {
                "source": "immutable unmarked snapshot already active",
                "target": "immutable same-size marked snapshot",
                "semantic_delta": "OpenScope marker is added to the base record",
                "timed_scope": [
                    "deserialization with validation, canonicalization, and index construction",
                    "active-policy replacement",
                    "fixed route first returns OpenScope",
                ],
                "excluded_scope": [
                    "file acquisition",
                    "ROA repository and relying-party refresh",
                    "RTR transfer",
                    "router installation",
                    "forwarding",
                ],
            },
            "statistics": {
                "classification": "arithmetic mean across five fresh worker processes per displayed bar",
                "update": "arithmetic mean across twenty fresh processes per displayed bar",
            },
            "classification_y_axis": {
                "label": "Throughput (routes/s)",
                "ticks": [0, 10000, 20000, 30000],
            },
            "error_bars": False,
            "y_axes_start_at_zero": True,
            "bar_value_annotations": False,
            "four_visible_spines": True,
            "ticks": "left and bottom only, inward",
        },
        "data_integrity": {
            "processing": {
                "cells": len(rows),
                "classification_workers_per_cell": 5,
                "worker_records": 50,
                "all_roundtrips_identical": True,
                "all_results_open_scope": True,
                "all_summary_cells_independently_recomputed": True,
            },
            "policy_update": {
                "cells": len(update_rows),
                "fresh_processes_per_cell": 20,
                "worker_records": sum(
                    int(item["repetitions"]) for item in update_rows
                ),
                "same_size_snapshot_pairs": True,
                "only_base_marker_state_changes": True,
                "all_unmarked_probes_invalid": True,
                "all_updated_probes_open_scope": True,
                "all_active_replacements_confirmed": True,
                "all_summary_cells_independently_recomputed": True,
            },
            "live_path": {
                "outage_episodes": int(outage["episodes"]),
                "outage_checks": int(outage["checks_total"]),
            },
        },
        "claim_boundary": {
            "allowed": [
                "version-specific fixed-output classification throughput",
                "descriptive mean same-size policy-replacement and first-classification latency",
            ],
            "forbidden": [
                "causal address-family performance effect",
                "complete relying-party or router throughput",
                "RTR, FRR, forwarding, or line-rate performance",
                "production or Internet-wide generalization",
            ],
        },
        "input_sha256": hashes,
        "report_sha256": {repo_path(REPORT): sha256(REPORT)},
        "output_sha256": {
            repo_path(path): sha256(path) for path in OUTPUTS.values()
        },
    }
    MANIFEST.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-only", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    hashes = verify_inputs()
    rows = load_rows()
    update_rows = load_update_rows()
    outage = load_outage_control()
    if args.verify_only:
        print(
            json.dumps(
                {
                    "policy_update_cells": len(update_rows),
                    "policy_update_workers": sum(
                        int(row["repetitions"]) for row in update_rows
                    ),
                    "processing_cells": len(rows),
                    "verified": True,
                },
                sort_keys=True,
            )
        )
        return

    FIGURES.mkdir(parents=True, exist_ok=True)
    for panel in PROCESSING_PANELS:
        figure = draw_panel(rows, panel)
        export_figure(
            figure,
            panel,
            f"S2-ROV dual-stack processing-cost {panel} panel",
        )
    draw_update_latency_panel(update_rows)
    write_report(rows, update_rows, outage, hashes)
    write_manifest(rows, update_rows, outage, hashes)
    print(
        json.dumps(
            {
                "policy_update_cells": len(update_rows),
                "policy_update_workers": sum(
                    int(row["repetitions"]) for row in update_rows
                ),
                "manifest": repo_path(MANIFEST),
                "outputs": [repo_path(path) for path in OUTPUTS.values()],
                "processing_cells": len(rows),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
