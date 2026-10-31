#!/usr/bin/env python3
"""Recompute and draw the dual-stack matched-handoff figure.

Both accepted experiments record every timing marker with one persistent
``time.monotonic_ns`` helper.  This script treats each ``events.jsonl`` as the
numeric source of truth.  The corresponding ``trials.csv`` supplies the
randomized-round map and is used only as a cross-check of recomputed endpoints.

Outputs
-------
* figures/source_data/handoff_latency_trials.csv
* figures/source_data/handoff_latency_stages.csv
* figures/source_data/handoff_endpoint_rounds_recomputed.csv
* figures/source_data/handoff_latency_contrasts.csv
* figures/fig_handoff_benefit.{pdf,svg,png,tiff}
* figures/fig_handoff_benefit_reanalysis.{pdf,svg,png,tiff}
* figures/HANDOFF_FIG2_REANALYSIS_PROVENANCE.md
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import shutil
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import matplotlib

matplotlib.use("Agg")
import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np


SCRIPT = Path(__file__).resolve()
PROJECT = SCRIPT.parents[2]
REPO = PROJECT
FIGURES = PROJECT / "figure-data"
SOURCE_DATA = FIGURES / "source_data"
TRIAL_CSV = SOURCE_DATA / "handoff_latency_trials.csv"
STAGE_CSV = SOURCE_DATA / "handoff_latency_stages.csv"
ROUND_CSV = SOURCE_DATA / "handoff_endpoint_rounds_recomputed.csv"
CONTRAST_CSV = SOURCE_DATA / "handoff_latency_contrasts.csv"
OUTPUT_STEM = FIGURES / "fig_handoff_benefit"
REANALYSIS_STEM = FIGURES / "fig_handoff_benefit_reanalysis"
PROVENANCE = FIGURES / "HANDOFF_FIG2_REANALYSIS_PROVENANCE.md"

ARMS = ("reactive_exact", "open_dynamic", "prepublished_exact")
ARM_REPORT_LABELS = {
    "reactive_exact": "Reactive exact",
    "open_dynamic": "Preinstalled scope",
    "prepublished_exact": "Prepublished exact",
}

STAGES = (
    "input_capture_ms",
    "online_roa_update_ms",
    "compile_ms",
    "action_install_ms",
    "probe_confirmation_ms",
)
STAGE_LABELS = {
    "input_capture_ms": "Input capture",
    "online_roa_update_ms": "ROA update",
    "compile_ms": "Compile",
    "action_install_ms": "Install",
    "probe_confirmation_ms": "Probe",
}
BASE_EVENTS = {
    "switch_requested",
    "old_route_absent",
    "new_route_in_adj_rib_in",
    "rp_policy_available",
    "compiler_started",
    "compiler_completed",
    "action_installed",
    "probe_succeeded",
}
REACTIVE_EVENT = "signed_roa_requested"
BOOTSTRAP_REPLICATES = 100_000
BOOTSTRAP_SEED = 20_260_828


@dataclass(frozen=True)
class RunSpec:
    address_family: str
    run_id: str
    protocol_address_family: str | None
    pinned_input_hashes: Mapping[str, str]

    @property
    def directory(self) -> Path:
        return REPO / "implementation" / "prototype" / "e2e" / "outputs" / self.run_id


# Pins prevent silently changed runs from being presented as accepted evidence.
RUN_SPECS = (
    RunSpec(
        address_family="IPv4",
        run_id="handoff-benefit-20260828T143741Z",
        protocol_address_family=None,
        pinned_input_hashes={
            "events.jsonl": "5ec7b8238a8d58f3d48376d15ff1670f9cd6e82c85ba44188f0d4082698fa6f7",
            "trials.csv": "eb7ea5a490c9755c2fc141491f67907cf9e40b0c39bbd7192fbf15ff3d61ef1c",
            "protocol.json": "47f4145b9336aaf57773625b62e320e7035089b18fa03d5ca54097b035c48d3f",
            "independent-audit.json": "b3471111394a7c7501bfe5396c456df2919c24136fc164c66ad5304f54587be3",
            "manifest.sha256": "2388faf2fed40fa3bd4fbd9b7d1bbfa882643438fd8f5759a91f6b2ef9938b5c",
            "source.sha256": "2ba376a8d430e6d33d583c29fea0c2dc882f2269c50102ef0116e00f693539b6",
        },
    ),
    RunSpec(
        address_family="IPv6",
        run_id="handoff-benefit-ipv6-20260829T002536Z",
        protocol_address_family="ipv6",
        pinned_input_hashes={
            "events.jsonl": "e4db8f4cdd12e832af8ccc614da3cfb06788b0911e7d993f7f8266553fe70c1b",
            "trials.csv": "b6eb75721bcce3ceb0f5d4b5342ca5a29b82cf047e794d51ed7561b7dde84b10",
            "protocol.json": "645fe44ad48b31df6ae59ccba371a69abe5e824df1ced30f6319d63237396c10",
            "independent-audit.json": "11f752c8bec49e7583646bda37210a5a74353b24c2d86a4942c6706b70442b4d",
            "manifest.sha256": "5972a257a048c93ece1cf6a1802b9c2400f503da64cd301e4011b81c6e599045",
            "source.sha256": "963b255d186891234b7ad9966beae2603916494a7cde3b5c5e8c88b40b7e9fee",
        },
    ),
)

TRIAL_FIELDS = (
    "run_id",
    "address_family",
    "round",
    "block",
    "block_trial",
    "arm",
    "arm_label",
    "lane_trial",
    "direction",
    *STAGES,
    "observed_to_action_ms",
    "observed_to_probe_ms",
    "stage_sum_ms",
    "timing_source",
    "inference_cluster",
)
STAGE_FIELDS = (
    "run_id",
    "address_family",
    "arm",
    "arm_label",
    "stage",
    "stage_label",
    "n_handoffs",
    "mean_ms",
    "median_ms",
    "p95_nearest_rank_ms",
    "endpoint_total_mean_ms",
)
ROUND_FIELDS = (
    "run_id",
    "address_family",
    "round",
    "arm",
    "arm_label",
    "n_handoffs",
    "observed_to_action_mean_ms",
    "observed_to_probe_mean_ms",
    "inference_unit",
)
CONTRAST_FIELDS = (
    "run_id",
    "address_family",
    "contrast",
    "contrast_label",
    "estimate_ms",
    "ci95_lower_ms",
    "ci95_upper_ms",
    "n_complete_rounds",
    "bootstrap_replicates",
    "bootstrap_seed",
)

PLOTTED_CONTRASTS = (
    (
        "reactive_exact_minus_open_dynamic",
        "Reactive exact minus preinstalled scope",
    ),
    (
        "open_dynamic_minus_prepublished_exact",
        "Preinstalled scope minus prepublished exact",
    ),
)

TEXT = "#25292D"
MUTED = "#626970"
GRID = "#D9DDE1"
WHITE = "#FFFFFF"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_pinned_inputs(spec: RunSpec) -> None:
    for relative, expected in spec.pinned_input_hashes.items():
        path = spec.directory / relative
        if not path.is_file():
            raise FileNotFoundError(f"missing accepted-run input: {path}")
        actual = sha256(path)
        if actual != expected:
            raise ValueError(
                f"{spec.address_family} accepted-run hash mismatch for {relative}: "
                f"{actual} != {expected}"
            )


def parse_manifest(path: Path) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            expected, relative = line.split("  ", 1)
        except ValueError as exc:
            raise ValueError(f"malformed manifest line {line_number}") from exc
        candidate = Path(relative)
        if (
            len(expected) != 64
            or any(character not in "0123456789abcdef" for character in expected)
            or candidate.is_absolute()
            or ".." in candidate.parts
            or relative in seen
        ):
            raise ValueError(f"invalid manifest entry on line {line_number}")
        seen.add(relative)
        entries.append((relative, expected))
    if not entries:
        raise ValueError("accepted-run artifact manifest is empty")
    return entries


def verify_artifact_manifest(spec: RunSpec) -> int:
    entries = parse_manifest(spec.directory / "manifest.sha256")
    for relative, expected in entries:
        path = spec.directory / relative
        if not path.is_file():
            raise FileNotFoundError(f"manifest artifact is missing: {path}")
        if sha256(path) != expected:
            raise ValueError(
                f"{spec.address_family} artifact manifest mismatch: {relative}"
            )
    return len(entries)


def verify_protocol(spec: RunSpec) -> Mapping[str, Any]:
    protocol = json.loads(
        (spec.directory / "protocol.json").read_text(encoding="utf-8")
    )
    expected = {
        "analysis_role": "primary_matched_handoff",
        "design": "randomized complete-block unknown-origin handoff",
        "arms": list(ARMS),
        "trials_per_lane": 40,
        "trials_per_block": 4,
        "randomized_complete_block_rounds": 10,
        "inference_unit": "complete-round arm mean",
    }
    for field, value in expected.items():
        if protocol.get(field) != value:
            raise ValueError(
                f"{spec.address_family} protocol mismatch for {field}: "
                f"{protocol.get(field)!r} != {value!r}"
            )
    if protocol.get("address_family") != spec.protocol_address_family:
        raise ValueError(
            f"{spec.address_family} protocol address-family mismatch: "
            f"{protocol.get('address_family')!r} != "
            f"{spec.protocol_address_family!r}"
        )
    timing = protocol.get("timing", {})
    if timing.get("source") != "one persistent Python time.monotonic_ns helper":
        raise ValueError(
            f"the accepted {spec.address_family} protocol does not identify "
            "monotonic_ns timing"
        )
    return protocol


def load_trial_map(spec: RunSpec) -> dict[tuple[str, int], dict[str, str]]:
    with (spec.directory / "trials.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
    required = {
        "round",
        "block",
        "block_trial",
        "lane",
        "trial",
        "direction",
        "observed_to_action_ms",
        "observed_to_probe_ms",
        "completion",
        "deadline_miss",
        "status",
        "passed",
    }
    if reader.fieldnames is None or not required.issubset(reader.fieldnames):
        raise ValueError("trials.csv lacks fields needed for the design cross-check")
    if len(rows) != 120:
        raise ValueError(f"expected 120 trials, found {len(rows)}")

    trial_map: dict[tuple[str, int], dict[str, str]] = {}
    for row in rows:
        key = (row["lane"], int(row["trial"]))
        if key in trial_map:
            raise ValueError(f"duplicate trial key: {key}")
        if (
            row["completion"].lower() != "true"
            or row["deadline_miss"].lower() != "false"
            or row["status"] != "complete"
            or row["passed"].lower() != "true"
        ):
            raise ValueError(f"accepted trial is not complete: {key}")
        trial_map[key] = row

    expected = {(arm, trial) for arm in ARMS for trial in range(1, 41)}
    if set(trial_map) != expected:
        raise ValueError("trial keys do not form the expected 3 by 40 design")
    cells = Counter((int(row["round"]), row["lane"]) for row in rows)
    expected_cells = {(round_id, arm) for round_id in range(1, 11) for arm in ARMS}
    if set(cells) != expected_cells or any(value != 4 for value in cells.values()):
        raise ValueError("trial map is not ten complete rounds with four handoffs per arm")
    return trial_map


def load_events(spec: RunSpec) -> dict[tuple[str, int], dict[str, int]]:
    grouped: dict[tuple[str, int], dict[str, int]] = defaultdict(dict)
    last_global_timestamp = -1
    with (spec.directory / "events.jsonl").open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            event = json.loads(line)
            key = (str(event["lane"]), int(event["trial"]))
            name = str(event["event"])
            timestamp = int(event["monotonic_ns"])
            if name in grouped[key]:
                raise ValueError(f"duplicate event {name} for {key}")
            if timestamp <= last_global_timestamp:
                raise ValueError(
                    f"events are not globally monotone at JSONL line {line_number}"
                )
            last_global_timestamp = timestamp
            grouped[key][name] = timestamp
    if len(grouped) != 120:
        raise ValueError(f"expected events for 120 trials, found {len(grouped)}")
    return dict(grouped)


def milliseconds(later_ns: int, earlier_ns: int) -> float:
    value = (later_ns - earlier_ns) / 1_000_000.0
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"invalid elapsed time: {value}")
    return value


def recompute_trials(
    spec: RunSpec,
    trial_map: Mapping[tuple[str, int], Mapping[str, str]],
    events: Mapping[tuple[str, int], Mapping[str, int]],
) -> list[dict[str, Any]]:
    if set(events) != set(trial_map):
        raise ValueError("events.jsonl and trials.csv identify different trials")

    output: list[dict[str, Any]] = []
    for key, metadata in trial_map.items():
        arm, lane_trial = key
        stamps = events[key]
        expected_events = set(BASE_EVENTS)
        if arm == "reactive_exact":
            expected_events.add(REACTIVE_EVENT)
        if set(stamps) != expected_events:
            missing = sorted(expected_events - set(stamps))
            extra = sorted(set(stamps) - expected_events)
            raise ValueError(f"event-set mismatch for {key}: missing={missing}, extra={extra}")

        observed = stamps["new_route_in_adj_rib_in"]
        rp_available = stamps["rp_policy_available"]
        compiler_started = stamps["compiler_started"]
        compiler_completed = stamps["compiler_completed"]
        action_installed = stamps["action_installed"]
        probe_succeeded = stamps["probe_succeeded"]
        if not (
            observed
            <= rp_available
            <= compiler_started
            <= compiler_completed
            <= action_installed
            <= probe_succeeded
        ):
            raise ValueError(f"invalid event ordering for {key}")

        if arm == "reactive_exact":
            signed_requested = stamps[REACTIVE_EVENT]
            if not observed <= signed_requested <= rp_available:
                raise ValueError(f"signed-update marker is out of order for {key}")
            input_capture = milliseconds(signed_requested, observed)
            online_update = milliseconds(rp_available, signed_requested)
        else:
            input_capture = milliseconds(rp_available, observed)
            online_update = 0.0

        compile_ms = milliseconds(compiler_completed, rp_available)
        install_ms = milliseconds(action_installed, compiler_completed)
        probe_ms = milliseconds(probe_succeeded, action_installed)
        observed_to_action = milliseconds(action_installed, observed)
        observed_to_probe = milliseconds(probe_succeeded, observed)
        stage_sum = input_capture + online_update + compile_ms + install_ms + probe_ms
        if abs(stage_sum - observed_to_probe) > 1e-9:
            raise ValueError(f"stage decomposition does not sum to endpoint for {key}")
        if abs(float(metadata["observed_to_action_ms"]) - observed_to_action) > 0.001:
            raise ValueError(f"recomputed action endpoint disagrees with trials.csv for {key}")
        if abs(float(metadata["observed_to_probe_ms"]) - observed_to_probe) > 0.001:
            raise ValueError(f"recomputed probe endpoint disagrees with trials.csv for {key}")

        output.append(
            {
                "run_id": spec.run_id,
                "address_family": spec.address_family,
                "round": int(metadata["round"]),
                "block": int(metadata["block"]),
                "block_trial": int(metadata["block_trial"]),
                "arm": arm,
                "arm_label": ARM_REPORT_LABELS[arm],
                "lane_trial": lane_trial,
                "direction": metadata["direction"],
                "input_capture_ms": input_capture,
                "online_roa_update_ms": online_update,
                "compile_ms": compile_ms,
                "action_install_ms": install_ms,
                "probe_confirmation_ms": probe_ms,
                "observed_to_action_ms": observed_to_action,
                "observed_to_probe_ms": observed_to_probe,
                "stage_sum_ms": stage_sum,
                "timing_source": "events.jsonl monotonic_ns",
                "inference_cluster": f"round-{int(metadata['round']):02d}",
            }
        )
    output.sort(key=lambda row: (int(row["round"]), int(row["block"]), int(row["block_trial"])))
    return output


def nearest_rank(values: Iterable[float], fraction: float) -> float:
    sample = sorted(float(value) for value in values)
    if not sample or not 0 < fraction <= 1:
        raise ValueError("nearest-rank requires a nonempty sample and fraction in (0, 1]")
    return sample[max(1, math.ceil(fraction * len(sample))) - 1]


def derive_rounds(
    spec: RunSpec, rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    grouped: dict[tuple[int, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(int(row["round"]), str(row["arm"]))].append(row)
    expected = {(round_id, arm) for round_id in range(1, 11) for arm in ARMS}
    if set(grouped) != expected or any(len(cell) != 4 for cell in grouped.values()):
        raise ValueError("recomputed rows do not form the accepted complete-round design")

    result: list[dict[str, Any]] = []
    for round_id in range(1, 11):
        for arm in ARMS:
            cell = grouped[(round_id, arm)]
            result.append(
                {
                    "run_id": spec.run_id,
                    "address_family": spec.address_family,
                    "round": round_id,
                    "arm": arm,
                    "arm_label": ARM_REPORT_LABELS[arm],
                    "n_handoffs": len(cell),
                    # Six decimals matches the accepted summarizer before
                    # the paired round contrast is formed.
                    "observed_to_action_mean_ms": round(
                        statistics.fmean(row["observed_to_action_ms"] for row in cell),
                        6,
                    ),
                    "observed_to_probe_mean_ms": round(
                        statistics.fmean(row["observed_to_probe_ms"] for row in cell),
                        6,
                    ),
                    "inference_unit": "complete-round arm mean",
                }
            )
    return result


def derive_stage_summary(
    spec: RunSpec, rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_arm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_arm[str(row["arm"])].append(row)
    result: list[dict[str, Any]] = []
    for arm in ARMS:
        sample = by_arm[arm]
        if len(sample) != 40:
            raise ValueError(f"expected 40 handoffs for {arm}")
        total_mean = statistics.fmean(row["observed_to_probe_ms"] for row in sample)
        for stage in STAGES:
            values = [float(row[stage]) for row in sample]
            result.append(
                {
                    "run_id": spec.run_id,
                    "address_family": spec.address_family,
                    "arm": arm,
                    "arm_label": ARM_REPORT_LABELS[arm],
                    "stage": stage,
                    "stage_label": STAGE_LABELS[stage],
                    "n_handoffs": len(values),
                    "mean_ms": statistics.fmean(values),
                    "median_ms": statistics.median(values),
                    "p95_nearest_rank_ms": nearest_rank(values, 0.95),
                    "endpoint_total_mean_ms": total_mean,
                }
            )
    return result


def cluster_bootstrap(
    round_rows: list[dict[str, Any]],
) -> dict[str, dict[str, dict[str, Any]]]:
    """Replicate the accepted complete-round bootstrap from event-derived data."""

    cells = {
        (int(row["round"]), str(row["arm"])): row for row in round_rows
    }
    contrasts = (
        ("reactive_exact_minus_open_dynamic", "reactive_exact", "open_dynamic"),
        (
            "reactive_exact_minus_prepublished_exact",
            "reactive_exact",
            "prepublished_exact",
        ),
        (
            "open_dynamic_minus_prepublished_exact",
            "open_dynamic",
            "prepublished_exact",
        ),
    )
    metrics = ("observed_to_action_mean_ms", "observed_to_probe_mean_ms")
    rng = random.Random(BOOTSTRAP_SEED)
    result: dict[str, dict[str, dict[str, Any]]] = {}
    for name, arm_a, arm_b in contrasts:
        result[name] = {}
        for metric in metrics:
            differences = [
                float(cells[(round_id, arm_a)][metric])
                - float(cells[(round_id, arm_b)][metric])
                for round_id in range(1, 11)
            ]
            replicates = [
                statistics.fmean(
                    differences[rng.randrange(len(differences))]
                    for _ in differences
                )
                for _ in range(BOOTSTRAP_REPLICATES)
            ]
            result[name][metric] = {
                "estimate_ms": statistics.fmean(differences),
                "ci95_ms": (
                    nearest_rank(replicates, 0.025),
                    nearest_rank(replicates, 0.975),
                ),
                "round_differences_ms": differences,
                "n_complete_rounds": len(differences),
            }
    return result


def derive_contrast_rows(
    spec: RunSpec,
    inference: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for contrast, label in PLOTTED_CONTRASTS:
        result = inference[contrast]["observed_to_probe_mean_ms"]
        lower, upper = result["ci95_ms"]
        rows.append(
            {
                "run_id": spec.run_id,
                "address_family": spec.address_family,
                "contrast": contrast,
                "contrast_label": label,
                "estimate_ms": result["estimate_ms"],
                "ci95_lower_ms": lower,
                "ci95_upper_ms": upper,
                "n_complete_rounds": result["n_complete_rounds"],
                "bootstrap_replicates": BOOTSTRAP_REPLICATES,
                "bootstrap_seed": BOOTSTRAP_SEED,
            }
        )
    return rows


def verify_against_independent_audit(
    spec: RunSpec,
    round_rows: list[dict[str, Any]],
    inference: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> int:
    audit = json.loads(
        (spec.directory / "independent-audit.json").read_text(encoding="utf-8")
    )
    if audit.get("passed") is not True:
        raise ValueError(f"the {spec.address_family} independent audit did not pass")
    checks = audit.get("checks", {})
    required = {
        "all_trial_assertions_pass",
        "artifact_manifest_matches",
        "probe_event_matches_ping_capture",
        "schedule_is_complete_randomized_round",
        "source_hashes_match",
        "trials_csv_matches_raw_artifacts",
    }
    failed = sorted(check for check in required if checks.get(check) is not True)
    if failed:
        raise ValueError(f"required independent-audit checks failed: {failed}")

    cells = {
        (int(row["round"]), str(row["arm"])): row for row in round_rows
    }
    for round_id in range(1, 11):
        for arm in ARMS:
            audited = audit["round_arm_means_ms"][str(round_id)][arm]
            for local_metric, audit_metric in (
                ("observed_to_action_mean_ms", "observed_to_action_ms"),
                ("observed_to_probe_mean_ms", "observed_to_probe_ms"),
            ):
                actual = float(cells[(round_id, arm)][local_metric])
                expected = float(audited[audit_metric]["mean_ms"])
                if abs(actual - expected) > 1e-6:
                    raise ValueError(
                        f"round mean differs from audit: round={round_id}, arm={arm}, "
                        f"metric={local_metric}, actual={actual}, expected={expected}"
                    )

    metric_map = {
        "observed_to_action_mean_ms": "observed_to_action_ms",
        "observed_to_probe_mean_ms": "observed_to_probe_ms",
    }
    for contrast, metrics in inference.items():
        for local_metric, value in metrics.items():
            audited = audit["inference"]["contrasts"][contrast]["metrics"][
                metric_map[local_metric]
            ]
            expected_ci = tuple(float(item) for item in audited["ci95_nearest_rank_ms"])
            if abs(float(value["estimate_ms"]) - float(audited["estimate_ms"])) > 0.001:
                raise ValueError(f"contrast estimate differs from audit: {contrast}")
            if any(abs(left - right) > 0.001 for left, right in zip(value["ci95_ms"], expected_ci)):
                raise ValueError(f"contrast interval differs from audit: {contrast}")
    return sum(value is True for value in checks.values())


def format_float(value: Any) -> str:
    return f"{float(value):.6f}"


def write_csv(path: Path, fields: Iterable[str], rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    field_list = list(fields)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=field_list, lineterminator="\n")
        writer.writeheader()
        for source in rows:
            row = dict(source)
            for field in field_list:
                if field.endswith("_ms") and field in row:
                    row[field] = format_float(row[field])
            writer.writerow(row)


def configure_style() -> None:
    mpl.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans", "sans-serif"],
            "font.size": 7.0,
            "axes.titlesize": 7.5,
            "axes.labelsize": 7.0,
            "xtick.labelsize": 6.4,
            "ytick.labelsize": 6.4,
            "legend.fontsize": 5.9,
            "axes.linewidth": 0.7,
            "axes.edgecolor": TEXT,
            "axes.labelcolor": TEXT,
            "xtick.color": TEXT,
            "ytick.color": TEXT,
            "text.color": TEXT,
            "lines.linewidth": 1.0,
            "legend.frameon": False,
            "pdf.fonttype": 42,
            "svg.fonttype": "none",
            "svg.hashsalt": "ssrov-handoff-fig2-dual-stack-v5",
            "hatch.linewidth": 0.45,
            "figure.facecolor": WHITE,
            "axes.facecolor": WHITE,
            "savefig.facecolor": WHITE,
        }
    )


def style_axis(ax: plt.Axes, *, grid_axis: str) -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis=grid_axis, color=GRID, linewidth=0.55, linestyle=(0, (1.4, 2.2)))
    ax.set_axisbelow(True)
    ax.tick_params(length=2.5, width=0.65)


def bootstrap_arm_means(
    round_rows: list[dict[str, Any]],
) -> dict[str, dict[str, dict[str, Any]]]:
    """Estimate workflow means and round-cluster bootstrap intervals."""

    cells = {
        (str(row["address_family"]), int(row["round"]), str(row["arm"])): row
        for row in round_rows
    }
    summaries: dict[str, dict[str, dict[str, Any]]] = {}
    for family_index, spec in enumerate(RUN_SPECS):
        family = spec.address_family
        rng = random.Random(BOOTSTRAP_SEED + family_index)
        sampled_rounds = [
            [rng.randrange(1, 11) for _ in range(10)]
            for _ in range(BOOTSTRAP_REPLICATES)
        ]
        summaries[family] = {}
        for arm in ARMS:
            values = [
                float(cells[(family, round_id, arm)]["observed_to_probe_mean_ms"])
                for round_id in range(1, 11)
            ]
            replicates = [
                statistics.fmean(
                    float(cells[(family, round_id, arm)]["observed_to_probe_mean_ms"])
                    for round_id in sampled
                )
                for sampled in sampled_rounds
            ]
            summaries[family][arm] = {
                "estimate_ms": statistics.fmean(values),
                "ci95_ms": (
                    nearest_rank(replicates, 0.025),
                    nearest_rank(replicates, 0.975),
                ),
                "n_complete_rounds": len(values),
            }
    return summaries


def bootstrap_lane_average_arm_means(
    round_rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Equal-weight the two lanes and bootstrap complete rounds within lane."""

    cells = {
        (str(row["address_family"]), int(row["round"]), str(row["arm"])): row
        for row in round_rows
    }
    families = tuple(spec.address_family for spec in RUN_SPECS)
    estimates = {
        arm: statistics.fmean(
            statistics.fmean(
                float(cells[(family, round_id, arm)]["observed_to_probe_mean_ms"])
                for round_id in range(1, 11)
            )
            for family in families
        )
        for arm in ARMS
    }
    replicates: dict[str, list[float]] = {arm: [] for arm in ARMS}
    rng = random.Random(BOOTSTRAP_SEED + 100)
    for _ in range(BOOTSTRAP_REPLICATES):
        sampled_by_family = {
            family: [rng.randrange(1, 11) for _ in range(10)]
            for family in families
        }
        for arm in ARMS:
            replicates[arm].append(
                statistics.fmean(
                    statistics.fmean(
                        float(cells[(family, round_id, arm)]["observed_to_probe_mean_ms"])
                        for round_id in sampled_by_family[family]
                    )
                    for family in families
                )
            )
    return {
        arm: {
            "estimate_ms": estimates[arm],
            "ci95_ms": (
                nearest_rank(replicates[arm], 0.025),
                nearest_rank(replicates[arm], 0.975),
            ),
            "n_complete_rounds_per_family": 10,
            "n_address_families": len(families),
        }
        for arm in ARMS
    }


def draw_figure(
    lane_average_arm_means: Mapping[str, Mapping[str, Any]],
    inference_by_family: Mapping[
        str, Mapping[str, Mapping[str, Mapping[str, Any]]]
    ],
) -> plt.Figure:
    configure_style()
    fig, ax_effect = plt.subplots(figsize=(3.5, 2.35), constrained_layout=False)
    fig.subplots_adjust(left=0.16, right=0.985, bottom=0.225, top=0.955)

    # The bars expose workflow latency directly without treating address family
    # as a visual factor.  Each lane contributes equal weight, and complete
    # rounds remain the inferential unit for every interval.
    family_order = tuple(spec.address_family for spec in RUN_SPECS)
    x = np.arange(len(ARMS), dtype=float)
    summaries = [lane_average_arm_means[arm] for arm in ARMS]
    estimates = np.array(
        [float(summary["estimate_ms"]) / 1000.0 for summary in summaries]
    )
    intervals = [
        tuple(float(value) / 1000.0 for value in summary["ci95_ms"])
        for summary in summaries
    ]
    yerr = np.array(
        [
            [estimate - lower for estimate, (lower, _upper) in zip(estimates, intervals)],
            [upper - estimate for estimate, (_lower, upper) in zip(estimates, intervals)],
        ]
    )
    arm_colors = ["#B24745", "#0077BB", "#4A7C59"]
    bars = ax_effect.bar(
        x,
        estimates,
        width=0.58,
        yerr=yerr,
        capsize=2.5,
        color=arm_colors,
        edgecolor=TEXT,
        linewidth=0.6,
        error_kw={"elinewidth": 0.9, "capthick": 0.8, "ecolor": TEXT},
        zorder=3,
    )
    for bar, estimate, (_lower, upper), color in zip(
        bars, estimates, intervals, arm_colors
    ):
        ax_effect.text(
            bar.get_x() + bar.get_width() / 2,
            upper + 0.045,
            f"{estimate:.1f}",
            ha="center",
            va="bottom",
            fontsize=6.4,
            fontweight="bold",
            color=color,
        )

    paired_effects = [
        float(
            inference_by_family[family]["reactive_exact_minus_open_dynamic"]
            ["observed_to_probe_mean_ms"]["estimate_ms"]
        )
        / 1000.0
        for family in family_order
    ]
    if max(paired_effects) - min(paired_effects) >= 0.05:
        raise ValueError("the shared paired-effect annotation would hide a family difference")
    bracket_y = 2.76
    bracket_drop = 0.055
    ax_effect.plot(
        [x[0], x[0], x[1], x[1]],
        [bracket_y - bracket_drop, bracket_y, bracket_y, bracket_y - bracket_drop],
        color=MUTED,
        linewidth=0.8,
        clip_on=False,
    )
    ax_effect.text(
        (x[0] + x[1]) / 2,
        bracket_y + 0.035,
        f"{statistics.fmean(paired_effects):.1f} s faster",
        ha="center",
        va="bottom",
        fontsize=6.4,
        fontweight="bold",
        color=TEXT,
    )

    ax_effect.set_ylabel("Observation-to-probe time (s)")
    ax_effect.set_xticks(
        x,
        ["Reactive\nexact", "Preinstalled\nscope", "Prepublished\nexact"],
    )
    ax_effect.set_xlim(-0.62, 2.62)
    ax_effect.set_ylim(0.0, 3.05)
    ticks = np.arange(0.0, 3.01, 0.5)
    ax_effect.set_yticks(ticks, [f"{value:.1f}" for value in ticks])
    style_axis(ax_effect, grid_axis="y")
    return fig


def export_figure(fig: plt.Figure) -> list[Path]:
    canonical = [
        OUTPUT_STEM.with_suffix(".pdf"),
        OUTPUT_STEM.with_suffix(".svg"),
        OUTPUT_STEM.with_suffix(".png"),
        OUTPUT_STEM.with_suffix(".tiff"),
    ]
    fig.savefig(
        canonical[0],
        metadata={
            "Title": "Unknown-origin handoff time",
            "Creator": SCRIPT.name,
            "CreationDate": None,
            "ModDate": None,
        },
    )
    fig.savefig(
        canonical[1],
        metadata={
            "Title": "Unknown-origin handoff time",
            "Creator": SCRIPT.name,
            "Date": None,
        },
    )
    fig.savefig(canonical[2], dpi=300, metadata={"Software": SCRIPT.name})
    fig.savefig(
        canonical[3],
        dpi=600,
        pil_kwargs={"compression": "tiff_lzw"},
    )

    retained = [
        REANALYSIS_STEM.with_suffix(".pdf"),
        REANALYSIS_STEM.with_suffix(".svg"),
        REANALYSIS_STEM.with_suffix(".png"),
        REANALYSIS_STEM.with_suffix(".tiff"),
    ]
    for source, destination in zip(canonical, retained):
        shutil.copyfile(source, destination)
    return [*canonical, *retained]


def markdown_path(path: Path) -> str:
    return str(path.relative_to(REPO))


def write_provenance(
    analyses: list[dict[str, Any]],
    arm_means_by_family: Mapping[str, Mapping[str, Mapping[str, Any]]],
    lane_average_arm_means: Mapping[str, Mapping[str, Any]],
    output_paths: list[Path],
) -> None:
    trial_rows = [row for analysis in analyses for row in analysis["trials"]]
    stage_rows = [row for analysis in analyses for row in analysis["stages"]]
    stage_lookup = {
        (
            str(row["address_family"]),
            str(row["arm"]),
            str(row["stage"]),
        ): float(row["mean_ms"])
        for row in stage_rows
    }
    total_lookup = {
        (spec.address_family, arm): statistics.fmean(
            float(row["observed_to_probe_ms"])
            for row in trial_rows
            if row["address_family"] == spec.address_family and row["arm"] == arm
        )
        for spec in RUN_SPECS
        for arm in ARMS
    }
    products = [TRIAL_CSV, STAGE_CSV, ROUND_CSV, CONTRAST_CSV, *output_paths]

    input_rows = "\n".join(
        f"| {spec.address_family} | `{name}` | `{digest}` |"
        for spec in RUN_SPECS
        for name, digest in spec.pinned_input_hashes.items()
    )
    accepted_rows = "\n".join(
        f"| {analysis['spec'].address_family} | `{analysis['spec'].run_id}` | "
        f"{len(analysis['trials'])} | {analysis['manifest_entries']} | "
        f"{analysis['audit_checks']} |"
        for analysis in analyses
    )
    result_rows = []
    for spec in RUN_SPECS:
        for arm in ARMS:
            result_rows.append(
                "| "
                + spec.address_family
                + " | "
                + ARM_REPORT_LABELS[arm]
                + " | "
                + " | ".join(
                    f"{stage_lookup[(spec.address_family, arm, stage)]:.1f}"
                    for stage in STAGES
                )
                + f" | {total_lookup[(spec.address_family, arm)]:.1f} |"
            )
    contrast_rows = []
    for analysis in analyses:
        family = analysis["spec"].address_family
        inference = analysis["inference"]
        for contrast, label in PLOTTED_CONTRASTS:
            result = inference[contrast]["observed_to_probe_mean_ms"]
            lower, upper = result["ci95_ms"]
            contrast_rows.append(
                f"| {family} | {label} | {float(result['estimate_ms']):.1f} | "
                f"[{float(lower):.1f}, {float(upper):.1f}] |"
            )
    arm_mean_rows = []
    for spec in RUN_SPECS:
        family = spec.address_family
        for arm in ARMS:
            summary = arm_means_by_family[family][arm]
            lower, upper = summary["ci95_ms"]
            arm_mean_rows.append(
                f"| {family} | {ARM_REPORT_LABELS[arm]} | "
                f"{float(summary['estimate_ms']):.1f} | "
                f"[{float(lower):.1f}, {float(upper):.1f}] |"
            )
    lane_average_rows = []
    for arm in ARMS:
        summary = lane_average_arm_means[arm]
        lower, upper = summary["ci95_ms"]
        lane_average_rows.append(
            f"| {ARM_REPORT_LABELS[arm]} | {float(summary['estimate_ms']):.1f} | "
            f"[{float(lower):.1f}, {float(upper):.1f}] |"
        )
    output_rows = "\n".join(
        f"| `{markdown_path(path)}` | `{sha256(path)}` |" for path in products
    )
    report = f"""# Fig. 2 dual-stack handoff provenance

## Accepted runs

| Address family | Run | Handoffs | Manifest entries | Passing audit checks |
|---|---|---:|---:|---:|
{accepted_rows}

Each run retains 40 handoffs per workflow, arranged as four handoffs per workflow in each of ten complete randomized rounds. Both use one persistent `time.monotonic_ns` helper. The numeric sources are the two accepted `events.jsonl` streams.

## Pinned inputs

| Address family | Input | SHA-256 |
|---|---|---|
{input_rows}

Each `trials.csv` supplies round, block, and direction labels. Every plotted latency is recomputed from the matching `events.jsonl`; stored trial endpoints are used only as a cross-check.

## Event-derived stages

The mutually exclusive stages sum exactly to the primary endpoint for every handoff:

1. **Input capture:** route observation to `signed_roa_requested` for reactive exact, and route observation to `rp_policy_available` for the two preinstalled arms. This interval contains the common post-observation input captures.
2. **ROA update:** `signed_roa_requested` to `rp_policy_available` for reactive exact; zero for the two arms whose policy was already effective.
3. **Compile:** `rp_policy_available` to `compiler_completed`, including compiler dispatch.
4. **Install:** `compiler_completed` to `action_installed`.
5. **Probe:** `action_installed` to `probe_succeeded`.

## Recomputed stage means

All values are milliseconds across 40 handoffs per workflow and address family.

| Address family | Workflow | Input capture | ROA update | Compile | Install | Probe | Total |
|---|---|---:|---:|---:|---:|---:|---:|
{chr(10).join(result_rows)}

## Complete-round summaries and contrasts

The figure bars equal-weight the two address-family lanes. Their error bars use
a stratified bootstrap that resamples ten complete rounds independently within
each lane before averaging the two lane means.

| Workflow | Equal-weight mean (ms) | 95% interval (ms) |
|---|---:|---:|
{chr(10).join(lane_average_rows)}

The family-specific inputs to that summary are:

| Address family | Workflow | Mean (ms) | 95% interval (ms) |
|---|---|---:|---:|
{chr(10).join(arm_mean_rows)}

The bracket annotation reports the accepted paired complete-round contrast:

| Address family | Contrast | Estimate (ms) | 95% interval (ms) |
|---|---|---:|---:|
{chr(10).join(contrast_rows)}

The bootstrap independently resamples each address family's ten paired complete-round differences with replacement for {BOOTSTRAP_REPLICATES:,} replicates using seed {BOOTSTRAP_SEED}. Nearest-rank bounds match both accepted independent audits.

## IPv6 implementation boundary

The IPv6 lane uses an independent dual-stack policy model over validated local output. It does not carry the experimental IPv6 encoding through Krill, Routinator, and FRR. Figure 2 combines the two lanes only as an equal-weight visual summary; the manuscript reports their estimates separately and does not test a cross-family performance difference.

## Integrity checks

- All 240 trials have one copy of each required event; only reactive exact has `signed_roa_requested`.
- Event timestamps are globally monotone and correctly ordered within each trial.
- Each five-stage sum equals `probe_succeeded - new_route_in_adj_rib_in` to within 1 ns-equivalent floating-point tolerance.
- Recomputed action and probe endpoints match the rounded values in `trials.csv` within 0.001 ms.
- All 60 address-family, round, and workflow means and all accepted contrast estimates and intervals match the corresponding `independent-audit.json`.

## Figure/table trace

```yaml
figure_table_trace:
  - artifact_id: "fig-2"
    source_data:
      dataset_id: "dual-stack matched unknown-origin handoff"
      file: "figure-data/source_data/handoff_endpoint_rounds_recomputed.csv"
    transformation:
      script: "experiments/analysis_scripts/analyze_handoff_fig2.py"
      hash: "{sha256(SCRIPT)}"
    caption_claim: "Reactive exact adds 1.4 s relative to preinstalled scope in both tested handoff lanes."
    supported_manuscript_claims:
      - claim: "Reactive exact minus preinstalled scope is 1.4 s in both tested lanes."
        locator: "Section V-A"
    limitations:
      - "The IPv6 lane uses an independent dual-stack policy model rather than end-to-end transport of the experimental IPv6 encoding."
      - "The experiment measures controlled workflow latency, not Internet-wide convergence or routing benefit."
```

## Generated products

Generator: `{markdown_path(SCRIPT)}` (`{sha256(SCRIPT)}`)

| Product | SHA-256 |
|---|---|
{output_rows}
"""
    PROVENANCE.write_text(report, encoding="utf-8")


def main() -> None:
    analyses: list[dict[str, Any]] = []
    for spec in RUN_SPECS:
        verify_pinned_inputs(spec)
        manifest_entries = verify_artifact_manifest(spec)
        verify_protocol(spec)
        trial_map = load_trial_map(spec)
        events = load_events(spec)
        trials = recompute_trials(spec, trial_map, events)
        rounds = derive_rounds(spec, trials)
        stages = derive_stage_summary(spec, trials)
        inference = cluster_bootstrap(rounds)
        audit_checks = verify_against_independent_audit(spec, rounds, inference)
        analyses.append(
            {
                "spec": spec,
                "manifest_entries": manifest_entries,
                "audit_checks": audit_checks,
                "trials": trials,
                "rounds": rounds,
                "stages": stages,
                "inference": inference,
                "contrasts": derive_contrast_rows(spec, inference),
            }
        )

    trials = [row for analysis in analyses for row in analysis["trials"]]
    rounds = [row for analysis in analyses for row in analysis["rounds"]]
    stages = [row for analysis in analyses for row in analysis["stages"]]
    contrasts = [row for analysis in analyses for row in analysis["contrasts"]]
    inference_by_family = {
        analysis["spec"].address_family: analysis["inference"]
        for analysis in analyses
    }
    arm_means_by_family = bootstrap_arm_means(rounds)
    lane_average_arm_means = bootstrap_lane_average_arm_means(rounds)

    write_csv(TRIAL_CSV, TRIAL_FIELDS, trials)
    write_csv(STAGE_CSV, STAGE_FIELDS, stages)
    write_csv(ROUND_CSV, ROUND_FIELDS, rounds)
    write_csv(CONTRAST_CSV, CONTRAST_FIELDS, contrasts)
    figure = draw_figure(lane_average_arm_means, inference_by_family)
    outputs = export_figure(figure)
    plt.close(figure)
    write_provenance(
        analyses,
        arm_means_by_family,
        lane_average_arm_means,
        outputs,
    )

    print(f"trials recomputed from events: {len(trials)}")
    for analysis in analyses:
        family = analysis["spec"].address_family
        print(f"accepted {family} run: {analysis['spec'].run_id}")
        for contrast, label in PLOTTED_CONTRASTS:
            result = analysis["inference"][contrast]["observed_to_probe_mean_ms"]
            lower, upper = result["ci95_ms"]
            print(
                f"{family} {label.lower()}: {result['estimate_ms']:.1f} ms, "
                f"95% CI [{lower:.1f}, {upper:.1f}] ms"
            )
    for path in [
        TRIAL_CSV,
        STAGE_CSV,
        ROUND_CSV,
        CONTRAST_CSV,
        *outputs,
        PROVENANCE,
    ]:
        print(markdown_path(path))


if __name__ == "__main__":
    main()
