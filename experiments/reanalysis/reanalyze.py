#!/usr/bin/env python3
"""Correct competitor-dependent uncertainty targets without rerunning BGPy."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

import numpy as np


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "results"
def _input(relative: str) -> Path:
    """Accept the run output in place or its archived copy."""
    local = ROOT / relative
    if local.exists():
        return local
    return ROOT / "results/tables" / relative.split("/", 1)[1]


ROUTING_MODEL_CONTRASTS = _input(
    "experiments/routing_model/results/paper_campaign/analysis/holder_contrasts.jsonl"
)
ROUTING_MODEL_CELLS = _input(
    "experiments/routing_model/results/paper_campaign/analysis/raw_cell_summary.csv"
)
ATTACK_REACHABILITY_CONTRASTS = _input(
    "experiments/attack_reachability/results/analysis/holder_contrasts.jsonl"
)
ATTACK_REACHABILITY_SUMMARY = _input(
    "experiments/attack_reachability/results/analysis/summary.json"
)
REPLICATES = 10_000
ROUTING_MODEL_SEED = 20260804
ATTACK_REACHABILITY_SEED = 20260823
EXPECTED_STRATA = {"S1": 50, "S2": 50, "S3": 50, "S4": 50}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise TypeError(f"non-object JSONL row in {path}")
                yield value


def bootstrap_weights(
    metadata: dict[int, tuple[str, float]], *, seed: int
) -> tuple[list[int], np.ndarray]:
    holders = sorted(metadata)
    if len(holders) != 200:
        raise ValueError(f"expected 200 holders, found {len(holders)}")
    counts = Counter(metadata[holder][0] for holder in holders)
    if dict(counts) != EXPECTED_STRATA:
        raise ValueError(f"unexpected stratum counts: {dict(counts)}")

    rng = np.random.default_rng(seed)
    weights = np.zeros((REPLICATES, len(holders)), dtype=np.float64)
    holder_index = {holder: index for index, holder in enumerate(holders)}
    for stratum in EXPECTED_STRATA:
        members = [holder for holder in holders if metadata[holder][0] == stratum]
        draw_counts = rng.multinomial(
            len(members), np.full(len(members), 1.0 / len(members)), REPLICATES
        )
        design_weights = {metadata[holder][1] for holder in members}
        if len(design_weights) != 1:
            raise ValueError(f"inconsistent weights in {stratum}: {design_weights}")
        weight = design_weights.pop()
        for column, holder in enumerate(members):
            weights[:, holder_index[holder]] = draw_counts[:, column] * weight

    totals = weights.sum(axis=1)
    if not np.allclose(totals, totals[0], rtol=0, atol=1e-10):
        raise ValueError("bootstrap total weights are not constant")
    return holders, weights


def summarize_groups(
    groups: dict[tuple[Any, ...], list[dict[str, Any]]],
    key_names: tuple[str, ...],
    *,
    seed: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not groups:
        raise ValueError("no groups selected")
    first_rows = next(iter(groups.values()))
    metadata = {
        int(row["holder_asn"]): (str(row["stratum"]), float(row["design_weight"]))
        for row in first_rows
    }
    holders, weights = bootstrap_weights(metadata, seed=seed)
    holder_index = {holder: index for index, holder in enumerate(holders)}
    denominator = weights.sum(axis=1)
    summaries: list[dict[str, Any]] = []
    for key in sorted(groups, key=lambda value: tuple(str(item) for item in value)):
        rows = groups[key]
        if len(rows) != 200 or len({int(row["holder_asn"]) for row in rows}) != 200:
            raise ValueError(f"group {key!r} does not contain 200 unique units")
        if Counter(str(row["stratum"]) for row in rows) != Counter(EXPECTED_STRATA):
            raise ValueError(f"group {key!r} has invalid stratum allocation")
        row_by_holder = {int(row["holder_asn"]): row for row in rows}
        if set(row_by_holder) != set(holders):
            raise ValueError(f"group {key!r} holder set differs")
        for holder, row in row_by_holder.items():
            observed = (str(row["stratum"]), float(row["design_weight"]))
            if observed != metadata[holder]:
                raise ValueError(
                    f"group {key!r} changes metadata for holder {holder}: "
                    f"{observed!r} != {metadata[holder]!r}"
                )
        delta = np.zeros(200, dtype=np.float64)
        treatment = np.zeros(200, dtype=np.float64)
        reference = np.zeros(200, dtype=np.float64)
        fixed_weights = np.zeros(200, dtype=np.float64)
        for holder, index in holder_index.items():
            row = row_by_holder[holder]
            delta[index] = float(row["delta"])
            treatment[index] = float(row["treatment_fraction"])
            reference[index] = float(row["reference_fraction"])
            fixed_weights[index] = float(row["design_weight"])
        point = float(np.average(delta, weights=fixed_weights))
        treatment_mean = float(np.average(treatment, weights=fixed_weights))
        reference_mean = float(np.average(reference, weights=fixed_weights))
        replicates = (weights @ delta) / denominator
        lower, upper = np.percentile(
            replicates, (2.5, 97.5), method="linear"
        ).tolist()
        summary = {name: value for name, value in zip(key_names, key)}
        summary.update(
            {
                "selected_units": 200,
                "stratum_standardized_selected_unit_mean": point,
                "raw_treatment_stratum_standardized_mean": treatment_mean,
                "raw_reference_stratum_standardized_mean": reference_mean,
                "resampling_interval95_lower": float(lower),
                "resampling_interval95_upper": float(upper),
                "bootstrap_replicates": REPLICATES,
                "bootstrap_seed": seed,
                "interval_type": (
                    "ordinary_stratified_paired_percentile_selected_unit_stability"
                ),
                "finite_population_correction": False,
            }
        )
        summaries.append(summary)
    audit = {
        "holders": len(holders),
        "strata": dict(sorted(Counter(metadata[h][0] for h in holders).items())),
        "replicate_weight_total": float(denominator[0]),
        "replicate_weight_total_constant": True,
    }
    return summaries, audit


def routing_model_groups() -> dict[tuple[Any, ...], list[dict[str, Any]]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in read_jsonl(ROUTING_MODEL_CONTRASTS):
        if (
            row.get("estimand") not in {"Delta_E_rov", "Delta_E_exact"}
            or row.get("metric_level") != "destination"
            or row.get("population") != "all"
            or row.get("deployment_strategy") != "random"
            or row.get("attacker_class") not in {"uniform", "edge", "high_degree"}
        ):
            continue
        key = (
            str(row["estimand"]),
            str(row["metric_level"]),
            str(row["population"]),
            str(row["attacker_class"]),
            str(row["deployment_strategy"]),
            int(row["deployment_percent_target"]),
        )
        groups[key].append(row)
    return groups


def attack_reachability_groups() -> dict[tuple[Any, ...], list[dict[str, Any]]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in read_jsonl(ATTACK_REACHABILITY_CONTRASTS):
        if (
            row.get("estimand") != "Delta_E_sibling"
            or row.get("population") != "all"
            or row.get("metric_level") not in {"route", "destination"}
            or int(row.get("deployment_percent_target", -1)) != 100
        ):
            continue
        key = (
            str(row["estimand"]),
            str(row["metric_level"]),
            str(row["population"]),
            int(row["deployment_percent_target"]),
        )
        groups[key].append(row)
    return groups


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise ValueError(f"refusing to write empty {path}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def frozen_routing_model_points() -> dict[tuple[Any, ...], float]:
    result: dict[tuple[Any, ...], float] = {}
    with ROUTING_MODEL_CELLS.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if (
                row["estimand"] not in {"Delta_E_rov", "Delta_E_exact"}
                or row["metric_level"] != "destination"
                or row["population"] != "all"
                or row["deployment_strategy"] != "random"
            ):
                continue
            key = (
                row["estimand"],
                row["metric_level"],
                row["population"],
                row["attacker_class"],
                row["deployment_strategy"],
                int(row["deployment_percent_target"]),
            )
            result[key] = float(row["paired_delta_design_weighted_mean"])
    return result


def headline(
    rows: list[dict[str, Any]], **criteria: Any
) -> dict[str, Any]:
    matches = [
        row for row in rows if all(row.get(key) == value for key, value in criteria.items())
    ]
    if len(matches) != 1:
        raise ValueError(f"headline criteria {criteria!r} matched {len(matches)} rows")
    return matches[0]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    routing_model, routing_model_audit = summarize_groups(
        routing_model_groups(),
        (
            "estimand",
            "metric_level",
            "population",
            "attacker_class",
            "deployment_strategy",
            "deployment_percent_target",
        ),
        seed=ROUTING_MODEL_SEED,
    )
    frozen_points = frozen_routing_model_points()
    max_point_error = max(
        abs(
            row["stratum_standardized_selected_unit_mean"]
            - frozen_points[
                (
                    row["estimand"],
                    row["metric_level"],
                    row["population"],
                    row["attacker_class"],
                    row["deployment_strategy"],
                    row["deployment_percent_target"],
                )
            ]
        )
        for row in routing_model
    )
    if max_point_error > 1e-12:
        raise ValueError(f"routing-model point estimate mismatch: {max_point_error}")

    attack_reachability, attack_reachability_audit = summarize_groups(
        attack_reachability_groups(),
        ("estimand", "metric_level", "population", "deployment_percent_target"),
        seed=ATTACK_REACHABILITY_SEED,
    )
    frozen_attack_reachability = json.loads(ATTACK_REACHABILITY_SUMMARY.read_text(encoding="utf-8"))
    route = headline(attack_reachability, metric_level="route")
    destination = headline(attack_reachability, metric_level="destination")
    frozen_cells = [
        cell
        for cell in frozen_attack_reachability["cells"]
        if cell["estimand"] == "Delta_E_sibling"
        and cell["population"] == "all"
        and int(cell["deployment_percent_target"]) == 100
    ]
    frozen_route = float(
        next(
            cell["paired_delta_design_weighted_mean"]
            for cell in frozen_cells
            if cell["metric_level"] == "route"
        )
    )
    frozen_destination = float(
        next(
            cell["paired_delta_design_weighted_mean"]
            for cell in frozen_cells
            if cell["metric_level"] == "destination"
        )
    )
    max_attack_reachability_error = max(
        abs(route["stratum_standardized_selected_unit_mean"] - frozen_route),
        abs(destination["stratum_standardized_selected_unit_mean"] - frozen_destination),
    )
    if max_attack_reachability_error > 1e-12:
        raise ValueError(f"attack-reachability point estimate mismatch: {max_attack_reachability_error}")

    write_csv(OUT / "competition_cells.csv", routing_model)
    write_csv(OUT / "sibling_cells.csv", attack_reachability)

    full_exposure = headline(
        routing_model,
        estimand="Delta_E_rov",
        attacker_class="uniform",
        deployment_percent_target=100,
    )
    full_exact = headline(
        routing_model,
        estimand="Delta_E_exact",
        attacker_class="uniform",
        deployment_percent_target=100,
    )
    edge = headline(
        routing_model,
        estimand="Delta_E_rov",
        attacker_class="edge",
        deployment_percent_target=100,
    )
    high = headline(
        routing_model,
        estimand="Delta_E_rov",
        attacker_class="high_degree",
        deployment_percent_target=100,
    )
    summary = {
        "schema_version": "reanalysis-selected-unit-reanalysis-v1",
        "status": "complete",
        "analysis_artifacts_sha256": {
            "EXPERIMENT_CONTRACT.md": sha256(
                Path(__file__).resolve().parent / "EXPERIMENT_CONTRACT.md"
            ),
            "reanalyze.py": sha256(Path(__file__).resolve()),
        },
        "inputs_sha256": {
            str(path.relative_to(ROOT)): sha256(path)
            for path in (
                ROUTING_MODEL_CONTRASTS,
                ROUTING_MODEL_CELLS,
                ATTACK_REACHABILITY_CONTRASTS,
                ATTACK_REACHABILITY_SUMMARY,
            )
        },
        "contract": {
            "selected_units": 200,
            "strata": EXPECTED_STRATA,
            "standardization": "fixed routing-model stratum frame shares",
            "finite_population_correction": False,
            "interval_interpretation": (
                "descriptive ordinary stratified paired bootstrap stability "
                "over selected units; not 691-frame confidence"
            ),
        },
        "audits": {
            "routing_model": routing_model_audit,
            "attack_reachability": attack_reachability_audit,
            "routing_model_max_point_error_vs_frozen": max_point_error,
            "attack_reachability_max_point_error_vs_frozen": max_attack_reachability_error,
        },
        "headlines": {
            "full_uniform_open_minus_aggregate": full_exposure,
            "full_uniform_open_minus_exact": full_exact,
            "full_edge_open_minus_aggregate": edge,
            "full_high_degree_open_minus_aggregate": high,
            "full_sibling_route": route,
            "full_sibling_destination": destination,
        },
    }
    summary_path = OUT / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary["headlines"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
