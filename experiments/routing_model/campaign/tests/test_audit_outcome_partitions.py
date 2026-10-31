"""Synthetic tests for the independent routing-model partition audit."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from experiments.routing_model.campaign.audit_outcome_partitions import (
    CELL_SELECTORS,
    DESTINATIONS,
    PartitionAuditError,
    audit,
    canonical_manifest_sha256,
    write_json,
)


def _ids_sha256(values: list[str]) -> str:
    return hashlib.sha256(
        "".join(f"{value}\n" for value in sorted(values)).encode()
    ).hexdigest()


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    units = [
        {
            "unit_id": "u1",
            "holder_asn": 101,
            "holder_stratum": "S1",
            "N_h": 1,
            "n_h": 1,
            "design_weight": 1,
        },
        {
            "unit_id": "u2",
            "holder_asn": 202,
            "holder_stratum": "S2",
            "N_h": 3,
            "n_h": 1,
            "design_weight": 3,
        },
    ]
    plan: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    attacker_counts = {
        "b2_exact_delegate_only": (0, 0),
        "d1_open_delegate_only_100": (0, 0),
        "b1_uniform_competition": (1, 3),
        "b2_exact_uniform_competition": (0, 2),
        "a1_open_uniform_competition_100": (5, 7),
    }
    for cell, selector in CELL_SELECTORS.items():
        for index, unit in enumerate(units):
            scenario_id = f"{unit['unit_id']}--{cell}"
            item = {
                "scenario_id": scenario_id,
                "unit_id": unit["unit_id"],
                **selector,
                "deployment_seed": None,
                "order_id": None,
            }
            plan.append(item)
            attacker = attacker_counts[cell][index]
            counts = {
                "delegate": 10 - attacker,
                "attacker": attacker,
                "holder_fallback": 0,
                "disconnected": 0,
                "loop": 0,
            }
            rows.append(
                {
                    **item,
                    "attempt": 1,
                    "status": "success",
                    "holder_asn": unit["holder_asn"],
                    "design_weight": unit["design_weight"],
                    "outcomes": {
                        "all": {
                            "denominator_asns": 10,
                            "destination": {
                                "counts": counts,
                                "fractions": {
                                    outcome: counts[outcome] / 10
                                    for outcome in DESTINATIONS
                                },
                            },
                        }
                    },
                }
            )
    ids = [item["scenario_id"] for item in plan]
    manifest: dict[str, Any] = {
        "selected_units": units,
        "trial_plan": plan,
        "expected_scenario_ids": {
            "count": len(ids),
            "sorted_newline_sha256": _ids_sha256(ids),
        },
    }
    manifest["manifest_sha256"] = canonical_manifest_sha256(manifest)
    for row in rows:
        row["manifest_sha256"] = manifest["manifest_sha256"]

    manifest_path = tmp_path / "manifest.json"
    results_path = tmp_path / "raw.jsonl"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    results_path.write_text(
        "".join(json.dumps(row) + "\n" for row in reversed(rows)), encoding="utf-8"
    )
    return manifest_path, results_path


def test_audit_recomputes_weighted_partitions_and_is_deterministic(
    tmp_path: Path,
) -> None:
    manifest, results = _fixture(tmp_path)
    payload = audit(
        manifest,
        results,
        expected_holders=2,
        expected_weight_sum=Decimal(4),
    )

    assert payload["validation"]["raw_rows"] == 10
    assert payload["validation"]["selected_cell_rows"] == 10
    assert payload["cells"]["a1_open_uniform_competition_100"]["partition"][
        "attacker"
    ] == pytest.approx(0.65)
    assert payload["contrasts_percentage_points"] == {
        "a1_100_minus_b1_uniform_attacker_exposure": pytest.approx(40.0),
        "a1_100_minus_b2_exact_uniform_attacker": pytest.approx(50.0),
    }

    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    write_json(first, payload)
    write_json(second, payload)
    assert first.read_bytes() == second.read_bytes()


def test_audit_fails_closed_on_nonpartition_row(tmp_path: Path) -> None:
    manifest, results = _fixture(tmp_path)
    rows = [json.loads(line) for line in results.read_text().splitlines()]
    broken = deepcopy(rows)
    broken[0]["outcomes"]["all"]["destination"]["counts"]["loop"] = 1
    results.write_text(
        "".join(json.dumps(row) + "\n" for row in broken), encoding="utf-8"
    )

    with pytest.raises(PartitionAuditError, match="do not sum"):
        audit(
            manifest,
            results,
            expected_holders=2,
            expected_weight_sum=Decimal(4),
        )
