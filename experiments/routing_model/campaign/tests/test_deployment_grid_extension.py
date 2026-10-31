"""Contract tests for the independent routing-model grid extension."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest
from bgpy.as_graphs import ASGraph, ASGraphInfo, CustomerProviderLink, PeerLink
from bgpy.simulation_engine import SimulationEngine

from experiments.routing_model.campaign import deployment_grid_extension as extension
from experiments.routing_model.campaign.full_graph_gate import (
    A1_OPEN_COMPETITION,
    D1_OPEN_DELEGATE,
)
from experiments.routing_model.campaign.paper_campaign import (
    CampaignTrial,
    DeploymentOrder,
    SampledUnit,
    _order_hash,
)


@pytest.fixture(autouse=True)
def _freeze_runtime_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep manifest unit tests independent of the optional vendor checkout."""

    source = json.loads(extension.SOURCE_MANIFEST_PATH.read_text(encoding="utf-8"))
    runtime = source["runtime_environment"]
    monkeypatch.setattr(
        extension.paper,
        "runtime_environment_fingerprint",
        lambda: json.loads(json.dumps(runtime)),
    )


def _small_graph() -> ASGraph:
    links = (
        (10, 100),
        (10, 11),
        (11, 200),
        (20, 21),
        (21, 300),
        (10, 1),
        (20, 2),
        (11, 3),
        (21, 4),
    )
    return ASGraph(
        ASGraphInfo(
            customer_provider_links=frozenset(
                CustomerProviderLink(provider_asn=provider, customer_asn=customer)
                for provider, customer in links
            ),
            peer_links=frozenset({PeerLink(10, 20)}),
            input_clique_asns=frozenset({10, 20}),
        ),
        store_customer_cone_size=False,
    )


def _unit() -> SampledUnit:
    return SampledUnit(
        unit_id="unit0001",
        pair_index=1,
        source_row=2,
        root_prefix="10.0.0.0/16",
        holder_asn=100,
        leaf_prefix="10.0.1.0/24",
        delegate_asn=200,
        holder_degree=1,
        delegate_degree=1,
        holder_stratum="S1",
        holder_stratum_degree_range="1-2",
        N_h=161,
        n_h=50,
        stratum_population_N_h=161,
        stratum_sample_n_h=50,
        design_weight=161 / 50,
        cluster_id="holder:100",
        holder_selection_sha256="h" * 64,
        root_selection_sha256="r" * 64,
        delegate_selection_sha256="d" * 64,
        leaf_selection_sha256="l" * 64,
        uniform_attacker_asn=300,
        uniform_attacker_degree=2,
        edge_attacker_asn=4,
        edge_attacker_degree=1,
        high_degree_attacker_asn=10,
        high_degree_attacker_degree=4,
    )


def test_formal_manifest_is_exact_additive_14000_trial_plan() -> None:
    manifest = extension.build_manifest_document("formal")

    assert len(manifest["selected_units"]) == 200
    assert [order["order_id"] for order in manifest["deployment_orders"]] == [
        "random_01",
        "random_02",
        "random_03",
        "random_04",
        "random_05",
    ]
    assert manifest["design"]["deployment_percentages"] == [
        20,
        30,
        40,
        60,
        70,
        80,
        90,
    ]
    assert manifest["design"]["deployment_counts"] == {
        "20": 117,
        "30": 176,
        "40": 235,
        "60": 353,
        "70": 412,
        "80": 471,
        "90": 530,
    }
    assert len(manifest["trial_plan"]) == 14_000
    assert manifest["expected_scenario_ids"]["count"] == 14_000
    assert {trial["lane"] for trial in manifest["trial_plan"]} == {
        D1_OPEN_DELEGATE,
        A1_OPEN_COMPETITION,
    }
    assert {
        trial["attacker_class"]
        for trial in manifest["trial_plan"]
        if trial["lane"] == A1_OPEN_COMPETITION
    } == {"uniform"}
    assert manifest["source_campaign"]["source_trials_reused"] == 0
    assert manifest["source_campaign"]["source_raw_results_modified"] is False


def test_smoke_manifest_is_separate_four_trial_contract() -> None:
    manifest = extension.build_manifest_document("smoke")

    assert len(manifest["selected_units"]) == 1
    assert len(manifest["deployment_orders"]) == 1
    assert manifest["design"]["deployment_percentages"] == [20, 90]
    assert len(manifest["trial_plan"]) == 4
    assert all(
        trial["order_id"] == "random_01" for trial in manifest["trial_plan"]
    )


def test_manifest_and_output_boundaries_fail_closed(tmp_path: Path) -> None:
    manifest = extension.build_manifest_document("smoke")
    tampered = json.loads(json.dumps(manifest))
    tampered["trial_plan"][0]["deployment_percent_target"] = 30
    with pytest.raises(ValueError, match="manifest SHA256"):
        extension.validate_manifest(tampered)

    with pytest.raises(ValueError, match="paper_campaign directory"):
        extension.plan_campaign(extension.SOURCE_MANIFEST_PATH.parent, mode="smoke")

    output = tmp_path / "smoke-plan"
    planned = extension.plan_campaign(output, mode="smoke")
    checkpoint = json.loads((output / "checkpoint.json").read_text())
    assert planned["manifest_sha256"] == extension.load_manifest(
        output / "manifest.json"
    )["manifest_sha256"]
    assert checkpoint["status"] == "planned"
    assert checkpoint["planned_trials"] == 4
    assert not (output / "raw_scenarios.jsonl").exists()


def test_new_percentage_trial_reuses_propagation_and_row_schema() -> None:
    graph = _small_graph()
    engine = SimulationEngine(graph)
    unit = _unit()
    rov = frozenset({10, 11, 20, 21})
    order_asns = (10, 11, 20, 21)
    order = DeploymentOrder(
        order_id="random_01",
        strategy="random",
        seed=1,
        asns=order_asns,
        order_sha256=_order_hash(order_asns),
    )
    trial = extension.build_trial_plan((unit,), (order,), (20,))[0]
    digest = "b" * 64
    row = extension.run_extension_trial(
        engine,
        trial,
        unit,
        rov_asns=rov,
        orders={order.order_id: order},
        manifest_digest=digest,
        worker_metadata={
            "worker_pid": 1,
            "worker_trial_sequence": 1,
            "worker_graph_build_seconds": 0.1,
            "worker_graph_build_peak_rss_bytes": 1,
            "attempt": 1,
            "prior_failure_count": 0,
            "retry_authorized": False,
        },
    )
    manifest = {
        "manifest_sha256": digest,
        "design": {"deployment_percentages": [20]},
        "trial_plan": [json.loads(json.dumps(asdict(trial)))],
        "selected_units": [json.loads(json.dumps(asdict(unit)))],
        "deployment_orders": [
            {
                **json.loads(json.dumps(asdict(order))),
                "deployment_counts": {"20": 0},
            }
        ],
        "topology": {
            "asns": len(graph),
            "fixed_rov_asns": sorted(rov),
            "fixed_rov_count": len(rov),
        },
    }
    extension.validate_success_result_row(row, manifest)
    assert row["lane"] == D1_OPEN_DELEGATE
    assert row["deployment_percent_target"] == 20
    assert row["deployment_count"] == 0
    assert set(row["outcomes"]) == {"all", "rov", "non_rov"}

    bad = {**row, "deployment_set_sha256": "0" * 64}
    with pytest.raises(ValueError, match="deployment_set_sha256"):
        extension.validate_success_result_row(bad, manifest)


def test_trial_plan_never_includes_old_grid_or_nonrandom_orders() -> None:
    unit = _unit()
    order_asns = tuple(range(1, 590))
    order = DeploymentOrder(
        "random_01", "random", 1, order_asns, _order_hash(order_asns)
    )
    trials = extension.build_trial_plan((unit,), (order,), (20, 90))
    assert len(trials) == 4
    assert {trial.deployment_percent_target for trial in trials} == {20, 90}

    with pytest.raises(ValueError, match="non-extension percentage"):
        extension.build_trial_plan((unit,), (order,), (25,))
    nonrandom = DeploymentOrder(
        "degree", "degree", None, order_asns, _order_hash(order_asns)
    )
    with pytest.raises(ValueError, match="only frozen random orders"):
        extension.build_trial_plan((unit,), (nonrandom,), (20,))
