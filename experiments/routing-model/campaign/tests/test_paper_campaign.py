"""Unit tests for the paper-scale S2-ROV campaign contract."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from bgpy.as_graphs import ASGraph, ASGraphInfo, CustomerProviderLink, PeerLink
from bgpy.simulation_engine import SimulationEngine

import phase7_simulation.campaign.paper_campaign as paper
from phase7_simulation.campaign.full_graph_gate import B1_DELEGATE, CandidateRow
from phase7_simulation.campaign.paper_campaign import (
    A1_OPEN_COMPETITION,
    ATTACKER_CLASSES,
    B1_COMPETITION,
    CampaignTrial,
    DeploymentOrder,
    D1_OPEN_DELEGATE,
    SampledUnit,
    attach_attackers,
    build_deployment_orders,
    build_trial_plan,
    record_incremental_zero_equivalence,
    run_paper_trial,
    runtime_environment_fingerprint,
    sample_holder_units,
    scan_failures_jsonl,
    scan_results_jsonl,
    verify_runtime_environment,
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
                CustomerProviderLink(provider_asn=p, customer_asn=c)
                for p, c in links
            ),
            peer_links=frozenset({PeerLink(10, 20)}),
            input_clique_asns=frozenset({10, 20}),
        ),
        store_customer_cone_size=False,
    )


def _unit(index: int = 1) -> SampledUnit:
    return SampledUnit(
        unit_id=f"unit{index:04d}",
        pair_index=index,
        source_row=index + 1,
        root_prefix=f"10.{index}.0.0/16",
        holder_asn=100 + index,
        leaf_prefix=f"10.{index}.1.0/24",
        delegate_asn=200 + index,
        holder_degree=1,
        delegate_degree=1,
        holder_stratum="S1",
        holder_stratum_degree_range="1-2",
        N_h=161,
        n_h=50,
        stratum_population_N_h=161,
        stratum_sample_n_h=50,
        design_weight=161 / 50,
        cluster_id=f"holder:{100 + index}",
        holder_selection_sha256="h" * 64,
        root_selection_sha256="r" * 64,
        delegate_selection_sha256="d" * 64,
        leaf_selection_sha256="l" * 64,
        uniform_attacker_asn=300 + index,
        uniform_attacker_degree=2,
        edge_attacker_asn=400 + index,
        edge_attacker_degree=1,
        high_degree_attacker_asn=500 + index,
        high_degree_attacker_degree=500,
    )


def _valid_checkpoint_fixture() -> tuple[dict, dict]:
    graph = _small_graph()
    engine = SimulationEngine(graph)
    unit = SampledUnit(
        **{
            **_unit().__dict__,
            "root_prefix": "10.0.0.0/16",
            "leaf_prefix": "10.0.1.0/24",
            "holder_asn": 100,
            "delegate_asn": 200,
            "uniform_attacker_asn": 300,
        }
    )
    trial = CampaignTrial(
        scenario_id=(
            "unit0001__B1_delegate_only__atk-none__reference__"
            "seed-na__pct-000"
        ),
        unit_id=unit.unit_id,
        pair_index=unit.pair_index,
        lane=B1_DELEGATE,
        announcement_set="delegate_only",
        policy_reference="aggregate_only_reference",
        attacker_class=None,
        deployment_strategy="reference",
        deployment_seed=None,
        deployment_percent_target=0,
        order_id=None,
    )
    rov = frozenset({10, 11, 20, 21})
    digest = "b" * 64
    row = run_paper_trial(
        engine,
        trial,
        unit,
        rov_asns=rov,
        orders={},
        manifest_digest=digest,
        worker_metadata={
            "worker_pid": 1,
            "attempt": 1,
            "prior_failure_count": 0,
            "retry_authorized": False,
        },
    )
    manifest = {
        "manifest_sha256": digest,
        "trial_plan": [json.loads(json.dumps(asdict(trial)))],
        "selected_units": [json.loads(json.dumps(asdict(unit)))],
        "deployment_orders": [],
        "topology": {
            "asns": len(graph),
            "fixed_rov_asns": sorted(rov),
            "fixed_rov_count": len(rov),
        },
    }
    return manifest, row


def _synthetic_sampling_inputs() -> tuple[list[CandidateRow], dict[int, int]]:
    rows: list[CandidateRow] = []
    degrees: dict[int, int] = {}
    stratum_degrees = (1, 3, 19, 102)
    holder_index = 0
    for degree in stratum_degrees:
        for _ in range(4):
            holder_index += 1
            holder = 1000 + holder_index
            delegate = 2000 + holder_index
            degrees[holder] = degree
            degrees[delegate] = 1
            for root_variant in range(2):
                octet = holder_index * 2 + root_variant
                rows.append(
                    CandidateRow(
                        source_row=holder_index * 10 + root_variant,
                        root_prefix=f"10.{octet}.0.0/16",
                        holder_asn=holder,
                        leaf_prefix=f"10.{octet}.1.0/24",
                        delegate_asn=delegate,
                    )
                )
    return rows, degrees


def test_holder_sampling_is_four_strata_unique_and_deterministic() -> None:
    rows, degrees = _synthetic_sampling_inputs()

    first, metadata = sample_holder_units(
        rows,
        degrees,
        seed=17,
        n_per_stratum=2,
        expected_populations=None,
    )
    second, _ = sample_holder_units(
        rows,
        degrees,
        seed=17,
        n_per_stratum=2,
        expected_populations=None,
    )

    assert first == second
    assert len(first) == 8
    assert {unit.holder_stratum for unit in first} == {"S1", "S2", "S3", "S4"}
    assert len({unit.holder_asn for unit in first}) == 8
    assert len({unit.root_prefix for unit in first}) == 8
    assert all(unit.N_h == 4 and unit.n_h == 2 for unit in first)
    assert metadata["hierarchy"] == "holder -> root -> distinct delegate -> leaf"


def test_three_attacker_classes_are_paired_distinct_and_without_replacement() -> None:
    rows, endpoint_degrees = _synthetic_sampling_inputs()
    units, _ = sample_holder_units(
        rows,
        endpoint_degrees,
        n_per_stratum=2,
        expected_populations=None,
    )
    degrees = {asn: 1 for asn in range(1, 5001)}
    for asn in range(1, 101):
        degrees[asn] = 10_000 - asn
    degrees.update(endpoint_degrees)

    attached, provenance = attach_attackers(units, degrees, seed=23)

    for attacker_class in ATTACKER_CLASSES:
        values = [unit.attacker(attacker_class)[0] for unit in attached]
        assert len(values) == len(set(values)) == len(attached)
    for unit in attached:
        assert len({unit.attacker(name)[0] for name in ATTACKER_CLASSES}) == 3
    assert provenance["without_replacement_within_class"] is True


def test_deployment_orders_and_frozen_plan_have_expected_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(paper, "ROV_COUNT", 8)
    rov = frozenset(range(1, 9))
    degrees = {asn: 20 - asn for asn in rov}
    cones = {asn: asn * 2 for asn in rov}
    orders = build_deployment_orders(rov, degrees, cones)

    assert [order.order_id for order in orders] == [
        "degree",
        "customer_cone",
        "random_01",
        "random_02",
        "random_03",
        "random_04",
        "random_05",
    ]
    assert all(set(order.asns) == set(rov) for order in orders)

    plan = build_trial_plan((_unit(1), _unit(2)), orders)
    assert len(plan) == 368
    assert len({trial.scenario_id for trial in plan}) == 368
    assert sum(trial.deployment_strategy == "reference" for trial in plan) == 16
    assert sum(trial.deployment_strategy == "shared" for trial in plan) == 16
    assert all(
        trial.attacker_class is None
        for trial in plan
        if trial.announcement_set == "delegate_only"
    )
    assert {
        trial.deployment_seed
        for trial in plan
        if trial.deployment_strategy == "random"
    } == {1, 2, 3, 4, 5}


def test_grouped_outcomes_partition_all_rov_and_non_rov() -> None:
    graph = _small_graph()
    engine = SimulationEngine(graph)
    unit = SampledUnit(
        **{
            **_unit().__dict__,
            "root_prefix": "10.0.0.0/16",
            "leaf_prefix": "10.0.1.0/24",
            "holder_asn": 100,
            "delegate_asn": 200,
            "uniform_attacker_asn": 300,
        }
    )
    trial = CampaignTrial(
        scenario_id="unit0001__B1_delegate_only__atk-none__reference__seed-na__pct-000",
        unit_id=unit.unit_id,
        pair_index=unit.pair_index,
        lane=B1_DELEGATE,
        announcement_set="delegate_only",
        policy_reference="aggregate_only_reference",
        attacker_class=None,
        deployment_strategy="reference",
        deployment_seed=None,
        deployment_percent_target=0,
        order_id=None,
    )
    rov = frozenset({10, 11, 20, 21})

    row = run_paper_trial(
        engine,
        trial,
        unit,
        rov_asns=rov,
        orders={},
        manifest_digest="a" * 64,
        worker_metadata={"worker_pid": 1},
    )

    assert row["attacker_class"] is None
    assert row["attacker_asn"] is None
    assert row["outcomes"]["all"]["denominator_asns"] == 11
    assert row["outcomes"]["rov"]["denominator_asns"] == 4
    assert row["outcomes"]["non_rov"]["denominator_asns"] == 7
    assert all(row["partition_checks"].values())
    for partition in ("child", "destination"):
        for outcome, all_count in row["outcomes"]["all"][partition][
            "counts"
        ].items():
            assert all_count == (
                row["outcomes"]["rov"][partition]["counts"][outcome]
                + row["outcomes"]["non_rov"][partition]["counts"][outcome]
            )


def test_checkpoint_resume_rejects_duplicates_and_repairs_only_tail(
    tmp_path: Path,
) -> None:
    manifest, row = _valid_checkpoint_fixture()
    scenario_id = row["scenario_id"]
    path = tmp_path / "raw.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    completed, repair = scan_results_jsonl(path, manifest)
    assert completed == frozenset({scenario_id})
    assert repair is None

    path.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate scenario"):
        scan_results_jsonl(path, manifest)

    path.write_text(json.dumps(row) + "\n" + '{"broken":', encoding="utf-8")
    completed, repair = scan_results_jsonl(
        path, manifest, repair_truncated_tail=True
    )
    assert completed == frozenset({scenario_id})
    assert repair is not None
    assert path.read_text(encoding="utf-8") == json.dumps(row) + "\n"


def test_resume_revalidates_deployment_and_policy_metadata(tmp_path: Path) -> None:
    manifest, row = _valid_checkpoint_fixture()
    path = tmp_path / "raw.jsonl"

    bad_set = {**row, "deployment_set_sha256": "0" * 64}
    path.write_text(json.dumps(bad_set) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="deployment_set_sha256"):
        scan_results_jsonl(path, manifest)

    bad_assignment = {
        **row,
        "policy_assignment_counts": {
            **row["policy_assignment_counts"],
            "rov": row["policy_assignment_counts"]["rov"] - 1,
        },
    }
    path.write_text(json.dumps(bad_assignment) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="policy assignments"):
        scan_results_jsonl(path, manifest)


def test_failure_history_requires_sequential_explicit_attempts(tmp_path: Path) -> None:
    manifest, row = _valid_checkpoint_fixture()
    failure = {
        "schema_version": 1,
        "status": "failed",
        "scenario_id": row["scenario_id"],
        "manifest_sha256": manifest["manifest_sha256"],
        "attempt": 1,
        "prior_failure_count": 0,
        "retry_authorized": False,
        "exception": {"type": "RuntimeError", "message": "boom"},
    }
    path = tmp_path / "failures.jsonl"
    path.write_text(json.dumps(failure) + "\n", encoding="utf-8")
    history = scan_failures_jsonl(path, manifest)
    assert len(history[row["scenario_id"]]) == 1

    bad = {**failure, "attempt": 2, "prior_failure_count": 1, "retry_authorized": True}
    path.write_text(json.dumps(bad) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not sequential"):
        scan_failures_jsonl(path, manifest)


def test_unresolved_failure_is_fail_closed_without_explicit_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = {
        "manifest_sha256": "b" * 64,
        "trial_plan": [{"scenario_id": "scenario-1"}],
    }
    failure = {
        "attempt": 1,
        "prior_failure_count": 0,
        "retry_authorized": False,
    }
    monkeypatch.setattr(paper, "load_manifest", lambda *_args, **_kwargs: manifest)
    monkeypatch.setattr(paper, "verify_artifact_hashes", lambda _manifest: None)
    monkeypatch.setattr(paper, "verify_runtime_environment", lambda _manifest: None)
    monkeypatch.setattr(
        paper,
        "scan_results_jsonl",
        lambda *_args, **_kwargs: (frozenset(), None),
    )
    monkeypatch.setattr(
        paper,
        "scan_failures_jsonl",
        lambda *_args, **_kwargs: {"scenario-1": (failure,)},
    )
    kwargs = {
        "workers": 1,
        "max_new_trials": 1,
        "dry_run": True,
        "repair_truncated_tail": False,
        "fsync_every": 1,
        "checkpoint_every": 1,
    }
    with pytest.raises(ValueError, match="--retry-failures"):
        paper.run_campaign(tmp_path, retry_failures=False, **kwargs)
    status = paper.run_campaign(tmp_path, retry_failures=True, **kwargs)
    assert status["retry_failures_authorized"] is True
    assert status["new_trials_selected"] == 1


def test_incremental_zero_equivalence_fails_on_first_complete_pair() -> None:
    _manifest, baseline = _valid_checkpoint_fixture()
    staged = {
        **baseline,
        "scenario_id": "unit0001__D1_zero",
        "lane": D1_OPEN_DELEGATE,
        "policy_reference": "open_staged",
        "deployment_strategy": "shared",
    }
    state: dict = {}
    record_incremental_zero_equivalence(staged, state)
    record_incremental_zero_equivalence(baseline, state)

    bad_staged = json.loads(json.dumps(staged))
    counts = bad_staged["outcomes"]["all"]["child"]["counts"]
    counts["delegate"] -= 1
    counts["absent"] += 1
    bad_state: dict = {}
    record_incremental_zero_equivalence(baseline, bad_state)
    with pytest.raises(ValueError, match="zero-upgrade outcome mismatch"):
        record_incremental_zero_equivalence(bad_staged, bad_state)


def test_runtime_fingerprint_is_machine_independent_and_fail_closed() -> None:
    if not paper.VENDOR_PATH.is_dir():
        pytest.skip("requires the pinned phase7_simulation/vendor/bgpy checkout")

    runtime = runtime_environment_fingerprint()
    assert runtime["bgpy"]["import_source_kind"] in {
        "vendor_checkout",
        "installed_distribution",
    }
    assert not runtime["bgpy"]["import_source_label"].startswith("/")
    assert not runtime["dependencies"]["lock_path"].startswith("/")
    verify_runtime_environment({"runtime_environment": runtime})

    tampered = json.loads(json.dumps(runtime))
    tampered["bgpy"]["imported_package_tree_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="differ from manifest"):
        verify_runtime_environment({"runtime_environment": tampered})


def test_competition_matrix_crosses_all_three_attacker_classes() -> None:
    orders = tuple(
        DeploymentOrder(
            order_id=order_id,
            strategy=strategy,
            seed=seed,
            asns=tuple(range(1, 590)),
            order_sha256=str(index) * 64,
        )
        for index, (order_id, strategy, seed) in enumerate(
            (
                ("degree", "degree", None),
                ("customer_cone", "customer_cone", None),
                ("random_01", "random", 1),
                ("random_02", "random", 2),
                ("random_03", "random", 3),
                ("random_04", "random", 4),
                ("random_05", "random", 5),
            ),
            start=1,
        )
    )
    plan = build_trial_plan((_unit(),), orders)

    for lane in (B1_COMPETITION, A1_OPEN_COMPETITION):
        assert {
            trial.attacker_class for trial in plan if trial.lane == lane
        } == set(ATTACKER_CLASSES)
    assert any(trial.lane == D1_OPEN_DELEGATE for trial in plan)
