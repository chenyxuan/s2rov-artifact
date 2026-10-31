"""Unit tests for the BGPy Internet-scale resource gate."""

from pathlib import Path

import pytest

from bgpy.as_graphs import ASGraph, ASGraphInfo, CustomerProviderLink, PeerLink
from bgpy.simulation_engine import SimulationEngine
from implementation.s2rov_codec.scripts.utils.s2rov import ValidationState

from experiments.routing_model.campaign.full_graph_gate import (
    A1_OPEN_COMPETITION,
    B1_COMPETITION,
    B1_DELEGATE,
    B2_COMPETITION,
    B2_DELEGATE,
    CandidateRow,
    D1_OPEN_DELEGATE,
    PairSpec,
    build_fixed_graph,
    build_trial_plan,
    degree_deployment_sets,
    make_closed_child_policy,
    result_fingerprint,
    run_trial,
    select_pair_specs,
    check_zero_percent_equivalence,
    TrialSpec,
)


def _small_graph() -> ASGraph:
    pairs = (
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
                for p, c in pairs
            ),
            peer_links=frozenset({PeerLink(10, 20)}),
            input_clique_asns=frozenset({10, 20}),
        ),
        store_customer_cone_size=False,
    )


def _pair() -> PairSpec:
    return PairSpec(
        pair_index=1,
        source_row=2,
        root_prefix="10.0.0.0/16",
        holder_asn=100,
        leaf_prefix="10.0.1.0/24",
        delegate_asn=200,
        holder_degree=1,
        delegate_degree=1,
        degree_bin=1,
        attacker_asn=300,
        attacker_class="edge",
        attacker_degree=1,
    )


def test_fixed_graph_parser_accepts_prepared_three_column_format(tmp_path: Path) -> None:
    path = tmp_path / "as-rel.txt"
    path.write_text("10|20|0\n10|30|-1\n", encoding="utf-8")
    graph = build_fixed_graph(path)

    assert len(graph) == 3
    assert graph.as_dict[20] in graph.as_dict[10].peers
    assert graph.as_dict[30] in graph.as_dict[10].customers


def test_fixed_graph_parser_rejects_unknown_relationship(tmp_path: Path) -> None:
    path = tmp_path / "as-rel.txt"
    path.write_text("10|20|1\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported relationship"):
        build_fixed_graph(path)


def test_pair_and_attacker_selection_is_deterministic_and_stratified() -> None:
    degrees = {asn: 1 for asn in range(1, 1001)}
    for asn in range(1, 31):
        degrees[asn] = 1000 - asn
    rows = tuple(
        CandidateRow(
            source_row=1000 + i,
            root_prefix=f"10.{i}.0.0/16",
            holder_asn=31 + i,
            leaf_prefix=f"10.{i}.1.0/24",
            delegate_asn=61 + i,
        )
        for i in range(20)
    )

    first = select_pair_specs(rows, degrees, seed=17)
    second = select_pair_specs(rows, degrees, seed=17)

    assert first == second
    assert len({(pair.holder_asn, pair.delegate_asn) for pair in first}) == 10
    assert {pair.attacker_class for pair in first} == {"edge", "high_degree"}
    assert len({pair.attacker_asn for pair in first}) == 10


def test_trial_plan_has_matched_baselines_and_three_stages_per_active_lane() -> None:
    pairs = tuple(_pair().__class__(**{**_pair().__dict__, "pair_index": i}) for i in range(1, 11))
    plan = build_trial_plan(pairs)

    assert len(plan) == 100
    for lane in (B1_DELEGATE, B2_DELEGATE, B1_COMPETITION, B2_COMPETITION):
        assert sum(spec.lane == lane for spec in plan) == 10
    assert {
        spec.deployment_percent
        for spec in plan
        if spec.lane == D1_OPEN_DELEGATE
    } == {0, 5, 100}


def test_exact_roa_overlay_does_not_shadow_open_scope() -> None:
    """Exercise the current profile without changing the hash-bound helper."""
    pair = _pair()
    policy = make_closed_child_policy(pair)
    assert (
        policy.validate_route(pair.leaf_prefix, pair.delegate_asn)
        == ValidationState.EXPLICIT
    )
    assert (
        policy.validate_route(pair.leaf_prefix, pair.attacker_asn)
        == ValidationState.DELEGATED
    )


def test_degree_deployment_never_adds_an_as_outside_rov(monkeypatch: pytest.MonkeyPatch) -> None:
    import experiments.routing_model.campaign.full_graph_gate as gate

    monkeypatch.setattr(gate, "ROV_COUNT", 4)
    rov = frozenset({10, 11, 20, 21})
    degrees = {10: 10, 11: 9, 20: 8, 21: 7, 999: 100}

    sets = degree_deployment_sets(rov, degrees)

    assert all(selected.issubset(rov) for selected in sets.values())
    assert sets[100] == rov
    assert 999 not in sets[100]


def test_reused_engine_zero_percent_is_exact_rov_and_partitions_complete() -> None:
    graph = _small_graph()
    engine = SimulationEngine(graph)
    pair = _pair()
    rov = frozenset({10, 11, 20, 21})

    baseline = run_trial(
        engine,
        TrialSpec(pair, B1_DELEGATE, 0),
        rov_asns=rov,
        da_asns=frozenset(),
    )
    staged_zero = run_trial(
        engine,
        TrialSpec(pair, D1_OPEN_DELEGATE, 0),
        rov_asns=rov,
        da_asns=frozenset(),
    )
    competition_baseline = run_trial(
        engine,
        TrialSpec(pair, B1_COMPETITION, 0),
        rov_asns=rov,
        da_asns=frozenset(),
    )
    competition_zero = run_trial(
        engine,
        TrialSpec(pair, A1_OPEN_COMPETITION, 0),
        rov_asns=rov,
        da_asns=frozenset(),
    )
    mixed = run_trial(
        engine,
        TrialSpec(pair, A1_OPEN_COMPETITION, 100),
        rov_asns=rov,
        da_asns=rov,
    )

    assert result_fingerprint(baseline) == result_fingerprint(staged_zero)
    assert result_fingerprint(competition_baseline) == result_fingerprint(
        competition_zero
    )
    assert baseline["policy_assignment_counts"] == {"bgp": 7, "rov": 4, "s2rov": 0}
    assert mixed["policy_assignment_counts"] == {"bgp": 7, "rov": 0, "s2rov": 4}
    for row in (
        baseline,
        staged_zero,
        competition_baseline,
        competition_zero,
        mixed,
    ):
        denominator = row["outcomes"]["denominator_asns"]
        assert sum(row["outcomes"]["child"]["counts"].values()) == denominator
        assert sum(row["outcomes"]["destination"]["counts"].values()) == denominator

    rows = []
    for pair_index in range(1, 11):
        for row in (baseline, staged_zero, competition_baseline, competition_zero):
            rows.append({**row, "pair_index": pair_index})
    assert check_zero_percent_equivalence(rows)
