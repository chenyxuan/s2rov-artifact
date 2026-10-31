"""Regression tests for the independent IPv6 sensitivity campaign."""

from __future__ import annotations

from collections import Counter
from ipaddress import IPv6Network, ip_network

from bgpy.simulation_engine import SimulationEngine

from phase7_simulation.campaign.full_graph_gate import (
    A1_OPEN_COMPETITION,
    B1_COMPETITION,
    B1_DELEGATE,
    B2_COMPETITION,
    B2_DELEGATE,
    D1_OPEN_DELEGATE,
    PairSpec,
    run_trial,
)
from phase7_simulation.campaign.ipv6_sensitivity import (
    DEPLOYMENT_PERCENTAGES,
    EXPECTED_TOPOLOGY_ROWS,
    EXPECTED_TRIALS,
    EXPECTED_UNIQUE_PAIRS,
    EXPECTED_UNIQUE_ROOTS,
    ExecutionSpec,
    IPv6Unit,
    attach_uniform_competitors,
    build_manifest_document,
    build_trial_plan,
    collapse_candidate_pairs,
    load_ipv6_candidates,
    load_manifest,
    load_topology_degrees,
    plan_campaign,
)
from phase7_simulation.darov.pilot import ROV_ASNS, build_pilot_graph


def _planned_units() -> tuple[tuple[IPv6Unit, ...], dict[str, object]]:
    degrees, _ = load_topology_degrees()
    candidates, audit = load_ipv6_candidates(set(degrees))
    units = collapse_candidate_pairs(candidates, degrees)
    units, _ = attach_uniform_competitors(units, degrees)
    return units, audit


def test_ipv6_filter_funnel_and_pair_collapse_are_exact() -> None:
    units, audit = _planned_units()

    assert audit["ipv6_rows"] == 83
    assert audit["retained_rows"] == EXPECTED_TOPOLOGY_ROWS
    assert audit["topology_membership_categories"] == {
        "both_absent": 13,
        "both_present": 42,
        "endpoint_absent": 26,
        "holder_absent": 2,
    }
    assert len(units) == EXPECTED_UNIQUE_PAIRS
    assert len({unit.root_prefix for unit in units}) == EXPECTED_UNIQUE_ROOTS
    assert sum(len(unit.source_rows) for unit in units) == EXPECTED_TOPOLOGY_ROWS
    assert len({unit.competitor_asn for unit in units}) == len(units)

    for unit in units:
        root = ip_network(unit.root_prefix)
        endpoint = ip_network(unit.endpoint_prefix)
        assert isinstance(root, IPv6Network)
        assert isinstance(endpoint, IPv6Network)
        assert endpoint != root and endpoint.subnet_of(root)
        assert unit.selected_source_row == min(unit.source_rows)
        assert unit.competitor_asn not in {unit.holder_asn, unit.endpoint_asn}


def test_compact_plan_has_ten_trials_per_pair() -> None:
    units, _ = _planned_units()
    trials = build_trial_plan(units)

    assert len(trials) == EXPECTED_TRIALS
    assert len({trial.scenario_id for trial in trials}) == EXPECTED_TRIALS
    assert Counter(trial.lane for trial in trials) == {
        B1_DELEGATE: 21,
        B2_DELEGATE: 21,
        B1_COMPETITION: 21,
        B2_COMPETITION: 21,
        D1_OPEN_DELEGATE: 63,
        A1_OPEN_COMPETITION: 63,
    }
    for unit in units:
        unit_trials = [trial for trial in trials if trial.unit_id == unit.unit_id]
        assert len(unit_trials) == 10
        assert {
            trial.deployment_percent_target
            for trial in unit_trials
            if trial.lane in {D1_OPEN_DELEGATE, A1_OPEN_COMPETITION}
        } == set(DEPLOYMENT_PERCENTAGES)
        assert {
            trial.deployment_count
            for trial in unit_trials
            if trial.deployment_percent_target == 50
        } == {294}


def test_manifest_records_complete_selection_provenance(tmp_path) -> None:
    output_dir = tmp_path / "ipv6-plan"
    planned = plan_campaign(output_dir)
    loaded = load_manifest(output_dir)

    assert loaded["manifest_sha256"] == planned["manifest_sha256"]
    assert loaded["filter_audit"]["ipv6_rows"] == 83
    assert loaded["filter_audit"]["topology_eligible_rows_before_pair_collapse"] == 42
    assert loaded["filter_audit"]["unique_pairs_after_collapse"] == 21
    assert loaded["filter_audit"]["rows_collapsed_as_repeated_pair_prefixes"] == 21
    assert loaded["filter_audit"]["unique_roots_after_collapse"] == 8
    assert loaded["design"]["planned_trials"] == 210
    assert loaded["phase4_ipv6_interface"]["round_trip"] is True
    assert loaded["phase4_ipv6_interface"]["delegated_state"] == "Delegated"
    assert (output_dir / "selected_units.csv").is_file()


def test_ipv6_open_scope_matches_controls_on_small_bgpy_graph() -> None:
    pair = PairSpec(
        pair_index=1,
        source_row=1,
        root_prefix="2001:db8::/32",
        holder_asn=100,
        leaf_prefix="2001:db8:1::/48",
        delegate_asn=200,
        holder_degree=2,
        delegate_degree=1,
        degree_bin=0,
        attacker_asn=300,
        attacker_class="uniform_unlisted",
        attacker_degree=1,
    )
    engine = SimulationEngine(build_pilot_graph())

    def run(lane: str, percent: int, da_asns: frozenset[int]):
        return run_trial(
            engine,
            ExecutionSpec(
                pair=pair,
                lane=lane,
                deployment_percent=percent,
                deployment_strategy="test",
                scenario_id=f"ipv6-test-{lane}-{percent}",
            ),
            rov_asns=ROV_ASNS,
            da_asns=da_asns,
        )

    b1_intended = run(B1_DELEGATE, 0, frozenset())
    d0 = run(D1_OPEN_DELEGATE, 0, frozenset())
    b2_intended = run(B2_DELEGATE, 0, frozenset())
    d100 = run(D1_OPEN_DELEGATE, 100, ROV_ASNS)
    b1_competition = run(B1_COMPETITION, 0, frozenset())
    a0 = run(A1_OPEN_COMPETITION, 0, frozenset())

    assert d0["outcomes"] == b1_intended["outcomes"]
    assert d100["outcomes"] == b2_intended["outcomes"]
    assert a0["outcomes"] == b1_competition["outcomes"]
    assert d100["policy_assignment_counts"]["darov"] == len(ROV_ASNS)


def test_in_memory_manifest_is_bound_to_ipv6_inputs() -> None:
    manifest = build_manifest_document()

    assert manifest["design"]["units"] == 21
    assert manifest["design"]["planned_trials"] == 210
    assert manifest["deployment_order_length"] == 589
    assert manifest["sources"]["visibility_candidates"]["sha256"]
    assert manifest["sources"]["as_relationship_topology"]["sha256"]
    assert manifest["sources"]["phase4_oracle"]["sha256"]
