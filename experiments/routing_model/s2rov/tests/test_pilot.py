"""Regression tests for the project-owned BGPy S2-ROV pilot."""

from ipaddress import ip_network
from types import SimpleNamespace

from roa_checker import ROA

from bgpy.shared.enums import Relationships
from bgpy.simulation_engine import Announcement, Policy

from implementation.s2rov_codec.scripts.utils.s2rov import ValidationState

from experiments.routing_model.s2rov.policy import S2ROV
from experiments.routing_model.s2rov.pilot import (
    AGGREGATE,
    ANNOUNCEMENT_KEYS,
    ATTACKER_ASN,
    CHILD,
    DELEGATE_ASN,
    FULL_DA_ASNS,
    HOLDER_ASN,
    MIXED_DA_ASNS,
    ROV_ASNS,
    UNRELATED,
    make_open_policy,
    make_policy_with_exact_overlay,
    run_trial,
)


def _stable_outcomes(result: dict[str, object]) -> tuple[object, object, object]:
    return (
        result["policy_assignments"],
        result["control_plane"],
        result["destination_outcomes"],
    )


def test_s2rov_codec_oracle_exercises_all_four_states() -> None:
    policy = make_open_policy()

    assert policy.validate_route(AGGREGATE, HOLDER_ASN) == ValidationState.EXPLICIT
    assert policy.validate_route(CHILD, DELEGATE_ASN) == ValidationState.DELEGATED
    assert policy.validate_route(AGGREGATE, ATTACKER_ASN) == ValidationState.INVALID
    assert policy.validate_route(UNRELATED, ATTACKER_ASN) == ValidationState.NOT_FOUND


def test_s2rov_policy_composes_four_states_with_native_rov() -> None:
    """Exercise the project adapter, including NotFound-to-ROV fallback."""

    s2rov = make_open_policy()
    S2ROV.configure(s2rov)
    receiver = S2ROV(as_=SimpleNamespace(asn=400))
    unrelated_roa = ROA(ip_network(UNRELATED), 999, max_length=24)
    Policy.roa_checker.clear()
    Policy.roa_checker.insert(unrelated_roa.prefix, unrelated_roa)

    def ann(prefix: str, origin: int) -> Announcement:
        return Announcement(prefix=prefix, as_path=(origin,))

    try:
        # Explicit and Delegated bypass the aggregate-only conventional VRP.
        assert receiver._valid_ann(
            ann(AGGREGATE, HOLDER_ASN), Relationships.CUSTOMERS
        )
        assert receiver._valid_ann(
            ann(CHILD, DELEGATE_ASN), Relationships.CUSTOMERS
        )
        # Invalid is rejected by the DA object itself.
        assert not receiver._valid_ann(
            ann(AGGREGATE, ATTACKER_ASN), Relationships.CUSTOMERS
        )
        # The route is DA-NotFound, then rejected by the unrelated native ROA.
        assert s2rov.validate_route(UNRELATED, ATTACKER_ASN) == ValidationState.NOT_FOUND
        assert not receiver._valid_ann(
            ann(UNRELATED, ATTACKER_ASN), Relationships.CUSTOMERS
        )
    finally:
        Policy.roa_checker.clear()


def test_zero_percent_da_is_route_outcome_equivalent_to_rov() -> None:
    staged_zero = run_trial(
        da_aware_asns=frozenset(),
        include_attacker=True,
        enable_s2rov=True,
    )
    conventional = run_trial(
        da_aware_asns=frozenset(),
        include_attacker=True,
        enable_s2rov=False,
    )

    assert _stable_outcomes(staged_zero) == _stable_outcomes(conventional)
    assignments = staged_zero["policy_assignments"]
    assert isinstance(assignments, dict)
    assert all(assignments[str(asn)] == "ROV" for asn in ROV_ASNS)


def test_open_scope_treats_delegate_and_eligible_attacker_identically() -> None:
    policy = make_open_policy()

    assert policy.validate_route(CHILD, DELEGATE_ASN) == ValidationState.DELEGATED
    assert policy.validate_route(CHILD, ATTACKER_ASN) == ValidationState.DELEGATED


def test_exact_roa_overlay_does_not_shadow_open_scope() -> None:
    open_policy = make_open_policy()
    overlay_policy = make_policy_with_exact_overlay()

    assert open_policy.validate_route(AGGREGATE, ATTACKER_ASN) == ValidationState.INVALID
    assert overlay_policy.validate_route(CHILD, DELEGATE_ASN) == ValidationState.EXPLICIT
    assert overlay_policy.validate_route(CHILD, ATTACKER_ASN) == ValidationState.DELEGATED


def test_reversing_announcement_input_order_does_not_change_results() -> None:
    forward = run_trial(
        da_aware_asns=FULL_DA_ASNS,
        include_attacker=True,
        announcement_order=ANNOUNCEMENT_KEYS,
    )
    reverse = run_trial(
        da_aware_asns=FULL_DA_ASNS,
        include_attacker=True,
        announcement_order=tuple(reversed(ANNOUNCEMENT_KEYS)),
    )

    assert _stable_outcomes(forward) == _stable_outcomes(reverse)


def test_mixed_deployment_has_complete_nontrivial_partitions() -> None:
    result = run_trial(
        da_aware_asns=MIXED_DA_ASNS,
        include_attacker=True,
    )
    denominator = result["num_ases"]
    control = result["control_plane"]
    destinations = result["destination_outcomes"]
    assignments = result["policy_assignments"]
    assert isinstance(control, dict)
    assert isinstance(destinations, dict)
    assert isinstance(assignments, dict)

    control_counts = control["counts"]
    destination_counts = destinations["counts"]
    assert isinstance(control_counts, dict)
    assert isinstance(destination_counts, dict)
    assert sum(control_counts.values()) == denominator
    assert sum(destination_counts.values()) == denominator
    assert control_counts["child_selected_delegate"] > 0
    assert control_counts["child_selected_attacker"] > 0
    assert control_counts["child_absent"] > 0
    assert destination_counts["holder_fallback"] > 0
    assert all(assignments[str(asn)] == "S2-ROV routing-model" for asn in MIXED_DA_ASNS)
    assert all(assignments[str(asn)] == "ROV" for asn in ROV_ASNS - MIXED_DA_ASNS)
