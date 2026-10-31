#!/usr/bin/env python3
"""Executable boundary check for the disjoint S²-ROV equation in Section III."""

from enum import Enum


class State(str, Enum):
    NOT_FOUND = "NotFound"
    INVALID = "Invalid"
    EXPLICIT = "Explicit"
    OPEN_SCOPE = "OpenScope"


def classify(*, in_scope: bool, length_ok: bool, listed: bool,
             open_mode: bool, proper: bool, eligible: bool) -> State:
    """Mirror the mutually exclusive predicates in the manuscript equation."""
    if not in_scope:
        return State.NOT_FOUND
    if not length_ok:
        return State.INVALID
    if listed:
        return State.EXPLICIT
    if open_mode and proper and eligible:
        return State.OPEN_SCOPE
    return State.INVALID


def main() -> None:
    cases = {
        "listed_open_descendant": (
            dict(in_scope=True, length_ok=True, listed=True,
                 open_mode=True, proper=True, eligible=True),
            State.EXPLICIT,
        ),
        "listed_beyond_maximum": (
            dict(in_scope=True, length_ok=False, listed=True,
                 open_mode=True, proper=True, eligible=True),
            State.INVALID,
        ),
        "unlisted_open_exact": (
            dict(in_scope=True, length_ok=True, listed=False,
                 open_mode=True, proper=False, eligible=True),
            State.INVALID,
        ),
        "unlisted_open_descendant": (
            dict(in_scope=True, length_ok=True, listed=False,
                 open_mode=True, proper=True, eligible=True),
            State.OPEN_SCOPE,
        ),
        "outside_policy": (
            dict(in_scope=False, length_ok=True, listed=True,
                 open_mode=True, proper=True, eligible=True),
            State.NOT_FOUND,
        ),
    }
    for name, (inputs, expected) in cases.items():
        actual = classify(**inputs)
        assert actual is expected, f"{name}: expected {expected}, got {actual}"
    print(f"classifier boundary checks passed: {len(cases)}")


if __name__ == "__main__":
    main()
