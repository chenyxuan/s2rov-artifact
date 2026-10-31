from __future__ import annotations

import unittest

from experiments.semantic_gate.oracle import (
    OraclePolicy,
    OracleRule,
    OracleState,
    VRP,
    classify,
    conventional_rov,
    wildcard_exact,
)


class OracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = OraclePolicy(
            "10.0.0.0/16",
            24,
            15169,
            (
                OracleRule("10.0.0.0/16", frozenset({15169}), True),
                OracleRule("10.0.1.0/24", frozenset({16509}), False),
            ),
        )

    def test_four_states_and_proper_descendant_boundary(self) -> None:
        cases = (
            ("10.0.0.0/16", 15169, OracleState.EXPLICIT),
            ("10.0.0.0/16", 13335, OracleState.INVALID),
            ("10.0.1.0/24", 16509, OracleState.EXPLICIT),
            ("10.0.1.0/24", 13335, OracleState.INVALID),
            ("10.0.2.0/24", 13335, OracleState.OPEN_SCOPE),
            ("192.0.2.0/24", 13335, OracleState.NOT_FOUND),
        )
        for prefix, origin, expected in cases:
            self.assertEqual(classify(self.policy, prefix, origin), expected)

    def test_conventional_and_wildcard_are_separate_oracles(self) -> None:
        aggregate = VRP("10.0.0.0/16", 15169, 24)
        exact = VRP("10.0.1.0/24", 16509, 24)
        self.assertEqual(
            conventional_rov("10.0.1.0/24", 13335, [aggregate, exact]).value,
            "Invalid",
        )
        self.assertEqual(
            wildcard_exact("10.0.1.0/24", "10.0.1.0/24", 13335).value,
            "WildcardValid",
        )
        self.assertEqual(
            wildcard_exact(
                "10.0.1.0/24",
                "10.0.1.0/24",
                13335,
                [exact],
            ).value,
            "Invalid",
        )


if __name__ == "__main__":
    unittest.main()
