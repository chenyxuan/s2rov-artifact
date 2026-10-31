#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("run_controlled_policy_benchmark.py")
SPEC = importlib.util.spec_from_file_location("controlled_policy_benchmark", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ControlledPolicyBenchmarkTests(unittest.TestCase):
    def fixture(self):
        rows = [
            ("10.0.0.0/8", 174),
            ("10.0.0.0/24", 13335),
            ("10.0.1.0/24", 15169),
            ("10.0.2.0/24", 8075),
            ("10.0.3.0/24", 18403),
            ("10.1.0.0/16", 3356),
            ("10.1.1.0/24", 1299),
            ("10.1.2.0/24", 6939),
        ]
        return MODULE.select_fixture(
            rows,
            ip_version=4,
            base_prefix="10.0.0.0/8",
            holder_asn=174,
            max_subprefixes=2,
            query_count=2,
            seed=20260829,
        )

    def test_selection_is_deterministic(self):
        first = self.fixture()
        second = self.fixture()
        self.assertEqual(first["selected_children"], second["selected_children"])
        self.assertEqual(first["queries"], second["queries"])
        self.assertEqual(first["queries_sha256"], second["queries_sha256"])

    def test_subprefix_count_excludes_base_entry(self):
        fixture = self.fixture()
        for count in (0, 2):
            policy, payload, spec = MODULE.build_policy(fixture, count)
            self.assertEqual(len(policy.stripes), count + 1)
            self.assertEqual(spec["subprefix_entries"], count)
            self.assertEqual(spec["total_policy_entries"], count + 1)
            self.assertEqual(MODULE.DAROA.deserialize(payload).serialize(), payload)

    def test_fixed_queries_are_open_scope_at_every_size(self):
        fixture = self.fixture()
        queries = [
            (item["prefix"], int(item["origin"])) for item in fixture["queries"]
        ]
        vectors = []
        for count in (0, 1, 2):
            policy, _payload, _spec = MODULE.build_policy(fixture, count)
            vector = [policy.validate_route(prefix, origin) for prefix, origin in queries]
            self.assertEqual(
                vector,
                [MODULE.ValidationState.DELEGATED] * len(queries),
            )
            vectors.append(vector)
        self.assertEqual(vectors[0], vectors[1])
        self.assertEqual(vectors[1], vectors[2])


if __name__ == "__main__":
    unittest.main()
