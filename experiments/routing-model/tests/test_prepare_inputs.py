from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from prepare_inputs import (  # noqa: E402
    EXPECTED_CSV_HEADER,
    InputValidationError,
    prepare_inputs,
)


class PrepareInputsTests(unittest.TestCase):
    def _write_valid_topology_and_rov(self, directory: Path) -> tuple[Path, Path]:
        topology = directory / "as-rel-fixed.txt"
        lines = [f"{asn}|{asn + 1}|-1\n" for asn in range(1, 600)]
        topology.write_text("".join(lines), encoding="utf-8")
        rov = directory / "hlavacek_rov.json"
        rov.write_text(
            json.dumps(
                [
                    {
                        "label": "hlavacek_589",
                        "rov_ases": list(range(1, 590)),
                        "amber_ases": [],
                    }
                ]
            ),
            encoding="utf-8",
        )
        return topology, rov

    def _write_candidates(self, path: Path, rows: list[dict[str, str]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=EXPECTED_CSV_HEADER)
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def _row(
        root_origins: str = "10",
        leaf_origins: str = "20",
        root_prefix: str = "192.0.2.0/24",
        leaf_prefix: str = "192.0.2.0/25",
    ) -> dict[str, str]:
        return {
            "root_prefix": root_prefix,
            "root_status": "ALLOCATED PA",
            "root_origins": root_origins,
            "leaf_prefix": leaf_prefix,
            "leaf_status": "ASSIGNED PA",
            "leaf_origins": leaf_origins,
            "classification": "disjoint_origin_sets",
        }

    def test_filters_candidates_and_records_all_reasons(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            topology, rov = self._write_valid_topology_and_rov(base)
            candidates = base / "candidates.csv"
            self._write_candidates(
                candidates,
                [
                    self._row(),
                    self._row(root_origins="10;11"),
                    self._row(leaf_origins="20;21"),
                    self._row(leaf_prefix="198.51.100.0/25"),
                    self._row(leaf_origins="10"),
                    self._row(root_origins="700"),
                    self._row(leaf_origins="701"),
                ],
            )
            output = base / "output"
            summary = prepare_inputs(
                candidates,
                topology,
                rov,
                output,
                generated_at_utc="2026-08-04T00:00:00Z",
            )

            self.assertEqual(summary["retained_candidate_rows"], 1)
            self.assertEqual(summary["unique_holder_delegate_pairs"], 1)
            provenance = json.loads((output / "provenance.json").read_text())
            counts = provenance["filtering"]["exclusion_counts_independent"]
            self.assertEqual(counts["root_origin_not_singleton"], 1)
            self.assertEqual(counts["leaf_origin_not_singleton"], 1)
            self.assertEqual(counts["leaf_not_proper_descendant"], 1)
            self.assertEqual(counts["holder_equals_delegate"], 1)
            self.assertEqual(counts["holder_absent_from_topology"], 1)
            self.assertEqual(counts["delegate_absent_from_topology"], 1)
            self.assertIn("do not assert or infer", provenance["interpretation_warning"])

            with (output / "origin_divergence_candidates.csv").open(newline="") as stream:
                retained = list(csv.DictReader(stream))
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0]["holder_asn"], "10")
            self.assertEqual(retained[0]["delegate_asn"], "20")

    def test_source_schema_mismatch_fails_without_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            topology, rov = self._write_valid_topology_and_rov(base)
            candidates = base / "bad.csv"
            candidates.write_text("unexpected,header\n1,2\n", encoding="utf-8")
            output = base / "output"

            with self.assertRaises(InputValidationError):
                prepare_inputs(candidates, topology, rov, output)
            self.assertFalse(output.exists())

    def test_repeated_topology_pair_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            topology, rov = self._write_valid_topology_and_rov(base)
            with topology.open("a", encoding="utf-8") as stream:
                stream.write("2|1|0\n")
            candidates = base / "candidates.csv"
            self._write_candidates(candidates, [self._row()])

            with self.assertRaisesRegex(InputValidationError, "repeated AS pair"):
                prepare_inputs(candidates, topology, rov, base / "output")

    def test_rov_cardinality_is_strictly_589(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            topology, rov = self._write_valid_topology_and_rov(base)
            document = json.loads(rov.read_text())
            document[0]["rov_ases"].pop()
            rov.write_text(json.dumps(document), encoding="utf-8")
            candidates = base / "candidates.csv"
            self._write_candidates(candidates, [self._row()])

            with self.assertRaisesRegex(InputValidationError, "expected 589"):
                prepare_inputs(candidates, topology, rov, base / "output")


if __name__ == "__main__":
    unittest.main()
