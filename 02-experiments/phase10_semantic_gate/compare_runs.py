"""Compare two complete E1a V3 runs without trusting their report prose."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


DETERMINISTIC_OUTPUTS = (
    "semantic_vectors.jsonl",
    "differential_results.jsonl",
    "invalid_objects.jsonl",
    "invalid_results.jsonl",
    "projection_census.json",
    "mutation_results.json",
    "composition_results.json",
    "baseline_matrix.json",
    "coverage.json",
)


class ComparisonFailure(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ComparisonFailure(f"expected JSON object: {path}")
    return value


def verify_run(directory: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    directory = directory.resolve(strict=True)
    manifest = load_json(directory / "manifest.json")
    summary = load_json(directory / "summary.json")
    if manifest.get("schema_version") != "e1a-manifest-v3":
        raise ComparisonFailure(f"not an E1a V3 manifest: {directory}")
    if manifest.get("status") != "COMPLETE_PASS" or summary.get("status") != "PASS":
        raise ComparisonFailure(f"run did not pass: {directory}")
    recorded = manifest.get("artifact_sha256")
    if not isinstance(recorded, dict):
        raise ComparisonFailure(f"artifact hash map missing: {directory}")
    actual_files = {
        str(path.relative_to(directory))
        for path in directory.rglob("*")
        if path.is_file()
    }
    allowed = set(manifest.get("allowed_artifacts", []))
    if actual_files != allowed:
        raise ComparisonFailure(
            f"artifact set mismatch in {directory}: "
            f"missing={sorted(allowed - actual_files)}, extra={sorted(actual_files - allowed)}"
        )
    for relative, expected in recorded.items():
        actual = sha256(directory / relative)
        if actual != expected:
            raise ComparisonFailure(
                f"artifact hash mismatch in {directory}: {relative} {actual} != {expected}"
            )
    if sha256(directory / "summary.json") != manifest.get("summary_sha256"):
        raise ComparisonFailure(f"summary hash mismatch: {directory}")
    if summary.get("failure_artifacts") != 0 or manifest.get("failure_artifacts"):
        raise ComparisonFailure(f"failure artifacts present: {directory}")
    return manifest, summary


def compare(left: Path, right: Path) -> dict[str, Any]:
    left_manifest, left_summary = verify_run(left)
    right_manifest, right_summary = verify_run(right)
    if left.resolve() == right.resolve():
        raise ComparisonFailure("comparison requires two distinct run directories")
    if left_manifest["environment"]["source_sha256"] != right_manifest["environment"]["source_sha256"]:
        raise ComparisonFailure("execution source hashes differ")
    left_outputs = left_summary.get("deterministic_output_sha256")
    right_outputs = right_summary.get("deterministic_output_sha256")
    if left_outputs != right_outputs:
        raise ComparisonFailure("deterministic output hash maps differ")
    if set(left_outputs) != set(DETERMINISTIC_OUTPUTS):
        raise ComparisonFailure("deterministic output set differs from V3 contract")
    byte_matches = {
        name: sha256(left / name) == sha256(right / name)
        for name in DETERMINISTIC_OUTPUTS
    }
    if not all(byte_matches.values()):
        raise ComparisonFailure("one or more deterministic outputs differ byte-for-byte")
    if left_summary["counts"] != right_summary["counts"]:
        raise ComparisonFailure("scientific count maps differ")
    if left_summary["scientific_results_sha256"] != right_summary["scientific_results_sha256"]:
        raise ComparisonFailure("scientific result digests differ")
    return {
        "schema_version": "e1a-run-comparison-v3",
        "status": "VERIFIED_EXACT_REPRODUCTION",
        "left": str(left.resolve()),
        "right": str(right.resolve()),
        "left_manifest_sha256": sha256(left / "manifest.json"),
        "right_manifest_sha256": sha256(right / "manifest.json"),
        "source_sha256": left_manifest["environment"]["source_sha256"],
        "deterministic_output_sha256": left_outputs,
        "byte_matches": byte_matches,
        "counts": left_summary["counts"],
        "scientific_results_sha256": left_summary["scientific_results_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ComparisonFailure(f"comparison output already exists: {args.output}")
    result = compare(args.left, args.right)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ComparisonFailure as exc:
        print(f"E1a comparison failure: {exc}")
        raise SystemExit(2)
