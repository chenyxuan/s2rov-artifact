#!/usr/bin/env python3
"""Build the processing-cost source table from the accepted controlled run."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


SCRIPT = Path(__file__).resolve()
PAPER_DIR = SCRIPT.parents[2]
REPO_ROOT = PAPER_DIR
DEFAULT_RUN = (
    REPO_ROOT
    / "experiments" / "cost"
    / "processing_benchmark"
    / "results"
    / "controlled-processing-20260830T-marker-final-v1"
)
DEFAULT_OUTPUT = PAPER_DIR / "results" / "tables" / "processing_cost_dual_stack.csv"
DEFAULT_TEX = PAPER_DIR / "results" / "tables" / "processing_cost_dual_stack.tex"
DEFAULT_MANIFEST = (
    PAPER_DIR / "results" / "tables" / "processing_cost_dual_stack.manifest.json"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, default=DEFAULT_RUN)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--tex", type=Path, default=DEFAULT_TEX)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()

    run_dir = args.run_dir.resolve()
    summary_path = run_dir / "summary.json"
    audit_path = run_dir / "independent_audit.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    if not summary["gates"]["all_gates_pass"]:
        raise RuntimeError("accepted run did not pass its internal gates")
    if not audit["checks"]["all_checks_pass"]:
        raise RuntimeError("accepted run did not pass the independent audit")

    rows = []
    for source in summary["rows"]:
        rows.append(
            {
                "ip_version": source["label"],
                "subprefix_entries": int(source["subprefix_entries"]),
                "total_policy_entries": int(source["total_policy_entries"]),
                "load_ms_mean": float(source["load_ms_mean"]),
                "load_ms_median": float(source["load_ms_median"]),
                "load_ms_q1": float(source["load_ms_q1"]),
                "load_ms_q3": float(source["load_ms_q3"]),
                "classify_kpairs_s_mean": float(
                    source["classify_kpairs_s_mean"]
                ),
                "classify_kpairs_s_median": float(
                    source["classify_kpairs_s_median"]
                ),
                "classify_kpairs_s_min": float(source["classify_kpairs_s_min"]),
                "classify_kpairs_s_max": float(source["classify_kpairs_s_max"]),
                "load_ms_display": f"{source['load_ms_mean']:.1f}",
                "classify_kpairs_s_display": (
                    f"{source['classify_kpairs_s_mean']:.1f}"
                ),
            }
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        r"\begin{tabular}{@{}lrrr@{}}",
        r"\toprule",
        r"Version & Records & Load & Classify \\",
        r" & & (ms) & (routes/s) \\",
        r"\midrule",
    ]
    for row in rows:
        lines.append(
            f"{row['ip_version']} & {row['total_policy_entries']:,} & "
            f"{row['load_ms_display']} & "
            f"{float(row['classify_kpairs_s_mean']) * 1000.0:,.1f} \\\\"
        )
    lines.extend([r"\bottomrule", r"\end{tabular}", ""])
    args.tex.write_text("\n".join(lines), encoding="utf-8")

    manifest = {
        "schema_version": "processing-cost-table-v2",
        "accepted_run": str(run_dir),
        "source_summary": {
            "path": str(summary_path),
            "sha256": sha256_file(summary_path),
        },
        "independent_audit": {
            "path": str(audit_path),
            "sha256": sha256_file(audit_path),
            "all_checks_pass": True,
        },
        "builder": {"path": str(SCRIPT), "sha256": sha256_file(SCRIPT)},
        "rows": rows,
        "display_statistic": "arithmetic mean across fresh worker processes",
        "display_rounding": "one decimal place",
    }
    args.manifest.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"rows": len(rows), "output": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
