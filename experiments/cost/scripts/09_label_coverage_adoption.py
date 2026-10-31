#!/usr/bin/env python3
"""Scenario analysis: relationship-label coverage over holder adoption.

This does not estimate false-positive rate.  It asks how many
relationship-labeled occurrence rows would be covered if a uniformly sampled
fraction of observed ROA-origin ASNs adopted open policy for every such row.
The assumption is deliberately strong and the output is a scenario, not a
deployment forecast.

Usage: python scripts/09_label_coverage_adoption.py
"""
import pandas as pd
import numpy as np
import random
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE_DIR = Path(__file__).resolve().parents[1]
TABLE_DIR = HERE_DIR / "outputs/tables"
TABLE_DIR.mkdir(parents=True, exist_ok=True)

CANDIDATES_TABLE_DIR = ROOT / "experiments/candidates/ndss26_analysis/outputs/tables"
CANDIDATES_DATA = CANDIDATES_TABLE_DIR / "data_processed.parquet"
CANDIDATES_CSV = CANDIDATES_TABLE_DIR / "data_processed.csv.gz"
RAW_DATA_DIR = ROOT / "data/roa-misconfiguration-data/datas"
random.seed(42)
np.random.seed(42)

ADOPTION_RATES = [0.0, 0.05, 0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.75, 0.90, 1.0]
N_TRIALS = 10
SAMPLE_SIZE = None


def load_candidates_dataframe() -> pd.DataFrame:
    if CANDIDATES_CSV.exists():
        return pd.read_csv(CANDIDATES_CSV)
    if CANDIDATES_DATA.exists():
        try:
            return pd.read_parquet(CANDIDATES_DATA)
        except ImportError as exc:
            raise RuntimeError(
                "Only a Parquet cache is available; rerun the candidate-selection loader "
                "to create data_processed.csv.gz"
            ) from exc

    frames = []
    for f in sorted(RAW_DATA_DIR.glob("*.csv")):
        frames.append(pd.read_csv(f))
    if not frames:
        raise FileNotFoundError(f"No candidate-selection data found under {CANDIDATES_TABLE_DIR} or {RAW_DATA_DIR}")
    return pd.concat(frames, ignore_index=True)


def main():
    if not CANDIDATES_DATA.exists() and not CANDIDATES_CSV.exists() and not RAW_DATA_DIR.exists():
        print("candidate-selection data not found"); return

    print("Loading candidate-selection data...")
    df = load_candidates_dataframe()
    if SAMPLE_SIZE and len(df) > SAMPLE_SIZE:
        df = df.sample(n=SAMPLE_SIZE, random_state=42)
    print(f"  {len(df):,} rows")

    relationship_columns = [
        "customer",
        "org_transit",
        "direct_leasing",
        "hidden_transit",
        "broker_leasing",
    ]
    df["is_relationship_labeled"] = df[relationship_columns].gt(0).any(axis=1)

    n_semantic = df["is_relationship_labeled"].sum()
    n_total = len(df)
    baseline_share = n_semantic / n_total * 100

    print(f"  Total routes:            {n_total:,}")
    print(f"  Relationship-labeled:    {n_semantic:,} ({baseline_share:.1f}%)")
    print(f"  Unique holder ASes:      {df['roa_origin'].nunique():,}")

    # Group by holder
    holder_stats = df.groupby("roa_origin").agg(
        total_routes=("is_relationship_labeled", "count"),
        labeled_routes=("is_relationship_labeled", "sum"),
    ).reset_index()
    holder_stats.columns = ["holder_asn", "total_routes", "labeled_routes"]

    # Only holders with at least one semantic conflict route
    holders = holder_stats[holder_stats["labeled_routes"] > 0].reset_index(drop=True)
    n_holders = len(holders)
    total_semantic = holders["labeled_routes"].sum()

    print(f"  Holders with labels:     {n_holders:,}")
    print(f"  Labeled occurrences:     {total_semantic:,}\n")

    print(f"Running {N_TRIALS} trials x {len(ADOPTION_RATES)} adoption rates...")
    all_results = []

    for rate in ADOPTION_RATES:
        trial_remaining_shares, trial_covered_shares = [], []

        for t in range(N_TRIALS):
            n_adopters = int(n_holders * rate)
            adopt_idx = random.sample(range(n_holders), n_adopters)
            adopt_mask = np.zeros(n_holders, dtype=bool)
            adopt_mask[adopt_idx] = True

            covered = holders.loc[adopt_mask, "labeled_routes"].sum()
            remaining = total_semantic - covered
            remaining_share = remaining / n_total * 100

            trial_remaining_shares.append(remaining_share)
            trial_covered_shares.append(covered / total_semantic * 100)

        avg_remaining = np.mean(trial_remaining_shares)
        avg_covered = np.mean(trial_covered_shares)
        std_remaining = np.std(trial_remaining_shares)

        result = {
            "adoption_rate": rate,
            "adoption_pct": f"{rate*100:.0f}%",
            "remaining_labeled_share_pct": f"{avg_remaining:.2f}",
            "remaining_labeled_share_std": f"{std_remaining:.2f}",
            "covered_labeled_occurrences_pct": f"{avg_covered:.1f}",
            "trials": N_TRIALS,
        }
        all_results.append(result)

        bar = "█" * int(rate * 20)
        print(f"  Adopt {rate*100:3.0f}% {bar:20s}  "
              f"remaining={avg_remaining:.2f}% +/-{std_remaining:.2f}  "
              f"covered={avg_covered:.1f}%")

    full_share = float(all_results[-1]["remaining_labeled_share_pct"])
    coverage = (baseline_share - full_share) / baseline_share * 100

    print(f"\n{'='*60}")
    print(f"SUMMARY:")
    print(f"  Labeled share at   0% adoption: {baseline_share:.2f}%")
    print(f"  Labeled share remaining at 100%: {full_share:.2f}%")
    print(f"  Labeled occurrences covered:     {coverage:.1f}%")

    keys = ["adoption_rate", "adoption_pct", "remaining_labeled_share_pct",
            "remaining_labeled_share_std", "covered_labeled_occurrences_pct",
            "trials"]
    with open(TABLE_DIR / "label_coverage_adoption.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(all_results)

    with open(TABLE_DIR / "label_coverage_adoption_summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["metric", "value"])
        w.writeheader()
        w.writerows([
            {"metric": "baseline_relationship_labeled_share_pct", "value": f"{baseline_share:.2f}"},
            {"metric": "remaining_labeled_share_at_full_adoption_pct", "value": f"{full_share:.2f}"},
            {"metric": "covered_labeled_occurrences_pct", "value": f"{coverage:.1f}"},
        ])

    print(f"\nResults -> {TABLE_DIR}")


if __name__ == "__main__":
    main()
