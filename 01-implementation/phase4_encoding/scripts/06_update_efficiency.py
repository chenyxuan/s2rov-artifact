#!/usr/bin/env python3
"""Task 6: Update Efficiency — measure incremental Stripe insertion/deletion cost.

Usage: python scripts/06_update_efficiency.py
"""
import sys
from pathlib import Path
import csv
import time

PHASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PHASE_DIR / "scripts"))
from utils.daroa import DAROA, Stripe  # noqa: E402
from utils.merge import merge_stripes  # noqa: E402

TABLE_DIR = PHASE_DIR / "outputs/tables"
TABLE_DIR.mkdir(parents=True, exist_ok=True)


def build_daroa(num_customers: int) -> DAROA:
    """Build a DA-ROA with N explicit customer Stripes."""
    stripes = [
        Stripe("10.0.0.0/16", {64501}, is_open=True),
    ]
    for i in range(num_customers):
        prefix = f"10.0.{i}.0/24"
        stripes.append(Stripe(prefix, {64502 + i}, is_open=False))

    merged = merge_stripes(stripes)
    return DAROA("10.0.0.0/16", 24, 64501, merged)


def main():
    results = []
    sizes = [10, 50, 100, 200]

    for n in sizes:
        daroa = build_daroa(n)
        base_stripes = list(daroa.stripes)

        # ── Add Stripe ──
        # Keep the inserted prefix outside every baseline set (N <= 200).
        add_stripe = Stripe("10.0.250.0/24", {65999}, is_open=False)
        trials = 100
        t0 = time.perf_counter_ns()
        for _ in range(trials):
            test_stripes = list(base_stripes) + [add_stripe]
            _ = merge_stripes(test_stripes)
        add_ns = (time.perf_counter_ns() - t0) / trials

        # ── Remove Stripe (remove the last customer) ──
        remove_prefix = f"10.0.{n-1}.0/24"
        t0 = time.perf_counter_ns()
        for _ in range(trials):
            test_stripes = [s for s in base_stripes if s.prefix != remove_prefix]
            _ = merge_stripes(test_stripes)
        remove_ns = (time.perf_counter_ns() - t0) / trials

        # ── Full re-encode ──
        t0 = time.perf_counter_ns()
        for _ in range(trials):
            _ = build_daroa(n)
            _ = merge_stripes(list(daroa.stripes))
        reencode_ns = (time.perf_counter_ns() - t0) / trials

        results.append({
            "num_customers": n,
            "num_stripes": len(base_stripes),
            "add_stripe_ns": int(add_ns),
            "remove_stripe_ns": int(remove_ns),
            "full_reencode_ns": int(reencode_ns),
            "add_vs_reencode": f"{add_ns / max(reencode_ns, 1):.1f}x",
            "remove_vs_reencode": f"{remove_ns / max(reencode_ns, 1):.1f}x",
        })

        print(f"  N={n:3d} stripes={len(base_stripes):3d}  "
              f"add={int(add_ns):>6d}ns  remove={int(remove_ns):>6d}ns  "
              f"reencode={int(reencode_ns):>6d}ns")

    # Write CSV
    keys = ["num_customers", "num_stripes", "add_stripe_ns", "remove_stripe_ns",
            "full_reencode_ns", "add_vs_reencode", "remove_vs_reencode"]
    with open(TABLE_DIR / "update_costs.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(results)

    print(f"\n✅ Update efficiency results → {TABLE_DIR / 'update_costs.csv'}")


if __name__ == "__main__":
    main()
