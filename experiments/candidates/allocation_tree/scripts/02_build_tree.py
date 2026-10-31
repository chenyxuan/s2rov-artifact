#!/usr/bin/env python3
"""Build RIPE IPv4 allocation tree — efficient root→leaves matching via binary search.
IMC'24 Step 2: parse inetnum, build prefix tree (root = portable, leaf = non-portable)."""
import ipaddress as ip, csv, bisect
from pathlib import Path

HERE_DIR = Path(__file__).resolve().parents[1]
TABLE_DIR = HERE_DIR / "outputs" / "tables"

ROOT_ST = {"ALLOCATED PA","ALLOCATED PI","ALLOCATED UNSPECIFIED","ALLOCATED-BY-RIR","LEGACY"}
LEAF_ST = {"ASSIGNED PA","ASSIGNED PI","ASSIGNED","ASSIGNED ANYCAST",
           "SUB-ALLOCATED PA","LIR-PARTITIONED PA","ALLOCATED-ASSIGNED PA"}

# ═══ Stream inetnum → roots/leaves ═══
print("Streaming RIPE inetnum...")
roots, leaves = [], []
with open(TABLE_DIR/"ripe_inetnum.csv") as f:
    for i, r in enumerate(csv.DictReader(f)):
        if i and i % 1000000 == 0:
            print(f"  {i/1e6:.1f}M  r={len(roots):,} l={len(leaves):,}", flush=True)
        st = r.get("status","").strip()
        inum = r.get("inetnum","").strip()
        if not inum: continue
        parts = inum.split("-")
        if len(parts)!=2: continue
        try:
            si = int(ip.IPv4Address(parts[0].strip()))
            ei = int(ip.IPv4Address(parts[1].strip()))
        except: continue
        if st in ROOT_ST:   roots.append((si, ei, st))
        elif st in LEAF_ST: leaves.append((si, ei, st))
print(f"Roots={len(roots):,}  Leaves={len(leaves):,}", flush=True)

# ═══ Match: process roots smallest-first (most-specific) ═══
roots.sort(key=lambda x: (x[1]-x[0], x[0]))
leaves.sort(key=lambda x: x[0])
leaf_starts = [l[0] for l in leaves]
leaf_ends   = [l[1] for l in leaves]
matched = [None] * len(leaves)

print("Matching roots→leaves (smallest root first)...")
for ri, (r_si, r_ei, r_st) in enumerate(roots):
    if ri and ri % 20000 == 0:
        done = sum(1 for m in matched if m is not None)
        print(f"  root {ri:,}/{len(roots):,}  matched={done:,}", flush=True)
    li = bisect.bisect_left(leaf_starts, r_si)
    while li < len(leaves):
        if leaf_starts[li] > r_ei: break
        if leaf_ends[li] <= r_ei and matched[li] is None:
            matched[li] = (r_si, r_ei, r_st)
        li += 1

mc = sum(1 for m in matched if m is not None)
print(f"  Matched: {mc:,} / {len(leaves):,} ({mc/len(leaves)*100:.1f}%)", flush=True)

# ═══ Write ═══
with open(TABLE_DIR/"allocation_tree_pairs.csv","w",newline="") as f:
    w = csv.writer(f)
    w.writerow(["root_start","root_end","root_status","leaf_start","leaf_end","leaf_status"])
    for li, m in enumerate(matched):
        if m:
            w.writerow([m[0],m[1],m[2],leaves[li][0],leaves[li][1],leaves[li][2]])
print(f"Done → {TABLE_DIR}/allocation_tree_pairs.csv")
