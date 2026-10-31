#!/usr/bin/env python3
"""Attach registry organization-associated aut-num records to root ranges.

The resulting values are descriptive registry associations.  They are not a
RIR assignment of one origin AS to a prefix and are not used by the strict
BGP endpoint comparison in Step 5.
"""
import csv
from pathlib import Path
from collections import defaultdict

PHASE_DIR = Path(__file__).resolve().parents[1]
TABLE_DIR = PHASE_DIR / "outputs" / "tables"

# ─── Load org→AS mapping from aut-num ───
print("Loading org→associated aut-num mapping...")
org_as = defaultdict(set)
with open(TABLE_DIR/"ripe_autnum.csv") as f:
    for r in csv.DictReader(f):
        o = r.get("org","").strip()
        a = r.get("aut-num","").strip()
        if o and a and a.upper().startswith("AS"):
            try: org_as[o].add(int(a[2:]))
            except: pass
print(f"  {len(org_as):,} orgs with associated aut-num records")

# ─── Load inetnum → org mapping (for root nodes) ───
print("Loading inetnum org assignments...")
# Build: (start_int, end_int) → org
inet_org = {}
ROOT_ST = {"ALLOCATED PA","ALLOCATED PI","ALLOCATED UNSPECIFIED","ALLOCATED-BY-RIR","LEGACY"}
with open(TABLE_DIR/"ripe_inetnum.csv") as f:
    for r in csv.DictReader(f):
        st = r.get("status","").strip()
        if st not in ROOT_ST: continue
        org = r.get("org","").strip()
        if org == "nan" or not org: continue
        inum = r.get("inetnum","").strip()
        parts = inum.split("-")
        if len(parts) != 2: continue
        try:
            import ipaddress as ip
            si = int(ip.IPv4Address(parts[0].strip()))
            ei = int(ip.IPv4Address(parts[1].strip()))
            inet_org[(si, ei)] = org
        except: pass
print(f"  {len(inet_org):,} root prefixes with org")

# ─── Annotate allocation tree ───
print("Annotating allocation tree pairs...")
infile = TABLE_DIR/"allocation_tree_pairs.csv"
outfile = TABLE_DIR/"allocation_tree_with_as.csv"

with open(infile) as fin, open(outfile, "w", newline="") as fout:
    reader = csv.DictReader(fin)
    cols = reader.fieldnames + ["root_org", "root_as"]
    writer = csv.DictWriter(fout, fieldnames=cols)
    writer.writeheader()

    annotated = 0
    for r in reader:
        rs, re_ = int(r["root_start"]), int(r["root_end"])
        org = inet_org.get((rs, re_), "")
        ases = org_as.get(org, set())
        r["root_org"] = org
        r["root_as"] = ",".join(str(a) for a in sorted(ases))
        if ases: annotated += 1
        writer.writerow(r)

with open(infile) as f:
    total = sum(1 for _ in f) - 1
print(f"  Annotated: {annotated:,} / {total:,} pairs with org-associated aut-num records ({annotated/total*100:.1f}%)")
print(f"Done → {outfile}")
