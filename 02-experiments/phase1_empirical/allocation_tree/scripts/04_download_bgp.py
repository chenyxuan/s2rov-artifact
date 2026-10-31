#!/usr/bin/env python3
"""IMC'24 Step 4: Download RouteViews RIB dump (matched to RIPE WHOIS date: Jun 2026) + extract (prefix, origin_AS) via bgpdump."""
import subprocess, csv, gzip, sys
from pathlib import Path
from urllib.request import urlretrieve
from collections import defaultdict

PHASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = PHASE_DIR / "data"
TABLE_DIR = PHASE_DIR / "outputs" / "tables"
DATA_DIR.mkdir(parents=True, exist_ok=True)

RIB_URL = "http://archive.routeviews.org/bgpdata/2026.06/RIBS/rib.20260624.0000.bz2"
RIB_FILE = DATA_DIR / "rib.20260624.0000.bz2"
BGP_CSV = TABLE_DIR / "bgp_origins.csv"

# ─── Download ───
if not RIB_FILE.exists():
    print(f"Downloading {RIB_URL} ...")
    urlretrieve(RIB_URL, RIB_FILE)
    print(f"  Done: {RIB_FILE.stat().st_size / 1e6:.1f} MB")
else:
    print(f"Already downloaded: {RIB_FILE.stat().st_size / 1e6:.1f} MB")

# ─── Parse with bgpdump ───
print("Parsing with bgpdump (this may take a few minutes)...")

# bgpdump outputs: TABLE_DUMP2|timestamp|type|peer_ip|peer_as|prefix|as_path|...
# We need: prefix and the rightmost AS in as_path (= origin AS)
prefix_as = defaultdict(set)
count = 0

proc = subprocess.Popen(
    ["bgpdump", "-m", "-O", "/dev/stdout", str(RIB_FILE)],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
)

for line in proc.stdout:
    count += 1
    if count % 1000000 == 0:
        print(f"  {count/1e6:.1f}M routes  prefixes={len(prefix_as):,}", flush=True)
    parts = line.strip().split("|")
    if len(parts) < 7:
        continue
    # Format: TABLE_DUMP2|ts|type|peer_ip|peer_as|prefix|as_path|origin|...
    prefix = parts[5].strip()
    as_path = parts[6].strip()
    if not prefix or not as_path:
        continue
    # Origin AS is the rightmost AS in the path
    asns = as_path.split()
    if not asns:
        continue
    # Remove AS_SET markers { } and commas
    origin = asns[-1].strip("{},")
    try:
        prefix_as[prefix].add(int(origin))
    except:
        pass

return_code = proc.wait()
if return_code != 0:
    raise subprocess.CalledProcessError(return_code, proc.args)

# ─── Write CSV ───
print(f"\nParsed {count:,} routes → {len(prefix_as):,} unique prefixes")
print(f"Writing {BGP_CSV}...")

with open(BGP_CSV, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["prefix", "origin_as"])
    for pfx, ases in prefix_as.items():
        for asn in ases:
            w.writerow([pfx, asn])

print(f"Done → {BGP_CSV}")
