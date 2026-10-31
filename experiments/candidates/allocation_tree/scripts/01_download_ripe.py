"""Download RIPE WHOIS database dump and parse inetnum/aut-num/org objects."""
import gzip
import re
import sys
from pathlib import Path
from urllib.request import urlretrieve

RIPE_DB_URL = "https://ftp.ripe.net/ripe/dbase/ripe.db.gz"
HERE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = HERE_DIR / "data"
OUTPUT_DIR = HERE_DIR / "outputs" / "tables"

DB_GZ = DATA_DIR / "ripe.db.gz"
INETNUM_CSV = OUTPUT_DIR / "ripe_inetnum.csv"
AUTNUM_CSV = OUTPUT_DIR / "ripe_autnum.csv"
ORG_CSV = OUTPUT_DIR / "ripe_organisation.csv"


def download_ripe_db():
    """Download RIPE WHOIS database if not already present."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if DB_GZ.exists():
        print(f"Already downloaded: {DB_GZ} ({DB_GZ.stat().st_size / 1e6:.1f} MB)")
        return

    print(f"Downloading {RIPE_DB_URL} ...")
    urlretrieve(RIPE_DB_URL, DB_GZ)
    print(f"Downloaded: {DB_GZ.stat().st_size / 1e6:.1f} MB")


def parse_ripe_objects():
    """Parse inetnum, aut-num, and organisation objects from ripe.db.gz."""
    inetnums = []
    autnums = []
    orgs = []

    current = {}
    current_type = None

    with gzip.open(DB_GZ, "rt", encoding="latin-1", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")

            # Object boundary
            if line == "":
                if current_type == "inetnum" and current:
                    inetnums.append(current)
                elif current_type == "aut-num" and current:
                    autnums.append(current)
                elif current_type == "organisation" and current:
                    orgs.append(current)
                current = {}
                current_type = None
                continue

            # Detect object type from first key
            if not current_type and ":" in line:
                key = line.split(":", 1)[0].strip().lower()
                if key in ("inetnum", "inet6num"):
                    current_type = "inetnum"
                elif key == "aut-num":
                    current_type = "aut-num"
                elif key == "organisation":
                    current_type = "organisation"

            # Parse key: value
            if ":" in line and current_type:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()

                # Collect multi-line values (continuation lines start with space or +)
                if key in current:
                    current[key] += " " + value
                else:
                    current[key] = value

    # Don't forget last object
    if current_type == "inetnum" and current:
        inetnums.append(current)
    elif current_type == "aut-num" and current:
        autnums.append(current)
    elif current_type == "organisation" and current:
        orgs.append(current)

    return inetnums, autnums, orgs


def write_csv(objects, path, columns):
    """Write list of dicts to CSV."""
    import csv
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(objects)
    print(f"  Wrote {len(objects):,} objects → {path}")


def main():
    download_ripe_db()

    print("Parsing RIPE WHOIS database...")
    inetnums, autnums, orgs = parse_ripe_objects()
    print(f"Parsed: {len(inetnums):,} inetnum, {len(autnums):,} aut-num, {len(orgs):,} organisation")

    # Write CSVs
    inetnum_cols = ["inetnum", "netname", "descr", "country", "org", "status",
                    "mnt-by", "mnt-lower", "mnt-routes", "source", "last-modified"]
    autnum_cols = ["aut-num", "as-name", "descr", "org", "status", "mnt-by", "source"]
    org_cols = ["organisation", "org-name", "org-type", "descr", "country", "source"]

    write_csv(inetnums, INETNUM_CSV, inetnum_cols)
    write_csv(autnums, AUTNUM_CSV, autnum_cols)
    write_csv(orgs, ORG_CSV, org_cols)

    # Quick stats
    statuses = {}
    for obj in inetnums:
        st = obj.get("status", "unknown")
        statuses[st] = statuses.get(st, 0) + 1
    print("\ninetnum status distribution:")
    for st, cnt in sorted(statuses.items(), key=lambda x: -x[1]):
        print(f"  {st:40s}: {cnt:8,}")


if __name__ == "__main__":
    main()
