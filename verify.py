#!/usr/bin/env python3
"""Verify this bundle against MANIFEST.json.

    python3 verify.py

Recomputes SHA-256 for every bundled file and reports anything missing or
modified.  Exits non-zero on any problem, so it works in CI.
"""

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
    bad = []
    for rec in manifest["files"]:
        path = HERE / rec["bundle_path"]
        if not path.is_file():
            bad.append(("missing", rec["bundle_path"]))
        elif hashlib.sha256(path.read_bytes()).hexdigest() != rec["sha256"]:
            bad.append(("modified", rec["bundle_path"]))

    for kind, name in bad:
        print(f"{kind}: {name}")
    print(f"checked {manifest['file_count']} files, {len(bad)} problem(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
