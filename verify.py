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
    listed = {rec["bundle_path"] for rec in manifest["files"]}
    bad = []
    for rec in manifest["files"]:
        path = HERE / rec["bundle_path"]
        if not path.is_file():
            bad.append(("missing", rec["bundle_path"]))
        elif hashlib.sha256(path.read_bytes()).hexdigest() != rec["sha256"]:
            bad.append(("modified", rec["bundle_path"]))

    # The manifest cannot hash itself, so everything else must be listed.
    for path in sorted(HERE.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(HERE).as_posix()
        if relative == "MANIFEST.json" or relative in listed:
            continue
        if "__pycache__" in relative or relative.endswith(".pyc"):
            continue
        bad.append(("unlisted", relative))

    for kind, name in bad:
        print(f"{kind}: {name}")
    print(f"checked {manifest['file_count']} files, {len(bad)} problem(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
