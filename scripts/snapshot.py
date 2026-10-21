#!/usr/bin/env python3
"""Vendor the pinned source of every index entry into rules/<id>.yar.

  snapshot.py            write or refresh rules/<id>.yar from cache/<id>.yar (run fetch.py first)
  snapshot.py --check    exit 1 if any rules/<id>.yar differs from its cached pinned source,
                         or is missing for an entry that allows vendoring

Each snapshot starts with a provenance header naming the upstream URL, the
author, the license the source declares and the retrieval date, so the copy
can never be mistaken for original work. Entries with "vendor": false are
skipped (use it when a license forbids redistribution); the index entry and
the cached fetch still drive the compile checks for them.
"""
import argparse, json, sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX, CACHE, RULES = ROOT / "index", ROOT / "cache", ROOT / "rules"

def header(e):
    return "\n".join([
        "// Vendored copy for study. Not original work of this repository.",
        f"// Source:   {e['html_url']}",
        f"// Pinned:   {e['source_url']}",
        f"// Author:   {e.get('author', 'unknown')}",
        f"// License:  {e.get('license', 'unspecified')} (as declared by the source; see it for terms)",
        f"// Fetched:  {e.get('fetched', date.today().isoformat())}",
        "",
    ]) + "\n"

def body_of(text):
    """Strip a provenance header so comparisons see only the rule text."""
    lines = text.split("\n")
    i = 0
    while i < len(lines) and lines[i].startswith("// ") and lines[i].split()[1].rstrip(":") in \
            ("Vendored", "Source", "Pinned", "Author", "License", "Fetched"):
        i += 1
    return "\n".join(lines[i:]).lstrip("\n")

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--check", action="store_true"); a = ap.parse_args()
    RULES.mkdir(exist_ok=True)
    problems, written = [], 0
    for p in sorted(INDEX.glob("*.json")):
        e = json.loads(p.read_text()); eid = e.get("id", p.stem)
        if not e.get("vendor", True):
            continue
        src = CACHE / f"{eid}.yar"; dst = RULES / f"{eid}.yar"
        if not src.exists():
            problems.append(f"{eid}: not fetched (run fetch.py)"); continue
        fresh = src.read_text(errors="replace")
        if a.check:
            if not dst.exists():
                problems.append(f"{eid}: rules/{eid}.yar missing")
            elif body_of(dst.read_text(errors="replace")) != fresh:
                problems.append(f"{eid}: vendored copy differs from the pinned source")
            continue
        if dst.exists() and body_of(dst.read_text(errors="replace")) == fresh:
            continue
        e.setdefault("fetched", date.today().isoformat())
        dst.write_text(header(e) + fresh); written += 1
        if "fetched" not in json.loads(p.read_text()):
            p.write_text(json.dumps(e, indent=2) + "\n")
    for m in problems: print(m, file=sys.stderr)
    if not a.check: print(f"{written} snapshot(s) written")
    sys.exit(1 if problems else 0)

if __name__ == "__main__":
    main()
