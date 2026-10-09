#!/usr/bin/env python3
"""Resolve index/*.json entries into cache/<id>.yar.

Downloads each entry's source_url (skipping files already cached unless
--force), and for format "markdown-fenced" extracts the ``` code blocks.
Exit code 1 if any entry could not be fetched.
"""
import argparse, json, re, sys, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX, CACHE = ROOT / "index", ROOT / "cache"

def load_index():
    entries = []
    for p in sorted(INDEX.glob("*.json")):
        e = json.loads(p.read_text())
        e.setdefault("id", p.stem); e.setdefault("format", "yara"); e.setdefault("expect", "pass")
        entries.append(e)
    return entries

def fenced_blocks(text):
    blocks = re.findall(r"```[a-zA-Z]*\n(.*?)```", text, re.S)
    return "\n\n".join(b for b in blocks if "rule " in b)

def fetch(entry, force=False):
    out = CACHE / f"{entry['id']}.yar"
    if out.exists() and not force:
        return out
    req = urllib.request.Request(entry["source_url"], headers={"User-Agent": "yara-lapidary/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read().decode("utf-8", "replace")
    if entry["format"] == "markdown-fenced":
        data = fenced_blocks(data)
    if "rule " not in data:
        raise ValueError("no rule found in fetched content")
    out.write_text(data)
    return out

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--force", action="store_true"); a = ap.parse_args()
    CACHE.mkdir(exist_ok=True)
    failed = 0
    for e in load_index():
        try:
            p = fetch(e, a.force); print(f"ok    {e['id']:40} {p.stat().st_size:>8} bytes")
        except Exception as ex:
            failed += 1; print(f"FAIL  {e['id']:40} {ex}", file=sys.stderr)
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
