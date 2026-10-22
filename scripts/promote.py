#!/usr/bin/env python3
"""Promote discovery candidates into index/ and rules/, one entry per distinct rule.

  promote.py [--runs GLOB] [--min-density F] [--dry-run]

Reads every candidate record under discovery/runs/*.json, fetches each
pinned source, groups records by content (dedup.content_id), picks the
original among copies (dedup.choose_original), skips anything whose content
is already indexed, and writes index/<id>.json plus rules/<id>.yar with a
provenance header. Entries carry "promoted_from" naming the run file and
"copies" naming the other locations seen, so attribution and provenance
are explicit. Candidates that failed to compile are indexed with
expect "fail" so the technique is still recorded; prune by hand if unwanted.
"""
import argparse, glob, json, re, sys, urllib.request
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dedup import content_id, choose_original, foreign_copies, entry_id  # noqa: E402
from snapshot import body_of, header  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
INDEX, RULES, CACHE, SEEN = ROOT / "index", ROOT / "rules", ROOT / "cache", ROOT / "discovery" / "seen.json"

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "yara-lapidary/1.0"})
    return urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace")

def existing_ids_and_cids():
    ids, cids = set(), {}
    for p in INDEX.glob("*.json"):
        e = json.loads(p.read_text()); ids.add(e.get("id", p.stem))
        r = RULES / f"{e.get('id', p.stem)}.yar"
        if r.exists(): cids[content_id(body_of(r.read_text(errors="replace")))] = e.get("id", p.stem)
    return ids, cids

def unique_id(base, taken):
    eid, n = base, 2
    while eid in taken: eid, n = f"{base}_{n}", n + 1
    taken.add(eid); return eid

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default=str(ROOT / "discovery" / "runs" / "*.json"))
    ap.add_argument("--min-density", type=float, default=0.0)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    ids, cids = existing_ids_and_cids()
    # one record per repo:path, keeping the latest run (a file examined in two runs is one rule)
    latest = {}
    for f in sorted(glob.glob(a.runs)):
        for c in json.load(open(f)):
            if c.get("density", 0) < a.min_density: continue
            c["_run"] = Path(f).name; latest[f"{c['repo'].lower()}:{c['path']}"] = c
    records = list(latest.values())
    texts = {}
    for i, c in enumerate(records):
        try: texts[i] = fetch(c["source_url"])
        except Exception as ex: print(f"skip {c['repo']}/{c['path']}: {ex}", file=sys.stderr)
    records = [r for i, r in enumerate(records) if i in texts]; texts = {i: texts[j] for i, j in enumerate(sorted(texts))}
    # drop copies of another owner's rule before content grouping; remember them per (owner, basename)
    foreign = foreign_copies(records, texts)
    copies_of, seen = {}, (json.loads(SEEN.read_text()) if SEEN.exists() else {})
    for i, o in foreign.items():
        r = records[i]; base = r["path"].split("/")[-1].lower()
        copies_of.setdefault((o, base), []).append(f"{r['repo']}/{r['path']}")
        prev = seen.get(f"{r['repo'].lower()}:{r['path']}")
        seen[f"{r['repo'].lower()}:{r['path']}"] = {"date": prev["date"] if isinstance(prev, dict) else (prev or date.today().isoformat()),
                                                     "sha256": content_id(texts[i]), "canonical": f"copy of {o}'s {base}"}
        print(f"copy   {r['repo']}/{r['path']}  (copy of {o}'s rule)")
    groups = {}
    for i, c in enumerate(records):
        if i in foreign: continue
        g = groups.setdefault(content_id(texts[i]), {"text": texts[i], "copies": [], "runs": set()})
        g["copies"].append(c); g["runs"].add(c["_run"])
    written, skipped = 0, 0
    for cid, g in groups.items():
        if cid in cids:
            skipped += 1; continue
        orig, reason = choose_original(g["copies"], g["text"])
        eid = unique_id(entry_id(orig["author"], orig["path"]), ids)
        base = orig["path"].split("/")[-1].lower()
        same_name = sorted({r["repo"] for r in records if r["path"].split("/")[-1].lower() == base
                            and r["repo"].split("/")[0].lower() != orig["repo"].split("/")[0].lower()})
        hint = f" Same filename also under {', '.join(same_name)}; content differs, verify which is the author's." if same_name else ""
        extra = copies_of.get((orig["repo"].split("/")[0].lower(), orig["path"].split("/")[-1].lower()), [])
        entry = {
            "id": eid, "source_url": orig["source_url"], "html_url": orig["html_url"], "author": orig["author"],
            "license": orig.get("license", "unspecified"), "techniques": sorted(orig.get("signals", {})),
            "notes": f"Auto-promoted from discovery; origin chosen because: {reason}. Review the technique tags.{hint}",
            "expect": orig.get("status", "pass"), "promoted_from": sorted(g["runs"]),
            "copies": sorted({f"{c['repo']}/{c['path']}" for c in g["copies"] if c is not orig} | set(extra)),
            "fetched": date.today().isoformat(),
        }
        if orig.get("origin_note"): entry["origin_note"] = orig["origin_note"]
        print(f"{'would write' if a.dry_run else 'write'} {eid:55} <- {orig['repo']}/{orig['path']}  ({reason}; {len(entry['copies'])} copies)")
        if a.dry_run: continue
        (INDEX / f"{eid}.json").write_text(json.dumps(entry, indent=2) + "\n")
        CACHE.mkdir(exist_ok=True); (CACHE / f"{eid}.yar").write_text(g["text"])
        (RULES / f"{eid}.yar").write_text(header(entry) + g["text"]); written += 1
        for c in g["copies"]:
            k = f"{c['repo'].lower()}:{c['path']}"; prev = seen.get(k)
            seen[k] = {"date": prev["date"] if isinstance(prev, dict) else (prev or entry["fetched"]), "sha256": cid,
                       "canonical": f"{orig['repo'].lower()}:{orig['path']}", "indexed_as": eid}
    if not a.dry_run:
        for k, v in list(seen.items()):
            if not isinstance(v, dict): seen[k] = {"date": v, "sha256": None, "canonical": None}
        SEEN.write_text(json.dumps(seen, indent=2, sort_keys=True) + "\n")
    print(f"{written} entries written, {skipped} already indexed, {len(groups)} distinct rules across candidates")

if __name__ == "__main__":
    main()
