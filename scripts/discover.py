#!/usr/bin/env python3
"""Find advanced YARA rules on GitHub and store them in rules/.

  discover.py [--max-queries N] [--max-candidates N]   search GitHub code
  discover.py --add URL [--notes TEXT]                 add one rule by hand

Searches skip forks: a hit is only taken from a repository that is not a
fork, and resolve() refuses forks again before anything is downloaded.
Each new file is pinned to a commit, compared by content with the rules
already stored, scored for advanced constructs and, if it scores high
enough, written to rules/<id>.yar. Every examined repo:path is listed in
discovery/seen.txt so later runs skip it. Writes report/summary.md for the
pull request. Needs GH_TOKEN or GITHUB_TOKEN (code search requires auth).
"""
import argparse, os, sys, time, urllib.error, urllib.parse
from datetime import date
from common import (RULES, ROOT, NotOriginal, all_rules, api, compile_status, content_id, fenced, get,
                    resolve, rule_id, score, write_rule)

SEEN = ROOT / "discovery" / "seen.txt"
SELF = {r.lower() for r in (os.environ.get("GITHUB_REPOSITORY", ""), "r0ny123/yara-lapidary") if r}
THRESHOLD = 4

# Literal-token searches (the REST API takes no regexes). Each targets a
# construct that only appears in rules that parse structure or relate matches.
QUERIES = [
    '"math.min" "for any"', '"math.max" "for any"', '"rva_to_offset(" "uint32("', '"not defined"',
    '"for any of" "uint8(@"', '"for any of" "uint32(@"', '"math.entropy(" "@"', '"hash.md5(" "export_details"',
    '"hash.sha256(" "resources["', '"data_directories[" "virtual_address" "filesize"',
    '"rich_signature.clear_data" "for"', '"overlay.offset" "uint16"', '"@" "in (@"', '"with " "dotnet."',
    '"macho.dylib_hash"', '"elf.dynsym" "for any"', '"dotnet.user_strings" "for any"', '"lnk." "for any"',
    '"icontains" "version_info"', '"console.hex("',
]


def search(q):
    url = "/search/code?per_page=100&q=" + urllib.parse.quote(q + " language:yara")
    for attempt in (1, 2):
        try:
            return api(url).get("items", [])
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and attempt == 1:   # secondary rate limit
                time.sleep(min(int(e.headers.get("Retry-After") or 60), 120)); continue
            print(f"search failed ({e.code}): code search needs a user token (DISCOVERY_TOKEN)", file=sys.stderr)
            return None
    return None


def store(meta, text, taken, notes=""):
    """Write rules/<id>.yar; returns the id."""
    rid = base = rule_id(meta["Author"], meta["Pinned"].split("/", 6)[-1])
    n = 2
    while rid in taken:
        rid, n = f"{base}_{n}", n + 1
    taken.add(rid)
    path = RULES / f"{rid}.yar"
    meta = {**meta, "Fetched": date.today().isoformat(), "Techniques": ", ".join(score(text)[2]),
            "Expect": "pass", "Notes": notes}
    write_rule(path, meta, text)
    status, _ = compile_status(path)
    if status != "pass":   # record what YARA-X says today so CI only flags regressions
        write_rule(path, {**meta, "Expect": status}, text)
    return rid, status


def add(url, notes):
    meta = resolve(url)
    text = get(meta["Pinned"])
    text = fenced(text) if meta.get("Format") == "markdown-fenced" else text
    rid, status = store(meta, text, set(all_rules()), notes)
    print(f"rules/{rid}.yar ({status})")


def discover(max_queries, max_candidates):
    seen = set(SEEN.read_text().split()) if SEEN.exists() else set()
    rules = all_rules()
    known = {content_id(body) for _, body in rules.values()}
    known_paths = {m.get("Pinned", "") for m, _ in rules.values()}

    hits, ok = {}, 0
    for q in QUERIES[:max_queries]:
        items = search(q)
        ok += items is not None
        for it in items or []:
            repo = it["repository"]; key = f"{repo['full_name'].lower()}:{it['path']}"
            if repo.get("fork") or repo.get("private") or repo["full_name"].lower() in SELF or key in seen:
                continue
            hits.setdefault(key, [repo["owner"]["login"], repo["name"], it["path"], 0])[3] += 1
        time.sleep(8)   # code search secondary limits bite well below the documented 30/min
    if not ok:
        sys.exit("every search failed; nothing examined")

    added = []
    for key, (owner, name, path, nq) in sorted(hits.items(), key=lambda kv: -kv[1][3])[:max_candidates]:
        seen.add(key)
        try:
            meta = resolve(f"https://github.com/{owner}/{name}/blob/HEAD/{path}")
            if meta["Pinned"] in known_paths:
                continue
            text = get(meta["Pinned"])
        except (NotOriginal, ValueError, OSError) as e:
            print(f"skip {key}: {e}", file=sys.stderr); continue
        cid = content_id(text)
        total, per_rule, tags = score(text)
        if cid in known or total < THRESHOLD or per_rule < 1.0:
            continue
        known.add(cid)
        rid, status = store(meta, text, set(rules) | {a[0] for a in added})
        added.append((rid, status, total, per_rule, meta["Source"]))

    SEEN.parent.mkdir(exist_ok=True)
    SEEN.write_text("\n".join(sorted(seen)) + "\n")
    report = ROOT / "report"; report.mkdir(exist_ok=True)
    lines = [f"{len(added)} new rules from {len(hits)} unseen hits. Delete any you don't want before merging.\n",
             "| rule | status | score | per rule |", "|---|---|---|---|"]
    lines += [f"| [{rid}]({src}) | {st} | {t} | {p} |" for rid, st, t, p, src in added]
    (report / "summary.md").write_text("\n".join(lines) + "\n")
    print(f"{len(added)} new rules from {len(hits)} unseen hits")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-queries", type=int, default=len(QUERIES))
    ap.add_argument("--max-candidates", type=int, default=40)
    ap.add_argument("--add", metavar="URL")
    ap.add_argument("--notes", default="")
    a = ap.parse_args()
    if a.add:
        add(a.add, a.notes)
    else:
        discover(a.max_queries, a.max_candidates)


if __name__ == "__main__":
    main()
