#!/usr/bin/env python3
"""Find candidate rules on GitHub, resolve them upstream, compile and score them.

  discover.py [--max-queries N] [--max-candidates N] [--out DIR]

Runs the token-level code searches in QUERIES through the REST API (which
takes literal tokens, not regexes), drops hits from forks after resolving
them to the network source, pins each file to a commit, downloads it,
compiles it with YARA-X and scores the rule text for advanced constructs.

Identity is by content: files with the same normalized text are one rule.
Copies already indexed or already examined are skipped, and among copies
found in one run the original is chosen (see dedup.py). discovery/seen.json
maps every examined repo:path to {date, sha256, canonical}. Writes
<out>/candidates.md and <out>/candidates.json. Never touches index/.
Needs GH_TOKEN or GITHUB_TOKEN (code search requires auth).
"""
import argparse, json, os, re, subprocess, sys, time, urllib.error, urllib.parse, urllib.request
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from origin import api, resolve_repo  # noqa: E402
from dedup import content_id, choose_original, foreign_copies  # noqa: E402
from snapshot import body_of  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
INDEX, RULES, SEEN = ROOT / "index", ROOT / "rules", ROOT / "discovery" / "seen.json"
YR = os.environ.get("YR") or "yr"
# This repository's own vendored copies are indexed by code search too; never propose them back.
SELF_REPOS = {r.lower() for r in (os.environ.get("GITHUB_REPOSITORY", ""), "r0ny123/yara-lapidary") if r}

# Literal-token searches. Each targets a construct that only appears in rules
# that parse structure or relate matches to each other.
QUERIES = [
    '"math.min" "for any" language:yara',
    '"math.max" "for any" language:yara',
    '"rva_to_offset(" "uint32(" language:yara',
    '"not defined" language:yara',
    '"for any of" "uint8(@" language:yara',
    '"for any of" "uint32(@" language:yara',
    '"math.entropy(" "@" language:yara',
    '"hash.md5(" "export_details" language:yara',
    '"hash.sha256(" "resources[" language:yara',
    '"data_directories[" "virtual_address" "filesize" language:yara',
    '"rich_signature.clear_data" "for" language:yara',
    '"overlay.offset" "uint16" language:yara',
    '"@" "in (@" language:yara',
    '"with " "dotnet." language:yara',
    '"macho.dylib_hash" language:yara',
    '"elf.dynsym" "for any" language:yara',
    '"dotnet.user_strings" "for any" language:yara',
    '"lnk." "for any" language:yara',
    '"icontains" "version_info" language:yara',
    '"console.hex(" language:yara',
]

# Signals in the rule text and their weights.
SIGNALS = [
    (r"@[A-Za-z_0-9]+(\[[^\]]+\])?\s*[-+<>=]", 3, "match-offset-arithmetic"),
    (r"![A-Za-z_0-9]+(\[[^\]]+\])?\s*[-+<>=)]", 3, "match-length"),
    (r"for\s+(any|all|\d+)\s+[a-z_]+\s+in\s*\([^)]*\)\s*:\s*\(\s*for\s", 3, "nested-loop"),
    (r"for\s+(any|all|\d+)\s+[a-z_]+\s+in\s+(pe|elf|macho|dotnet|lnk|dex)\.", 2, "module-iterator"),
    (r"uint(8|16|32)(be)?\([^)]*\)\s*(\^|<<|>>|&|%|\\)", 2, "read-arithmetic"),
    (r"uint(16|32)\(uint(16|32)\(", 2, "header-arithmetic"),
    (r"math\.(entropy|mean|mode|percentage|count)\(\s*(pe\.|@|uint)", 2, "entropy-range"),
    (r"hash\.(md5|sha1|sha256|crc32|checksum32)\(\s*(pe\.|@|uint|int32)", 2, "content-hash-range"),
    (r"math\.(min|max)\(", 1, "capped-loop"),
    (r"\bwith\s+[a-z_]+\s*=", 2, "yara-x-only"),
    (r"\bdefined\s", 1, "defined"),
    (r"rva_to_offset\(|data_directories\[|export_details|rich_signature|overlay\.", 1, "pe-structure"),
    (r"\$[A-Za-z_0-9]+\s+at\s+(pe\.|uint|@|\()", 2, "at-computed-offset"),
    (r"\$[A-Za-z_0-9]+\s+in\s*\(@", 2, "pattern-in-window"),
    (r"\(\s*[0-9A-Fa-f?]{2}(\s+[0-9A-Fa-f?]{2})*\s*\|", 1, "hex-alternatives"),
    (r"\b(macho|elf|dotnet|lnk|dex)\.[a-z_]+", 1, "non-pe-module"),
]
THRESHOLD = 4
SEARCH_OK = 0

def search(q):
    global SEARCH_OK
    url = "/search/code?q=" + urllib.parse.quote(q) + "&per_page=100"
    for attempt in (1, 2):
        try:
            items = api(url).get("items", []); SEARCH_OK += 1; return items
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and attempt == 1:
                time.sleep(min(int(e.headers.get("Retry-After") or 60), 120)); continue  # secondary rate limit
            print(f"search failed ({e.code}) for {q}: code search needs a user token with public repo read "
                  f"(DISCOVERY_TOKEN); the Actions token is rate-limited to nothing", file=sys.stderr)
            return []
    return []

def load_seen():
    """seen.json: repo:path -> {date, sha256, canonical}. Older string values are migrated."""
    raw = json.loads(SEEN.read_text()) if SEEN.exists() else {}
    return {k: (v if isinstance(v, dict) else {"date": v, "sha256": None, "canonical": None}) for k, v in raw.items()}

def indexed():
    """(repo:path) keys and content ids of everything already in index/ and rules/."""
    keys, cids = set(), {}
    for p in INDEX.glob("*.json"):
        e = json.loads(p.read_text())
        m = re.match(r"https://raw\.githubusercontent\.com/([^/]+/[^/]+)/[^/]+/(.+)", e["source_url"])
        if m: keys.add(f"{m.group(1).lower()}:{urllib.parse.unquote(m.group(2))}")
        r = RULES / f"{e.get('id', p.stem)}.yar"
        if r.exists(): cids[content_id(body_of(r.read_text(errors='replace')))] = e.get("id", p.stem)
    return keys, cids

def yr(*args):
    r = subprocess.run([YR, *args], capture_output=True, text=True); return r.returncode, r.stdout + r.stderr

def assess(text):
    hits, score = {}, 0
    for rx, w, tag in SIGNALS:
        n = len(re.findall(rx, text, re.M))
        if n: hits[tag] = n; score += w * min(n, 3)
    return score, hits

def compile_info(out, text):
    tmp = out / "cand.yar"; tmp.write_text(text)
    chk = yr("check", str(tmp))[1]; diags = sorted(set(re.findall(r"^(?:error|warning)\[([A-Za-z0-9_]+)\]", chk, re.M)))
    status = "fail" if "[ FAIL ]" in chk else ("warn" if diags else "pass")
    rc, at = yr("debug", "atoms", "--json", str(tmp)); min_atom = None
    if rc == 0 and at.strip().startswith("["):
        lens = [len(x) // 2 for e in json.loads(at) for x in e["atoms"]]; min_atom = min(lens) if lens else 0
    tmp.unlink(missing_ok=True)
    return status, diags, min_atom

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-queries", type=int, default=len(QUERIES))
    ap.add_argument("--max-candidates", type=int, default=40)
    ap.add_argument("--out", default=str(ROOT / "report"))
    a = ap.parse_args()
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    seen = load_seen(); known_keys, known_cids = indexed()
    seen_cids = {v["sha256"]: v["canonical"] or k for k, v in seen.items() if v.get("sha256")}
    today = date.today().isoformat()

    hits = {}
    for q in QUERIES[: a.max_queries]:
        for it in search(q):
            repo = it["repository"]; key = f"{repo['full_name'].lower()}:{it['path']}"
            if repo.get("private") or repo["full_name"].lower() in SELF_REPOS: continue
            if key in seen or key in known_keys: continue
            hits.setdefault(key, {"repo": repo["full_name"], "path": it["path"], "html_url": it["html_url"],
                                  "queries": []})["queries"].append(q.split(" language")[0])
        time.sleep(8)   # code search secondary limits bite well below the documented 30/min
    print(f"{len(hits)} unseen hits from {min(a.max_queries, len(QUERIES))} queries ({SEARCH_OK} succeeded)", file=sys.stderr)
    if SEARCH_OK == 0:
        sys.exit("every search failed; nothing examined, seen.json untouched")

    # resolve, fetch and group by content
    groups = {}   # content id -> {"text", "copies": [ {repo, path, resolved, html_url, queries} ]}
    for h in sorted(hits.values(), key=lambda h: -len(h["queries"]))[: a.max_candidates]:
        key = f"{h['repo'].lower()}:{h['path']}"
        try:
            owner, repo = h["repo"].split("/")
            r = resolve_repo(owner, repo, "HEAD", h["path"])
            req = urllib.request.Request(r["source_url"], headers={"User-Agent": "yara-lapidary/1.0"})
            text = body_of(urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace"))  # strip any provenance header a re-vendored copy carries
        except Exception as ex:
            seen[key] = {"date": today, "sha256": None, "canonical": None}
            print(f"skip {h['repo']}/{h['path']}: {ex}", file=sys.stderr); continue
        cid = content_id(text)
        if cid in known_cids or cid in seen_cids:
            seen[key] = {"date": today, "sha256": cid, "canonical": known_cids.get(cid) or seen_cids[cid]}
            continue
        g = groups.setdefault(cid, {"text": text, "copies": []})
        g["copies"].append({**h, "resolved": r, "key": key})

    # copies stored under another owner's name (or whose meta names another owner) are not candidates
    allc = [c for g in groups.values() for c in g["copies"]]
    foreign = foreign_copies(allc, {i: next(g["text"] for g in groups.values() if c in g["copies"]) for i, c in enumerate(allc)})
    for i, o in foreign.items():
        c = allc[i]; seen[c["key"]] = {"date": today, "sha256": None, "canonical": f"copy of {o}'s {c['path'].split('/')[-1]}"}
        for g in groups.values():
            if c in g["copies"]: g["copies"].remove(c)
    groups = {cid: g for cid, g in groups.items() if g["copies"]}
    cands = []
    for cid, g in groups.items():
        orig, reason = choose_original(g["copies"], g["text"])
        for c in g["copies"]:
            seen[c["key"]] = {"date": today, "sha256": cid, "canonical": orig["key"]}
        text = g["text"]
        score, sig = assess(text)
        rules = len(re.findall(r"^\s*(?:private\s+|global\s+)?rule\s+\w+", text, re.M))
        density = round(score / max(rules, 1), 1)   # per rule, so collections do not outrank single clever rules
        if score < THRESHOLD or density < 1.0: continue
        status, diags, min_atom = compile_info(out, text)
        r = orig["resolved"]
        cands.append({**r, "repo": orig["repo"], "path": orig["path"], "from_fork": bool(r.get("origin_note")),
                      "content_id": cid, "copies": [c["key"] for c in g["copies"] if c is not orig], "origin_reason": reason,
                      "score": score, "density": density, "signals": sig, "status": status, "diagnostics": diags,
                      "min_atom": min_atom, "rules": rules, "queries": sorted({q for c in g["copies"] for q in c["queries"]})})

    cands.sort(key=lambda c: (-c["density"], -c["score"]))
    (out / "candidates.json").write_text(json.dumps(cands, indent=2))
    SEEN.parent.mkdir(exist_ok=True); SEEN.write_text(json.dumps(seen, indent=2, sort_keys=True) + "\n")
    md = [f"# Discovery candidates {today}\n",
          f"{len(cands)} distinct rules scoring >= {THRESHOLD} from {sum(len(g['copies']) for g in groups.values())} examined files "
          f"({len(groups)} distinct by content). Copies are attributed to one origin; see the copies column. "
          "Review, then run `scripts/promote.py` or add entries by hand.\n",
          "| score/rule | score | status | rules | min atom | origin | copies | signals |", "|---|---|---|---|---|---|---|---|"]
    for c in cands:
        am = "n/a" if c["min_atom"] is None else f"{c['min_atom']}B"
        md.append(f"| {c['density']} | {c['score']} | {c['status']} {', '.join(c['diagnostics'])} | {c['rules']} | {am} | "
                  f"[{c['repo']}/{c['path']}]({c['html_url']}) ({c['origin_reason']}) | {len(c['copies'])} | "
                  f"{', '.join(f'{k}:{v}' for k, v in c['signals'].items())} |")
    md.append("\n## Entry skeletons\n")
    for c in cands:
        eid = re.sub(r"[^a-z0-9]+", "_", f"{c['author']}_{Path(c['path']).stem}".lower()).strip("_")
        md.append("```json\n" + json.dumps({"id": eid, "source_url": c["source_url"], "html_url": c["html_url"], "author": c["author"],
                  "license": c["license"], "techniques": sorted(c["signals"]), "notes": "", "expect": c["status"]}, indent=2) + "\n```")
    (out / "candidates.md").write_text("\n".join(md) + "\n")
    print("\n".join(md[:4 + len(cands)]))

if __name__ == "__main__":
    main()
