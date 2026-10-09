#!/usr/bin/env python3
"""Resolve GitHub URLs to their upstream origin and verify index entries.

  origin.py resolve <url>      print an index-entry skeleton for a github.com blob URL,
                               a raw.githubusercontent.com URL or a gist URL, rewritten to
                               the upstream (non-fork) repository and pinned to a commit
  origin.py verify             check every index/*.json: repository is not a fork, URL is
                               pinned to a 40-hex commit (or gist revision); exit 1 on failure

GitHub code search returns files from forks, which may be modified or stale.
The API's `source` object is "the ultimate source for the network", so a fork
of a fork still resolves to the root. Gists expose `fork_of`. Set GH_TOKEN or
GITHUB_TOKEN to raise the rate limit (60/h unauthenticated, 5000/h with a token).
"""
import json, os, re, sys, urllib.error, urllib.parse, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "index"
API = "https://api.github.com"
SHA40 = re.compile(r"^[0-9a-f]{40}$")

def api(path):
    req = urllib.request.Request(API + path, headers={"Accept": "application/vnd.github+json",
                                                      "User-Agent": "yara-lapidary/1.0"})
    tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        # The Actions GITHUB_TOKEN is refused by the gists API (403); public data is still
        # readable anonymously, so retry once without credentials.
        if tok and e.code in (401, 403):
            req.remove_header("Authorization")
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        raise

RE_BLOB = re.compile(r"^https?://github\.com/([^/]+)/([^/]+)/(?:blob|raw)/([^/]+)/(.+?)(?:#.*)?$")
RE_RAW = re.compile(r"^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$")
RE_GIST = re.compile(r"^https?://gist\.github(?:usercontent)?\.com/(?:([^/]+)/)?([0-9a-f]{20,32})(?:/raw(?:/([0-9a-f]{40}))?/(.+))?")

def resolve_repo(owner, repo, ref, path):
    meta = api(f"/repos/{owner}/{repo}")
    origin = meta["source"]["full_name"] if meta.get("fork") else meta["full_name"]
    note = ""
    if origin != f"{owner}/{repo}":
        note = f"resolved from fork {owner}/{repo}"
    o_owner = origin.split("/")[0]
    o_meta = meta["source"] if meta.get("fork") else meta
    branch = o_meta["default_branch"]
    # pin to the newest commit that touched this path on the default branch of the origin
    commits = api(f"/repos/{origin}/commits?path={urllib.parse.quote(path)}&sha={branch}&per_page=1")
    if not commits:
        raise SystemExit(f"{path} does not exist in {origin}@{branch}; the fork may have added it")
    sha = commits[0]["sha"]
    if SHA40.match(ref) and ref != sha and not meta.get("fork"):
        note = (note + "; " if note else "") + f"requested ref {ref[:12]} differs from latest {sha[:12]}"
    qpath = urllib.parse.quote(path, safe="/")
    return {
        "source_url": f"https://raw.githubusercontent.com/{origin}/{sha}/{qpath}",
        "html_url": f"https://github.com/{origin}/blob/{sha}/{qpath}",
        "author": o_owner, "license": (o_meta.get("license") or {}).get("spdx_id") or "unspecified",
        "origin_note": note,
    }

def resolve_gist(owner, gid, path):
    g = api(f"/gists/{gid}")
    if g.get("fork_of"):
        g = api(f"/gists/{g['fork_of']['id']}")
    owner, gid, ver = g["owner"]["login"], g["id"], g["history"][0]["version"]
    files = list(g["files"])
    if path is None and len(files) == 1:
        path = files[0]
    if path is None or path not in files:
        raise SystemExit(f"gist has files {files}; pass the file in the URL")
    return {
        "source_url": f"https://gist.githubusercontent.com/{owner}/{gid}/raw/{ver}/{urllib.parse.quote(path)}",
        "html_url": f"https://gist.github.com/{owner}/{gid}", "author": owner, "license": "unspecified",
        "format": "markdown-fenced" if path.lower().endswith(".md") else "yara",
    }

def resolve(url):
    m = RE_BLOB.match(url) or RE_RAW.match(url)
    if m:
        return resolve_repo(*m.groups())
    m = RE_GIST.match(url)
    if m:
        owner, gid, _, path = m.groups()
        return resolve_gist(owner, gid, urllib.parse.unquote(path) if path else None)
    raise SystemExit("unsupported URL; give a github.com blob, raw.githubusercontent.com or gist URL")

def _meta(path):
    """API lookup that degrades to None when the token is refused or the quota is gone."""
    try:
        return api(path)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403, 429):
            return None
        raise

def verify():
    bad = 0
    for p in sorted(INDEX.glob("*.json")):
        e = json.loads(p.read_text()); url = e["source_url"]; problems = []
        m = RE_RAW.match(url)
        g = RE_GIST.match(url)
        if m:
            owner, repo, ref, _ = m.groups()
            meta = _meta(f"/repos/{owner}/{repo}")
            if meta is None:
                problems.append("fork status unverified (API unavailable)")
            elif meta.get("fork"):
                problems.append(f"fork of {meta['source']['full_name']}")
            if not SHA40.match(ref):
                problems.append(f"not pinned to a commit (ref '{ref}')")
        elif g:
            owner, gid, ver, _ = g.groups()
            meta = _meta(f"/gists/{gid}")
            if meta is None:
                problems.append("fork status unverified (API unavailable)")
            elif meta.get("fork_of"):
                problems.append(f"gist fork of {meta['fork_of']['owner']['login']}/{meta['fork_of']['id']}")
            if not ver:
                problems.append("gist not pinned to a revision")
        else:
            problems.append("not a GitHub URL, verify origin manually") if e.get("origin_check", True) else None
        status = "ok " if not problems else "BAD"
        print(f"{status} {e.get('id', p.stem):40} {'; '.join(problems)}")
        bad += any(x.startswith(("fork", "gist fork")) for x in problems)
    return 1 if bad else 0

if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) == 2 and a[0] == "resolve":
        print(json.dumps(resolve(a[1]), indent=2))
    elif a == ["verify"]:
        sys.exit(verify())
    else:
        sys.exit(__doc__)
