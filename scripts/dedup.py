#!/usr/bin/env python3
"""Content identity for rule files and selection of the original among copies.

Rules travel: collection repositories copy them, sometimes under the
author's name as a directory. Two files with the same normalized text are
one rule, examined once, attributed to one origin. The origin is chosen by:

1. the rule's own meta (`author`, `reference`, `source`, `url`) naming the
   repository owner or repository;
2. the path NOT placing the file under a directory named after another
   owner (`SEKOIA-IO/x.yar` inside someone else's repo is a copy);
3. the earliest first-commit date of the file in each repository.
"""
import hashlib, os, re, urllib.parse, urllib.request
from datetime import datetime

from origin import API, api

META_RX = re.compile(r'^\s*(author|reference|references|source|url|link)\s*=\s*"([^"]*)"', re.I | re.M)

def normalize(text):
    lines = [ln.rstrip() for ln in text.replace("\r\n", "\n").split("\n")]
    out, blank = [], False
    for ln in lines:
        if ln.strip() == "":
            if not blank: out.append("")
            blank = True
        else:
            out.append(ln); blank = False
    return "\n".join(out).strip("\n") + "\n"

def content_id(text):
    return hashlib.sha256(normalize(text).encode()).hexdigest()

def meta_mentions(text, repo):
    owner = repo.lower().split("/")[0]
    vals = " ".join(v for _, v in META_RX.findall(text)).lower()
    return repo.lower() in vals or f"github.com/{owner}/" in vals or (owner in vals and len(owner) > 3)

def under_foreign_owner(path, repo, owners):
    """True when a path directory, or the filename's prefix, names another known owner.

    `mikesxrs/.../juanandresgs/x.yara` and `CYB3RMX/.../volexity_2024_x.yar` are copies of
    rules by juanandresgs and volexity when those owners are known.
    """
    own = repo.split("/")[0].lower()
    parts = [p.lower() for p in path.split("/")[:-1]]
    base = path.split("/")[-1].lower()
    others = {o for o in owners if o != own}
    return any(p in others for p in parts) or any(base.startswith(o + "_") or base.startswith(o + "-") for o in others if len(o) > 3)

def foreign_copies(records, texts=None):
    """Map record index -> owner it copies from, for records that are copies of another owner's rule.

    A record is a copy when a path directory or the filename prefix names another owner
    among the records, or when the rule's own meta names another owner whose repository
    holds a file with the same basename. Different versions of a copied rule do not share
    a content id, so this runs before content grouping.
    """
    owners = {r["repo"].split("/")[0].lower() for r in records}
    by_owner_base = {}
    for r in records:
        by_owner_base.setdefault(r["repo"].split("/")[0].lower(), set()).add(r["path"].split("/")[-1].lower())
    out = {}
    for i, r in enumerate(records):
        own = r["repo"].split("/")[0].lower()
        parts = [p.lower() for p in r["path"].split("/")[:-1]]; base = r["path"].split("/")[-1].lower()
        for o in owners - {own}:
            if o in parts or (len(o) > 3 and (base.startswith(o + "_") or base.startswith(o + "-"))):
                out[i] = o; break
        if i in out or not texts: continue
        text = texts.get(i) or ""
        for o in owners - {own}:
            if base in by_owner_base.get(o, ()) and meta_mentions(text, f"{o}/x"):
                out[i] = o; break
    return out

GENERIC_STEMS = {"yara", "yar", "rules", "rule", "index", "main", "all", "signatures", "sigs"}

def entry_id(author, path):
    """<author>_<stem>, using the parent directory too when the stem says nothing."""
    parts = path.split("/"); stem = re.sub(r"\.(yara?|yar)$", "", parts[-1], flags=re.I)
    if stem.lower() in GENERIC_STEMS and len(parts) > 1:
        stem = parts[-2] + "_" + stem
    return re.sub(r"[^a-z0-9]+", "_", f"{author}_{stem}".lower()).strip("_")[:60]

def first_commit_date(repo, path):
    """Date of the earliest commit touching path on the default branch, via the Link header."""
    q = "/repos/%s/commits?path=%s&per_page=1" % (repo, urllib.parse.quote(path))
    try:
        req = urllib.request.Request(API + q, headers={"Accept": "application/vnd.github+json", "User-Agent": "yara-lapidary/1.0"})
        tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if tok: req.add_header("Authorization", f"Bearer {tok}")
        with urllib.request.urlopen(req, timeout=60) as r:
            link = r.headers.get("Link") or ""
        m = re.search(r'<([^>]+)>;\s*rel="last"', link)
        last = api(m.group(1).split("api.github.com")[1]) if m else api(q)
        return datetime.fromisoformat(last[-1]["commit"]["committer"]["date"].replace("Z", "+00:00"))
    except Exception:
        return None

def choose_original(copies, text):
    """copies: list of dicts with 'repo' and 'path'. Returns (original, reason)."""
    if len(copies) == 1:
        return copies[0], "only copy"
    owners = {c["repo"].split("/")[0].lower() for c in copies}
    named = [c for c in copies if meta_mentions(text, c["repo"])]
    if len(named) == 1:
        return named[0], "rule meta names this repository"
    pool = named or copies
    not_foreign = [c for c in pool if not under_foreign_owner(c["path"], c["repo"], owners)]
    if len(not_foreign) == 1:
        return not_foreign[0], "others keep it under a directory named after another owner"
    pool = not_foreign or pool
    dated = [(first_commit_date(c["repo"], c["path"]), c) for c in pool]
    dated = [(d, c) for d, c in dated if d]
    if dated:
        d, c = min(dated, key=lambda x: x[0])
        return c, f"earliest first commit ({d.date()})"
    return pool[0], "undecidable; first seen"
