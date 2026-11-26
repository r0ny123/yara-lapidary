"""Shared helpers: GitHub API, origin resolution, rule files, YARA-X, scoring.

Every rule lives in rules/<id>.yar. The file starts with a header of
`// Key: value` lines (see FIELDS), then a blank line, then the rule text
exactly as published upstream. The header is the only metadata there is.
"""
import hashlib, json, os, re, shutil, subprocess, textwrap, urllib.error, urllib.parse, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
API = "https://api.github.com"
UA = {"User-Agent": "yara-lapidary/1.0"}
SHA40 = re.compile(r"^[0-9a-f]{40}$")
RE_BLOB = re.compile(r"^https?://github\.com/([^/]+)/([^/]+)/(?:blob|raw)/([^/]+)/(.+?)(?:#.*)?$")
RE_RAW = re.compile(r"^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$")
RE_GIST = re.compile(r"^https?://gist\.github(?:usercontent)?\.com/(?:([^/]+)/)?([0-9a-f]{20,32})(?:/raw(?:/([0-9a-f]{40}))?/(.+))?")


class NotOriginal(Exception):
    """The URL points at a fork; only original repositories are accepted."""


# ---- HTTP ---------------------------------------------------------------

def api(path):
    req = urllib.request.Request(API + path, headers={"Accept": "application/vnd.github+json", **UA})
    tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if tok and e.code in (401, 403):   # the Actions token is refused by some endpoints (gists)
            req.remove_header("Authorization")
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        raise


def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def fenced(text):
    """Rule text from the ``` blocks of a markdown file."""
    return "\n\n".join(b for b in re.findall(r"```[a-zA-Z]*\n(.*?)```", text, re.S) if "rule " in b)


def fetch_body(meta):
    text = get(meta["Pinned"])
    return fenced(text) if meta.get("Format") == "markdown-fenced" else text


# ---- origin -------------------------------------------------------------

def resolve(url):
    """Pin a github.com, raw or gist URL to a commit. Raises NotOriginal for forks."""
    m = RE_BLOB.match(url) or RE_RAW.match(url)
    if m:
        owner, repo, _, path = m.groups()
        return resolve_repo(owner, repo, urllib.parse.unquote(path))
    m = RE_GIST.match(url)
    if m:
        _, gid, _, path = m.groups()
        return resolve_gist(gid, urllib.parse.unquote(path) if path else None)
    raise ValueError("unsupported URL; give a github.com blob, raw.githubusercontent.com or gist URL")


def resolve_repo(owner, repo, path):
    meta = api(f"/repos/{owner}/{repo}")
    if meta.get("fork"):
        raise NotOriginal(f"{owner}/{repo} is a fork of {meta['source']['full_name']}")
    name, branch = meta["full_name"], meta["default_branch"]
    commits = api(f"/repos/{name}/commits?path={urllib.parse.quote(path)}&sha={branch}&per_page=1")
    if not commits:
        raise ValueError(f"{path} not found on {name}@{branch}")
    sha, q = commits[0]["sha"], urllib.parse.quote(path, safe="/")
    return {"Source": f"https://github.com/{name}/blob/{sha}/{q}",
            "Pinned": f"https://raw.githubusercontent.com/{name}/{sha}/{q}",
            "Author": meta["owner"]["login"],
            "License": (meta.get("license") or {}).get("spdx_id") or "unspecified"}


def resolve_gist(gid, path):
    g = api(f"/gists/{gid}")
    if g.get("fork_of"):
        raise NotOriginal(f"gist {gid} is a fork of {g['fork_of']['id']}")
    files = list(g["files"])
    path = path or (files[0] if len(files) == 1 else None)
    if path not in files:
        raise ValueError(f"gist has files {files}; pass the file in the URL")
    owner, ver = g["owner"]["login"], g["history"][0]["version"]
    meta = {"Source": f"https://gist.github.com/{owner}/{gid}",
            "Pinned": f"https://gist.githubusercontent.com/{owner}/{gid}/raw/{ver}/{urllib.parse.quote(path)}",
            "Author": owner, "License": "unspecified"}
    if path.lower().endswith(".md"):
        meta["Format"] = "markdown-fenced"
    return meta


# ---- rule files ---------------------------------------------------------

FIELDS = ["Source", "Pinned", "Author", "License", "Fetched", "Techniques", "Expect", "Format", "Notes"]
NOTICE = "// Vendored copy of a public rule, not original work of this repository."
HEADER_RX = re.compile(r"^// (%s):\s?(.*)$" % "|".join(FIELDS))


def read_rule(path):
    """Return (meta, body) for rules/<id>.yar."""
    with open(path, encoding="utf-8", errors="replace", newline="") as f:   # keep upstream CRLF intact
        lines = f.read().split("\n")
    meta, key, i = {}, None, int(lines[0] == NOTICE)
    while i < len(lines):
        m = HEADER_RX.match(lines[i])
        if m:
            key = m.group(1); meta[key] = m.group(2).strip()
        elif key and lines[i].startswith("//   "):   # wrapped continuation
            meta[key] += " " + lines[i][5:].strip()
        else:
            break
        i += 1
    if i < len(lines) and lines[i] == "":
        i += 1
    return meta, "\n".join(lines[i:])


def write_rule(path, meta, body):
    head = [NOTICE]
    for k in FIELDS:
        v = meta.get(k)
        if not v:
            continue
        wrapped = (textwrap.wrap(v, 90, break_on_hyphens=False, break_long_words=False) or [v]) if k == "Notes" else [v]   # never wrap URLs
        head.append(f"// {k}: {wrapped[0]}")
        head += [f"//   {w}" for w in wrapped[1:]]
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write("\n".join(head) + "\n\n" + body)


def all_rules():
    return {p.stem: read_rule(p) for p in sorted(RULES.glob("*.yar"))}


def content_id(text):
    """Hash of the rule text with trailing spaces and blank-line runs normalized."""
    lines = [ln.rstrip() for ln in text.replace("\r\n", "\n").split("\n")]
    norm = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip("\n")
    return hashlib.sha256(norm.encode()).hexdigest()


def rule_id(author, path):
    parts = path.split("/")
    stem = re.sub(r"\.(yara?|yar|md)$", "", parts[-1], flags=re.I)
    if stem.lower() in {"yara", "yar", "rules", "rule", "index", "main", "all", "signatures"} and len(parts) > 1:
        stem = parts[-2] + "_" + stem
    return re.sub(r"[^a-z0-9]+", "_", f"{author}_{stem}".lower()).strip("_")[:60]


# ---- YARA-X -------------------------------------------------------------

def yr(*args):
    exe = os.environ.get("YR") or shutil.which("yr")
    if not exe:
        raise SystemExit("no yr binary: set YR or put yr on PATH")
    r = subprocess.run([exe, *args], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def compile_status(path):
    """('pass'|'warn'|'fail', [diagnostic codes]) from `yr check`."""
    out = yr("check", str(path))[1]
    diags = sorted(set(re.findall(r"^(?:error|warning)\[([A-Za-z0-9_]+)\]", out, re.M)))
    errors = re.search(r"^error\[", out, re.M) or "[ FAIL ]" in out
    return ("fail" if errors else "warn" if diags else "pass"), diags


# ---- scoring ------------------------------------------------------------

# Signals in the rule text that mark an advanced technique, with weights.
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


def score(text):
    """(score, score per rule, sorted technique tags)."""
    total, tags = 0, []
    for rx, w, tag in SIGNALS:
        n = len(re.findall(rx, text, re.M))
        if n:
            total += w * min(n, 3); tags.append(tag)
    rules = len(re.findall(r"^\s*(?:private\s+|global\s+)?rule\s+\w+", text, re.M))
    return total, round(total / max(rules, 1), 1), sorted(tags)
