# yara-lapidary

An index of public YARA rules that use advanced techniques (loops over match
offsets, arithmetic on integer reads, known-plaintext tricks, module field
relationships, hex alternatives), with a workflow that keeps them compiling
under the current YARA-X.

The repository stores metadata, not copies. Each entry in `index/` points at
a public source URL and records the license, the author, and the techniques
the rule demonstrates. `scripts/fetch.py` downloads the sources into
`cache/` at test time; `scripts/check.py` runs `yr check`, `yr fmt --check`,
`yr compile` and `yr debug atoms` on every file and writes `report/`.

## Layout

```
index/            one JSON file per source (see schema below)
scripts/fetch.py  resolve index entries into cache/<id>.yar
scripts/check.py  compile every cached file with YARA-X, write report/
docs/queries.md   GitHub code-search queries that surface candidate rules
.github/workflows/test.yml   weekly and on push: fetch, check, publish report
```

## Index entry

```json
{
  "id": "wxs_xor_pe_header_arith",
  "source_url": "https://gist.githubusercontent.com/.../raw/rules.md",
  "html_url": "https://gist.github.com/wxsBSD/bf7b88b27e9f879016b5ce2c778d3e83",
  "author": "wxs",
  "license": "unspecified",
  "format": "markdown-fenced",
  "techniques": ["known-plaintext", "header-arithmetic", "at-computed-offset"],
  "notes": "Recovers 1-, 2- and 4-byte XOR keys from the MZ/PE header without a key search.",
  "expect": "pass"
}
```

- `format` is `yara` (default) or `markdown-fenced` (rules inside ``` blocks).
- `expect` is `pass`, `warn` (compiles with known warnings) or `fail` (known
  not to compile under YARA-X, kept for the technique; the reason goes in
  `notes`). The workflow fails only when an entry does worse than expected.
- `techniques` uses the vocabulary in `docs/techniques.md`.

## Discovery

A second workflow, `discover.yml`, runs weekly and on demand. It executes
the token-level searches in `scripts/discover.py` through the GitHub REST
API, resolves every hit to its upstream repository and pins it, skips forks,
private repositories and anything already in `index/` or
`discovery/seen.json`, downloads each file, compiles it with YARA-X and
scores the rule text for advanced constructs (match-offset and match-length
arithmetic, nested loops, module iterators, read arithmetic, hashes and
entropy over computed ranges, `with`, `defined`, computed anchors). Hits at
or above the threshold become a pull request on a `discovery/<date>` branch
containing the candidate table, entry skeletons and the updated seen list.
The workflow never writes to `index/`; promoting a candidate is a human
decision made in the pull request.

Code search needs a user token. Add a fine-grained personal access token
with public repository read access as the `DISCOVERY_TOKEN` secret; without
it the workflow tries the Actions token, which GitHub may refuse. If the
repository does not allow Actions to open pull requests, the run files an
issue instead and the branch still holds the report.

Collections that copy other people's rules are not forks and pass the origin
check. Read the rule's `author` and `reference` meta and index the author's
own repository.

## Adding an entry

1. Find a rule worth learning from (see `docs/queries.md`).
2. Add `index/<id>.json` with a stable raw URL (pin a commit for repositories).
3. Run `python3 scripts/fetch.py && python3 scripts/check.py` locally.
4. Open a pull request; the workflow attaches the report.

## Origin policy

GitHub code search returns files from forks as well as originals, and a fork
may be modified, renamed or years stale. Every entry must point at the
upstream repository, pinned to a commit, so the rule tested is the one its
author published:

```bash
python3 scripts/origin.py resolve "https://github.com/<owner>/<repo>/blob/<ref>/<path>"
python3 scripts/origin.py resolve "https://gist.github.com/<owner>/<id>"
```

The resolver asks the API for the repository; if `fork` is true it follows
`source`, which GitHub defines as "the ultimate source for the network", so a
fork of a fork still lands on the root. It then pins the path to the newest
commit on the origin's default branch and prints the entry fields. Gists are
resolved through `fork_of` and pinned to their latest revision. The workflow
runs `scripts/origin.py verify`, which fails on any entry whose repository or
gist is a fork and reports unpinned URLs. Entries that are not on GitHub set
`"origin_check": false` and explain the provenance in `notes`.

When searching, add `NOT is:fork` to exclude forks up front; see
`docs/queries.md`.

## License policy

Rules stay at their source. The index records the license stated by the
source (`unspecified` when none). Do not vendor rule text into this
repository unless the license permits redistribution, and keep attribution
in the entry.

## Workflow hygiene

Both workflows pin third-party actions to commit SHAs (Dependabot proposes
updates weekly), install YARA-X through `.github/actions/install-yara-x`,
which verifies the release tarball's SHA-256 before use, run with the
minimum token permissions each job needs, pass workflow inputs through
environment variables rather than interpolating them into scripts, and
carry timeouts and concurrency groups. Bumping YARA-X means changing the
version and checksum defaults in the composite action.

## Atoms in CI

The GitHub release binaries of YARA-X do not include the `debug` command,
so the hosted workflows report atoms as `n/a`. Atom inspection needs a
source build with `--features debug-cmd`; run `scripts/check.py` locally
with `YR` pointing at such a build to fill the column, or build one in CI
if the cost of a Rust compile is acceptable.

## Local requirements

Python 3.9+ (stdlib only) and a `yr` binary on `PATH`, or set `YR` to its
path. `yr debug atoms` needs a build with the `debug-cmd` feature; the check
script records when atoms are unavailable instead of failing.
