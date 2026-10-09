# yara-exemplars

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

## Adding an entry

1. Find a rule worth learning from (see `docs/queries.md`).
2. Add `index/<id>.json` with a stable raw URL (pin a commit for repositories).
3. Run `python3 scripts/fetch.py && python3 scripts/check.py` locally.
4. Open a pull request; the workflow attaches the report.

## License policy

Rules stay at their source. The index records the license stated by the
source (`unspecified` when none). Do not vendor rule text into this
repository unless the license permits redistribution, and keep attribution
in the entry.

## Local requirements

Python 3.9+ (stdlib only) and a `yr` binary on `PATH`, or set `YR` to its
path. `yr debug atoms` needs a build with the `debug-cmd` feature; the check
script records when atoms are unavailable instead of failing.
