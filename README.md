# yara-lapidary

A collection of public YARA rules that use advanced techniques (loops over
match offsets, arithmetic on integer reads, known-plaintext tricks, module
field relationships, hex alternatives), kept compiling under the current
YARA-X.

## Layout

```
rules/<id>.yar          the rules, each with a provenance header
discovery/seen.txt      repo:path of every file discovery has already examined
scripts/discover.py     find new rules on GitHub, or --add one by URL
scripts/check.py        compile every rule; --upstream also re-checks sources and origins
scripts/common.py       shared helpers
docs/                   technique tags and search queries
```

## Rule files

Each file in `rules/` is the upstream rule text exactly as published, below
a header:

```
// Vendored copy of a public rule, not original work of this repository.
// Source: https://github.com/<owner>/<repo>/blob/<commit>/<path>
// Pinned: https://raw.githubusercontent.com/<owner>/<repo>/<commit>/<path>
// Author: <owner>
// License: MIT
// Fetched: 2026-11-26
// Techniques: match-offset-arithmetic, read-arithmetic
// Expect: warn
// Notes: optional free text
```

`Expect` is `pass`, `warn` (compiles with known warnings) or `fail` (kept for
the technique). CI fails only when a rule does worse than expected.
`Format: markdown-fenced` marks a source whose rules sit inside ``` blocks.
Tags come from `docs/techniques.md`.

## Originals only

Sources must be the original repository or gist, never a fork, pinned to a
commit. Discovery drops search hits from forks before downloading anything,
`discover.py --add` refuses fork URLs, and `check.py --upstream` fails on any
rule whose source is a fork or no longer matches its pin.

## Adding rules

By hand:

```bash
python3 scripts/discover.py --add "https://github.com/<owner>/<repo>/blob/<ref>/<path>" --notes "why it is interesting"
python3 scripts/check.py
```

Automatically: `discover.yml` runs weekly (and on demand). It searches
GitHub code, skips forks and anything already in `rules/` or
`discovery/seen.txt`, scores each new file for advanced constructs, and
opens a pull request that adds the rules scoring high enough. Delete the
ones you don't want, then merge.

Code search needs a user token: add a fine-grained personal access token
with public repository read access as the `DISCOVERY_TOKEN` secret.

## License

Each rule keeps the license its source declares (`unspecified` when none)
and names its source and author in the header. Rules are kept for study
with attribution. Delete a rule on a takedown request or when its license
forbids redistribution.

## Requirements

Python 3.9+ (standard library only) and a `yr` binary on `PATH`, or set `YR`.
The workflows install a pinned, checksum-verified YARA-X through
`.github/actions/install-yara-x`.
