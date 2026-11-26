#!/usr/bin/env python3
"""Check every rules/*.yar: header, pin, origin and YARA-X compile.

  check.py              compile each rule and compare with its Expect value
  check.py --upstream   also re-download each pinned source, require it to match
                        the stored rule, and require GitHub sources to be originals (not forks)

Prints one line per problem and a summary, writes report/REPORT.md, and
exits 1 on any problem. Expect is pass, warn or fail; only doing worse
than expected is a problem.
"""
import argparse, sys
from common import RE_GIST, RE_RAW, ROOT, SHA40, NotOriginal, all_rules, api, compile_status, fetch_body, RULES

LEVEL = {"pass": 0, "warn": 1, "fail": 2}


def origin_problems(meta):
    url = meta.get("Pinned", "")
    m, g = RE_RAW.match(url), RE_GIST.match(url)
    try:
        if m:
            owner, repo, ref, _ = m.groups()
            if not SHA40.match(ref):
                return [f"not pinned to a commit ({ref})"]
            info = api(f"/repos/{owner}/{repo}")
            if info.get("fork"):
                raise NotOriginal(f"fork of {info['source']['full_name']}")
        elif g:
            if not g.group(3):
                return ["gist not pinned to a revision"]
            if api(f"/gists/{g.group(2)}").get("fork_of"):
                raise NotOriginal("gist is a fork")
    except NotOriginal as e:
        return [str(e)]
    except Exception as e:   # API unavailable or rate-limited: warn, do not fail
        print(f"warning: origin of {url} unverified ({e})", file=sys.stderr)
    return []


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--upstream", action="store_true"); a = ap.parse_args()
    rows, problems = [], []
    for rid, (meta, body) in all_rules().items():
        mine = [f"missing {k}" for k in ("Source", "Pinned", "Author", "License", "Expect") if not meta.get(k)]
        if a.upstream:
            mine += origin_problems(meta)
            try:
                if fetch_body(meta) != body:
                    mine.append("differs from the pinned source")
            except Exception as e:
                mine.append(f"fetch failed ({e})")
        status, diags = compile_status(RULES / f"{rid}.yar")
        expect = meta.get("Expect", "pass")
        if LEVEL[status] > LEVEL.get(expect, 0):
            mine.append(f"{status} but expected {expect} ({', '.join(diags)})")
        problems += [f"{rid}: {p}" for p in mine]
        rows.append(f"| [{rid}]({meta.get('Source', '')}) | {status} | {expect} | {', '.join(diags)} | {'; '.join(mine)} |")
    report = ROOT / "report"; report.mkdir(exist_ok=True)
    (report / "REPORT.md").write_text(
        f"# Rule check\n\n{len(rows)} rules, {len(problems)} problems.\n\n"
        "| rule | status | expect | diagnostics | problems |\n|---|---|---|---|---|\n" + "\n".join(rows) + "\n")
    for p in problems:
        print(p)
    print(f"{len(rows)} rules, {len(problems)} problems")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
