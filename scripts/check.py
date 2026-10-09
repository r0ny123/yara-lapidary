#!/usr/bin/env python3
"""Compile every cached rule file with YARA-X and write report/.

For each index entry: yr check (diagnostics), yr fmt --check, yr compile,
yr debug atoms --json (if the binary has it). Writes report/report.json and
report/REPORT.md. Exit code 1 when an entry does worse than its `expect`
value (pass < warn < fail).
"""
import json, os, re, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX, CACHE, REPORT = ROOT / "index", ROOT / "cache", ROOT / "report"
YR = os.environ.get("YR") or shutil.which("yr") or sys.exit("no yr binary: set YR or put yr on PATH")
LEVEL = {"pass": 0, "warn": 1, "fail": 2}

def run(*args):
    r = subprocess.run([YR, *args], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr

def diagnostics(text):
    return sorted(set(re.findall(r"^(error|warning)\[([A-Za-z0-9_]+)\]", text, re.M)))

def atoms(path):
    rc, out = run("debug", "atoms", "--json", str(path))
    if rc != 0 or not out.strip().startswith("["):
        return None
    lens = [len(a) // 2 for e in json.loads(out) for a in e["atoms"]]
    return {"count": len(lens), "min_bytes": min(lens) if lens else 0}

def main():
    REPORT.mkdir(exist_ok=True)
    version = run("--version")[1].strip()
    rows, worst_exceeded = [], 0
    for p in sorted(INDEX.glob("*.json")):
        e = json.loads(p.read_text()); eid = e.get("id", p.stem); expect = e.get("expect", "pass")
        src = CACHE / f"{eid}.yar"
        if not src.exists():
            rows.append({"id": eid, "status": "missing", "expect": expect}); worst_exceeded += 1; continue
        out = run("check", str(src))[1]; diags = diagnostics(out)
        errors = [d for d in diags if d[0] == "error"]; warns = [d for d in diags if d[0] == "warning"]
        # yr check exits 0 on pass, 2 on warnings, 1 on errors; trust the diagnostics, not the code
        status = "fail" if errors or "[ FAIL ]" in out else ("warn" if warns else "pass")
        fmt_ok = run("fmt", "--check", str(src))[0] == 0
        compiled = run("compile", "-o", os.devnull, str(src))[0] == 0
        rule_count = len(re.findall(r"^\s*(?:private\s+|global\s+)?rule\s+\w+", src.read_text(errors="replace"), re.M))
        row = {"id": eid, "expect": expect, "status": status, "rules": rule_count, "fmt_ok": fmt_ok,
               "compiled": compiled, "errors": [d[1] for d in errors], "warnings": [d[1] for d in warns],
               "atoms": atoms(src), "techniques": e.get("techniques", []), "html_url": e.get("html_url", "")}
        if LEVEL[status] > LEVEL.get(expect, 0):
            row["exceeded"] = True; worst_exceeded += 1
        rows.append(row)
    (REPORT / "report.json").write_text(json.dumps({"yara_x": version, "entries": rows}, indent=2))
    md = [f"# yara-exemplars report\n\nYARA-X: `{version}`  \nEntries: {len(rows)}, regressions: {worst_exceeded}\n",
          "| id | rules | status | expect | fmt | min atom | diagnostics | techniques |", "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        if r["status"] == "missing":
            md.append(f"| {r['id']} | - | missing | {r['expect']} | - | - | not fetched | |"); continue
        a = r["atoms"]; am = "n/a" if a is None else ("no patterns" if a["count"] == 0 else f"{a['min_bytes']}B/{a['count']}")
        diag = ", ".join(r["errors"] + r["warnings"]) or "clean"
        flag = " **regression**" if r.get("exceeded") else ""
        md.append(f"| [{r['id']}]({r['html_url']}) | {r['rules']} | {r['status']}{flag} | {r['expect']} | "
                  f"{'ok' if r['fmt_ok'] else 'diff'} | {am} | {diag} | {', '.join(r['techniques'])} |")
    (REPORT / "REPORT.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))
    sys.exit(1 if worst_exceeded else 0)

if __name__ == "__main__":
    main()
