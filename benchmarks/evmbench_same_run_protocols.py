#!/usr/bin/env python3
"""Score ONE MIESC run on EVMBench under every protocol (Paper 1, Section IV).

The paper's lenient-matcher figures and its official-grader figure came from
separate runs of the same pipeline. This script scans each audit once, stores
the findings, and scores that same set of findings with:

  * the lenient multi-signal matcher (keyword signals only, as in the paper),
    on all local vulnerabilities and on the control-resistant subset;
  * the official EVMBench detect JUDGE_PROMPT, once per judge model
    (default: gpt-4o and gpt-5, the latter being EVMBench's own judge).

Per-vulnerability verdicts are saved, so lenient/official agreement can be
computed (Reviewer B's request). Findings are saved per audit, so a run can be
re-judged later without re-scanning (--rejudge).

Usage (repository root, keys loaded from .env):
    set -a; source .env; set +a
    git clone --depth 1 --recurse-submodules https://github.com/paradigmxyz/evmbench /tmp/evmbench
    python benchmarks/evmbench_same_run_protocols.py --model claude \
        --judges gpt-4o,gpt-5 --out benchmarks/results/evmbench/same_run_claude_20261016
    # re-judge stored findings only:
    python benchmarks/evmbench_same_run_protocols.py --rejudge --judges gpt-5 \
        --out benchmarks/results/evmbench/same_run_claude_20261016
"""

import argparse
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ev = _load("evmbench_eval")
ev._USE_LLM_JUDGE = False
od = _load("evmbench_official_detect")
nc = _load("evmbench_matcher_null_control")


def judge(audit_md, vuln_text, model):
    """Official JUDGE_PROMPT. Reasoning models (gpt-5, o*) need a large completion
    budget; an empty answer is an error, never a silent 'not detected'."""
    if not audit_md.strip():
        return False
    if not model.startswith(("gpt-5", "o1", "o3", "o4")):
        return od.official_judge(audit_md, vuln_text, model)
    import openai

    client = openai.OpenAI()
    user = f"Audit content:\n{audit_md}\n\nVulnerability description:\n{vuln_text}"
    last = None
    for attempt in range(6):
        try:
            r = client.chat.completions.create(
                model=model,
                max_completion_tokens=4000,
                messages=[
                    {"role": "system", "content": od.JUDGE_PROMPT},
                    {"role": "user", "content": user},
                ],
            )
            txt = (r.choices[0].message.content or "").lower()
            if not txt.strip():
                raise RuntimeError("empty judge answer")
            return '"detected": true' in txt or '"detected":true' in txt
        except (
            openai.RateLimitError,
            openai.APIConnectionError,
            openai.APITimeoutError,
            openai.InternalServerError,
            RuntimeError,
        ) as e:
            last = e
            time.sleep(min(60, 10 * (attempt + 1)))
    raise RuntimeError(f"judge {model} failed: {last}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="claude")
    ap.add_argument("--judges", default="gpt-4o,gpt-5")
    ap.add_argument("--max-audits", type=int, default=40)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--rejudge", action="store_true", help="reuse stored findings, do not scan")
    a = ap.parse_args()
    judges = [j.strip() for j in a.judges.split(",") if j.strip()]
    fdir = a.out / "findings"
    fdir.mkdir(parents=True, exist_ok=True)
    os.environ["MIESC_FRONTIER_NO_FALLBACK"] = "1"

    local = ev.load_audits()
    generic = nc.GENERIC_FINDINGS
    audit_dirs = sorted(
        d for d in od.OFFICIAL_AUDITS.iterdir() if d.is_dir() and (d / "config.yaml").exists()
    )[: a.max_audits]
    verdict_path = a.out / "verdicts.json"
    verdicts = json.loads(verdict_path.read_text()) if verdict_path.exists() else {}

    for i, ad in enumerate(audit_dirs, 1):
        name = ad.name
        fpath = fdir / f"{name}.json"
        if fpath.exists():
            findings = json.loads(fpath.read_text())
        elif a.rejudge:
            print(f"[{i}] {name}: no stored findings, skipped")
            continue
        else:
            repo = od.clone_audit(name)
            if not repo:
                print(f"[{i}] {name}: clone failed")
                continue
            findings = od.miesc_ensemble_scan(repo, [a.model], 1)
            fpath.write_text(json.dumps(findings, indent=1, default=str))
        audit_md = od.findings_to_audit_md(findings, name)
        rec = verdicts.setdefault(
            name, {"n_findings": len(findings), "lenient": {}, "official": {}}
        )
        for v in local.get(name, {}).get("vulns", []):
            rec["lenient"][v["id"]] = {
                "matched": any(ev.match_finding_to_vuln(f, v) for f in findings),
                "null_control": any(ev.match_finding_to_vuln(g, v) for g in generic),
            }
        for vid, _award, text in od.load_official_vulns(ad):
            slot = rec["official"].setdefault(vid, {})
            for j in judges:
                if j not in slot:
                    slot[j] = judge(audit_md, text, j)
        verdict_path.write_text(json.dumps(verdicts, indent=1, sort_keys=True))
        print(f"[{i}/{len(audit_dirs)}] {name}: {len(findings)} findings scored")

    # summary
    len_all = [x for r in verdicts.values() for x in r["lenient"].values()]
    resist = [x for x in len_all if not x["null_control"]]
    summary = {
        "model": a.model,
        "audits": len(verdicts),
        "lenient_all": [sum(x["matched"] for x in len_all), len(len_all)],
        "lenient_control_resistant": [sum(x["matched"] for x in resist), len(resist)],
        "official": {},
    }
    for j in judges:
        vals = [s[j] for r in verdicts.values() for s in r["official"].values() if j in s]
        summary["official"][j] = [sum(vals), len(vals)]
    if len(judges) >= 2:
        pairs = [
            (s[judges[0]], s[judges[1]])
            for r in verdicts.values()
            for s in r["official"].values()
            if judges[0] in s and judges[1] in s
        ]
        summary["judge_agreement"] = [sum(x == y for x, y in pairs), len(pairs)]
    (a.out / "summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
