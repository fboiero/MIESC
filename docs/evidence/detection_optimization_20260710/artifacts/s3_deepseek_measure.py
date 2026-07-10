"""Stage-3 measurement: DeepSeek-V4 type-aware recall on the 29-vuln corpus.

Runs DeepSeek (reasoner) over the 4 frozen corpus contracts, parses structured
findings, and matches them to the ground truth (line +/-5 AND a type keyword).
Prompt is configurable so we can compare a neutral baseline against a
DeFi-economic-aware "lever" prompt. Additive dated artifact; reads corpus,
writes JSON. Usage: python3 s3_deepseek_measure.py <baseline|lever>
"""
import json
import os
import re
import sys
from pathlib import Path

import openai

CORPUS = Path("docs/evidence/corpus_revalidation_20260709/corpus")
MODEL = "deepseek-reasoner"

# Ground truth: (contract, line, {type keywords}) — 29 vulns, from the dossier
# EVIDENCE.md section 4 (per-vuln verification table).
GT = {
    "VulnerableBank.sol": [
        (34, {"reentran"}), (51, {"reentran"}),
    ],
    "UnsafeToken.sol": [
        (32, {"zero", "address"}), (44, {"approve", "race", "front", "tod"}),
        (53, {"unchecked", "return"}), (66, {"mint", "unrestricted", "access", "rug"}),
        (77, {"burn", "unrestricted", "access"}), (88, {"reentran", "external", "call"}),
        (101, {"dos", "gas", "denial"}), (109, {"timestamp", "time"}),
        (115, {"random", "weak"}), (138, {"locked", "ether", "lock"}),
    ],
    "AccessControlFlawed.sol": [
        (27, {"access", "owner", "unprotected"}), (34, {"origin", "tx.origin"}),
        (45, {"admin", "access"}), (52, {"selfdestruct", "suicide"}),
        (59, {"pause", "access"}), (65, {"initiali", "unprotected"}),
        (74, {"front", "ownership", "transfer"}),
    ],
    "FlashLoanVault.sol": [
        (52, {"oracle", "price", "manipulation"}), (58, {"reentran", "flash"}),
        (72, {"unchecked", "external", "call"}), (85, {"price", "manipulation", "oracle"}),
        (92, {"slippage", "mev", "sandwich"}), (112, {"first", "depositor", "inflation", "share"}),
        (125, {"round", "share", "precision"}), (138, {"borrow", "state", "check"}),
        (156, {"arithmetic", "overflow", "underflow", "unchecked"}),
        (167, {"timelock", "emergency", "withdraw"}),
    ],
}

BASELINE_PROMPT = (
    "You are a smart-contract security auditor. Analyze the contract and report "
    "EVERY security vulnerability you find. Respond ONLY with a JSON array; each "
    "item: {{\"line\": <int>, \"type\": \"<short type>\", \"swc\": \"<SWC-id or ''>\", "
    "\"severity\": \"<critical|high|medium|low>\"}}.\n\nContract {name}:\n```solidity\n{code}\n```"
)

LEVER_PROMPT = (
    "You are a senior DeFi smart-contract security auditor. Analyze the contract "
    "and report EVERY vulnerability, paying special attention to BUSINESS-LOGIC and "
    "DeFi-ECONOMIC flaws that pattern scanners miss: oracle/price manipulation (spot "
    "price without TWAP), share-inflation / first-depositor attacks, rounding in share "
    "math, flash-loan-enabled state manipulation, missing slippage/timelock, and "
    "unchecked cross-function reentrancy. Do not only report syntactic issues. Respond "
    "ONLY with a JSON array; each item: {{\"line\": <int>, \"type\": \"<short type>\", "
    "\"swc\": \"<SWC-id or ''>\", \"severity\": \"<critical|high|medium|low>\"}}.\n\n"
    "Contract {name}:\n```solidity\n{code}\n```"
)


def extract_json(text):
    m = re.search(r"\[.*\]", text or "", re.DOTALL)
    if not m:
        return []
    try:
        return json.loads(m.group(0))
    except Exception:
        return []


def matched(gt_line, kws, findings):
    for f in findings:
        try:
            fl = int(f.get("line", -999))
        except Exception:
            continue
        if abs(fl - gt_line) <= 5:
            blob = f"{f.get('type','')} {f.get('swc','')} {f.get('severity','')}".lower()
            if any(k in blob for k in kws):
                return True
    return False


def main():
    variant = sys.argv[1] if len(sys.argv) > 1 else "baseline"
    prompt_tmpl = LEVER_PROMPT if variant == "lever" else BASELINE_PROMPT
    client = openai.OpenAI(base_url="https://api.deepseek.com",
                           api_key=os.environ["DEEPSEEK_API_KEY"])
    per_contract, total_hit, total = {}, 0, 0
    raw = {}
    for name, vulns in GT.items():
        code = (CORPUS / name).read_text()
        resp = client.chat.completions.create(
            model=MODEL, max_tokens=32768,
            messages=[{"role": "user", "content": prompt_tmpl.format(name=name, code=code)}],
        )
        findings = extract_json(resp.choices[0].message.content)
        raw[name] = {"n_findings": len(findings), "findings": findings}
        hits = sum(1 for (ln, kws) in vulns if matched(ln, kws, findings))
        per_contract[name] = {"hit": hits, "total": len(vulns), "findings": len(findings)}
        total_hit += hits
        total += len(vulns)
        print(f"  {name:26} {hits}/{len(vulns)}  ({len(findings)} findings)")
    recall = round(total_hit / total, 4)
    out = {"variant": variant, "model": MODEL, "type_aware_recall": recall,
           "detected": total_hit, "total": total, "per_contract": per_contract, "raw": raw}
    Path(f"benchmarks/results/detection_optimization_20260710/s3_ds_{variant}.json").write_text(
        json.dumps(out, indent=2))
    print(f"\n=== {variant.upper()} DeepSeek {MODEL}: type-aware recall = "
          f"{total_hit}/{total} = {recall:.1%} ===")


if __name__ == "__main__":
    main()
