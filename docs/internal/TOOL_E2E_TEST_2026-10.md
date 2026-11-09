# MIESC — End-to-End Tool Test (new-user walkthrough, main v6.1.0)

**Date:** 2026-10-20
**Tester role:** First-time user, following only the public docs (`README.md`, `docs/`), no prior knowledge of the code.
**Machine:** macOS (Darwin 25.4.0), Apple Silicon (ARM64).
**Python available:** 3.14.5 (system), 3.12.6 and 3.13 via Homebrew. Installed under `python3.12` (`requires-python = ">=3.12"`).
**Base under test:** `origin/main` at commit `69d2f421` (code `miesc 6.1.0`, package layout `miesc/`, no `src/`).
**Install under test:** editable repo install (`pip install -e .`) in a fresh venv, per `docs/INSTALLATION.md`.

> Scope note: this is an honest functional pass over the **documented** happy path on one
> ARM64 macOS box. It is not a benchmark re-run and does not touch `paper/`,
> `benchmarks/results/`, or `docs/tesis`. All generated artifacts (results.json, html/pdf,
> sarif, audit json) were written to a scratch dir **outside** the repo. Frontier LLM APIs
> were **not** used: no `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` were set, and every `miesc`
> command ran under `env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY`.

> This is an independent re-run on **main v6.1.0**. A prior pass was accidentally run against
> a stale v5.5.0 branch; this report re-verifies each of that pass's findings against current
> main and tags every one as **persiste en main** or **corregido en main**. Numbers and prose
> here are from this run.

---

## TL;DR

The **core product is healthy on main**: `pip install -e .` is fast (~17 s), and
`scan` / `doctor` / `report` (html, markdown) / `export` all run with exit 0 and produce
correct output. `pytest tests/ --no-cov -q` is green (**9327 passed, 30 skipped**).
`audit full --skip-unavailable` completes in ~4 min with graceful degradation (6 missing
tools fail cleanly, run does not abort). SARIF is valid 2.1.0.

The one **blocking** bug for a new user is unchanged from the prior pass: the documented
`pip install 'miesc[mcp]'` + `miesc-mcp` path is **broken on a clean install** because the
`[mcp]` extra has no upper bound and pulls `mcp` 2.x, which the server code
(`from mcp.server.fastmcp import FastMCP`) is not written for — and the resulting error is
misleading ("MCP SDK not installed" when it *is* installed). **Persiste en main.**

Everything else is documentation drift: inconsistent tool count (50 / 35 / 29 / 51),
a version string lag (docs say 6.0.0, code is 6.1.0), a stale README MCP tool list
(11 listed incl. a non-existent `miesc_doctor`; 22 actually exposed), the minimal-install
`verify_installation.py` false alarm (django), the silent PDF→HTML fallback with exit 0,
the Ollama default picking 32b and failing to parse, and — new on v6 — several docs still
reference a `src/` package that was removed in the v6 refactor.

**Verdict on the 7 prior findings: all 7 persist on main.** One (version drift) is narrower
than before (6.0.0 vs 6.1.0, was 5.4.3 vs 5.5.0). None is corrected.

---

## Step → Expected → Observed → Severity

Severity: **bloquea** (blocks the documented workflow) · **molesta** (works but confuses /
misleads) · **cosmético** (trivial). "Expected" quotes the doc that a new user would follow.

| # | Step (as a new user would do it) | Expected (per docs) | Observed on main v6.1.0 | Severity |
|---|---|---|---|---|
| 1 | `python3.12 -m venv .venv` (INSTALLATION.md Step 2) | venv created | OK, Python 3.12.6. Command works verbatim. | — |
| 2 | `pip install -e .` (INSTALLATION.md Step 3) | installs MIESC + core deps | OK, ~17 s, exit 0. `miesc`, `miesc-mcp`, `slither` (0.11.6), `solc-select` land on PATH. | — |
| 3 | README "Slither installs automatically" (L275) | slither usable after plain install | **TRUE** — `slither-analyzer` is a core dep; `slither` runs with no extra step. INSTALLATION.md Step 5 (`pip install slither-analyzer`, L110) is therefore redundant. | cosmético |
| 4 | `python scripts/verify_installation.py` (INSTALLATION.md Verification) | "MIESC is ready to use!" | **Reports "MIESC installation has issues: Missing package: django / djangorestframework"** on the documented minimal install, **exit 1**, and tells you to run `.[full]` — a false alarm for core scanning (the quick functionality test in the same run passes). Body says "42 tools currently available"; summary line says "Tools available: **50/50**". | molesta |
| 5 | `miesc --version` | prints version | `MIESC version 6.1.0`. Code is correct; docs lag (see #15). | — |
| 6 | `miesc --help` | command list | OK, exit 0. All documented commands present (`scan`, `audit`, `report`, `export`, `doctor`, `watch`, …) plus more (`baseline`, `compliance`, `lsp`, `detect`, `evaluate`). | — |
| 7 | `miesc doctor` | tool availability table | OK, exit 0. Header "**Security Tools (50 Total)**", **42/50 available**, "Loaded 51 adapters", clear per-tool install hints, Ollama detected ("running, 15 models"). Core deps row shows Python **3.12.6** when the venv is activated (see note on the prior "3.14.5" artifact below). | — |
| 8 | `miesc scan examples/contracts/VulnerableBank.sol` | quick scan "in seconds" | OK, exit 0, ~1 s of tool time. slither + aderyn + solhint ran; FP filter removed 3, intelligence engine merged 5 dupes → **11 findings (4 HIGH, 7 MEDIUM)**. | — |
| 9 | `miesc scan … -o results.json` | writes JSON | OK, exit 0, ~39 KB valid JSON. | — |
| 10 | `miesc report results.json -f html` | HTML report | OK, exit 0, valid `<!DOCTYPE html>`. Markdown (`-f markdown`) also OK. | — |
| 11 | `miesc report results.json -t premium -f pdf -o report.pdf` **(minimal install)** | PDF report at `report.pdf` | **No PDF produced, but exit 0** and prints "OK Report saved". It silently falls back to **HTML** (writes `report.html`; `report.pdf` is never created). A CI checking the exit code would believe the PDF succeeded. | molesta |
| 12 | Troubleshooting fix `pip install -e '.[pdf]'`, retry (README L264) | PDF generated | **Works** — WeasyPrint 70.0 → valid **%PDF-1.7**, ~262 KB. Only the pip extra was missing; system libs present. README troubleshooting is accurate. | — |
| 13 | `miesc export results.json -f sarif` | SARIF file | OK, exit 0. Valid SARIF **2.1.0** (1 run, 11 results). | — |
| 14 | `miesc scan … --model ollama` (doctor's own suggestion) | local AI semantic pass | Connects to Ollama, **picks `qwen2.5-coder:32b`** (config default, not the doc-recommended 14b), runs ~42 s, then **"Could not parse response (1419 chars)" → 0 LLM findings**. Scan still completes (exit 0) with the 11 static findings — graceful, but the `--model ollama` path adds nothing here. | molesta |
| 15 | `pip install 'miesc[mcp]'` then `miesc-mcp` (README L530) | stdio MCP server starts | **BROKEN on clean install.** The `[mcp]` extra is `mcp[cli]>=1.0.0` with no upper bound → pip installs **mcp 2.3.0**, where `FastMCP` was renamed. `miesc-mcp` raises `ModuleNotFoundError: No module named 'mcp.server.fastmcp'` and surfaces the misleading **`RuntimeError: MCP SDK not installed. Install with: pip install 'mcp[cli]>=1.0.0'`** — the SDK *is* installed. `tools/list` unreachable. | **bloquea** |
| 16 | Workaround: `pip install 'mcp<2'`, probe `tools/list` over stdio | tools listed | **Works.** `mcp` 1.30.0 → `FastMCP` imports; server `miesc` (protocol 2025-11-25) returns **22 tools** via `tools/list`. README advertises only **11**, and one listed name (`miesc_doctor`) does not exist (closest real tool: `miesc_get_status`). | molesta (doc) |
| 17 | `miesc audit full … --skip-unavailable -t 120` (README "~10 min") | 9-layer audit, graceful degradation | OK, **exit 0, ~234 s**. `tools_run` = 50, **`tools_success` = 44**, `tools_failed` = 6 (`wake`, `semgrep`, `vertigo`, `mythril`, `manticore`, `certora`). Risk CRITICAL, **67 findings** (29 C / 11 H / 27 M / 0 L). Graceful degradation held. Two wrinkles below. | — |
| 18 | `pytest tests/ --no-cov -q` (README/CONTRIBUTING) | suite runs | **9327 passed, 30 skipped**, 3935 warnings, ~123 s, **exit 0**. | — |

### Two wrinkles in step 17 (`--skip-unavailable`)

- The flag is named *skip-unavailable*, but there is **no "skipped" category** in the output.
  The 6 unavailable tools that have no fallback are reported as **"Failed"** (`tools_failed`),
  which reads like an error to a new user, not an intentional skip.
- **`dagnn` and `smartbugs_ml`** are counted in **`tools_success`** (built-in ML fallback) even
  though `miesc doctor` lists them as "not installed". So the same run yields three different
  denominators: doctor 42/50 available, audit 44/50 successful, 50 adapters run — reinforcing
  the tool-count inconsistency (#b below).

---

## Re-verification of the 7 prior findings on main

| ID | Prior finding (v5.5.0) | Status on main v6.1.0 | Evidence |
|----|------------------------|-----------------------|----------|
| **(a)** | `[mcp]` extra unbounded → `miesc-mcp` breaks on mcp 2.x with misleading "MCP SDK not installed" | **persiste en main** | `pyproject.toml` L91–92 still `mcp[cli]>=1.0.0`; `.[mcp]` resolves mcp 2.3.0; `miesc/mcp_server.py` L44 imports `FastMCP`, L63 raises the misleading message. Reproduced end-to-end. |
| **(b)** | Inconsistent tool count across README / INSTALLATION / doctor | **persiste en main** | doctor "50 Total" / 42 available / "51 adapters"; README "35 analysis modules" (L201), "Tools executed: 12/29" (L108), "13 external tools" (L198); INSTALLATION "50 tools across 35 analysis modules" (L120); audit adds a 4th figure (44 successful). |
| **(c)** | Doc version strings lag the code (was 5.4.3 vs 5.5.0) | **persiste en main (narrower)** | INSTALLATION.md title (L1), "Expected output" (L321) and footer (L448) say **6.0.0**; README Docker block (L331) says "current release is **v6.0.0**"; code `__version__` is **6.1.0** (only `v6.0.0` is tagged). Also README L236 GitHub Action `uses: fboiero/MIESC@v5`. |
| **(d)** | README lists 11 MCP tools incl. a non-existent name; more are exposed | **persiste en main** | README L547 lists 11 incl. `miesc_doctor`; `tools/list` returns **22** and has **no** `miesc_doctor` (closest: `miesc_get_status`). |
| **(e)** | `verify_installation.py` fails on the minimal install due to django | **persiste en main** | On `pip install -e .`, script exits **1** with "Missing package: django / djangorestframework" and recommends `.[full]`, though core scanning works. |
| **(f)** | `miesc report -f pdf` without backend returns HTML with exit 0 | **persiste en main** | Requested `-o report.pdf` on the minimal install → exit 0, "OK Report saved", actual file is `report.html`; no `report.pdf` created. |
| **(g)** | `--model ollama` picks 32b and fails to parse the response | **persiste en main** | `miesc/data/config/miesc.yaml` `default_model: qwen2.5-coder:32b` (L556). `scan --model ollama` → `frontier_llm_adapter` calls 32b → "Could not parse response (1419 chars)" → 0 findings. *Nuance:* in `audit full` the Ollama Layer 5/9 adapters **do** parse (llamaaudit 1, iAudit 3); the failure is specific to the `--model ollama` scan path. SmartGuard also hit a "JSON parse error in CoT response" + 60 s budget — parsing is fragile across LLM adapters. |

### New on v6 (not in the prior pass)

| ID | Finding | Severity | Evidence |
|----|---------|----------|----------|
| **(h)** | Docs still reference a `src/` package that **no longer exists** on main (removed in the v6 refactor; package is now `miesc/` only) | molesta | README L574 and INSTALLATION L435 `python -m src.utils.web_dashboard` (won't run); README L629 Architecture "`src/` - Internal implementation" / "dual-package architecture"; README L806 `pytest tests/ --cov=src`. |

---

## Note on the prior "Python 3.14.5 / slither 0.11.3" rows

The prior pass flagged `miesc doctor` reporting Python 3.14.5 while running under 3.12.6, and
slither 0.11.3 vs the installed 0.11.6. On this run that is a **method artifact, not a bug**:
`doctor` resolves `python` / `slither` from `PATH` (not `sys.executable`), so when the venv is
**not** activated (calling `$VENV/bin/miesc` by absolute path) it picks up the system Python
3.14.5 and the Homebrew slither 0.11.3. With the venv on `PATH` (as a user who ran
`source .venv/bin/activate` per INSTALLATION.md Step 2 would have), `doctor` correctly reports
**Python 3.12.6**. Worth at most one cosmetic line: doctor should report the interpreter it is
actually running under.

---

## Documentation-accuracy issues (summary)

| Topic | Doc says | Reality | Where |
|---|---|---|---|
| Version | `6.0.0` | `6.1.0` (only `v6.0.0` tagged) | INSTALLATION.md title / expected output / footer; README Docker block L331 |
| Action ref | `uses: fboiero/MIESC@v5` | project is on v6 | README L236 |
| Tool count | "50 tools" / "35 analysis modules" / "12/29" / "13 external" | 50 adapters, 42 available here, 44 run in audit | README L201/L108/L198; INSTALLATION L120; doctor |
| MCP install | `pip install 'miesc[mcp]'` just works | pulls mcp 2.x → broken; needs `mcp<2` | README L530; `pyproject.toml` `[mcp]` extra |
| MCP tools | 11 tools incl. `miesc_doctor` | 22 tools; no `miesc_doctor` (it's `miesc_get_status`) | README L547 |
| `src/` package | dual-package `miesc/` + `src/`; `python -m src.utils...`; `--cov=src` | no `src/` on main | README L574/L629/L806; INSTALLATION L435 |
| Slither step | separate `pip install slither-analyzer` (Step 5) | already a core dep | INSTALLATION L110 |
| verify script | prints "ready to use" | exits 1 "missing django" on the minimal install it just told you to do | INSTALLATION Verification |
| LLM "returns empty" | troubleshooting says "model isn't pulled" | model IS pulled; the failure is response **parsing** | README L765 |

---

## Suggested documentation / packaging fixes (short list)

1. **Pin the MCP extra** (code, not just docs): `mcp[cli]>=1.0.0,<2` in `pyproject.toml` — the
   server imports `mcp.server.fastmcp.FastMCP` (v1 API). Alternatively migrate
   `miesc/mcp_server.py` to the v2 `MCPServer` API. Until then the README MCP section should
   say `mcp<2`. *(blocking — issue opened, see appendix)*
2. **Make the "MCP SDK not installed" message honest** (`mcp_server.py` L63) — it fires on any
   `ImportError`, including a version mismatch. Print the real exception.
3. **Single-source the tool count.** Pick one number (the code's 50 adapters) and fix the
   README "35 analysis modules" table, the "12/29" example output, and INSTALLATION "50 tools
   across 35 analysis modules".
4. **Bump the version strings** in `docs/INSTALLATION.md` (title / expected output / footer)
   and the README Docker block from 6.0.0 → 6.1.0 (or make them version-agnostic), and tag
   6.1.0.
5. **Fix the README MCP tool list** (11 → the real 22; drop `miesc_doctor`).
6. **Remove the stale `src/` references** (README L574/L629/L806, INSTALLATION L435) — the v6
   package is `miesc/` only; `python -m src.utils.web_dashboard` and `--cov=src` no longer work.
7. **`verify_installation.py`:** treat django/DRF as optional (only the REST API needs them),
   and reconcile "42 currently available" vs "Tools available: 50/50" so a clean minimal
   install reports success.
8. **PDF fallback:** when `-f pdf` can't produce a PDF, exit non-zero or make the "saved as
   HTML instead" loud — right now exit 0 + "OK Report saved" hides it from CI.
9. **Ollama defaults / troubleshooting:** the `--model ollama` default is `qwen2.5-coder:32b`
   while the docs recommend 14b; and the "LLM returns empty → model not pulled" troubleshooting
   is the wrong cause when parsing fails. Consider defaulting to 14b and/or logging the parse
   failure distinctly.
10. Minor: INSTALLATION Step 5 (`pip install slither-analyzer`) can be dropped (slither is a
    core dep). `--skip-unavailable` should label unavailable-no-fallback tools "skipped", not
    "failed".

---

## Appendix — exact commands

```bash
# Base: origin/main @ 69d2f421 (miesc 6.1.0). Every miesc command ran as:
#   env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY miesc ...
# All outputs written to a scratch dir OUTSIDE the repo.

python3.12 -m venv venv && . venv/bin/activate
pip install -e .
python scripts/verify_installation.py            # exits 1 (missing django) on minimal install
miesc --version                                  # MIESC version 6.1.0
miesc --help
miesc doctor                                     # 42/50 available; 3.12.6 when venv activated
miesc scan examples/contracts/VulnerableBank.sol
miesc scan examples/contracts/VulnerableBank.sol -o results.json
miesc report results.json -f html -o report.html
miesc report results.json -f markdown -o report.md
miesc report results.json -t premium -f pdf -o report.pdf   # minimal: exit 0 but writes HTML, no PDF
pip install -e '.[pdf]' && miesc report results.json -t premium -f pdf -o report.pdf  # real %PDF-1.7
miesc export results.json -f sarif -o results.sarif          # SARIF 2.1.0
miesc scan examples/contracts/VulnerableBank.sol --model ollama -o scan_ollama.json  # 32b, parse-fail, 0 LLM

# MCP tested in an ISOLATED venv to reproduce a clean `miesc[mcp]` install:
python3.12 -m venv venv_mcp
venv_mcp/bin/pip install -e '.[mcp]'             # pulls mcp 2.3.0 -> BROKEN
echo '{...initialize...}' | venv_mcp/bin/miesc-mcp   # RuntimeError: MCP SDK not installed (misleading)
venv_mcp/bin/pip install 'mcp<2'                 # 1.30.0
venv_mcp/bin/python -I mcp_probe.py venv_mcp/bin/miesc-mcp   # stdio client: tools/list -> 22 tools

miesc audit full examples/contracts/VulnerableBank.sol --skip-unavailable -t 120 -o audit_full.json  # exit 0, ~234s
pip install -e '.[dev]' && pytest tests/ --no-cov -q         # 9327 passed, 30 skipped, exit 0
```

`mcp_probe.py` is a ~20-line stdio client using the `mcp` SDK (`stdio_client` + `ClientSession`)
that performs the `initialize` → `list_tools` handshake and prints the server name, protocol,
and tool names. The raw `tools/list` call requires the handshake first, which is why a
one-shot pipe of a bare `tools/list` request looks like a false negative.

### Setup gotcha (local coordination, not a product bug)

The worktree for this task was cut from a **stale local `main`** (`be59229b`, diverged from
`origin/main` at `e5638873`, missing ~2,679 lines of `miesc/` package changes). `miesc --version`
still read 6.x, so the "if not 6.x, stop" guard did not catch it. It was fixed with
`git reset --hard origin/main` (confirming `HEAD` → `69d2f421`), leaving the local `main` ref
untouched. This is the third time a session in this family has started on a stale base; cut
tool-test worktrees from `origin/main`, not local `main`.
