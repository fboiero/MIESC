# Streamlit Cloud Deployment — MIESC Web Dashboard

Deploy the MIESC interactive dashboard at [share.streamlit.io](https://share.streamlit.io) in under five minutes.

---

## Prerequisites

- A GitHub account with access to `fboiero/MIESC` (or your own fork).
- A Streamlit Cloud account (free tier is enough for demos). Sign in with GitHub at https://share.streamlit.io.

---

## One-Time Setup

### 1. Fork or clone the repo

```bash
gh repo fork fboiero/MIESC --clone
```

### 2. Deploy from the Streamlit Cloud UI

1. Visit https://share.streamlit.io/
2. Click **"New app"**.
3. Fill in the form:
   - **Repository**: `<your-github-user>/MIESC`
   - **Branch**: `main`
   - **Main file path**: `streamlit_app.py`
   - **Python version**: `3.11` (recommended)
   - **App URL** (optional): `miesc-dashboard`
4. Click **"Deploy"**.

Streamlit Cloud will install the dependencies listed in `webapp/requirements.txt` and boot the app. First deploy takes ~3 minutes.

### 3. (Optional) Configure secrets

If you want to enable LLM features (Ollama is unavailable on Streamlit Cloud — you need a hosted provider), add them via **Settings → Secrets**:

```toml
# .streamlit/secrets.toml (managed in the Cloud UI)
OPENAI_API_KEY = "sk-..."
ANTHROPIC_API_KEY = "sk-ant-..."
```

Without secrets, the dashboard falls back to running rule-based analysis only (Slither/Aderyn/etc. are NOT installed on Streamlit Cloud — the dashboard is demo-mode: paste code, run lightweight static detectors, view results).

---

## Environment Notes

### What runs on Streamlit Cloud

- ✅ UI for code pasting, contract upload, demo contracts
- ✅ Pattern-based detectors (ClassicPatternDetector, DefiPatternDetector)
- ✅ Result visualization (Plotly charts, severity breakdowns)
- ✅ Spec generation preview (CVL / Scribble / SMTChecker snippets)
- ✅ Report rendering (Markdown / HTML)

### What does NOT run on Streamlit Cloud

- ❌ External binaries (Slither, Aderyn, Mythril, Halmos, Certora) — Streamlit Cloud is a read-only Python env.
- ❌ Ollama (requires local server) — use OpenAI/Anthropic secrets for LLM features, or disable them.
- ❌ Docker-dependent tools (Echidna, Medusa).

For full audits → use the `miesc` CLI locally or via Docker (`ghcr.io/fboiero/miesc:latest`).

---

## Updating the Deployed App

Streamlit Cloud auto-redeploys on every push to the configured branch. No action needed:

```bash
git push origin main
# → Streamlit Cloud detects the change and rebuilds within ~1 minute.
```

To force a rebuild (e.g. after editing `requirements.txt` or Streamlit secrets), use **"Reboot app"** in the Cloud UI.

---

## Troubleshooting

### `ModuleNotFoundError` on boot

Check that `webapp/requirements.txt` lists every third-party import used by `webapp/app.py`. Streamlit Cloud installs ONLY what's in that file.

### "App exceeded resource limits"

Streamlit's free tier offers 1 GB RAM / 1 CPU. The dashboard is tuned for that, but heavy LLM calls or huge contracts will OOM. Move long-running audits to the CLI.

### Import errors for `src.miesc_core`

Streamlit Cloud clones the whole repo — the `sys.path.insert` line in `webapp/app.py:22` must point at the repo root so `src/` is importable. This is already correct in the shipped code; don't remove it.

### "Repository not found"

Streamlit Cloud cannot access private repos unless you grant its GitHub app access. In GitHub → Settings → Applications → Streamlit, add the repo to the app's allowlist.

---

## Local Preview

Before pushing, verify the app runs locally:

```bash
cd /path/to/MIESC
pip install -r webapp/requirements.txt
streamlit run webapp/app.py
# Open http://localhost:8501
```

---

## Maintenance Checklist

- On every release (e.g. v5.4.2), `webapp/app.py` now reads `miesc.__version__` dynamically — no manual version bump needed.
- If a new dashboard feature requires a new dependency, add it to `webapp/requirements.txt` AND the root `pyproject.toml`.
- Keep `webapp/requirements.txt` pinned lightly (use `>=` not `==`) so Streamlit Cloud can resolve compatible versions.

---

## Live Example

If you're reading this after the public deployment is set up:
- Dashboard: https://miesc-dashboard.streamlit.app (set this once you've deployed).
- Source: https://github.com/fboiero/MIESC/blob/main/webapp/app.py
