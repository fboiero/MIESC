# xcapit-swarm — MIESC adoption (seed)

This branch seeds the **xcapit-swarm base** into MIESC: the reusable agent-swarm /
harness layer Xcapit maintains once and adopts across repos. It is the first proof
that the base works **beyond xNinja**, where it was extracted from.

Two independent pieces land here:

1. **The plugin** (`xcapit-swarm`) — installed from the private marketplace, giving
   MIESC the shared skills + builder agents + (default-OFF) hooks.
2. **The loop engine** — byte-identical vendored copies of the `swarm-ops` canonical
   lane scripts, plus MIESC's own config seam and a `k0+1-4` lane manifest.

---

## 1. The plugin (skills + agents)

Declared in `.claude/settings.json` (project scope), so anyone who clones MIESC and
opens Claude Code gets it:

```jsonc
"extraKnownMarketplaces": { "xcapit-marketplace": { "source": {
  "source": "git", "url": "https://gitlab.xcapit.com/fer/xcapit-marketplace.git" } } },
"enabledPlugins": { "xcapit-swarm@xcapit-marketplace": true }
```

It was added with:

```bash
claude plugin marketplace add https://gitlab.xcapit.com/fer/xcapit-marketplace.git --scope project
claude plugin install xcapit-swarm@xcapit-marketplace --scope project
```

Inventory (verify with `claude plugin details xcapit-swarm`): **20 skills**
(swarm-orchestration, sdd-enforcement, honesty-contract, coordination-protocol,
threat-modeling, the openspec-* set, the *-patterns, `swarm-status`, …), **8 builder
agents** (sdd-architect, backend/frontend-tdd-engineer, adversarial-reviewer,
lane-coordinator, threat-modeler, tdd-orchestrator, context-manager), and **2 hooks**.

> ⚠️ **Adoption constraint:** the marketplace is hosted on **GitLab**
> (`gitlab.xcapit.com`) while MIESC is on GitHub. A MIESC contributor who cannot
> reach that GitLab URL over HTTPS cannot fetch the plugin — Claude Code will run
> without it. This is the open input to the marketplace-namespace decision
> (`fer/` → an Xcapit group). It is a consumption gate, not a code dependency: the
> vendored engine below works with or without the plugin.

### Hooks stay OFF

The plugin ships two hooks (PreToolUse anti-clobber guard, PostToolUse OTel emitter)
**default-OFF**, gated on `XCAPIT_SWARM_HOOKS_ENFORCE` / `XCAPIT_SWARM_OTEL_EMIT`.
This seed sets **neither** — nothing in `.claude/settings.json` enables them. Do not
turn them on until the plugin's `HOOKS-REVIEW.md` is signed off.

---

## 2. The loop engine (vendored from swarm-ops)

`scripts/lane-*.sh` + `scripts/lib/*.sh` are **byte-identical copies** of the
`swarm-ops` canonical (`gitlab.xcapit.com/fer/swarm-ops`), pinned at commit
`be0013e5`. Copying alone is not single-source, so a drift guard keeps them honest:

```bash
python3 scripts/verify-engine-vendor.py        # exits 1 on any hand-edit to a vendored file
```

To change an engine file you edit **swarm-ops**, re-copy, and re-pin with `--write`
— you never hand-edit MIESC's copy. 13 files are adopted; the pin lives in
`scripts/lib/engine-sync-source.json`.

### Resolved: the hard-coded project label

This adoption surfaced that `swarm-ops` hard-coded **"xNinja"** in two *runtime*
strings — `lane-dispatch.sh` (the dispatch prompt) and `lane-status.sh` (the status
banner) — so a MIESC console would have been told it was on "the xNinja swarm". Not
cosmetic for an orchestration prompt: a wrong label can steer a console's priors
toward another project's conventions (develop, `make ci-verify`, glab).

**Fixed in `swarm-ops`** by parameterising it — `SWARM_PROJECT_LABEL`, defaulting to
`SWARM_PROJECT_ID` — and re-synced here; `swarm-config.local.sh` sets
`SWARM_PROJECT_LABEL=MIESC`, so this swarm now reads **"MIESC swarm"**. The change
was made in the canonical and re-copied — never hand-edited in the vendored copy,
which the drift guard forbids. (The swarm-ops commit and this re-sync are both
local until the operator pushes them; the swarm-ops `xNinja`-specific doc paths in
the dispatch prompt — `docs/AGENT-SWARM-OPERATIONS.md` etc. — remain a separate,
larger parameterisation left for later.)

The fix does **not** belong here: the drift guard correctly forbids hand-editing
MIESC's copy. It belongs in **swarm-ops** — parameterise the label (e.g. a
`SWARM_PROJECT_LABEL` defaulting to `SWARM_PROJECT_ID`), then re-sync + re-pin every
adopter (xNinja and MIESC). Tracked as a swarm-ops follow-up.

**Not vendored, on purpose:**

- `local-land.sh` / `land.sh` (the landers). The engine (dispatch / run / status /
  reap / live / loop) never *executes* them — landing is a deliberate operator step,
  and it is the most project-specific part. MIESC lands via **GitHub** (`gh`) with
  its own flow; it does not inherit xNinja's develop-branch landers.
- `scripts/lib/swarm-config.local.sh` — this is MIESC's own config, below.

### The adaptation seam — two files

Everything project-specific lives in exactly two places; the rest is identical to
every other adopter:

| File | What MIESC sets |
|------|------------------|
| `scripts/lib/swarm-config.local.sh` | base branch `main` (not develop), forge `gh` (not glab), worktree prefix `MIESC-`, verify gate `make quick-check`, project id `miesc` |
| `coordination/swarm-manifest.json` | the `k0+1-4` lane map (below) |

### The k0+1-4 lane map

A **hand-authored starter** agreement (`provenance: "authored"` — MIESC has no
manifest generator yet, so these bindings must not be rendered as "observed"):

| Lane | Console | Charter |
|------|---------|---------|
| **k0** | kimi | Orchestration, research, dispatch routing |
| **1** | claude | Detection quality + FP reduction, RAG/grounding, adversarial finding verification |
| **2** | codex | Scanner/tool-adapter integration, MCP server |
| **3** | claude | Reproducibility, benchmarks, defensive docs (not the frozen paper) |
| **4** | codex | Release readiness, GitHub Actions CI, packaging |

The engine reads only `lanes[].console`; the charters and agent bindings are a
sensible split to tune as the pool settles.

---

## 3. How this relates to MIESC's own `agentic_quality_loop.py`

They are **complementary, not competing**:

- `scripts/agentic_quality_loop.py` is MIESC's **in-repo** loop — it composes MIESC's
  grounding / FP components to separate CONFIRMED findings from false positives and
  hallucinations within a single analysis run.
- The **xcapit-swarm engine** is the **multi-console development harness** — it
  dispatches work across the Claude / Codex / Kimi console pool, each in its own
  worktree, and coordinates landing. It operates on MIESC's *development*, not on a
  scan's findings.

One verifies MIESC's security output; the other orchestrates the team that builds
MIESC. Keep them distinct.

---

## 4. Verify the seed

```bash
python3 scripts/verify-engine-vendor.py        # engine == pinned canonical (be0013e5)
claude plugin details xcapit-swarm             # 20 skills / 8 agents / swarm-status resolve
/swarm-status                                   # reads coordination/lane-events.jsonl (empty => honest UNKNOWN/STALE)
```

`coordination/lane-events.jsonl` ships **empty** — no fabricated runs. `/swarm-status`
reports UNKNOWN/STALE until a real dispatch writes events. A **live multi-console
dispatch is operator-driven** (it needs the actual consoles) and is intentionally not
part of this seed.
