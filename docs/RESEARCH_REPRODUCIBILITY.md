# Research Reproducibility

The scientific contribution of this project — the hybrid rule‑LLM defense
pipeline and the C1–C5 ablation over CEDA‑215 — **must remain reproducible**
through every production‑hardening change (brief §3, §49). This document records
the baseline, how to reproduce experiments, how provenance is captured, and the
process for recording any intentional behavioral change.

## 1. Preserved experimental configurations (C1–C5)

Toggled in the CLI (`/preset c1..c5`) and used by the ablation runner. These
semantics are **frozen** and must not change without an entry in §5 below.

| Preset | Rules | Semantic | Rate limit | Session memory | RAG |
|---|:--:|:--:|:--:|:--:|:--:|
| C1 — Rules only | ✓ | | | | |
| C2 — Semantic only | | ✓ | | | |
| C3 — Rules + Semantic | ✓ | ✓ | | | |
| C4 — + Rate limit + Session memory | ✓ | ✓ | ✓ | ✓ | |
| C5 — Full pipeline + RAG | ✓ | ✓ | ✓ | ✓ | ✓ |

## 2. Baseline (recorded 2026‑09‑17)

- Git commit: `42e0ab7` (branch `claude/upbeat-darwin-ctep8r`)
- Node.js: `v22.22.2`; npm: `10.9.7`
- Test suite: **106 tests / 10 suites — all passing** (`npm test`)
- Runtime deps: `chromadb`, `@chroma-core/default-embed`, `ollama`, `dotenv`
- Dataset: CEDA‑215 (`data/evaluation-dataset.json`) — 215 entries, 56‑entry fast subset
- Default model: `llama3.2:1b` (configurable); Qwen comparison: `qwen3.5:2b/4b/9b`

The lockfile (`package-lock.json`) is now committed to guarantee identical
dependency trees on re‑install.

## 3. Reproducing experiments

```bash
# environment
node --version           # expect v22.x (baseline v22.22.2)
ollama serve             # start local models
ollama pull llama3.2
npm ci                   # reproducible install from committed lockfile

# capture provenance FIRST (writes provenance.local.json)
npm run captureEnv

# full pipeline
npm run dataset:build            # or :fast for the 56-entry subset
npm run eval:ablation            # C1–C5 comparison
npm run eval:models              # llama size comparison
npm run eval:models:qwen         # qwen size comparison → data/result2/
npm run eval:report              # raw JSON → readable report

# figures
npm run eval:figures:qwen
```

Or the one‑shot wrapper: `./run.sh eval:qwen`.

## 4. Provenance capture

`scripts/captureEnvironment.js` (run via `npm run captureEnv`) records the exact
environment for an experiment run, satisfying §3's requirement to record git
commit, Node version, Ollama version, model name/digest, CUDA/NVIDIA driver, and
dataset version. It writes `provenance.local.json` (git‑ignored — it is a
per‑run snapshot; copy it next to your results to archive it). Fields that cannot
be detected on a given machine (e.g. no GPU) are recorded as `null` rather than
guessed. Attach the snapshot to any published result set.

## 5. Behavioral‑change log (OLD → NEW)

Any change that could alter experimental outcomes is recorded here with
**OLD behavior / NEW behavior / REASON / IMPACT ON EXPERIMENT**. If this section
lists no entries for a code area, that area's research behavior is unchanged.

### 2026‑09‑17 — Session/rate state made context‑aware (Phase 1)

- **OLD:** `sessionMemory` used a single module‑global history array; the
  policeman held one process‑global `RateLimiter`. All turns shared this state.
- **NEW:** both are keyed by an optional `contextId`. When no `contextId` is
  supplied (the CLI, the evaluation scripts, and all existing tests), a single
  **default context** is used, which is byte‑for‑byte the previous behavior.
- **REASON:** production multi‑user isolation (brief §8) without touching the
  research path.
- **IMPACT ON EXPERIMENT:** **None.** C1–C5 and all evaluation scripts pass no
  `contextId`, so they run on the default context exactly as before; the 106‑test
  baseline remains green, including all session‑memory and rate‑limiter tests.

### 2026‑09‑17 — `RESEARCH_MODE` / `PRODUCTION_MODE` config added (Phase 0)

- **OLD:** no mode flag.
- **NEW:** `config.mode` derived from env; **defaults to Research Mode**, which is
  the existing behavior (fail‑open semantic validation, shared memory permitted).
- **REASON:** allow production hardening to diverge explicitly (§3).
- **IMPACT ON EXPERIMENT:** **None** while `RESEARCH_MODE` is default/true.
  Production‑only branches are inert unless `PRODUCTION_MODE=true` is set.
