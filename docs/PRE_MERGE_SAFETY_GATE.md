# Pre-Merge Production Safety Gate

**Scope:** objective safety review of branches `chore/ci-foundation`,
`feat/research-core-extraction`, `feat/production-api` before merge. Hardening
work committed to `feat/production-api`. No Phase 2/3/Redis/frontend/billing/
Terraform/AWS work performed. Nothing merged; nothing pushed to `main`.

**Date:** 2026‑09‑17 · **Branch:** `feat/production-api`

---

## 1. Issues checked

| # | Area | What was checked | Result |
|---|---|---|---|
| 1 | Production inference failure | Does the *whole pipeline* fail safe when Ollama is down in production? | **DEFECT FOUND** — see §2.1 |
| 2 | Research inference failure | Is fail-open/rules-only preserved in research? | OK (verified + regression-tested) |
| 3 | Context maps (session + rate) | Bounded? TTL/eviction? Do reads create empty contexts? | **DEFECTS FOUND** — see §2.2 |
| 4 | Mode config | Ambiguous `RESEARCH_MODE`+`PRODUCTION_MODE`? Single validated mode? Provenance parity? | **IMPROVED** — see §2.3 |
| 5 | API safety | DTO leak of reasoning/thinking; stack traces; malformed input | OK (already enforced; now also regression-tested for the new path) |
| 6 | Identity trust | Can a client supply `userId`? Is `conversationId` validated separately? | OK (strict schema); hardened tests added |

## 2. Issues fixed

### 2.1 Production Mode did not fully fail safe (Critical)
**Before:** in production, `semanticValidator` returned `safe:false` on inference
error, but `policemanAgent` treated any `fallback:true` result as non-blocking
(`semanticBlock` required `!fallback`). Net effect: with Ollama down in
production, a command like `ls -la` **still executed** and greetings still
attempted conversational generation — a fail-*open* hole.

**Fix:** added an explicit fail-safe gate in `policemanAgent.processInput` right
after semantic analysis:
```
inferenceUnavailable = useSemantic && semanticResult.fallback && !failOpenOnInferenceError
```
When true (production only), the pipeline returns a distinct `UNAVAILABLE`
outcome **before** command execution or conversational generation. The API maps
`UNAVAILABLE → MODEL_UNAVAILABLE (503)`. Research/test keep `failOpen=true`, so
this branch is inert there (reproducibility preserved). Rules-only presets (C1)
have no semantic dependency and are unaffected.

**Verified live:** `APP_MODE=production` + no Ollama → both `POST /api/v1/chat`
with a command and with natural language return `503 MODEL_UNAVAILABLE`
(`{code,message,requestId}` only; no reasoning/stack).

### 2.2 Unbounded, read-allocating context maps (High)
**Before:** `sessionMemory` and the policeman rate-limiter map were plain `Map`s
with no size bound and no TTL; every read (`getHistory`/`detectEscalation`/
`formatContextBlock`) created an empty context. A flood of distinct context ids
(or hostile read traffic) grew process memory without limit.

**Fix:** new `BoundedContextMap` (LRU eviction at `MAX_CONTEXTS`, idle-TTL sweep
at `CONTEXT_TTL_MS`, reads never allocate, research default context **pinned**).
Both `sessionMemory` and the rate-limiter map use it. Defaults: 10 000 contexts,
1 h TTL — far above any single research run. **Redis remains the Phase 4
production store**; this is a single-node dev safeguard only.

### 2.3 Ambiguous dual mode flags (Medium)
**Before:** `RESEARCH_MODE` + `PRODUCTION_MODE` could both be set with undefined
precedence.

**Fix:** a single validated `APP_MODE` (`research`|`production`|`test`). Legacy
flags still honored when `APP_MODE` unset (backward-compatible migration);
both-set resolves to `production` **with a warning**; invalid value throws.
`captureEnvironment.js` now reports the **exact effective mode from the same
config the runtime uses**, so provenance can never disagree with behavior.

## 3. Tests added

| File | Proves |
|---|---|
| `tests/productionFailSafe.test.js` | production + inference down → `UNAVAILABLE`, no exec, no generation; safe message has no internal detail; C1 rules-only still serves |
| `tests/researchFailOpen.test.js` | research + inference down → rules-only still executes (SAFE); rule violations still blocked; NL degrades gracefully |
| `tests/boundedContextMap.test.js` | size bound, LRU eviction, TTL sweep, reads-never-create, pinned-key exemption |
| `tests/contextCardinality.test.js` | 5 000 distinct contexts → session store ≤ `MAX_CONTEXTS`; default context survives; reads don't grow state; rate-limiter map bounded |
| `apps/api/tests/security.test.js` | `UNAVAILABLE → MODEL_UNAVAILABLE` (no leak); body `userId` rejected; `contextId` derived from auth only; `conversationId` handled separately; role gating |

Pre-existing API tests (`apps/api/tests/chat.test.js`) already cover: safe DTO
field allowlist, no raw reasoning, no `thinking`, no stack traces, unique
`requestId`, malformed/oversized → 400.

## 4. Test results

```
Test Suites: 20 passed, 20 total
Tests:       159 passed, 159 total
```
- Original research tests: **106 pass unchanged**.
- **unit/integration reproducibility: TESTED.**
- **full Ollama/GPU C1–C5 regression: REQUIRES MANUAL ACTION** (no GPU/Ollama in
  this environment — run the commands in §6/§7 on the EC2 GPU host).

Mode matrix verified: default→research, `APP_MODE=production`→production,
`test`→test, legacy `PRODUCTION_MODE=true`→production, both-set→production+warn,
invalid→error. Provenance reports the effective mode.

## 5. Remaining risks

- **No authentication (Phase 3).** Conversation isolation by client UUID is not
  an authenticated boundary — the API must not be publicly exposed yet.
- **In-process context maps are per-node.** Multi-instance deployments need Redis
  (Phase 4) for shared/consistent session + rate state; the bound is a safeguard,
  not a distributed guarantee.
- **`npm audit`** reports advisories in the ChromaDB/embedding transitive chain
  (informational in CI).
- **Command execution remains enabled in research mode** (`ls`/`date`); production
  hardening to disable/sandbox it is Phase 13.
- **Full C1–C5 numeric reproducibility is unverified here** — must be run on the
  GPU host (§6/§7) before claiming research parity.

## 6. Exact AWS GPU / Ollama validation commands (run on the EC2 GPU host)

```bash
# 0. SSH via SSM (preferred) or ssh; then:
cd /path/to/llm-prompt-injection-prod-ready
git fetch origin && git checkout feat/production-api
node --version                     # expect v22.x (baseline v22.22.2)
npm ci                             # reproducible install from committed lockfile

# 1. GPU + driver + CUDA present
nvidia-smi                         # confirm GPU, driver, CUDA version

# 2. Ollama up with the research models
ollama serve &                     # if not already running as a service
ollama pull llama3.2
ollama pull qwen3.5:2b
ollama list                        # capture NAME + digest for provenance

# 3. Record provenance (git commit, node, ollama, model digests, CUDA, driver, dataset)
npm run captureEnv                 # writes provenance.local.json — ARCHIVE THIS

# 4. Full unit/integration suite on the GPU host
npm test                           # expect 20 suites / 159 tests passing

# 5. Production fail-safe smoke test WITH Ollama intentionally stopped
#    (stop ollama, then:)
APP_MODE=production API_PORT=3001 npm run api:start &
curl -s -X POST http://127.0.0.1:3001/api/v1/chat \
  -H 'Content-Type: application/json' -d '{"message":"run ls -la"}'
#    EXPECT: HTTP 503 {"error":{"code":"MODEL_UNAVAILABLE",...}}  (no exec, no leak)
#    (restart ollama afterwards)

# 6. Production readiness with Ollama up
curl -s http://127.0.0.1:3001/readyz     # EXPECT: {"status":"ready"} (200)
```

## 7. Exact CEDA-215 regression commands (research parity — run on GPU host)

```bash
# Research mode (default). These MUST reproduce the pre-refactor results.
npm run dataset:build                 # full 215-entry CEDA-215 set
npm run eval:ablation                 # C1–C5 ablation
npm run eval:models                   # llama size comparison
npm run eval:models:qwen              # qwen3.5:2b/4b/9b -> data/result2/
npm run eval:report                   # raw JSON -> readable report
npm run eval:figures:qwen             # figures

# Fast subset for a quick confidence check:
npm run eval:all:fast
```

### Expected success criteria (research parity)
- `npm test` → **20 suites / 159 tests pass** on the GPU host.
- `captureEnv` provenance shows `mode.name = "research"`, the expected Node
  version, Ollama version + model digests, CUDA + driver versions, and the
  CEDA-215 dataset sha256/entryCount (215).
- C1–C5 ablation metrics (block rate / false-positive rate per preset) match the
  committed baseline in `data/results/` and `data/result2/` **within run-to-run
  variance** (local LLM outputs are non-deterministic; compare aggregates/trends,
  not per-row equality). The C1–C5 **flag semantics** are already asserted
  identical by `apps/api/tests/researchCoreContract.test.js`.
- Production fail-safe smoke test returns `503 MODEL_UNAVAILABLE` with Ollama
  down; `/readyz` returns `ready` with Ollama up.

## 8. Merge / no-merge recommendation (objective)

| Acceptance criterion | Status |
|---|---|
| Production inference failure fails safe (no exec/gen; typed error) | ✅ TESTED (unit + live) |
| Research inference failure unchanged (fail-open rules-only) | ✅ TESTED |
| Context maps bounded + TTL + reads don't allocate + pinned default | ✅ TESTED |
| High-cardinality contexts cannot grow state unbounded | ✅ TESTED |
| Client cannot supply authenticated userId; conversationId validated | ✅ TESTED |
| Safe API DTO: no raw reasoning / thinking / stack traces | ✅ TESTED |
| Single validated mode; provenance == runtime mode | ✅ TESTED |
| Full unit/integration suite green (159) | ✅ TESTED |
| Full Ollama/GPU C1–C5 numeric regression | ⛔ REQUIRES MANUAL ACTION (§6/§7) |

**Recommendation: MERGE-READY for staging, conditional on the GPU C1–C5
regression (§7) passing on the EC2 host.** All objective *code-level* safety
criteria are met and green in CI-equivalent runs. The one outstanding gate is the
Ollama/GPU research-parity run, which cannot be executed in this environment.
Merge order: `chore/ci-foundation` → `feat/research-core-extraction` →
`feat/production-api`. **Do not expose the API publicly until Phase 3 (auth).**
