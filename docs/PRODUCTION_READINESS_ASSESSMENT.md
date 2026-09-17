# Production Readiness Assessment

**Project:** Hybrid Rule‑LLM Defense Pipelines for Command‑Execution AI Agents
**Assessment date:** 2026‑09‑17
**Assessed commit:** `42e0ab7` (baseline, branch `claude/upbeat-darwin-ctep8r`)
**Assessor role:** Principal Architect / DevSecOps / AppSec (audit before modification)

> This document is the **audit-before-modification** deliverable required by the
> brief (§2). It describes the repository **as it actually exists today**, the
> gap between that reality and the target production SaaS, the risks ranked by
> priority, and the migration plan. No destructive change was made before this
> assessment was written. See `docs/IMPLEMENTATION_PLAN.md` for the phased plan
> and `docs/ARCHITECTURE.md` for current‑vs‑target architecture.

---

## 0. Executive summary

The repository is a **local, single‑process research CLI** (~3,400 lines of
Node.js) that studies how to defend a command‑execution chatbot against prompt
injection using a hybrid rule‑based + local‑LLM (Ollama) pipeline, with a
ChromaDB/RAG layer, session memory, rate limiting, output filtering, and a
C1–C5 ablation harness. It has **106 passing unit/integration tests** and a
reproducible evaluation pipeline over the CEDA‑215 dataset.

**The single most important finding:** the production SaaS described in the
brief — a Node API service, a Next.js frontend, Nginx, authentication, a
database, billing, multi‑tenancy, and AWS deployment — **does not exist in the
repository yet.** There is no HTTP server, no web UI, no auth, no database, no
Docker image for the app, and no infrastructure‑as‑code. The brief is therefore
not a "harden the existing web app" task; it is a **"build a production SaaS
platform around a working research core"** task. That reframing drives the whole
plan: the research core is an asset to be *wrapped and isolated*, not rewritten.

**Readiness verdict for public deployment as a SaaS: NOT READY.** The research
CLI is fit for its purpose (local, single‑user, reproducible experiments). It is
categorically unsafe to expose to the public internet in its current form,
primarily because there is nothing between an anonymous user and an LLM‑driven
command executor: no authentication, no user isolation (session/rate state is
process‑global), no network isolation of Ollama/ChromaDB, and no HTTP surface at
all to attach controls to.

**What this milestone (Phase 0/1) delivers:** the mandated audit + architecture
+ security design + threat model + phased plan (this document set), plus safe,
tested, reproducibility‑preserving foundation work: dependency‑lockfile
reproducibility, environment provenance capture, `RESEARCH_MODE`/`PRODUCTION_MODE`
scaffolding, and a **behavior‑preserving session‑isolation refactor** of the
research core (the #1 production blocker that is fixable and testable without any
external account). Everything requiring AWS/Cognito/Stripe/domain accounts is
**designed and documented but not implemented**, and is clearly labelled as such.

---

## 1. What actually exists today (inventory)

| Area | File(s) | Reality |
|---|---|---|
| Entry point | `src/index.js` | Interactive **REPL CLI** with layer toggles + C1–C5 presets. Not a server. |
| Orchestrator | `src/agents/policemanAgent.js` | Runs the pipeline: rate‑limit → session memory → rules → semantic (Ollama) → execute → output filter → log. Holds **one process‑global** `RateLimiter`. |
| Command runner | `src/agents/chatbotAgent.js` | Executes `ls`/`date` via **`execFile`** (no shell), re‑checks whitelist. Also does Ollama "chat" for non‑commands. |
| Red‑team tooling | `src/agents/hackerAgent.js` (793 LoC), `src/hackerCli.js` | Attack generator/harness for research. |
| Rule validation | `src/validators/ruleBasedValidator.js` | ~29 regex rules: prompt injection, chaining, metachars, whitelist, path traversal, encoding/obfuscation. |
| Semantic validation | `src/validators/semanticValidator.js` | Ollama JSON classifier with JSON‑repair; **fails open** (`safe:true`) if Ollama is down. |
| Output filter | `src/validators/outputFilter.js` | Regex redaction (hashes, private keys, credentials, private IPs, AWS keys) + error sanitizer. |
| Session memory | `src/memory/sessionMemory.js` | **Module‑global `let history = []`** — shared across all callers. |
| Long‑term memory | `src/memory/longTermMemory.js` | Persists blocked patterns to ChromaDB; warms up from the log file. |
| Rate limiter | `src/middleware/rateLimiter.js` | In‑process sliding window + burst/probing heuristics. Correct as a class; used as a global singleton. |
| RAG | `src/rag/chromaClient.js`, `src/rag/ragRetriever.js` | ChromaDB few‑shot retrieval; graceful degradation to null. |
| Config | `src/utils/config.js` | `dotenv`‑based; Ollama host/model, rate‑limit, logging, ChromaDB, memory. |
| Logging | `src/utils/logger.js` | **Appends JSON lines to a local file** `logs/security.log`; stores up to 500 chars of raw input. |
| Evaluation | `scripts/*.js` | Dataset build, ablation (C1–C5), model comparison, report generation, ChromaDB seeding. |
| Data | `data/` | CEDA‑215 evaluation dataset + result JSONs. |
| Findings | `findings/generate_figures.py` | Python figure generation for the paper. |
| Tests | `tests/*.test.js` | **106 tests, 10 suites — all passing** (baseline recorded). |
| Infra | `docker-compose.yml` | ChromaDB only. **No app Dockerfile, no Nginx, no AWS/Terraform.** |

**Does not exist (despite being referenced in the brief):** `server/`,
`frontend/`, Next.js, Nginx config, any HTTP endpoint, authentication,
authorization, database/Prisma, Redis, billing, multi‑tenant anything, AWS/IaC,
CI/CD workflows, TypeScript, linting config, container images for the app.

**Baseline (recorded per §49):**
- Node `v22.22.2`, npm `10.9.7`
- `npm test` → **Test Suites: 10 passed; Tests: 106 passed**; ~1.1 s
- Runtime dependencies: `chromadb`, `@chroma-core/default-embed`, `ollama`, `dotenv`; dev: `jest`.

---

## 2. Architectural weaknesses

1. **No service boundary.** All logic is in‑process behind a REPL. There is no
   API to which authentication, authorization, quotas, tracing, or WAF can be
   attached. This is the root cause of most P0 gaps — you cannot secure an
   HTTP surface that does not exist.
2. **Process‑global mutable state.** `sessionMemory.history`, the single
   `RateLimiter` in `policemanAgent`, and the cached `ollamaClient`/`collection`
   singletons are all shared. Fine for one user in a REPL; a **correctness and
   security defect** the moment two users share a process (cross‑tenant history
   contamination, shared rate budgets, one user's escalation state influencing
   another's semantic prompt).
3. **Tight coupling to Ollama and ChromaDB.** Business logic imports the Ollama
   client and Chroma client directly. There is no `InferenceProvider` /
   `VectorStore` abstraction (§12, §30), so swapping providers or adding
   queueing/circuit‑breaking means editing core research code.
4. **No concurrency control for inference.** The GPU is the scarcest resource;
   nothing bounds concurrent Ollama calls, so N users = N simultaneous model
   loads → GPU saturation / OOM (a natural DoS, §12, §41).
5. **Synchronous, unbounded pipeline.** No request timeout budget end‑to‑end, no
   cancellation, no backpressure, no queue.
6. **No separation of research vs. production behavior.** Research needs
   *fail‑open* semantic validation and shared session memory for reproducibility;
   production needs *fail‑safe* and per‑user isolation. Today there is one code
   path (fixed in this milestone via mode scaffolding).

## 3. Production blockers (cannot ship publicly without these)

- No authentication / authorization (nothing identifies or gates a caller).
- No HTTP/API layer to host any of the above.
- Process‑global session + rate state → no multi‑user isolation.
- Ollama (11434) and ChromaDB (8000) are designed to be reachable on the host;
  in the described EC2 deployment they risk direct internet exposure.
- No TLS/HTTPS termination, no reverse proxy config in‑repo.
- No secrets management story for production (works today only because there are
  no secrets — local Ollama, no API keys).
- No persistent, queryable data store with ownership enforcement.
- No automated process supervision (README instructs `npm start` / `node` by
  hand; §36 explicitly forbids this for production).

## 4. Security vulnerabilities & risks (current code)

Severity is relative to the **intended production SaaS**, not the current local CLI.

| # | Severity | Finding | Location | Notes |
|---|---|---|---|---|
| S1 | Critical | No authN/authZ; anonymous access to an LLM command executor | (absent) | The defining P0. |
| S2 | High | Process‑global session/rate state → cross‑user leakage & shared quotas | `sessionMemory.js`, `policemanAgent.js` | **Fixed in this milestone** (behavior‑preserving, tested). |
| S3 | High | Semantic validator **fails open** when Ollama is down | `semanticValidator.js:127` | Correct for research reproducibility; unsafe default for production. Gated by mode in plan. |
| S4 | High | Ollama/ChromaDB intended to bind on host ports | deploy | Must be private‑subnet + localhost‑only (§22). |
| S5 | Medium | Log stores up to 500 chars of raw (possibly malicious/PII) input to a plaintext file | `logger.js`, `sessionMemory.js` | No retention, encryption, or access control (§18, §20, §27). |
| S6 | Medium | Command arg surface not fully constrained | `chatbotAgent.js`, `ruleBasedValidator.js` | `execFile` prevents shell injection (good), but `ls`/`date` args are only regex‑gated; `ls` can still enumerate any readable dir, `date -f <file>` can read a file. Needs structured arg allowlisting + sandbox (§13). |
| S7 | Medium | Output redaction is regex‑only (incomplete coverage) | `outputFilter.js` | Best‑effort; not a guarantee. Fine for `ls`/`date`, risky if whitelist grows. |
| S8 | Medium | `repairJSON` executes best‑effort parsing on model output | `semanticValidator.js` | No `eval`; bounded. Low risk but should have hard size/timeout limits in production. |
| S9 | Low | Base64/URL‑decode of arbitrary input for detection | `ruleBasedValidator.js:138` | CPU‑bounded; consider input length caps (ReDoS/CPU DoS surface with long inputs). |
| S10 | Low | Errors printed to stdout/stderr may leak internals in a server context | multiple | Needs typed errors + structured logging (§16, §43). |

**Note on what is already good:** command execution uses `execFile` (no
`exec`/`shell:true`/`eval`), the whitelist is tiny (`ls`, `date`) and
double‑checked at execution, user‑facing warnings avoid revealing rule internals,
`think:false` is set so chain‑of‑thought is not requested, and RAG/Chroma/Ollama
all degrade gracefully. These are solid foundations to build on.

## 5. Dependency & supply‑chain problems

- **`package-lock.json` was git‑ignored** → non‑reproducible installs, a direct
  threat to research reproducibility (§3, §49). **Fixed in this milestone**
  (un‑ignored + committed).
- `npm install` warns on deprecated transitive deps (`glob@10`, `boolean@3`) via
  the Chroma/embedding chain. No direct action required now; track via
  Dependabot (planned).
- No `npm audit` / SCA / secret scanning in CI (no CI exists). Planned (§33).
- `.DS_Store` files were committed. **Removed + ignored in this milestone.**

## 6. Scalability problems

- Single process, single GPU, no queue → throughput is bounded by one Ollama
  instance with no admission control. First concurrency spike degrades everyone.
- No horizontal scaling story (no statelessness: state is in‑process).
- ChromaDB single container, no HA, no backup.

## 7. Multi‑user isolation issues

- **Session memory** and **rate limiting** are process‑global (S2). This is the
  concrete manifestation of §8. Addressed in this milestone by keying both on a
  context id (`userId:conversationId`), with a default context that preserves
  exact single‑user research behavior.
- Long‑term memory (ChromaDB) is a **global** learned store — one user's blocked
  patterns influence everyone's retrieval. Acceptable/expected for research;
  for production it needs tenancy scoping or a mode gate (documented).

## 8. Authentication / authorization gaps

- None exist. Target: Amazon Cognito for identity; PostgreSQL for profile/roles;
  server‑side RBAC (`USER` / `RESEARCHER` / `ADMIN`); never trust frontend role
  checks (§7). Fully designed in `docs/AUTHENTICATION.md` (planned) and the plan.

## 9. Observability gaps

- No metrics, no tracing, no structured request logs, no health/readiness
  endpoints, no dashboards/alarms. Logging is a local append‑only file. Target:
  OpenTelemetry + CloudWatch, `/healthz` + `/readyz` (§25, §26).

## 10. Unsafe information disclosure

- Model **"thinking"** is already suppressed (`think:false`) — good, but there is
  no serializer/DTO enforcing that only safe fields leave the system, because no
  API exists. A response DTO (§42) must be built with the API so the raw internal
  result object (`reasoning`, rule evidence, threat internals) is never returned
  to non‑researchers.
- Security‑rule internals are kept out of user‑facing warnings today (good), but
  the full `reasoning`/`evidence` are returned in the result object the CLI
  prints — this must not become an API response body.

## 11. Deployment weaknesses

- Manual `npm start` / `node server/app.js` per README/brief §36. No process
  supervision, no auto‑restart, no zero‑downtime deploy, no image, no IaC.
  Target: containerize → ECS/Fargate for web/API, ECS‑EC2/GPU for the worker,
  Terraform for everything, GitHub Actions for CI/CD.

---

## 12. Risk register mapped to the brief's priorities

**P0 — must fix before any public deployment (§52):**

| Control | Status after this milestone |
|---|---|
| Authentication | NOT IMPLEMENTED (designed) — needs Cognito account |
| Authorization (RBAC, server‑side) | NOT IMPLEMENTED (designed) |
| Session isolation | **PARTIALLY IMPLEMENTED / TESTED** — research core now context‑keyed; API layer pending |
| DB ownership enforcement | NOT IMPLEMENTED (schema designed) — needs Postgres |
| HTTPS | NOT IMPLEMENTED (designed) — needs ACM/ALB/domain |
| Secrets management | PARTIALLY (repo hygiene + `.env.example` done; Secrets Manager needs AWS) |
| Internal service isolation | NOT IMPLEMENTED (network design done) — needs VPC |
| Safe API responses (DTO) | NOT IMPLEMENTED (designed) — needs API layer |
| Command sandbox / disable publicly | PARTIALLY (already `execFile`+whitelist; sandbox + prod‑disable designed) |
| Distributed rate limiting | NOT IMPLEMENTED (designed) — needs Redis |
| No chain‑of‑thought exposure | **IMPLEMENTED** (`think:false`; DTO will enforce at API) |
| Input validation | PARTIALLY (rules exist; Zod schema layer pending API) |
| Secure error handling (typed) | NOT IMPLEMENTED (typed‑error catalogue designed) |

**P1 — production readiness:** subscriptions, observability, CloudWatch, WAF,
backups, health checks, CI/CD, automated deployment, audit logging — all
**NOT IMPLEMENTED (designed)**; CI/CD is the cheapest first win (no external
account) and is the recommended next code deliverable.

**P2 — scale & UX:** advanced analytics, HA, autoscaling, organizations,
advanced billing, additional models — deferred.

---

## 13. Recommended technology adjustments (§56 — flag inappropriate choices)

The brief's stack is largely sound for a small team. Two honest caveats, offered
as *recommendations before changing anything*:

1. **ChromaDB in production.** Keep ChromaDB for **Research Mode** (it is part of
   the methodology — §30). For Production Mode, prefer **PostgreSQL `pgvector`**
   behind a `VectorStore` interface: one fewer stateful service to run/secure/back
   up, and it reuses the RDS you already need. Do **not** silently switch research
   experiments off ChromaDB. → build `VectorStore` with `ChromaVectorStore`
   (research) and `PgVectorStore` (production).
2. **Billing provider.** Stripe is the right default *if* the target account/
   country supports it. For Saudi deployment, Moyasar/HyperPay may be required.
   Therefore build a `BillingProvider` interface first (§10) and treat the
   concrete provider as a swappable, config‑selected implementation. Do not
   hard‑code Stripe into business logic.

Everything else (ECS over Kubernetes, Cognito, Prisma, Redis, Terraform,
Next.js) is appropriate and retained.

---

## 14. Migration principles (non‑negotiable)

1. **Never rewrite the research core; wrap it.** Extract it into
   `packages/research-core` behind stable interfaces; the API/worker consume it.
2. **Preserve C1–C5 and reproducibility at every step** (§3, §49): run the 106
   tests before and after each change; record provenance; document any behavioral
   delta with OLD/NEW/REASON/IMPACT.
3. **Additive, behavior‑preserving refactors** with a default context that equals
   today's behavior; new behavior is opt‑in via `PRODUCTION_MODE` / explicit ids.
4. **No big‑bang migration.** Phase by phase, each gated on green tests.
5. **Nothing requiring an external account is claimed as "done"** — it is
   `REQUIRES MANUAL CONFIGURATION` with exact acquisition steps.

See `docs/IMPLEMENTATION_PLAN.md` for the phase‑by‑phase execution plan, the
target repository layout, the database schema, and the security design; and
`docs/ARCHITECTURE.md` for current‑vs‑target diagrams.
