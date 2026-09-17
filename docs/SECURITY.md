# Security Overview

How security is implemented today, and the target controls per phase. Statuses:
`IMPLEMENTED` (in code now), `PARTIAL`, `PLANNED`.

## Reporting

Security issues: open a private report / issue to the maintainer. Do not file
public exploit details for unpatched issues.

## Implemented today (research core)

- **No shell execution.** Commands run via `execFile` — the shell never
  interprets input; metacharacters cannot chain commands. `IMPLEMENTED`
  (`src/agents/chatbotAgent.js`).
- **Tiny command whitelist** (`ls`, `date`) checked at validation **and** again
  at execution (defense in depth). `IMPLEMENTED`.
- **Hybrid rule + semantic validation** with ~29 rules + local‑LLM classifier;
  graceful degradation if Ollama is down. `IMPLEMENTED`.
- **Output redaction** of hashes, private keys, credentials, private IPs, AWS
  keys; error sanitization. `IMPLEMENTED` (`src/validators/outputFilter.js`).
- **No chain‑of‑thought.** `think:false` on all model calls; "thinking" is never
  requested or persisted. `IMPLEMENTED`.
- **User‑facing warnings do not reveal rule internals.** `IMPLEMENTED`.
- **Session/rate isolation in the core** via context keying (default context
  preserves single‑user research behavior). `PARTIAL` (core done + tested; API
  layer that supplies real `userId:conversationId` is `PLANNED`).
- **Dependency reproducibility:** `package-lock.json` committed. `IMPLEMENTED`.
- **Environment provenance capture** for experiments. `IMPLEMENTED`
  (`scripts/captureEnvironment.js`).
- **Research core isolation** (Phase 1b). The scientific pipeline lives in
  `packages/research-core` with no HTTP/auth/billing/DB/cloud dependencies, and
  infrastructure access goes through `InferenceProvider`/`VectorStore` interfaces.
  This shrinks the trusted surface the production API wraps and lets production
  backends be swapped without touching research code. `IMPLEMENTED`.

## API foundation controls (Phase 5, `apps/api`) — `IMPLEMENTED`

- **Response DTO** (`dto/chatResponse.js`): a strict field allowlist; the raw
  research result, internal `reasoning`/`threatCategory`/`violationType`, rule
  evidence, `logEntry`, hidden prompts, and any model `thinking`/chain-of-thought
  are dropped by construction. Verified by tests.
- **Typed errors + safe handler** (`errors/ApiError.js`, `middleware/errorHandler.js`):
  stable codes, stack traces/internals never returned; malformed JSON and
  oversized bodies map to 400.
- **HTTP hardening**: Helmet + strict CSP (`default-src 'none'`), strict CORS
  allowlist, `x-powered-by` disabled, HSTS in production.
- **Input validation**: Zod schemas with `.strict()` (unknown-key / mass-assignment
  rejection), prompt length cap, request body size limit.
- **Correlation ids**: per-request `requestId` (inbound honored only if well-formed)
  across logs, errors, and the DTO.
- **Timeouts**: end-to-end inference timeout → `INFERENCE_TIMEOUT`.
- **Auth boundary prepared**: `middleware/auth.js` isolates the future Cognito
  insertion point; routes/services depend only on `req.auth`. NOTE: until Phase 3,
  the API has no authentication and must not be publicly exposed.

## Planned (built in later phases — see IMPLEMENTATION_PLAN.md)

- Authentication (Cognito) + server‑side RBAC (`USER`/`RESEARCHER`/`ADMIN`).
- Per‑object ownership enforcement in every DB query.
- Distributed (Redis) rate limiting + per‑plan concurrent‑inference limits.
- API hardening: Helmet, strict CORS, CSP, HSTS, secure/HttpOnly/SameSite
  cookies, CSRF, body‑size limits, Zod validation, `requestId` correlation.
- Response DTOs + typed error catalogue (no stack traces to users).
- Secrets via AWS Secrets Manager / SSM + IAM roles (no static keys); Gitleaks
  in CI.
- Network isolation (VPC private subnets; Ollama/ChromaDB never public; SSM over
  SSH); TLS via ACM/ALB; AWS WAF.
- Command execution disabled by default in `PRODUCTION_MODE`; sandboxed runner if
  enabled (non‑root, read‑only FS, no network, resource caps, seccomp/AppArmor).
- SecurityEvent + append‑only AuditLog; CloudWatch alarms.
- Privacy controls (data export, deletion, retention, pseudonymized research
  retention) — see `docs/` privacy section (PLANNED) and PDPL alignment notes.

## Secrets policy

Never commit `.env`, DB passwords, JWT/billing secrets, or AWS keys. `.env.example`
documents every variable and where to obtain it. Production configuration is read
from Secrets Manager / SSM at runtime via IAM role — no long‑lived credentials on
instances or in images.

## Modes

`RESEARCH_MODE` preserves experimental behavior (fail‑open semantic validation,
shared session memory permitted, ChromaDB, command execution on). `PRODUCTION_MODE`
enforces fail‑safe, strict per‑user isolation, distributed rate limiting, DTO‑only
responses, and command execution off by default. The public production path must
run with `PRODUCTION_MODE` and must never enable Research Mode.
