# apps/api — Production API foundation (Phase 5)

A clean HTTP API built **around** `@llm-injection/research-core` (it consumes the
package's public barrel via `src/services/pipeline.js` and never reaches into its
internals). It is the seam where production concerns — authentication, quotas,
DTOs, typed errors, rate limiting — attach without touching the scientific code.

## Run

```bash
npm run api:start          # node apps/api/src/index.js  (default port 3001)
API_PORT=3055 npm run api:start
```

Configuration (all optional; see repo `.env.example`): `NODE_ENV`, `API_PORT`,
`API_CORS_ORIGINS`, `API_BODY_LIMIT`, `API_REQUEST_TIMEOUT_MS`,
`API_MAX_MESSAGE_LENGTH`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness — process is up. `{ "status": "ok" }` |
| GET | `/readyz` | Readiness — Ollama reachable + model available (RAG optional). `{ "status": "ready" \| "not_ready" }`, 200/503. Per-check detail is logged server-side only. |
| POST | `/api/v1/chat` | Run one turn through the pipeline. Returns the safe DTO. |

### `POST /api/v1/chat`

Request (validated by Zod, `.strict()`):

```json
{ "message": "list files", "conversationId": "<uuid?>", "sessionId": "<uuid?>", "preset": "c1..c5? (researcher-only)" }
```

Response DTO (the ONLY fields exposed — §42):

```json
{ "requestId": "...", "conversationId": "...", "status": "SAFE|BLOCKED", "response": "...", "model": "qwen3.5:2b", "latencyMs": 640 }
```

Never returned: the raw result object, internal security `reasoning`,
`threatCategory`/`violationType`, rule evidence, hidden prompts, model
`thinking`/chain-of-thought, internal logs, secrets, or stack traces.

## Security controls (this phase)

- Helmet security headers + strict CSP (`default-src 'none'` for a JSON API); HSTS in production.
- Strict CORS allowlist (`API_CORS_ORIGINS`); credentials off.
- Request body size limit; Zod schema validation; unknown-key rejection (mass-assignment defense).
- Correlation `requestId` on every request (honored from `x-request-id` only if well-formed) → logs, errors, DTO.
- Typed error catalogue + safe error middleware: `INVALID_REQUEST`, `AUTH_REQUIRED`, `RATE_LIMITED`, `SECURITY_BLOCKED`, `MODEL_UNAVAILABLE`, `INFERENCE_TIMEOUT`, `SERVICE_UNAVAILABLE`, `INTERNAL_ERROR`. Stack traces/internals never leave the process.
- End-to-end inference timeout (`INFERENCE_TIMEOUT`).
- Environment-specific error verbosity (`NODE_ENV`).

## Deferred (later phases — boundaries prepared)

- **Auth (Phase 3):** `src/middleware/auth.js` attaches an anonymous principal
  today; Cognito JWT verification drops in there without changing routes/services.
  **Until then the API must not be publicly exposed** — conversation isolation by
  client-supplied UUID is not an authenticated boundary.
- **Distributed rate limiting (Phase 4):** Redis replaces research-core's
  in-process limiter.
- **Command execution:** enabled in Research Mode (`ls`/`date`); Production Mode
  disables/sandboxes it (Phase 13).

## Layout

```
src/
  app.js            createApp() — middleware wiring
  index.js          server bootstrap + graceful shutdown
  config.js         API config (no research-core coupling)
  context/          per-request context (requestId/session/conversation/userId)
  middleware/       requestId, auth boundary, zod validate, safe errorHandler
  dto/              chatResponse serializer (safe field allowlist)
  errors/           ApiError typed catalogue
  routes/           health, chat
  services/         pipeline (research-core seam), chatService, readiness
tests/              health, chat, research-core contract (supertest + jest)
```
