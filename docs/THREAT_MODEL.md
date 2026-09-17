# Threat Model

Scope: the target production SaaS (`docs/ARCHITECTURE.md`). The current research
CLI is single‑user/local and out of scope except where its code is reused. This
is a living document; controls marked *(planned)* are not yet implemented.

## 1. Assets

- User accounts, credentials (in Cognito, not us), sessions, MFA secrets.
- User conversations & messages (confidential, per‑tenant).
- Billing/subscription data and provider secrets.
- The GPU/Ollama inference capacity (scarce, DoS‑sensitive).
- Security telemetry (SecurityEvent/AuditLog) and research datasets.
- Platform secrets (DB creds, JWT/JWKS, billing keys) and AWS credentials.

## 2. Trust boundaries

Internet → CloudFront/WAF → ALB → (web, api) → (Cognito, RDS, Redis) → inference
gateway → GPU worker → Ollama (localhost). Each arrow is a boundary; the
worker↔Ollama boundary is the most sensitive (command execution + model).

## 3. Actors & threats → controls

| Actor / threat | Vector | Primary controls *(status)* |
|---|---|---|
| **External attacker** | Unauthenticated API calls, credential stuffing, scraping | Cognito authN, WAF managed + rate rules, distributed rate limit, TLS *(planned)* |
| **Malicious registered user** | IDOR to other tenants' data, quota bypass, abuse | Server‑side ownership checks (`where {id,userId}`), RBAC, server‑side quota, audit log **(isolation core: PARTIAL/TESTED)** |
| **Compromised account** | Stolen token/session reuse | Short‑lived JWT + refresh, MFA, session expiry, anomaly SecurityEvents *(planned)* |
| **Prompt injection (direct)** | Malicious chat input to hijack the agent | Hybrid rule+semantic pipeline **(implemented, research core)**, `think:false`, DTO output filtering |
| **Indirect prompt injection** | Poisoned RAG/retrieved content | RAG provenance metadata, retrieved‑doc trust classification, content separation *(planned §14)* |
| **RAG poisoning** | Adversarial docs added to vector store | Restricted write path, per‑tenant scoping / mode gate, provenance *(planned)* |
| **Command execution abuse** | Trick agent into running commands | `execFile` (no shell) + whitelist + double‑check **(implemented)**; prod: disabled/sandboxed *(planned §13)* |
| **GPU denial‑of‑service** | Flood inference to saturate GPU | Bounded concurrency, queue + backpressure, circuit breaker, per‑plan concurrent‑inference limit *(planned §12)* |
| **Billing abuse** | Fake/replayed webhooks, entitlement forgery | Webhook signature verify + idempotency + replay protection, server‑side entitlements *(planned §10)* |
| **API abuse** | Malformed/oversized payloads, mass assignment | Zod validation, body size limits, unknown‑field rejection, typed errors *(planned §16)* |
| **Database compromise** | Exfiltration | Private subnet, TLS, encryption at rest (KMS), least‑priv creds, no `0.0.0.0/0` *(planned §22/§28)* |
| **Insider misuse** | Admin overreach | Append‑only AuditLog for privileged ops, least privilege, MFA for admin *(planned §19)* |
| **Supply‑chain compromise** | Malicious dep / build | Committed lockfile **(done)**, SCA + secret + container scans in CI *(planned §33)* |

## 4. OWASP mappings

**OWASP Top 10 (web):** A01 Broken Access Control → ownership checks + RBAC;
A02 Crypto Failures → TLS + KMS at rest; A03 Injection → `execFile`/whitelist +
Zod; A04 Insecure Design → this threat model + modes; A05 Misconfig → Helmet/CSP/
WAF/IaC; A07 Auth Failures → Cognito+MFA+lockout; A08 Integrity → signed webhooks
+ lockfile; A09 Logging → SecurityEvent/AuditLog + CloudWatch; A10 SSRF → egress
controls on worker.

**OWASP API Top 10:** API1 BOLA → per‑object ownership enforcement; API2 Broken
Auth → JWT/JWKS + MFA; API3 Property‑level authz → DTO serializer + mass‑assign
rejection; API4 Resource consumption → quotas + concurrency limits; API5 Function
authz → route‑level RBAC; API8 Misconfig → security headers; API10 unsafe
consumption of 3rd‑party → provider interfaces + timeouts/circuit breakers.

**OWASP LLM Top 10:** LLM01 Prompt Injection → hybrid pipeline (core);
LLM02 Insecure Output Handling → output filter + DTO; LLM04 Model DoS →
concurrency/queue/rate; LLM06 Sensitive Disclosure → redaction + no CoT + path
blocking; LLM07/08 Plugin/Excessive Agency → command whitelist/sandbox/disable;
LLM03 Training/Data Poisoning → RAG provenance & trust classification.

## 5. Residual risks (accepted / to revisit)

- Semantic validator quality is bounded by the local model; false negatives
  possible → defense in depth (rules + whitelist + sandbox) is the safety net.
- Regex‑based output redaction is best‑effort → keep the command whitelist tiny.
- Research Mode intentionally relaxes fail‑safe/isolation for reproducibility →
  must never be enabled on the public production path.
