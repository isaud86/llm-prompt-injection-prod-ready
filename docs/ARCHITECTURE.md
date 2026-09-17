# Architecture — Current vs. Target

**Status:** the *current* architecture is implemented and running. The *target*
architecture is a **design** to be built in phases (see
`docs/IMPLEMENTATION_PLAN.md`). Nothing in the target section should be read as
"already built." Diagrams use Mermaid.

---

## 1. Current architecture (as‑built, commit `42e0ab7`)

A single Node.js process, driven by a terminal REPL, orchestrating a hybrid
rule + local‑LLM defense pipeline over Ollama, with an optional ChromaDB RAG
sidecar and file‑based logging. Single user, single process, single host.

```mermaid
flowchart TD
    U[Operator at terminal] -->|stdin REPL| CLI[src/index.js<br/>REPL + C1–C5 toggles]
    CLI --> PA[policemanAgent.processInput]

    subgraph Pipeline [In-process pipeline - process-global state]
        PA --> RL[RateLimiter<br/>process-global instance]
        PA --> SM[sessionMemory<br/>module-global history array]
        PA --> RV[ruleBasedValidator<br/>~29 regex rules]
        PA --> SV[semanticValidator<br/>Ollama JSON classifier]
        SV --> RAG[ragRetriever + chromaClient]
        PA --> CB[chatbotAgent<br/>execFile ls/date + Ollama chat]
        CB --> OF[outputFilter<br/>regex redaction]
        PA --> LT[longTermMemory]
    end

    SV -->|HTTP 11434| OLL[(Ollama<br/>llama3.2 / qwen3.5)]
    CB -->|HTTP 11434| OLL
    RAG -->|HTTP 8000| CHR[(ChromaDB)]
    LT --> CHR
    PA --> LOG[[logs/security.log<br/>append-only JSON]]

    classDef ext fill:#eef,stroke:#88a
    class OLL,CHR ext
```

**Request flow:** rate‑limit → session‑memory context → rule validation →
semantic validation (+RAG) → combine (hybrid) → if safe, extract & `execFile`
allowed commands (or Ollama chat) → output filter → log. Ollama down ⇒ semantic
step **fails open** to rules‑only (by design, for reproducibility).

**C1–C5 presets** (research ablation) toggle which layers are active:

| Preset | Rules | Semantic | Rate limit | Session memory | RAG |
|---|---|---|---|---|---|
| C1 | ✓ | | | | |
| C2 | | ✓ | | | |
| C3 | ✓ | ✓ | | | |
| C4 | ✓ | ✓ | ✓ | ✓ | |
| C5 | ✓ | ✓ | ✓ | ✓ | ✓ |

### Current deployment (as described for the research EC2)

```mermaid
flowchart LR
    Op[Researcher via SSH] --> EC2
    subgraph EC2 [Single GPU EC2 instance]
        Node[Node REPL process]
        Node -->|localhost:11434| Ollama[(Ollama + GPU)]
        Node -->|localhost:8000| Chroma[(ChromaDB container)]
    end
```

Risk: if any of 11434 / 8000 / (a future) 3000 / 3001 are opened in the security
group, internal services are directly internet‑reachable. §22 forbids this.

---

## 2. Target architecture (design — to be built in phases)

### 2.1 Target repository layout (monorepo, incremental)

The research core is **extracted and wrapped**, never rewritten:

```
/
├── apps/
│   ├── web/          # Next.js + TypeScript + Tailwind + shadcn/ui (premium UI)
│   ├── api/          # Node/TypeScript HTTP API: authN/Z, quotas, DTOs, RBAC
│   └── worker/       # Inference worker: consumes queue, calls research-core
├── packages/
│   ├── research-core/  # the EXISTING pipeline, extracted verbatim behind interfaces
│   ├── database/       # Prisma schema, client, migrations
│   ├── auth/           # Cognito integration + session/JWT verification
│   ├── security/       # typed errors, input schemas (Zod), redaction, headers
│   ├── billing/        # BillingProvider interface + Stripe/Moyasar/HyperPay
│   ├── observability/  # OpenTelemetry + CloudWatch wiring, logger
│   └── shared/         # DTOs, types, constants shared across apps
├── infra/
│   ├── terraform/      # dev / staging / production stacks
│   ├── docker/         # Dockerfile.web / Dockerfile.api / Dockerfile.worker
│   └── nginx/          # local reverse proxy (dev/self-host)
├── scripts/            # existing evaluation + provenance capture (preserved)
├── tests/              # unit / integration / e2e / security / load
├── docs/
└── .github/workflows/  # CI/CD
```

Migration keeps the current `src/` working until `packages/research-core`
replaces it with green tests (strangler‑fig, not big‑bang).

**Status (Phase 1b — DONE/TESTED):** `src/` has been moved into
`packages/research-core/src/` (history preserved). The package exposes a
framework‑free public API (`packages/research-core/index.js`) and infrastructure
interfaces under `providers/` (`InferenceProvider`/`OllamaInferenceProvider`,
`VectorStore`/`ChromaVectorStore`). `apps/api` (Phase 5) consumes the package via
this barrel and never reaches into its internals. `apps/web` and `apps/worker`
remain to be built in later phases.

**Status (Phase 5 — DONE/TESTED):** `apps/api` is a runnable Express service over
research-core with `/healthz`, `/readyz`, and `POST /api/v1/chat`. It enforces a
response DTO (no raw result / reasoning / chain-of-thought), a typed-error
catalogue with a safe error handler, Helmet + strict CORS + CSP, Zod validation
with unknown-key rejection, body-size limits, per-request correlation ids, and an
end-to-end inference timeout. The auth middleware is a boundary placeholder
(anonymous principal) ready for Cognito in Phase 3; distributed rate limiting
(Redis) is Phase 4. The service is not yet fit for public exposure (no auth).

### 2.2 Target logical architecture

```mermaid
flowchart TD
    User((User / Researcher / Admin))
    User -->|HTTPS 443| CF[CloudFront + AWS WAF]
    CF --> ALB[Application Load Balancer<br/>ACM TLS, HTTP→HTTPS]

    ALB --> Web[Next.js Web<br/>ECS Fargate]
    ALB --> API[API Service<br/>ECS Fargate]

    Web -. auth .-> COG[Amazon Cognito<br/>User Pools + MFA]
    API --> COG
    API --> PG[(RDS PostgreSQL<br/>Multi-AZ, pgvector)]
    API --> REDIS[(ElastiCache Redis<br/>sessions, rate limit, queue, locks)]

    API -->|enqueue inference| IGW[Inference Gateway<br/>concurrency + circuit breaker]
    IGW --> Q{{Redis queue<br/>backpressure}}
    Q --> WK[GPU Worker<br/>ECS EC2 / GPU EC2]
    WK --> RC[research-core pipeline]
    RC -->|localhost| OLL[(Ollama<br/>Qwen / Llama)]
    RC --> VS[VectorStore]
    VS --> CHR[(ChromaDB — Research Mode)]
    VS --> PGV[(pgvector — Production Mode)]

    API --> SM[(Secrets Manager / KMS)]
    API --> OTEL[OpenTelemetry → CloudWatch / X-Ray]
    WK --> OTEL

    classDef ext fill:#eef,stroke:#88a
    class OLL,CHR,PGV ext
```

### 2.3 Target network isolation (VPC)

```mermaid
flowchart TB
    subgraph Public [Public subnets]
        ALB[ALB :443]
        NAT[NAT Gateway]
    end
    subgraph App [Private app subnets]
        WEB[Web tasks]
        APISVC[API tasks]
        IGW[Inference gateway]
    end
    subgraph Data [Private data subnets]
        RDS[(RDS PostgreSQL)]
        REDIS[(ElastiCache Redis)]
    end
    subgraph GPU [Private GPU subnet]
        WORKER[GPU worker]
        OLLAMA[(Ollama :11434 localhost only)]
    end

    Internet((Internet)) -->|443 only| ALB
    ALB --> WEB
    ALB --> APISVC
    APISVC -->|5432| RDS
    APISVC -->|6379| REDIS
    APISVC --> IGW
    IGW --> WORKER
    WORKER -->|localhost| OLLAMA
    App --> NAT --> Internet
```

**Security‑group rules (least privilege):** Internet→ALB:443 only; ALB→web/api;
api→RDS:5432; api→Redis:6379; api/igw→worker; worker→Ollama on localhost.
**Never** `0.0.0.0/0` → Postgres / Redis / Ollama / ChromaDB. Use SSM Session
Manager instead of SSH.

### 2.4 Research Mode vs. Production Mode

The same `research-core` runs in both modes; behavior differs by explicit flags
so production hardening **never silently changes experimental results** (§3):

| Concern | `RESEARCH_MODE` | `PRODUCTION_MODE` |
|---|---|---|
| Semantic validator when Ollama down | fail‑open (rules only) | fail‑safe (block / degrade to safe refusal) |
| Session memory | shared/global allowed for reproducibility | strictly per `userId:conversationId` |
| Rate limiting | in‑process (as in experiments) | distributed (Redis) |
| Vector store | ChromaDB | pgvector (configurable) |
| Command execution | enabled (`ls`,`date`) | disabled by default; sandboxed if enabled |
| Response shape | full diagnostic object | safe DTO only (researchers get diagnostics via a separate authorized endpoint) |
| C1–C5 presets | first‑class | available to `RESEARCHER` role only |

---

## 3. Sequence — a production chat request (target)

```mermaid
sequenceDiagram
    participant U as Browser
    participant W as Web (Next.js)
    participant A as API
    participant Z as Cognito
    participant R as Redis
    participant G as Inference Gateway
    participant K as GPU Worker
    participant O as Ollama

    U->>W: send message (conversationId)
    W->>A: POST /v1/chat (JWT, requestId)
    A->>Z: verify JWT (JWKS cache)
    A->>A: RBAC + Zod validation
    A->>R: quota + distributed rate limit check
    A->>R: load session:{userId}:{conversationId}
    A->>G: enqueue inference (bounded concurrency)
    G->>K: dispatch when slot free (circuit breaker)
    K->>O: research-core pipeline (think:false)
    O-->>K: model response (no chain-of-thought)
    K-->>G: SAFE/VIOLATION + safe fields
    G-->>A: result
    A->>A: serialize to DTO (strip internals)
    A-->>W: {requestId,status,response,latencyMs,model}
    W-->>U: render (streaming where appropriate)
```

---

## 4. Why these choices (brief §56 rationale)

- **ECS Fargate over Kubernetes:** manageable for a small research/eng team; no
  control‑plane ops burden. GPU worker on ECS‑EC2/GPU EC2 because Fargate lacks
  GPUs.
- **Cognito over home‑grown auth:** offload password storage, MFA, verification,
  reset — reduces the AppSec blast radius (§7).
- **Redis for ephemeral state only** (sessions, rate limit, queue, locks) — never
  the system of record (§29).
- **pgvector optional for production RAG** to cut a stateful service, while
  **ChromaDB stays canonical for research** (§30).
- **Provider interfaces** (`InferenceProvider`, `VectorStore`, `BillingProvider`)
  keep business logic decoupled and swappable (§10, §12, §30).
