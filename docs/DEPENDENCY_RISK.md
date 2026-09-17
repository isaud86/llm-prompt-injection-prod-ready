# Dependency Risk Record

Concise, living record of accepted dependency risk. Updated during the pre-merge
closure iteration (2026‑09‑17).

## High-severity npm audit findings (3)

All three are the **same transitive chain**, no direct fix available:

```
@chroma-core/default-embed  (direct dependency)
  └─ @huggingface/transformers  <=4.2.0
        └─ sharp  <=0.35.4-rc.0   ← the actual vulnerable package
```

| Field | Detail |
|---|---|
| Vulnerable package | `sharp` (native image processing; bundles libvips / libheif) |
| Advisories | libvips: CVE‑2026‑33327, CVE‑2026‑33328, CVE‑2026‑35590, CVE‑2026‑35591 (GHSA‑f88m‑g3jw‑g9cj); libheif: GHSA‑g89c‑p67h‑r497, GHSA‑2jg2‑4ch7‑h545 (GHSA‑rgj7‑g3m4‑5g8c) |
| Severity | high ×3 |
| Fix available | **No** (`npm audit` reports `fixAvailable:false`; upstream `sharp`/libvips/libheif fixes have not propagated through `@huggingface/transformers` → `@chroma-core/default-embed`) |
| Introduced via | `@chroma-core/default-embed` (the client-side embedding helper shipped alongside the `chromadb` client) |

## Reachability analysis

The vulnerable code is **image decoding** in libvips/libheif via `sharp`. This
project processes **no images**, and RAG embeddings are **text-only and computed
server-side** by the ChromaDB container (`queryTexts`), not by the local
`default-embed` package.

Verified in this repo:
- No source file (`packages/**`, `apps/**`, `scripts/**`, `tests/**`) requires
  `@chroma-core/default-embed`, `@huggingface/transformers`, or `sharp`.
- `require('chromadb')` does **not** load `sharp` (confirmed: `sharp` absent from
  the module cache after requiring the client).

| Surface | Reachable? |
|---|---|
| API runtime (`apps/api`) | **No** — text-only RAG; no image inputs; `sharp` never loaded |
| Research worker / CLI runtime | **No** — same; embeddings server-side in the Chroma container |
| Tests | **No** — chroma client is mocked; embedding lib never exercised |

## Disposition

**ACCEPTED TEMPORARY RISK — NOT RESOLVED.**

- No safe fix currently exists; force-upgrading (`npm audit fix --force`) would
  pull a different/again-vulnerable `default-embed` and risks breaking the
  research embedding path — **not done**.
- The vulnerable image-decoding functionality is not reachable in any runtime or
  test (see above), so exploitability in this application is effectively nil
  today.
- CI reports `npm audit` as **informational (non-blocking)**; this is accurate —
  it is a known, unresolved, unreachable transitive risk, not a fixed issue.
  Gitleaks remains the hard secret-scanning gate.

## Future architectural action (NOT this iteration)

Separate the **public API / Web runtime** from the **Research / GPU / Embedding
runtime** so the API container does not inherit `chromadb` /
`@huggingface/transformers` / `sharp` / ONNX / native dependencies at all. That
removes this chain from the internet-facing image entirely, independent of
whether an upstream fix lands. Tracked for a later phase; do not perform now.

## Re-check procedure

```bash
npm audit --audit-level=high          # expect the same 3 high (sharp chain) until upstream fixes land
npm ls sharp @huggingface/transformers @chroma-core/default-embed
```
Re-evaluate this record whenever `@chroma-core/default-embed` or `chromadb` is
upgraded, or when `npm audit` reports `fixAvailable` for `sharp`.
