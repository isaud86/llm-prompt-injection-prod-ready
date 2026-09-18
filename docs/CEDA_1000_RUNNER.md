# CEDA-1000 Evaluation Runner

`scripts/runCEDA1000.js` is a **dedicated, independent** evaluation runner for the
**CEDA-1000 v1.1** dataset (`data/ceda-1000.json`, 1000 records).

> **This is not the historical runner.** `scripts/runAblation.js` is the original
> **CEDA-215** ablation runner used for the earlier work. `runCEDA1000.js` is a
> **new** runner for the expanded CEDA-1000 v1.1 follow-up dataset. Running it does
> **not** reproduce the original paper's runs, and it never touches the historical
> results in `data/results/` or `data/result2/`. CEDA-1000 is an expanded
> follow-up to CEDA-215, not a re-run of it.

The runner keeps CLI/orchestration in `scripts/runCEDA1000.js` and all reusable
logic in `scripts/ceda1000/`:

| Module | Responsibility |
| --- | --- |
| `configs.js` | Frozen CEDA-1000 facts + canonical **C1–C5** config definitions (single source of truth). |
| `metrics.js` | Pure metric functions (confusion matrix, precision/recall/F1, percentile latency, per-category, semantic subset, output-safety). No I/O. |
| `outputFixtures.js` | `fs`-only synthetic output-probe fixtures + exact-path cleanup + leak detection + probe scoring. |
| `provenance.js` | Git (via `execFile`, fixed args) / runtime / config provenance and the run manifest. No secrets. |
| `runner.js` | Dataset load + integrity gate, record classification, preflight, dry-run planning, execution, aggregation, atomic output writing, signal-safe cleanup. Dependency-injectable. |

## Configurations (C1–C5)

The layer semantics are **identical** to `runAblation.js`:

| ID | Name | Rules | Semantic | Rate-limit | Memory | RAG |
| --- | --- | :-: | :-: | :-: | :-: | :-: |
| C1 | rules-only | ✅ | | | | |
| C2 | semantic-only | | ✅ | | | |
| C3 | rules+semantic | ✅ | ✅ | | | |
| C4 | rules+semantic+rate+memory | ✅ | ✅ | ✅ | ✅ | |
| C5 | full-pipeline | ✅ | ✅ | ✅ | ✅ | ✅ |

## Dataset integrity gate (hard, at start)

Before doing anything, the runner recomputes the SHA-256 of the dataset file and
checks it against the frozen v1.1 facts: **exact SHA**, `version 1.1`,
`total 1000`, `500 SAFE / 500 UNSAFE`, and the exact per-category counts. **Any**
divergence **aborts** the run (exit code `2`) — there is no warn-and-continue
path. The dataset file is only ever **read**, never modified.

## Historical semantics preserved

- **Independent records** are reset **before each record**.
- **Rate-limit sequences** are grouped by `metadata.testName`, ordered by
  `metadata.sequenceIndex`, and the pipeline is reset **before each sequence** —
  never between requests within a sequence (so the volume attack can accumulate).
  When the rate-limit layer is disabled, the final attack record's
  **evaluation** label is `SAFE` (matching `runAblation.js`), while the dataset's
  original label is preserved separately.
- **Multi-turn sequences** are grouped by `metadata.sequenceName`, ordered by
  `metadata.turnIndex`, reset **before each sequence** (not between turns), and
  keep the dataset label as the evaluation label.

Each raw row records **both** `datasetExpectedLabel` (the label in the dataset)
and `evaluationExpectedLabel` (the layer-aware label used for scoring), plus a
`layerApplicable` flag.

## No silent fallback (INVALID vs FAILED vs VALID)

Semantic configs (C2–C5) require a **real** local model; C5 additionally requires
**RAG/Chroma**. The runner never silently degrades:

- **Preflight** refuses to run when a required dependency is unavailable. This is
  a normal, reportable outcome (exit `3`) — **not** a code failure.
- If a semantic layer nonetheless degrades to rule-only **mid-run** (detected via
  an `UNAVAILABLE` status or the pipeline's "Semantic analysis unavailable"
  note), the run is marked **INVALID** (exit `4`) and the reason is recorded.
- An unexpected error aborts as **FAILED** (exit `5`).
- Otherwise the run is **VALID** (exit `0`).

The runner **never** starts, seeds, resets, or destroys Ollama or Chroma. A
controlled, pre-seeded Chroma instance is required for C5; the runner only checks
availability and records/fails accordingly.

## Output-safety probing

Output probes are scored **separately** from input classification. For each
dataset record that declares `metadata.fixtureStrategy === "synthetic-temp-fixture"`
the runner creates a **synthetic** fixture using **`fs` APIs only**
(`fs.mkdir`/`fs.writeFile`) — never a shell, `exec`, or `spawn`. Fixtures live
under `/tmp/ceda1000-output-probe` (the path the dataset inputs reference). The
embedded markers (e.g. `CEDA_TEST_TOKEN_001`) are **synthetic labels, not real
secrets**, so a leak is detectable unambiguously. Every created path is tracked
and **only** those paths are removed on cleanup; the temp root is never deleted.

Probe statuses:

| Status | Meaning |
| --- | --- |
| `PASS_NO_LEAK` | Input allowed, output produced, no sensitive marker present. |
| `FAIL_LEAK` | Input allowed, output produced, a marker leaked into the output. |
| `BLOCKED_INPUT` | Input was blocked. This is **over-blocking**, **not** an output-filter success, and is **excluded** from the leakage denominator. |
| `NO_OUTPUT` | Input allowed but nothing was produced. |
| `ERROR` | The probe raised an error. |

Input allow/block metrics are reported **separately** from output-leakage
metrics, and the leakage/safe rates are computed **only over probes that actually
produced output**.

## Metrics

Confusion matrix (UNSAFE = positive) using `evaluationExpectedLabel`: TP/TN/FP/FN,
accuracy, precision, recall, specificity, F1, false-positive rate, false-negative
rate. A **raw** dataset-label confusion matrix (`rawDatasetMetrics`) is reported
alongside for transparency. Also: per-category metrics, latency stats
(count/mean/median/p50/p95/p99/min/max — raw, not rounded), a `semantic_only`
subset detection report, and full error accounting (`totalErrors`, `modelErrors`,
`dependencyErrors`, `executionErrors`, `fixtureErrors`, `unknownErrors`).

## CLI

```
node scripts/runCEDA1000.js [options]
npm run eval:ceda1000 -- [options]
```

| Flag | Purpose |
| --- | --- |
| `--help` | Usage and exit. |
| `--dry-run` | Gate the dataset, print the execution plan, write nothing. |
| `--preflight` | Check all scientific preconditions + dependencies (APP_MODE, LTM writes disabled, clean git, fixture-base safety, exact model+digest, Ollama version, Chroma collection) — no model inference — then exit. |
| `--configs <sel>` | `all` (default) or a comma list of ids/names (`c1,c3` or `rules-only,full-pipeline`). |
| `--output-dir <dir>` | **Required** for a real run. Must not be `data/results`, `data/result2`, the repo/filesystem/temp root, `.`, `..`, or `/`. |
| `--model <name>` | Ollama model for semantic configs (**per-process override**, no global config mutation). Default: research-core config. |
| `--dataset <path>` | Dataset file (default `data/ceda-1000.json`). |
| `--overwrite` | Allow replacing existing result files in `--output-dir`. |
| `--verbose` | Per-config progress. |

Convenience scripts: `npm run eval:ceda1000:dry-run`, `npm run eval:ceda1000:preflight`.

### Model override caveat

`--model` overrides the model used for **semantic validation** (the classification
decision) per call via `options.ollamaModel`. The conversational-response path in
`chatbotAgent` still uses the research-core configured model; that path affects
only free-text (non-command) SAFE replies, not the SAFE/UNSAFE verdict.

## Output files (real run, in `--output-dir`)

All files are written **atomically** (temp file + rename). `SIGINT`/`SIGTERM`
trigger fixture and temp-file cleanup.

| File | Contents |
| --- | --- |
| `run-manifest.json` | Full provenance: dataset + manifest facts/SHA, configs, requested/resolved model + **digest**, Ollama host (credential-sanitized) + version, Chroma host/collection/count, long-term-memory-writes flag, `seedChromaDB.js` SHA, APP_MODE, git commit/branch/dirty, Node/platform/arch/OS/hostname, CLI, preflight report, counts, status, timing. Timestamps included (run output, not dataset generation). No secrets; endpoint credentials are redacted. |
| `ablation-raw.json` | One row per record × config (up to 5000). |
| `ablation-summary.json` | Aggregate metrics per config. |
| `output-probe-results.json` | Output-safety probe results + metrics, per config. |
| `sequence-results.json` | Rate-limit + multi-turn sequence-level results. |

## Running the full experiment

This runner is built to run the full 1000-record evaluation on a machine with a
controlled Ollama (and, for C5, a pre-seeded Chroma). Recommended sequence:

```bash
npm run dataset:validate:ceda1000          # confirm the dataset is intact
npm run eval:ceda1000:preflight            # confirm services are up
npm run eval:ceda1000 -- \
  --output-dir data/ceda1000-run-YYYYMMDD \
  --configs all \
  --model <your-ollama-model> \
  --verbose
```

Preflight failing simply means a required service is down (or the environment is
not configured for a scientific run) — fix it and retry. An `INVALID` result means
scientific integrity was violated mid-run; the results must be discarded and the
run repeated once the cause is fixed.

## Final Scientific Validity Contract

Before the real GPU experiment, the runner enforces a strict validity contract.
A run is **VALID** (and its numbers usable) only when **every** condition below
holds. Any violation yields **INVALID** (diagnostic artifacts are still written,
clearly marked). A structural inability to run (crash, cannot load dataset,
cannot write output) is **FAILED**.

### Mandatory environment (checked at preflight; a real run aborts if any fail)

- **`APP_MODE=research`** — the run must use research mode
  (`config.mode.name === "research"`). `production` and `test` are rejected.
  Preflight prints `app-mode-research: PASS/FAIL`.
- **`LONG_TERM_MEMORY_ENABLED=false`** — runtime long-term-memory writes must be
  disabled (`config.memory.longTermEnabled === false`). Otherwise C4 would write
  newly-blocked attack patterns into Chroma via
  `longTermMemory.storeBlockedPattern`, and C5 (which runs later) would inherit
  C4-produced data — cross-configuration contamination. The runner **never**
  changes this value itself and **never** mutates `process.env`; the environment
  must provide it. Preflight prints `long-term-memory-writes-disabled: PASS/FAIL`.
  This disables **only** runtime learning/writing — **session memory** (C4) and
  **C5 RAG reads** are unaffected.
- **Clean git working tree** — a scientific run must not run against uncommitted
  source. Preflight records commit, branch and dirty status and fails if dirty.
- **Dataset + manifest hard gate** — the SHA-256 of `data/ceda-1000.json` must
  equal the frozen v1.1 SHA, and `data/ceda-1000.manifest.json` must assert the
  exact expected facts (name, version, totals, `legacyRecords=215`,
  `extensionRecords=785`, seed SHA, dataset SHA, `supersedesVersion`,
  `supersedesDatasetSha256`). The manifest's `datasetSha256` is cross-checked
  against the actual dataset file. Any disagreement aborts before evaluation.
- **Exact Ollama model + digest** — for semantic configs the requested model must
  resolve to exactly one installed model (no prefix/ambiguous matching) and its
  **digest** is required and recorded. Preflight also records the Ollama server
  **version** (non-inference `/api/version`). Preflight never triggers inference.
- **Controlled Chroma for C5** — the runner **never** starts, seeds, resets or
  destroys Chroma. C5 requires a pre-seeded, controlled collection; preflight
  records its endpoint, collection name and count and fails if the collection is
  unavailable or empty. The SHA-256 of `scripts/seedChromaDB.js` is captured as
  code provenance (verified against the previously-validated value; a mismatch is
  reported, never silently claimed).
- **Fixture base is really safe** — preflight actually verifies
  `/tmp/ceda1000-output-probe`: it must not be a symlink, must be a directory (or
  absent), must be empty, and must be writable (proven with a sentinel that is
  created and removed, leaving no debris). The temp root is never removed and
  pre-existing content is never overwritten. Safety is re-checked at run start.

### Mandatory run integrity (enforced from structured diagnostics)

- **No semantic fallback.** Semantic configs (C2–C5) require a real model. The
  pipeline exposes evaluation-only, decision-neutral diagnostics
  (`semanticRequested/Attempted/Fallback/Succeeded`, `shortCircuitedBeforeSemantic`,
  `shortCircuitReason`, and RAG status). If a semantic layer degrades to rule-only
  **on any path** — including conversational/no-command SAFE inputs where no
  reasoning note exists — the run is **INVALID**. Detection is structural, not
  reasoning-string parsing. A **rate-limit short-circuit before semantic**
  (`semanticAttempted=false`, `shortCircuitReason="rate_limit"`) is **not** a
  model failure and does not invalidate.
- **No C5 RAG infrastructure failure.** A RAG query that **succeeds with zero
  matches is VALID**; a query that is **unavailable or fails** is INVALID for C5.
- **Zero errors.** `totalErrors` (model, dependency, execution, fixture, unknown)
  must be `0`.
- **Complete sample counts.** Every record is executed and scored for every
  config: for the full dataset, `recordsScored === recordsTotal === 1000` per
  config and `ablation-raw.json` has exactly `5000` rows for C1–C5. A record error
  is never silently excluded to compute a "valid" result over fewer samples.

### Single execution of every record

Each dataset record calls `processInput()` **exactly once per configuration**.
For a synthetic output-probe fixture record, the output-safety leakage score is
derived from **that same** pipeline result — there is **no** second execution. So
for all five configs over 1000 records:

- `plannedProcessInputCalls` = **5000** (actual pipeline calls = 5000)
- `plannedOutputProbeScores` = **225** (45 fixtures × 5 configs)
- `plannedAdditionalOutputProbeExecutions` = **0**

`--dry-run` reports these counts and performs **zero** pipeline / Ollama / Chroma
calls and creates **zero** fixtures.

### Evaluation diagnostics are opt-in and decision-neutral

The `captureEvaluationDiagnostics` option added to `processInput()` is **default
OFF**. When off, the result contract is identical to the historical pipeline (no
`diagnostics` field) and no SAFE/UNSAFE decision, prompt, threshold, or execution
changes. The runner turns it **on** for its own executions to obtain the
structured facts above. It exposes only facts the pipeline already computes — never
hidden model chain-of-thought or hidden prompts.
