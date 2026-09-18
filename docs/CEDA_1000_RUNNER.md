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
| `--preflight` | Check required dependencies (no model inference), then exit. |
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
| `run-manifest.json` | Provenance: dataset SHA, configs, CLI, preflight, git, runtime, config snapshot, status, timing. Timestamps are included (this is run output, not dataset generation). No secrets. |
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

Preflight failing simply means a required service is down — bring it up and retry.
An `INVALID` result means a semantic layer degraded mid-run; the results should be
discarded and the run repeated once the model is stable.
