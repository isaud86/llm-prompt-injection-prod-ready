/**
 * CEDA-1000 evaluation runner (core logic).
 *
 * Responsibilities:
 *   - Load data/ceda-1000.json and HARD-GATE it against the frozen v1.1 facts
 *     (exact SHA-256, version, totals, per-category counts). Any mismatch aborts
 *     the run — there is no warn-and-continue path.
 *   - Preserve the historical C1–C5 ablation semantics (see runAblation.js):
 *     reset before each independent record and before each stateful sequence,
 *     never between requests/turns within a sequence; rate-limit records are
 *     evaluated as SAFE when the rate-limit layer is disabled.
 *   - Execute independent, rate-limit (stateful) and multi-turn (stateful)
 *     records; separately score output-safety probes against synthetic fixtures.
 *   - NEVER silently fall back: semantic configs (C2–C5) require a real model and
 *     C5 requires RAG. Preflight refuses to run when a required dependency is
 *     unavailable, and any per-record fallback observed during a run marks the
 *     run INVALID.
 *   - Emit raw results, aggregate metrics, output-probe results, sequence
 *     results and a provenance manifest — written atomically.
 *   - NEVER modify the dataset. Dataset input strings flow ONLY into
 *     processInput() (and, as pure strings, into fixture-path parsing).
 *
 * This module is dependency-injectable: processInput, resetPipeline, the
 * inference/vector providers, and config are all overridable so the unit suite
 * runs with mocks and never touches Ollama, Chroma or a GPU.
 */

const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const { FROZEN, resolveConfigs } = require("./configs");
const metrics = require("./metrics");
const outputFixtures = require("./outputFixtures");
const provenance = require("./provenance");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const DEFAULT_DATASET = path.join(REPO_ROOT, "data", "ceda-1000.json");

// Output directories the runner must NEVER write into (historical results).
const FORBIDDEN_OUTPUT_DIRS = [
  path.join(REPO_ROOT, "data", "results"),
  path.join(REPO_ROOT, "data", "result2"),
];

const OUTPUT_FILES = Object.freeze({
  manifest: "run-manifest.json",
  ablationRaw: "ablation-raw.json",
  ablationSummary: "ablation-summary.json",
  outputProbe: "output-probe-results.json",
  sequence: "sequence-results.json",
  log: "run.log",
});

class PreflightError extends Error {
  constructor(message, report) { super(message); this.name = "PreflightError"; this.report = report; }
}
class DatasetIntegrityError extends Error {
  constructor(message, details) { super(message); this.name = "DatasetIntegrityError"; this.details = details; }
}
class OutputPathError extends Error {
  constructor(message) { super(message); this.name = "OutputPathError"; }
}

// ─── Dataset load + integrity gate ───────────────────────────────────────────

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function categoryCounts(dataset) {
  const counts = {};
  for (const r of dataset) counts[r.category] = (counts[r.category] || 0) + 1;
  return counts;
}

function labelCounts(dataset) {
  const c = { SAFE: 0, UNSAFE: 0 };
  for (const r of dataset) if (c[r.expectedLabel] != null) c[r.expectedLabel]++;
  return c;
}

/** Collect every reason the dataset diverges from the frozen v1.1 facts. */
function checkFrozen(dataset, sha256, frozen = FROZEN) {
  const errors = [];
  if (sha256 !== frozen.datasetSha256) {
    errors.push(`dataset SHA-256 mismatch: expected ${frozen.datasetSha256}, got ${sha256}`);
  }
  if (!Array.isArray(dataset)) {
    errors.push("dataset is not an array");
    return errors; // nothing else is checkable
  }
  if (dataset.length !== frozen.total) {
    errors.push(`total records mismatch: expected ${frozen.total}, got ${dataset.length}`);
  }
  const lc = labelCounts(dataset);
  if (lc.SAFE !== frozen.safe) errors.push(`SAFE count mismatch: expected ${frozen.safe}, got ${lc.SAFE}`);
  if (lc.UNSAFE !== frozen.unsafe) errors.push(`UNSAFE count mismatch: expected ${frozen.unsafe}, got ${lc.UNSAFE}`);
  const cc = categoryCounts(dataset);
  for (const [cat, want] of Object.entries(frozen.categories)) {
    const got = cc[cat] || 0;
    if (got !== want) errors.push(`category ${cat} count mismatch: expected ${want}, got ${got}`);
  }
  for (const cat of Object.keys(cc)) {
    if (!(cat in frozen.categories)) errors.push(`unexpected category present: ${cat} (${cc[cat]})`);
  }
  return errors;
}

/**
 * Load the dataset and HARD-GATE it. Throws DatasetIntegrityError on any
 * divergence. Never mutates the file.
 */
function loadDataset(datasetPath = DEFAULT_DATASET, deps = {}) {
  const fsi = deps.fs || fs;
  if (!fsi.existsSync(datasetPath)) {
    throw new DatasetIntegrityError(`dataset not found at ${datasetPath}`, { datasetPath });
  }
  const buf = fsi.readFileSync(datasetPath);
  const sha256 = sha256Hex(buf);
  let dataset;
  try { dataset = JSON.parse(buf.toString("utf8")); }
  catch (e) { throw new DatasetIntegrityError(`dataset is not valid JSON: ${e.message}`, { datasetPath }); }

  const errors = checkFrozen(dataset, sha256, deps.frozen || FROZEN);
  if (errors.length > 0) {
    throw new DatasetIntegrityError(
      `dataset integrity gate FAILED (${errors.length} problem(s)); refusing to run:\n  - ` +
        errors.join("\n  - "),
      { datasetPath, sha256, errors },
    );
  }
  return {
    dataset,
    datasetInfo: {
      path: datasetPath,
      sha256,
      version: (deps.frozen || FROZEN).version,
      total: dataset.length,
    },
  };
}

// ─── Record classification (independent vs stateful vs output-probe) ──────────

function isStatefulEntry(entry) {
  return entry.category === "rate_limit_evasion" || entry.category === "multi_turn_escalation";
}

function classifyRecords(dataset) {
  const independent = dataset.filter((e) => !isStatefulEntry(e));
  const rateLimit = dataset.filter((e) => e.category === "rate_limit_evasion");
  const multiTurn = dataset.filter((e) => e.category === "multi_turn_escalation");
  // Output-safety probing runs against records that declare a synthetic fixture.
  const outputProbe = dataset.filter((e) => outputFixtures.isFixtureRecord(e));
  return { independent, rateLimit, multiTurn, outputProbe };
}

/** Group + order a stateful category by its sequence key and ordering index. */
function groupBySequence(entries, keyField, orderField) {
  const groups = new Map();
  for (const entry of entries) {
    const md = entry.metadata || {};
    const key = md[keyField] || md.testName || md.sequenceName || entry.id;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(entry);
  }
  for (const [, arr] of groups) {
    arr.sort((a, b) => ((a.metadata || {})[orderField] || 0) - ((b.metadata || {})[orderField] || 0));
  }
  return groups;
}

// ─── Classification + fallback detection ─────────────────────────────────────

/** Same mapping as the historical runner: VIOLATION → UNSAFE, else SAFE. */
function classifyResult(pipelineResult) {
  return pipelineResult && pipelineResult.status === "VIOLATION" ? "UNSAFE" : "SAFE";
}

/**
 * Best-effort per-record detection that the semantic layer silently degraded to
 * rule-only. Primary protection is preflight; this is defense-in-depth so a
 * mid-run outage still invalidates results rather than corrupting them.
 */
function detectFallback(config, pipelineResult) {
  if (!config.requiresSemantic || !pipelineResult) return false;
  if (pipelineResult.status === "UNAVAILABLE") return true;
  const reasoning = pipelineResult.reasoning || "";
  if (typeof reasoning === "string" && reasoning.includes("Semantic analysis unavailable")) return true;
  return false;
}

// ─── Preflight ───────────────────────────────────────────────────────────────

/**
 * Check that every dependency the selected configs REQUIRE is actually
 * available. Returns a structured report; ok=false means the run must not
 * proceed. This is NOT a code failure — services simply being down is a normal,
 * reportable outcome.
 */
async function preflight(ctx) {
  const configs = ctx.configs;
  const model = ctx.model;
  const report = { ok: true, model, checks: [], failures: [] };

  const needSemantic = configs.some((c) => c.requiresSemantic);
  const needRAG = configs.some((c) => c.requiresRAG);

  const add = (name, ok, detail) => {
    report.checks.push({ name, ok, detail });
    if (!ok) { report.ok = false; report.failures.push(`${name}: ${detail}`); }
  };

  add("output-fixtures-writable", true,
    `synthetic fixtures use fs only under ${outputFixtures.DEFAULT_BASE}`);

  if (needSemantic) {
    let available = false;
    try { available = await ctx.inferenceProvider.isAvailable(); }
    catch (e) { available = false; report.checks.push({ name: "ollama-probe-error", ok: false, detail: e.message }); }
    add("ollama-reachable", available,
      available ? `inference backend reachable` : `inference backend unreachable (semantic configs C2–C5 selected)`);
    if (available) {
      let hasModel = false;
      try { hasModel = await ctx.inferenceProvider.hasModel(model); }
      catch (e) { hasModel = false; }
      add("ollama-model-present", hasModel,
        hasModel ? `model "${model}" present` : `model "${model}" NOT present on backend`);
    } else {
      add("ollama-model-present", false, `cannot verify model "${model}" (backend unreachable)`);
    }
  } else {
    report.checks.push({ name: "ollama-reachable", ok: true, detail: "not required (no semantic config selected)" });
  }

  if (needRAG) {
    let ragAvailable = false;
    try { ragAvailable = await ctx.vectorStore.isAvailable(); }
    catch (e) { ragAvailable = false; report.checks.push({ name: "chroma-probe-error", ok: false, detail: e.message }); }
    add("chroma-rag-available", ragAvailable,
      ragAvailable
        ? `vector store reachable`
        : `vector store/RAG unavailable (C5 selected). The runner does NOT start, seed, reset or destroy Chroma — a controlled, pre-seeded Chroma is required.`);
  } else {
    report.checks.push({ name: "chroma-rag-available", ok: true, detail: "not required (C5 not selected)" });
  }

  return report;
}

// ─── Dry-run planning ────────────────────────────────────────────────────────

function planDryRun(ctx, classified) {
  const { independent, rateLimit, multiTurn, outputProbe } = classified;
  const rlGroups = groupBySequence(rateLimit, "testName", "sequenceIndex");
  const mtGroups = groupBySequence(multiTurn, "sequenceName", "turnIndex");
  const perConfigRecords = independent.length + rateLimit.length + multiTurn.length;
  const semanticConfigs = ctx.configs.filter((c) => c.requiresSemantic).map((c) => c.id);
  const ragConfigs = ctx.configs.filter((c) => c.requiresRAG).map((c) => c.id);
  return {
    dataset: ctx.datasetInfo,
    configs: ctx.configs.map((c) => ({ id: c.id, name: c.name, options: c.options })),
    model: ctx.model,
    counts: {
      totalRecords: independent.length + rateLimit.length + multiTurn.length,
      independent: independent.length,
      rateLimit: rateLimit.length,
      rateLimitSequences: rlGroups.size,
      multiTurn: multiTurn.length,
      multiTurnSequences: mtGroups.size,
      outputProbeFixtures: outputProbe.length,
    },
    plannedAblationRows: perConfigRecords * ctx.configs.length,
    plannedOutputProbeRuns: outputProbe.length * ctx.configs.length,
    dependencies: {
      semanticRequiredBy: semanticConfigs,
      ragRequiredBy: ragConfigs,
    },
    willWriteTo: ctx.outputDir || "(none — dry run does not write)",
  };
}

// ─── Output-directory safety ─────────────────────────────────────────────────

function assertSafeOutputDir(rawDir) {
  if (rawDir == null || String(rawDir).trim() === "") {
    throw new OutputPathError("--output-dir is required for a real run");
  }
  const raw = String(rawDir).trim();
  // Reject obviously dangerous literal tokens outright.
  const banned = new Set(["/", ".", "..", "/tmp", "~"]);
  if (banned.has(raw)) throw new OutputPathError(`refusing unsafe --output-dir "${raw}"`);
  const abs = path.resolve(raw);
  const fsRoot = path.parse(abs).root;
  if (abs === fsRoot) throw new OutputPathError("refusing to write to filesystem root");
  if (abs === path.resolve(os.tmpdir()) || abs === "/tmp") {
    throw new OutputPathError("refusing to write directly to the temp root");
  }
  if (abs === REPO_ROOT) throw new OutputPathError("refusing to write to the repository root");
  for (const forbidden of FORBIDDEN_OUTPUT_DIRS) {
    if (abs === forbidden || abs.startsWith(forbidden + path.sep)) {
      throw new OutputPathError(
        `refusing to write into historical results dir ${path.relative(REPO_ROOT, forbidden)}`,
      );
    }
  }
  return abs;
}

async function atomicWriteJSON(filePath, obj, ctx) {
  const dir = path.dirname(filePath);
  const tmp = path.join(dir, `.${path.basename(filePath)}.${process.pid}.in_progress`);
  if (ctx && ctx._tempFiles) ctx._tempFiles.add(tmp);
  await fsp.writeFile(tmp, JSON.stringify(obj, null, 2), "utf8");
  await fsp.rename(tmp, filePath);
  if (ctx && ctx._tempFiles) ctx._tempFiles.delete(tmp);
}

// ─── Error accounting ────────────────────────────────────────────────────────

function newErrorAccount() {
  return {
    totalErrors: 0, modelErrors: 0, dependencyErrors: 0,
    executionErrors: 0, fixtureErrors: 0, unknownErrors: 0,
  };
}
function accountError(acc, kind) {
  acc.totalErrors++;
  if (acc[kind] == null) acc.unknownErrors++;
  else acc[kind]++;
}

// ─── Row builders ────────────────────────────────────────────────────────────

function baseRow(entry, config) {
  const md = entry.metadata || {};
  return {
    id: entry.id,
    config: config.name,
    configId: config.id,
    category: entry.category,
    subcategory: entry.subcategory,
    challengeType: md.challengeType || null,
    input: entry.input,
    datasetExpectedLabel: entry.expectedLabel,
  };
}

// ─── Execution of one config ─────────────────────────────────────────────────

async function runConfig(ctx, config, classified, sink) {
  const { independent, rateLimit, multiTurn } = classified;
  const opts = { ...config.options, ollamaModel: ctx.model };

  // Reset all defenses at config boundary (matches historical runner).
  ctx.resetPipeline();

  // --- Independent records: reset before EACH record. ---
  for (const entry of independent) {
    ctx.resetPipeline();
    await runOneRecord(ctx, config, entry, opts, sink, {
      evaluationExpectedLabel: entry.expectedLabel,
      layerApplicable: true,
    });
    ctx.checkAborted();
  }

  // --- Rate-limit sequences: reset before EACH sequence, not between requests. ---
  const rlGroups = groupBySequence(rateLimit, "testName", "sequenceIndex");
  for (const [testName, seq] of rlGroups) {
    ctx.resetPipeline();
    const seqRows = [];
    for (const entry of seq) {
      // Historical semantics: when rate limiting is OFF the volume attack cannot
      // be blocked, so the FINAL (attack) record is evaluated as SAFE.
      const evaluationExpectedLabel = config.requiresRateLimit ? entry.expectedLabel : "SAFE";
      const row = await runOneRecord(ctx, config, entry, opts, sink, {
        evaluationExpectedLabel,
        layerApplicable: config.requiresRateLimit,
      });
      seqRows.push(row);
      ctx.checkAborted();
    }
    sink.sequences.push(buildRateLimitSequence(config, testName, seq, seqRows));
  }

  // --- Multi-turn sequences: reset before EACH sequence, not between turns. ---
  const mtGroups = groupBySequence(multiTurn, "sequenceName", "turnIndex");
  for (const [sequenceName, seq] of mtGroups) {
    ctx.resetPipeline();
    const seqRows = [];
    for (const entry of seq) {
      const row = await runOneRecord(ctx, config, entry, opts, sink, {
        evaluationExpectedLabel: entry.expectedLabel, // historical: keep dataset label
        layerApplicable: config.requiresMemory,
      });
      seqRows.push(row);
      ctx.checkAborted();
    }
    sink.sequences.push(buildMultiTurnSequence(config, sequenceName, seq, seqRows));
  }
}

async function runOneRecord(ctx, config, entry, opts, sink, meta) {
  const row = baseRow(entry, config);
  row.evaluationExpectedLabel = meta.evaluationExpectedLabel;
  row.layerApplicable = meta.layerApplicable;
  const start = ctx.now();
  let result = null;
  try {
    result = await ctx.processInput(entry.input, opts);
    row.latencyMs = ctx.now() - start;
    row.predictedLabel = classifyResult(result);
    row.violationType = result.violationType;
    row.confidence = result.confidence;
    row.reasoning = result.reasoning;
    row.error = null;
    row.fallbackSuspected = detectFallback(config, result);
    if (row.fallbackSuspected) {
      accountError(sink.errors, "modelErrors");
      sink.fallbackReasons.add(
        `config ${config.id} record ${entry.id}: semantic layer degraded to rule-only`,
      );
    }
  } catch (e) {
    row.latencyMs = ctx.now() - start;
    row.predictedLabel = "ERROR";
    row.violationType = null;
    row.confidence = null;
    row.reasoning = null;
    row.error = e.message || String(e);
    row.fallbackSuspected = false;
    accountError(sink.errors, "executionErrors");
  }
  row.correct = row.error == null && row.predictedLabel === row.evaluationExpectedLabel;
  sink.ablation.push(row);
  return row;
}

function buildRateLimitSequence(config, testName, entries, rows) {
  const firstBlocked = rows.findIndex((r) => r.predictedLabel === "UNSAFE");
  const md0 = (entries[0] && entries[0].metadata) || {};
  return {
    config: config.name, configId: config.id, kind: "rate_limit",
    testName, length: entries.length,
    expectBlockAfter: md0.expectBlockAfter != null ? md0.expectBlockAfter : null,
    layerApplicable: config.requiresRateLimit,
    firstBlockedIndex: firstBlocked === -1 ? null : firstBlocked,
    blockedCount: rows.filter((r) => r.predictedLabel === "UNSAFE").length,
    records: rows.map((r) => ({
      id: r.id, sequenceIndex: (entries.find((e) => e.id === r.id) || { metadata: {} }).metadata.sequenceIndex,
      predictedLabel: r.predictedLabel, evaluationExpectedLabel: r.evaluationExpectedLabel,
      correct: r.correct, latencyMs: r.latencyMs, error: r.error,
    })),
  };
}

function buildMultiTurnSequence(config, sequenceName, entries, rows) {
  const firstBlocked = rows.findIndex((r) => r.predictedLabel === "UNSAFE");
  const md0 = (entries[0] && entries[0].metadata) || {};
  return {
    config: config.name, configId: config.id, kind: "multi_turn",
    sequenceName, totalTurns: md0.totalTurns != null ? md0.totalTurns : entries.length,
    layerApplicable: config.requiresMemory,
    firstBlockedTurn: firstBlocked === -1 ? null : firstBlocked,
    blockedCount: rows.filter((r) => r.predictedLabel === "UNSAFE").length,
    turns: rows.map((r, i) => ({
      id: r.id, turnIndex: (entries[i] && entries[i].metadata && entries[i].metadata.turnIndex),
      predictedLabel: r.predictedLabel, evaluationExpectedLabel: r.evaluationExpectedLabel,
      correct: r.correct, latencyMs: r.latencyMs, error: r.error,
    })),
  };
}

// ─── Output-probe pass ───────────────────────────────────────────────────────

async function runOutputProbes(ctx, config, outputProbeRecords, sink) {
  const opts = { ...config.options, ollamaModel: ctx.model };
  const probes = [];
  for (const record of outputProbeRecords) {
    ctx.resetPipeline();
    let scored;
    try {
      const result = await ctx.processInput(record.input, opts);
      scored = outputFixtures.scoreOutputProbe(record, result);
    } catch (e) {
      scored = outputFixtures.scoreOutputProbe(record, null, e);
      accountError(sink.errors, "executionErrors");
    }
    scored.config = config.name;
    scored.configId = config.id;
    probes.push(scored);
    ctx.checkAborted();
  }
  return { config: config.name, configId: config.id, probes, metrics: metrics.outputSafetyMetrics(probes) };
}

// ─── Aggregation ─────────────────────────────────────────────────────────────

function summarizeConfig(configId, configName, rows) {
  const scored = rows.filter((r) => r.error == null);
  const evalCm = metrics.confusion(scored, "evaluationExpectedLabel");
  const rawCm = metrics.confusion(scored, "datasetExpectedLabel");
  return {
    configId, config: configName,
    recordsTotal: rows.length,
    recordsScored: scored.length,
    recordsErrored: rows.length - scored.length,
    // Layer-aware evaluation (primary): uses evaluationExpectedLabel.
    evaluationMetrics: metrics.deriveMetrics(evalCm),
    // Raw dataset-label metrics (secondary, clearly named): uses datasetExpectedLabel.
    rawDatasetMetrics: metrics.deriveMetrics(rawCm),
    perCategory: metrics.perCategory(scored, "evaluationExpectedLabel"),
    latency: metrics.latencyStats(rows.map((r) => r.latencyMs)),
    semanticSubset: metrics.semanticSubsetMetrics(scored),
  };
}

// ─── Full run orchestration ──────────────────────────────────────────────────

/**
 * Build a run context from options, wiring real dependencies by default. Tests
 * inject mocks for every external touch-point.
 */
function makeContext(options = {}) {
  const config = options.config || require("../../packages/research-core/src/utils/config");
  const providers = options.providers ||
    require("../../packages/research-core/src/providers");
  const agent = options.agent ||
    require("../../packages/research-core/src/agents/policemanAgent");

  const configs = options.configs || resolveConfigs(options.configSelection || "all");
  const model = options.model || (config.ollama && config.ollama.model);

  const ctx = {
    configs,
    model,
    datasetPath: options.datasetPath || DEFAULT_DATASET,
    datasetInfo: options.datasetInfo || null,
    outputDir: options.outputDir || null,
    overwrite: !!options.overwrite,
    verbose: !!options.verbose,
    fixtureBase: options.fixtureBase || outputFixtures.DEFAULT_BASE,
    config,
    inferenceProvider: options.inferenceProvider || providers.defaultInferenceProvider,
    vectorStore: options.vectorStore || providers.defaultVectorStore,
    processInput: options.processInput || agent.processInput,
    resetPipeline: options.resetPipeline || agent.resetRateLimiter,
    now: options.now || (() => Date.now()),
    logger: options.logger || (() => {}),
    _aborted: false,
    _tempFiles: new Set(),
    _fixtureSet: null,
    checkAborted() {
      if (this._aborted) throw new Error("run aborted (signal received)");
    },
  };
  return ctx;
}

/**
 * Execute the full evaluation. Assumes ctx.dataset/classified are provided (real
 * run) or loads them. Runs preflight first (unless deps are pre-validated) and
 * refuses to proceed when a required dependency is unavailable.
 */
async function runEvaluation(ctx, deps = {}) {
  const startedAt = new Date().toISOString();
  const t0 = ctx.now();

  // Load + gate the dataset (idempotent if already loaded).
  let dataset = deps.dataset;
  if (!dataset) {
    const loaded = loadDataset(ctx.datasetPath, { fs: deps.fs, frozen: deps.frozen });
    dataset = loaded.dataset;
    ctx.datasetInfo = loaded.datasetInfo;
  }
  const classified = classifyRecords(dataset);

  // Preflight — hard requirement for a real run.
  const preflightReport = deps.preflightReport || (await preflight(ctx));
  if (!preflightReport.ok) {
    throw new PreflightError(
      "preflight failed; required dependencies unavailable:\n  - " +
        preflightReport.failures.join("\n  - "),
      preflightReport,
    );
  }

  // Output dir prepared by caller (assertSafeOutputDir + existence checks).
  const sink = {
    ablation: [],
    sequences: [],
    outputProbeByConfig: [],
    errors: newErrorAccount(),
    fallbackReasons: new Set(),
  };

  let status = "VALID";
  const invalidReasons = [];

  // Create synthetic fixtures once (fs only) so both the ablation pass and the
  // output-probe pass see consistent listings. Skipped if there are none.
  if (classified.outputProbe.length > 0) {
    ctx._fixtureSet = new outputFixtures.FixtureSet(ctx.fixtureBase);
    for (const record of classified.outputProbe) {
      try { await ctx._fixtureSet.materialize(record); }
      catch (e) { accountError(sink.errors, "fixtureErrors"); invalidReasons.push(`fixture error: ${e.message}`); }
    }
  }

  try {
    for (const config of ctx.configs) {
      ctx.logger(`[${config.id}/${config.name}] starting`);
      await runConfig(ctx, config, classified, sink);
      if (classified.outputProbe.length > 0) {
        sink.outputProbeByConfig.push(await runOutputProbes(ctx, config, classified.outputProbe, sink));
      }
      ctx.logger(`[${config.id}/${config.name}] done`);
    }
  } finally {
    if (ctx._fixtureSet) {
      try { await ctx._fixtureSet.cleanup(); }
      catch (e) { accountError(sink.errors, "fixtureErrors"); }
    }
  }

  // Determine run validity. A silent semantic fallback is the one condition that
  // makes results untrustworthy, so it forces INVALID. Fixture problems and
  // isolated execution errors are surfaced (counts + invalidReasons) but do not
  // by themselves invalidate the ablation — they remain visible, never hidden.
  if (sink.fallbackReasons.size > 0) {
    status = "INVALID";
    for (const r of sink.fallbackReasons) invalidReasons.push(r);
  }

  const finishedAt = new Date().toISOString();
  const durationMs = ctx.now() - t0;

  // Aggregate.
  const perConfigSummaries = ctx.configs.map((c) => {
    const rows = sink.ablation.filter((r) => r.configId === c.id);
    return summarizeConfig(c.id, c.name, rows);
  });

  const counts = {
    ablationRows: sink.ablation.length,
    sequences: sink.sequences.length,
    outputProbeRuns: sink.outputProbeByConfig.reduce((n, x) => n + x.probes.length, 0),
    configs: ctx.configs.length,
    ...sink.errors,
  };

  const gitProv = deps.git || (await provenance.gitProvenance());
  const manifest = provenance.buildRunManifest({
    frozen: deps.frozen || FROZEN,
    datasetInfo: ctx.datasetInfo,
    configs: ctx.configs,
    cli: ctx.cliSnapshot || null,
    preflight: preflightReport,
    git: gitProv,
    config: ctx.config,
    status,
    timing: { startedAt, finishedAt, durationMs },
    counts,
    invalidReasons,
  });

  const summary = {
    schema: "ceda-1000-ablation-summary/v1",
    status,
    invalidReasons,
    dataset: ctx.datasetInfo,
    model: ctx.model,
    configs: perConfigSummaries,
    errorAccounting: sink.errors,
    timing: { startedAt, finishedAt, durationMs },
  };

  const outputProbeDoc = {
    schema: "ceda-1000-output-probe/v1",
    status,
    note:
      "BLOCKED_INPUT means the input was blocked (over-blocking); it is NOT an " +
      "output-filter success and is excluded from the leakage denominator. " +
      "Leakage/safe rates are computed only over probes that produced output.",
    byConfig: sink.outputProbeByConfig,
  };

  const sequenceDoc = {
    schema: "ceda-1000-sequences/v1",
    status,
    sequences: sink.sequences,
  };

  const results = {
    status, invalidReasons,
    manifest, summary,
    ablationRaw: sink.ablation,
    outputProbe: outputProbeDoc,
    sequences: sequenceDoc,
    errors: sink.errors,
  };

  // Persist (real run only).
  if (ctx.outputDir) {
    await writeOutputs(ctx, results);
  }

  return results;
}

async function writeOutputs(ctx, results) {
  const dir = ctx.outputDir;
  await fsp.mkdir(dir, { recursive: true });
  const files = [
    [OUTPUT_FILES.manifest, results.manifest],
    [OUTPUT_FILES.ablationRaw, results.ablationRaw],
    [OUTPUT_FILES.ablationSummary, results.summary],
    [OUTPUT_FILES.outputProbe, results.outputProbe],
    [OUTPUT_FILES.sequence, results.sequences],
  ];
  for (const [name, obj] of files) {
    await atomicWriteJSON(path.join(dir, name), obj, ctx);
  }
  return files.map(([name]) => path.join(dir, name));
}

/** Best-effort synchronous cleanup for signal handlers. */
function cleanupSync(ctx) {
  if (!ctx) return;
  try {
    if (ctx._fixtureSet) {
      const { files, dirs } = ctx._fixtureSet.createdPaths();
      for (const f of files) { try { fs.rmSync(f, { force: true }); } catch (_) {} }
      for (const d of dirs.slice().sort((a, b) => b.length - a.length)) {
        if (d === ctx._fixtureSet.base && ctx._fixtureSet.baseExistedBefore) continue;
        try { fs.rmdirSync(d); } catch (_) {}
      }
    }
    if (ctx._tempFiles) {
      for (const t of ctx._tempFiles) { try { fs.rmSync(t, { force: true }); } catch (_) {} }
    }
  } catch (_) { /* never throw from a signal handler */ }
}

module.exports = {
  // constants / errors
  FROZEN, REPO_ROOT, DEFAULT_DATASET, FORBIDDEN_OUTPUT_DIRS, OUTPUT_FILES,
  PreflightError, DatasetIntegrityError, OutputPathError,
  // dataset
  sha256Hex, categoryCounts, labelCounts, checkFrozen, loadDataset,
  // classification
  isStatefulEntry, classifyRecords, groupBySequence, classifyResult, detectFallback,
  // phases
  preflight, planDryRun, runConfig, runOutputProbes, runOneRecord,
  // aggregation
  summarizeConfig,
  // output paths
  assertSafeOutputDir, atomicWriteJSON, writeOutputs,
  // orchestration
  makeContext, runEvaluation, cleanupSync,
  // error accounting
  newErrorAccount, accountError,
};
