/**
 * CEDA-1000 evaluation runner (core logic).
 *
 * Responsibilities:
 *   - Load data/ceda-1000.json AND data/ceda-1000.manifest.json and HARD-GATE
 *     both against the frozen v1.1 facts (exact SHA-256, version, totals,
 *     per-category counts, manifest cross-checks). Any mismatch aborts the run —
 *     there is no warn-and-continue path.
 *   - Preserve the historical C1–C5 ablation semantics (see runAblation.js):
 *     reset before each independent record and before each stateful sequence,
 *     never between requests/turns within a sequence; rate-limit records are
 *     evaluated as SAFE when the rate-limit layer is disabled.
 *   - Execute EVERY dataset record EXACTLY ONCE per configuration. Output-safety
 *     probes are scored from that SAME single pipeline execution — never a
 *     second call.
 *   - NEVER silently fall back: semantic configs (C2–C5) require a real model and
 *     C5 requires RAG. Preflight refuses to run when a required dependency is
 *     unavailable; a semantic fallback or a RAG infrastructure failure OBSERVED
 *     mid-run (via structured pipeline diagnostics) marks the run INVALID.
 *   - Enforce the scientific-validity contract: research mode, long-term-memory
 *     writes disabled, clean git, exact model+digest, zero errors, complete
 *     sample counts.
 *   - Emit raw results, aggregate metrics, output-probe results, sequence
 *     results and a full provenance manifest — written atomically.
 *   - NEVER modify the dataset. Dataset input strings flow ONLY into
 *     processInput() (and, as pure strings, into fixture-path parsing).
 *
 * This module is dependency-injectable: processInput, resetPipeline, the
 * inference/vector providers, git provenance, and config are all overridable so
 * the unit suite runs with mocks and never touches Ollama, Chroma or a GPU.
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
const DEFAULT_MANIFEST = path.join(REPO_ROOT, "data", "ceda-1000.manifest.json");

// Previously-validated SHA of the Chroma seed script (code provenance for C5).
const SEED_CHROMA_EXPECTED_SHA =
  "91454bec3d34e8ff0873023f65e11a8d20f0c081e96fbc914cf892dd70c036ca";

// Exact facts the dataset manifest MUST assert (anchored to the frozen dataset).
const MANIFEST_EXPECTED = Object.freeze({
  name: "CEDA-1000",
  version: "1.1",
  totalRecords: 1000,
  safe: 500,
  unsafe: 500,
  legacyRecords: 215,
  extensionRecords: 785,
  seedSha256: FROZEN.seedSha256,
  datasetSha256: FROZEN.datasetSha256,
  supersedesVersion: "1.0",
  supersedesDatasetSha256: "5048d9672bfef2f2c20b320417c3c241266faabc6f1039fafa35506b20fd75bc",
});

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

// ─── Dataset + manifest integrity gates ──────────────────────────────────────

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

/** Collect every reason the manifest diverges from the expected facts. */
function checkManifest(manifest, expected = MANIFEST_EXPECTED) {
  const errors = [];
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    errors.push("manifest is not an object");
    return errors;
  }
  for (const k of Object.keys(expected)) {
    if (manifest[k] !== expected[k]) {
      errors.push(`manifest.${k} mismatch: expected ${JSON.stringify(expected[k])}, got ${JSON.stringify(manifest[k])}`);
    }
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

/**
 * Load the dataset manifest and HARD-GATE it. Throws DatasetIntegrityError on
 * any divergence. Never mutates the file.
 */
function loadManifest(manifestPath = DEFAULT_MANIFEST, deps = {}) {
  const fsi = deps.fs || fs;
  if (!fsi.existsSync(manifestPath)) {
    throw new DatasetIntegrityError(`dataset manifest not found at ${manifestPath}`, { manifestPath });
  }
  let manifest;
  try { manifest = JSON.parse(fsi.readFileSync(manifestPath, "utf8")); }
  catch (e) { throw new DatasetIntegrityError(`manifest is not valid JSON: ${e.message}`, { manifestPath }); }

  const errors = checkManifest(manifest, deps.expected || MANIFEST_EXPECTED);
  if (errors.length > 0) {
    throw new DatasetIntegrityError(
      `manifest integrity gate FAILED (${errors.length} problem(s)); refusing to run:\n  - ` +
        errors.join("\n  - "),
      { manifestPath, errors },
    );
  }
  return { manifest, manifestInfo: { path: manifestPath, facts: manifest } };
}

/** Code-provenance for the Chroma seed script (verify, never assume). */
function seedChromaProvenance() {
  const abs = path.join(REPO_ROOT, "scripts", "seedChromaDB.js");
  if (!fs.existsSync(abs)) {
    return { path: "scripts/seedChromaDB.js", present: false, sha256: null,
      expectedSha256: SEED_CHROMA_EXPECTED_SHA, matches: false };
  }
  const sha = sha256Hex(fs.readFileSync(abs));
  return {
    path: "scripts/seedChromaDB.js", present: true, sha256: sha,
    expectedSha256: SEED_CHROMA_EXPECTED_SHA, matches: sha === SEED_CHROMA_EXPECTED_SHA,
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
  // Output-safety probing scores records that declare a synthetic fixture. These
  // are a SUBSET of the independent records — they are executed once (in the
  // independent pass) and scored from that same execution.
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

// ─── Classification + structured validity detection ──────────────────────────

/** Same mapping as the historical runner: VIOLATION → UNSAFE, else SAFE. */
function classifyResult(pipelineResult) {
  return pipelineResult && pipelineResult.status === "VIOLATION" ? "UNSAFE" : "SAFE";
}

function extractDiagnostics(result) {
  return (result && result.diagnostics) || null;
}

/**
 * Structured semantic-fallback detection. Uses the pipeline's evaluation-only
 * diagnostics (semanticAttempted && semanticFallback) — reliable on EVERY path
 * including conversational/no-command SAFE results where no reasoning note
 * exists. Falls back to legacy signals only if diagnostics are absent.
 */
function detectSemanticFallback(config, result) {
  if (!config.requiresSemantic || !result) return false;
  const d = extractDiagnostics(result);
  if (d) return d.semanticAttempted === true && d.semanticFallback === true;
  // Secondary net (diagnostics not captured): status/reasoning heuristics.
  if (result.status === "UNAVAILABLE") return true;
  const reasoning = result.reasoning || "";
  return typeof reasoning === "string" && reasoning.includes("Semantic analysis unavailable");
}

/**
 * Structured RAG-infrastructure-failure detection for C5. A query that succeeds
 * with zero matches is VALID; only an unavailable/failed vector-store query is a
 * scientific-validity failure.
 */
function detectRagInfraFailure(config, result) {
  if (!config.requiresRAG || !result) return false;
  const d = extractDiagnostics(result);
  if (!d) return false;
  return d.ragAttempted === true && (d.ragUnavailable === true || d.ragQueryFailed === true);
}

// Backwards-compatible alias (older name).
const detectFallback = detectSemanticFallback;

// ─── Fixture-base safety (real filesystem verification) ───────────────────────

/**
 * Really verify the synthetic-fixture base is safe to use: not a symlink, a
 * directory (or absent), empty, and actually writable — proven with a sentinel
 * that is removed afterward, leaving no debris. Never removes pre-existing
 * content and never touches the temp root itself.
 */
async function assertFixtureBaseSafe(base) {
  const abs = path.resolve(base);
  if (abs === "/" || abs === path.parse(abs).root || abs === path.resolve(os.tmpdir())) {
    return { ok: false, detail: `unsafe fixture base: ${abs}` };
  }
  let existed = false;
  try {
    const st = await fsp.lstat(abs);
    existed = true;
    if (st.isSymbolicLink()) return { ok: false, detail: `fixture base is a symlink: ${abs}` };
    if (!st.isDirectory()) return { ok: false, detail: `fixture base exists but is not a directory: ${abs}` };
    const entries = await fsp.readdir(abs);
    if (entries.length > 0) {
      return { ok: false, detail: `fixture base is non-empty (data from another run?): ${abs} (${entries.length} entr${entries.length === 1 ? "y" : "ies"})` };
    }
  } catch (e) {
    if (e.code !== "ENOENT") return { ok: false, detail: `cannot stat fixture base: ${e.message}` };
    existed = false;
  }
  try {
    if (!existed) await fsp.mkdir(abs, { recursive: true });
    const sentinel = path.join(abs, ".ceda1000-preflight-sentinel");
    await fsp.writeFile(sentinel, "ok", { encoding: "utf8", mode: 0o600 });
    await fsp.rm(sentinel, { force: true });
    if (!existed) await fsp.rmdir(abs); // remove ONLY the dir we created
  } catch (e) {
    return { ok: false, detail: `fixture base not writable: ${e.message}` };
  }
  return { ok: true, detail: `safe, empty, writable: ${abs}` };
}

// ─── Preflight ───────────────────────────────────────────────────────────────

/**
 * Verify every scientific precondition and dependency. Returns a structured
 * report; ok=false means the run must not proceed. Services being down (or the
 * environment not being configured for a real run) is a normal, reportable
 * outcome — NOT a code failure. report.infra collects provenance facts gathered
 * here (model digest, ollama version, chroma collection) with no inference.
 */
async function preflight(ctx) {
  const configs = ctx.configs;
  const model = ctx.model;
  const report = { ok: true, model, checks: [], failures: [], infra: {} };

  const add = (name, ok, detail) => {
    report.checks.push({ name, ok, detail });
    if (!ok) { report.ok = false; report.failures.push(`${name}: ${detail}`); }
  };
  const note = (name, ok, detail) => { report.checks.push({ name, ok, detail }); };

  // --- Scientific-mode gates (always enforced) ---
  const mode = ctx.config && ctx.config.mode && ctx.config.mode.name;
  add("app-mode-research", mode === "research",
    mode === "research" ? 'APP_MODE=research' : `APP_MODE must be "research" for a scientific run, got "${mode}"`);

  const ltmEnabled = !!(ctx.config && ctx.config.memory && ctx.config.memory.longTermEnabled);
  add("long-term-memory-writes-disabled", ltmEnabled === false,
    ltmEnabled === false
      ? "LONG_TERM_MEMORY_ENABLED=false (no runtime Chroma writes)"
      : "LONG_TERM_MEMORY_ENABLED must be false — runtime learning would write newly blocked patterns into Chroma and contaminate C5 with C4-produced data");

  // --- Git cleanliness (enforced for real runs) ---
  if (ctx.requireCleanGit) {
    let g = null;
    try { g = await ctx.gitProvenance(); } catch (_) { g = null; }
    report.infra.git = g;
    const clean = !!(g && g.dirty === false);
    add("git-clean", clean,
      clean ? `working tree clean @ ${g.commit} (${g.branch})`
            : `working tree must be clean for a scientific run${g ? ` (dirty @ ${g.commit})` : " (git state unavailable)"}`);
  } else {
    note("git-clean", true, "not enforced (exploratory preflight / not a real run)");
  }

  // --- Fixture base really writable + safe ---
  let fx;
  try { fx = await assertFixtureBaseSafe(ctx.fixtureBase); }
  catch (e) { fx = { ok: false, detail: e.message }; }
  add("fixture-base-safe", fx.ok, fx.detail);

  // --- Ollama (semantic configs C2–C5) ---
  const needSemantic = configs.some((c) => c.requiresSemantic);
  if (needSemantic) {
    let available = false;
    try { available = await ctx.inferenceProvider.isAvailable(); } catch (_) { available = false; }
    add("ollama-reachable", available,
      available ? "inference backend reachable" : "inference backend unreachable (semantic configs C2–C5 selected)");

    if (available) {
      let resolved = null;
      try {
        resolved = typeof ctx.inferenceProvider.resolveModel === "function"
          ? await ctx.inferenceProvider.resolveModel(model)
          : null;
      } catch (_) { resolved = null; }
      if (resolved) { report.infra.modelResolved = resolved.name; report.infra.modelDigest = resolved.digest || null; }
      // A scientific run must pin an exact model AND record its digest.
      const modelOk = !!(resolved && resolved.digest);
      add("ollama-model-resolved", modelOk,
        !resolved ? `model "${model}" not uniquely resolvable (absent or ambiguous tag)`
          : resolved.digest ? `model "${model}" → ${resolved.name} @ ${resolved.digest}`
            : `model "${model}" resolved to ${resolved.name} but NO digest is available`);

      let ver = null;
      try { ver = typeof ctx.inferenceProvider.version === "function" ? await ctx.inferenceProvider.version() : null; }
      catch (_) { ver = null; }
      report.infra.ollamaVersion = ver;
      // Version is recorded when the client exposes it (informational, non-gating).
      note("ollama-version", ver != null, ver != null ? `ollama server ${ver}` : "ollama server version not exposed by client");
      report.infra.ollamaHost = ctx.config && ctx.config.ollama && ctx.config.ollama.host;
    } else {
      add("ollama-model-resolved", false, `cannot resolve model "${model}" (backend unreachable)`);
    }
  } else {
    note("ollama-reachable", true, "not required (no semantic config selected)");
  }

  // --- Chroma / RAG (C5): STRICTLY READ-ONLY ---
  // The runner never starts, seeds, resets, mutates or CREATES a Chroma
  // collection. Preflight uses a read-only lookup (listCollections /
  // getExistingCollection) — never getOrCreateCollection — so a controlled,
  // pre-seeded collection is a hard requirement and preflight cannot bring one
  // into existence.
  const needRAG = configs.some((c) => c.requiresRAG);
  const seed = (ctx.seedChromaProvenance || seedChromaProvenance)();
  report.infra.seedChroma = seed; // provenance in all cases
  if (needRAG) {
    note("chroma-preflight-read-only", true,
      "Chroma lookup is read-only (getExistingCollection/listCollections); getOrCreateCollection is never called");
    report.infra.chromaHost = ctx.config && ctx.config.chromadb && ctx.config.chromadb.host;

    let info = null;
    let lookupError = null;
    if (typeof ctx.vectorStore.collectionInfoReadOnly === "function") {
      try { info = await ctx.vectorStore.collectionInfoReadOnly(); }
      catch (e) { lookupError = e; }
    } else {
      lookupError = new Error("read-only Chroma lookup not supported by the vector store");
    }
    report.infra.chromaAvailable = !!(info && info.exists);

    if (lookupError) {
      add("chroma-existing-collection", false, `Chroma read-only lookup failed: ${lookupError.message}`);
    } else if (!info || !info.exists) {
      add("chroma-existing-collection", false,
        'Chroma collection "security_patterns" does not exist; controlled seeded collection required for C5. The runner will NOT create it.');
    } else {
      report.infra.chromaCollectionName = info.name;
      report.infra.chromaCollectionCount = info.count;
      add("chroma-existing-collection", true, `security_patterns exists`);
      const nonEmpty = typeof info.count === "number" && info.count > 0;
      add("chroma-collection-nonempty", nonEmpty,
        nonEmpty ? `count=${info.count}`
          : `collection "${info.name}" is empty (count=${info.count}); a seeded collection is required for C5`);
    }

    // seedChromaDB.js SHA is a HARD C5 gate (frozen provenance).
    add("seed-chroma-script-sha", seed.present && seed.matches,
      !seed.present ? "scripts/seedChromaDB.js is missing"
        : seed.matches ? `${seed.sha256} matches frozen provenance`
          : `scripts/seedChromaDB.js SHA ${seed.sha256} does NOT match frozen ${seed.expectedSha256}`);
  } else {
    note("chroma-rag-available", true, "not required (C5 not selected)");
    // Non-C5: seed-script SHA is provenance only and never blocks the run.
    note("seed-chroma-script-sha", seed.matches,
      seed.present ? `${seed.sha256}${seed.matches ? " matches" : " differs from"} frozen provenance (informational; C5 not selected)`
        : "scripts/seedChromaDB.js missing (informational; C5 not selected)");
  }

  return report;
}

// ─── Dry-run planning ────────────────────────────────────────────────────────

function planDryRun(ctx, classified) {
  const { independent, rateLimit, multiTurn, outputProbe } = classified;
  const rlGroups = groupBySequence(rateLimit, "testName", "sequenceIndex");
  const mtGroups = groupBySequence(multiTurn, "sequenceName", "turnIndex");
  const perConfigRecords = independent.length + rateLimit.length + multiTurn.length;
  const nConfigs = ctx.configs.length;
  const semanticConfigs = ctx.configs.filter((c) => c.requiresSemantic).map((c) => c.id);
  const ragConfigs = ctx.configs.filter((c) => c.requiresRAG).map((c) => c.id);
  return {
    dataset: ctx.datasetInfo,
    configs: ctx.configs.map((c) => ({ id: c.id, name: c.name, options: c.options })),
    model: ctx.model,
    counts: {
      totalRecords: perConfigRecords,
      independent: independent.length,
      rateLimit: rateLimit.length,
      rateLimitSequences: rlGroups.size,
      multiTurn: multiTurn.length,
      multiTurnSequences: mtGroups.size,
      outputProbeFixtures: outputProbe.length,
    },
    // Every record is executed once per config; output probes reuse that same
    // execution and add ZERO additional pipeline calls.
    plannedRecordEvaluations: perConfigRecords * nConfigs,
    plannedProcessInputCalls: perConfigRecords * nConfigs,
    plannedOutputProbeScores: outputProbe.length * nConfigs,
    plannedAdditionalOutputProbeExecutions: 0,
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
  // Every record is executed once with diagnostics ON (evaluation-only).
  const opts = { ...config.options, ollamaModel: ctx.model, captureEvaluationDiagnostics: true };

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

/**
 * Execute ONE record ONCE and record everything derived from that single call:
 * the ablation row, structured validity signals, and — for a synthetic fixture
 * record — the output-safety score (from the SAME pipeline result, never a
 * second processInput call).
 */
async function runOneRecord(ctx, config, entry, opts, sink, meta) {
  const isFixture = outputFixtures.isFixtureRecord(entry);
  const row = baseRow(entry, config);
  row.evaluationExpectedLabel = meta.evaluationExpectedLabel;
  row.layerApplicable = meta.layerApplicable;
  const start = ctx.now();
  try {
    const result = await ctx.processInput(entry.input, opts);
    row.latencyMs = ctx.now() - start;
    row.predictedLabel = classifyResult(result);
    row.violationType = result.violationType;
    row.confidence = result.confidence;
    row.reasoning = result.reasoning;
    row.error = null;
    const diag = extractDiagnostics(result);
    row.diagnostics = diag ? { ...diag } : null;
    row.semanticFallback = detectSemanticFallback(config, result);
    row.ragInfraFailure = detectRagInfraFailure(config, result);
    if (row.semanticFallback) {
      accountError(sink.errors, "modelErrors");
      sink.fallbackReasons.add(`config ${config.id} record ${entry.id}: semantic layer degraded to rule-only (fallback)`);
    }
    if (row.ragInfraFailure) {
      accountError(sink.errors, "dependencyErrors");
      sink.ragFailureReasons.add(`config ${config.id} record ${entry.id}: RAG vector-store query failed/unavailable`);
    }
    if (isFixture) {
      const scored = outputFixtures.scoreOutputProbe(entry, result);
      scored.config = config.name; scored.configId = config.id;
      scored.derivedFromAblationExecution = true;
      sink.outputProbes.push(scored);
    }
  } catch (e) {
    row.latencyMs = ctx.now() - start;
    row.predictedLabel = "ERROR";
    row.violationType = null;
    row.confidence = null;
    row.reasoning = null;
    row.error = e.message || String(e);
    row.diagnostics = null;
    row.semanticFallback = false;
    row.ragInfraFailure = false;
    accountError(sink.errors, "executionErrors");
    if (isFixture) {
      const scored = outputFixtures.scoreOutputProbe(entry, null, e);
      scored.config = config.name; scored.configId = config.id;
      scored.derivedFromAblationExecution = true;
      sink.outputProbes.push(scored);
    }
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
    evaluationMetrics: metrics.deriveMetrics(evalCm),
    rawDatasetMetrics: metrics.deriveMetrics(rawCm),
    perCategory: metrics.perCategory(scored, "evaluationExpectedLabel"),
    latency: metrics.latencyStats(rows.map((r) => r.latencyMs)),
    semanticSubset: metrics.semanticSubsetMetrics(scored),
  };
}

function groupOutputProbes(outputProbes, configs) {
  const byConfig = [];
  for (const c of configs) {
    const probes = outputProbes.filter((p) => p.configId === c.id);
    byConfig.push({ config: c.name, configId: c.id, probes, metrics: metrics.outputSafetyMetrics(probes) });
  }
  return byConfig;
}

// ─── Full run orchestration ──────────────────────────────────────────────────

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
    manifestPath: options.manifestPath || DEFAULT_MANIFEST,
    datasetInfo: options.datasetInfo || null,
    outputDir: options.outputDir || null,
    overwrite: !!options.overwrite,
    verbose: !!options.verbose,
    requireCleanGit: !!options.requireCleanGit,
    fixtureBase: options.fixtureBase || outputFixtures.DEFAULT_BASE,
    config,
    inferenceProvider: options.inferenceProvider || providers.defaultInferenceProvider,
    vectorStore: options.vectorStore || providers.defaultVectorStore,
    processInput: options.processInput || agent.processInput,
    resetPipeline: options.resetPipeline || agent.resetRateLimiter,
    gitProvenance: options.gitProvenance || provenance.gitProvenance,
    seedChromaProvenance: options.seedChromaProvenance || seedChromaProvenance,
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
 * Execute the full evaluation. Loads + hard-gates the dataset AND manifest, runs
 * preflight (unless a report is injected), executes every record once per
 * config, scores output probes from those same executions, and computes the
 * scientific-validity status (VALID/INVALID). Structural failures throw and are
 * surfaced as FAILED by the CLI.
 */
async function runEvaluation(ctx, deps = {}) {
  const startedAt = new Date().toISOString();
  const t0 = ctx.now();

  // Load + gate the dataset.
  let dataset = deps.dataset;
  if (!dataset) {
    const loaded = loadDataset(ctx.datasetPath, { fs: deps.fs, frozen: deps.frozen });
    dataset = loaded.dataset;
    ctx.datasetInfo = loaded.datasetInfo;
  }

  // Load + gate the manifest, and cross-check it against the dataset SHA.
  let manifestInfo = deps.manifestInfo || null;
  if (!manifestInfo && !deps.skipManifestGate) {
    manifestInfo = loadManifest(ctx.manifestPath, { fs: deps.fs }).manifestInfo;
  }
  if (manifestInfo && ctx.datasetInfo && manifestInfo.facts) {
    if (manifestInfo.facts.datasetSha256 !== ctx.datasetInfo.sha256) {
      throw new DatasetIntegrityError(
        `dataset/manifest disagree: manifest.datasetSha256=${manifestInfo.facts.datasetSha256} but dataset file sha=${ctx.datasetInfo.sha256}`,
        { manifest: manifestInfo.facts.datasetSha256, dataset: ctx.datasetInfo.sha256 },
      );
    }
  }

  const classified = classifyRecords(dataset);

  // Preflight — hard requirement for a real run.
  const preflightReport = deps.preflightReport || (await preflight(ctx));
  if (!preflightReport.ok) {
    throw new PreflightError(
      "preflight failed; scientific preconditions/dependencies not met:\n  - " +
        preflightReport.failures.join("\n  - "),
      preflightReport,
    );
  }

  const sink = {
    ablation: [],
    sequences: [],
    outputProbes: [],
    errors: newErrorAccount(),
    fallbackReasons: new Set(),
    ragFailureReasons: new Set(),
  };

  const invalidReasons = [];

  // Create synthetic fixtures once (fs only) so the single execution of each
  // fixture record lists real content. Skipped if there are none.
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
      ctx.logger(`[${config.id}/${config.name}] done`);
    }
  } finally {
    if (ctx._fixtureSet) {
      try { await ctx._fixtureSet.cleanup(); }
      catch (e) { accountError(sink.errors, "fixtureErrors"); }
    }
  }

  // ── Scientific-validity contract ────────────────────────────────────────────
  // VALID requires: no semantic fallback, no C5 RAG infra failure, ZERO errors
  // of any kind, and COMPLETE sample counts (every record scored for every
  // config). Anything else → INVALID (diagnostic artifacts are still emitted).
  for (const r of sink.fallbackReasons) invalidReasons.push(r);
  for (const r of sink.ragFailureReasons) invalidReasons.push(r);

  const expectedPerConfig =
    classified.independent.length + classified.rateLimit.length + classified.multiTurn.length;
  const expectedAblation = expectedPerConfig * ctx.configs.length;
  if (sink.ablation.length !== expectedAblation) {
    invalidReasons.push(`incomplete ablation: got ${sink.ablation.length} rows, expected ${expectedAblation}`);
  }
  for (const c of ctx.configs) {
    const rows = sink.ablation.filter((r) => r.configId === c.id);
    const scored = rows.filter((r) => r.error == null).length;
    if (rows.length !== expectedPerConfig || scored !== expectedPerConfig) {
      invalidReasons.push(`config ${c.id} incomplete: scored ${scored}/${rows.length}, expected ${expectedPerConfig}`);
    }
  }
  const expectedProbeScores = classified.outputProbe.length * ctx.configs.length;
  if (classified.outputProbe.length > 0 && sink.outputProbes.length !== expectedProbeScores) {
    invalidReasons.push(`incomplete output-probe scores: got ${sink.outputProbes.length}, expected ${expectedProbeScores}`);
  }
  if (sink.errors.totalErrors > 0) {
    invalidReasons.push(`run contains ${sink.errors.totalErrors} error(s): ` +
      `model=${sink.errors.modelErrors} dependency=${sink.errors.dependencyErrors} ` +
      `execution=${sink.errors.executionErrors} fixture=${sink.errors.fixtureErrors} unknown=${sink.errors.unknownErrors}`);
  }

  const status = invalidReasons.length > 0 ? "INVALID" : "VALID";

  const finishedAt = new Date().toISOString();
  const durationMs = ctx.now() - t0;

  // Aggregate.
  const perConfigSummaries = ctx.configs.map((c) => {
    const rows = sink.ablation.filter((r) => r.configId === c.id);
    return summarizeConfig(c.id, c.name, rows);
  });
  const outputProbeByConfig = groupOutputProbes(sink.outputProbes, ctx.configs);

  const counts = {
    ablationRows: sink.ablation.length,
    processInputCalls: sink.ablation.length, // one per record per config
    sequences: sink.sequences.length,
    outputProbeScores: sink.outputProbes.length,
    additionalOutputProbeExecutions: 0,
    configs: ctx.configs.length,
    ...sink.errors,
  };

  const gitProv = deps.git ||
    (preflightReport.infra && preflightReport.infra.git) ||
    (await ctx.gitProvenance());

  const manifest = provenance.buildRunManifest({
    frozen: deps.frozen || FROZEN,
    datasetInfo: ctx.datasetInfo,
    manifestInfo,
    configs: ctx.configs,
    modelRequested: ctx.model,
    infra: preflightReport.infra || {},
    seedChroma: (preflightReport.infra && preflightReport.infra.seedChroma) || null,
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
      "Each output-probe score is derived from the SAME single pipeline " +
      "execution as its ablation row (no extra processInput calls). " +
      "BLOCKED_INPUT is over-blocking, NOT an output-filter success, and is " +
      "excluded from the leakage denominator; leakage/safe rates are computed " +
      "only over probes that produced output.",
    byConfig: outputProbeByConfig,
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
    counts,
  };

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
  FROZEN, REPO_ROOT, DEFAULT_DATASET, DEFAULT_MANIFEST, FORBIDDEN_OUTPUT_DIRS,
  OUTPUT_FILES, MANIFEST_EXPECTED, SEED_CHROMA_EXPECTED_SHA,
  PreflightError, DatasetIntegrityError, OutputPathError,
  // dataset + manifest
  sha256Hex, categoryCounts, labelCounts, checkFrozen, loadDataset,
  checkManifest, loadManifest, seedChromaProvenance,
  // classification
  isStatefulEntry, classifyRecords, groupBySequence, classifyResult,
  detectSemanticFallback, detectRagInfraFailure, detectFallback, extractDiagnostics,
  // phases
  preflight, planDryRun, runConfig, runOneRecord, assertFixtureBaseSafe,
  // aggregation
  summarizeConfig, groupOutputProbes,
  // output paths
  assertSafeOutputDir, atomicWriteJSON, writeOutputs,
  // orchestration
  makeContext, runEvaluation, cleanupSync,
  // error accounting
  newErrorAccount, accountError,
};
