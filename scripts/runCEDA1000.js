#!/usr/bin/env node
/**
 * runCEDA1000.js — dedicated CEDA-1000 v1.1 evaluation runner (public entry).
 *
 * This is a NEW, independent runner. It is NOT the historical CEDA-215 ablation
 * runner (scripts/runAblation.js) and does NOT reproduce the original paper's
 * runs. It consumes data/ceda-1000.json (the expanded 1000-record v1.1 dataset),
 * hard-gates dataset integrity, preserves the historical C1–C5 layer semantics,
 * separately scores output-safety probes, and captures full provenance.
 *
 * Reusable logic lives in scripts/ceda1000/. This file is CLI/orchestration only.
 *
 * Exit codes:
 *   0  success (VALID run, or --help / --dry-run / --preflight ok)
 *   1  usage error
 *   2  dataset integrity gate failed
 *   3  preflight failed (a required service is unavailable — NOT a code fault)
 *   4  run completed but INVALID (e.g. silent semantic fallback detected)
 *   5  run FAILED (unexpected error)
 *   6  output-path error
 */

const path = require("path");
const fs = require("fs");

const runner = require("./ceda1000/runner");
const { resolveConfigs, CONFIGS } = require("./ceda1000/configs");

const EXIT = { OK: 0, USAGE: 1, DATASET: 2, PREFLIGHT: 3, INVALID: 4, FAILED: 5, OUTPUT: 6 };

const HELP = `
runCEDA1000.js — CEDA-1000 v1.1 evaluation runner

USAGE
  node scripts/runCEDA1000.js [options]
  npm run eval:ceda1000 -- [options]

MODES
  --help              Show this help and exit.
  --dry-run           Load + integrity-gate the dataset, print the execution plan,
                      and exit WITHOUT running the pipeline or writing anything.
  --preflight         Check that dependencies required by the selected configs are
                      available (Ollama for C2–C5, Chroma/RAG for C5) and exit.
                      Does NOT trigger model inference. A failing preflight means a
                      service is down (exit 3); it is NOT a code failure.
  (no mode flag)      Perform a real evaluation run. Requires --output-dir.

OPTIONS
  --configs <sel>     Which configs to run: "all" (default) or a comma list of
                      ids/names, e.g. "c1,c3" or "rules-only,full-pipeline".
                      Valid: ${CONFIGS.map((c) => `${c.id}/${c.name}`).join(", ")}.
  --output-dir <dir>  REQUIRED for a real run. Destination for result files.
                      Must NOT be data/results or data/result2, the repo root,
                      the filesystem/temp root, ".", ".." or "/".
  --model <name>      Ollama model for semantic configs (per-process override;
                      no global config mutation). Default: research-core config.
  --dataset <path>    Dataset file. Default: data/ceda-1000.json.
  --overwrite         Allow replacing existing result files in --output-dir.
                      Without it, a real run aborts if result files already exist.
  --verbose           Print per-config progress.

OUTPUT FILES (real run, in --output-dir)
  ${runner.OUTPUT_FILES.manifest}          provenance + run manifest
  ${runner.OUTPUT_FILES.ablationRaw}          raw per-record × per-config results
  ${runner.OUTPUT_FILES.ablationSummary}      aggregate metrics (confusion matrix, latency, ...)
  ${runner.OUTPUT_FILES.outputProbe}   output-safety probe results
  ${runner.OUTPUT_FILES.sequence}      rate-limit + multi-turn sequence results

NOTES
  - The dataset is NEVER modified. Dataset inputs flow only into the defense
    pipeline (processInput).
  - This runner NEVER silently falls back: if a required model/dependency is
    unavailable, preflight refuses to run, and any fallback observed mid-run
    marks the run INVALID.
  - The runner never starts/seeds/resets/destroys Ollama or Chroma. A controlled,
    pre-seeded Chroma is required for C5.
`;

function parseArgs(argv) {
  const opts = {
    help: false, dryRun: false, preflight: false,
    configs: "all", outputDir: null, model: null,
    dataset: null, overwrite: false, verbose: false,
  };
  const takesValue = new Set(["--configs", "--output-dir", "--model", "--dataset"]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--help": case "-h": opts.help = true; break;
      case "--dry-run": opts.dryRun = true; break;
      case "--preflight": opts.preflight = true; break;
      case "--overwrite": opts.overwrite = true; break;
      case "--verbose": case "-v": opts.verbose = true; break;
      case "--configs": opts.configs = argv[++i]; break;
      case "--output-dir": opts.outputDir = argv[++i]; break;
      case "--model": opts.model = argv[++i]; break;
      case "--dataset": opts.dataset = argv[++i]; break;
      default:
        if (a.startsWith("--") && a.includes("=")) {
          const [k, ...rest] = a.split("=");
          const v = rest.join("=");
          if (takesValue.has(k)) {
            if (k === "--configs") opts.configs = v;
            else if (k === "--output-dir") opts.outputDir = v;
            else if (k === "--model") opts.model = v;
            else if (k === "--dataset") opts.dataset = v;
          } else throw new UsageError(`unknown flag: ${k}`);
        } else {
          throw new UsageError(`unexpected argument: ${a}`);
        }
    }
    if (takesValue.has(a) && (i >= argv.length || argv[i] === undefined)) {
      throw new UsageError(`${a} requires a value`);
    }
  }
  return opts;
}

class UsageError extends Error {}

function sanitizedCli(opts, resolvedConfigs, model) {
  return {
    mode: opts.preflight ? "preflight" : opts.dryRun ? "dry-run" : "run",
    configs: resolvedConfigs.map((c) => c.id),
    model,
    dataset: opts.dataset || runner.DEFAULT_DATASET,
    outputDir: opts.outputDir || null,
    overwrite: opts.overwrite,
    verbose: opts.verbose,
  };
}

function existingOutputFiles(dir) {
  return Object.values(runner.OUTPUT_FILES)
    .map((n) => path.join(dir, n))
    .filter((p) => fs.existsSync(p));
}

async function main() {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); }
  catch (e) {
    if (e instanceof UsageError) { console.error(`Error: ${e.message}\n${HELP}`); return EXIT.USAGE; }
    throw e;
  }

  if (opts.help) { console.log(HELP); return EXIT.OK; }

  // Resolve configs early so invalid selections fail fast in every mode.
  let configs;
  try { configs = resolveConfigs(opts.configs); }
  catch (e) { console.error(`Error: ${e.message}`); return EXIT.USAGE; }

  const config = require("../packages/research-core/src/utils/config");
  const model = opts.model || (config.ollama && config.ollama.model);
  const datasetPath = opts.dataset ? path.resolve(opts.dataset) : runner.DEFAULT_DATASET;

  // Dataset integrity gate (all real modes; dry-run/preflight also gate so they
  // are meaningful). Abort — never warn-and-continue.
  let loaded;
  try { loaded = runner.loadDataset(datasetPath); }
  catch (e) {
    if (e instanceof runner.DatasetIntegrityError) {
      console.error(`\nDATASET INTEGRITY GATE FAILED\n${e.message}\n`);
      return EXIT.DATASET;
    }
    throw e;
  }
  const { dataset, datasetInfo } = loaded;
  const classified = runner.classifyRecords(dataset);

  // Manifest integrity gate (hard, before evaluation). Also cross-checked
  // against the dataset SHA below. Abort — never warn-and-continue.
  const manifestPath = path.join(path.dirname(datasetPath), "ceda-1000.manifest.json");
  let manifestInfo;
  try { manifestInfo = runner.loadManifest(manifestPath).manifestInfo; }
  catch (e) {
    if (e instanceof runner.DatasetIntegrityError) {
      console.error(`\nMANIFEST INTEGRITY GATE FAILED\n${e.message}\n`);
      return EXIT.DATASET;
    }
    throw e;
  }
  if (manifestInfo.facts.datasetSha256 !== datasetInfo.sha256) {
    console.error(`\nMANIFEST/DATASET DISAGREE\n  manifest.datasetSha256=${manifestInfo.facts.datasetSha256}\n  dataset file sha=${datasetInfo.sha256}\n`);
    return EXIT.DATASET;
  }

  const ctx = runner.makeContext({
    configs, model,
    datasetPath, manifestPath, datasetInfo,
    outputDir: opts.outputDir,
    overwrite: opts.overwrite,
    verbose: opts.verbose,
    // Preflight (standalone or before a real run) enforces a clean working tree.
    requireCleanGit: !opts.dryRun,
    logger: opts.verbose ? (m) => console.log(`  ${m}`) : (() => {}),
  });
  ctx.cliSnapshot = sanitizedCli(opts, configs, model);

  // ── Dry-run ────────────────────────────────────────────────────────────────
  if (opts.dryRun) {
    const plan = runner.planDryRun(ctx, classified);
    console.log("\nCEDA-1000 DRY RUN (no pipeline execution, nothing written)\n");
    console.log(JSON.stringify(plan, null, 2));
    console.log("");
    return EXIT.OK;
  }

  // ── Preflight ────────────────────────────────────────────────────────────────
  if (opts.preflight) {
    const report = await runner.preflight(ctx);
    console.log("\nCEDA-1000 PREFLIGHT\n");
    console.log(`  model: ${ctx.model}`);
    for (const c of report.checks) {
      console.log(`  [${c.ok ? "OK " : "!! "}] ${c.name}: ${c.detail}`);
    }
    console.log(`\n  preflight: ${report.ok ? "PASS" : "FAIL"}\n`);
    return report.ok ? EXIT.OK : EXIT.PREFLIGHT;
  }

  // ── Real run ─────────────────────────────────────────────────────────────────
  let outputDir;
  try { outputDir = runner.assertSafeOutputDir(opts.outputDir); }
  catch (e) {
    if (e instanceof runner.OutputPathError) { console.error(`Error: ${e.message}`); return EXIT.OUTPUT; }
    throw e;
  }
  ctx.outputDir = outputDir;

  if (fs.existsSync(outputDir)) {
    const existing = existingOutputFiles(outputDir);
    if (existing.length > 0 && !opts.overwrite) {
      console.error(
        `Error: ${existing.length} result file(s) already exist in ${outputDir}.\n` +
        `       Use --overwrite to replace them, or choose a fresh --output-dir.`,
      );
      return EXIT.OUTPUT;
    }
  }

  // Signal-safe cleanup of fixtures + temp files.
  let cleaned = false;
  const onSignal = (sig) => {
    if (cleaned) return; cleaned = true;
    console.error(`\nReceived ${sig}; cleaning up fixtures/temp files...`);
    ctx._aborted = true;
    runner.cleanupSync(ctx);
    process.exit(130);
  };
  process.on("SIGINT", () => onSignal("SIGINT"));
  process.on("SIGTERM", () => onSignal("SIGTERM"));

  console.log(`\nCEDA-1000 EVALUATION RUN`);
  console.log(`  dataset : ${datasetInfo.path}`);
  console.log(`  sha256  : ${datasetInfo.sha256}`);
  console.log(`  configs : ${configs.map((c) => c.id).join(", ")}`);
  console.log(`  model   : ${ctx.model}`);
  console.log(`  output  : ${outputDir}\n`);

  let results;
  try {
    results = await runner.runEvaluation(ctx, { dataset, manifestInfo });
  } catch (e) {
    if (e instanceof runner.PreflightError) {
      console.error(`\nPREFLIGHT FAILED — run aborted (no results written)\n${e.message}\n`);
      return EXIT.PREFLIGHT;
    }
    console.error(`\nRUN FAILED: ${e.stack || e.message}\n`);
    return EXIT.FAILED;
  }

  // Human summary.
  console.log(`\n  Run status: ${results.status}`);
  if (results.invalidReasons.length > 0) {
    console.log("  Reasons:");
    for (const r of results.invalidReasons) console.log(`    - ${r}`);
  }
  for (const s of results.summary.configs) {
    const m = s.evaluationMetrics;
    console.log(
      `  [${s.configId}/${s.config}] acc=${(m.accuracy * 100).toFixed(1)}% ` +
      `P=${m.precision.toFixed(3)} R=${m.recall.toFixed(3)} F1=${m.f1.toFixed(3)} ` +
      `(scored ${s.recordsScored}/${s.recordsTotal})`,
    );
  }
  console.log(`\n  Results written to ${outputDir}\n`);

  if (results.status === "INVALID") return EXIT.INVALID;
  if (results.status === "FAILED") return EXIT.FAILED;
  return EXIT.OK;
}

if (require.main === module) {
  main()
    .then((code) => process.exit(code))
    .catch((err) => { console.error(err); process.exit(EXIT.FAILED); });
}

module.exports = { main, parseArgs, UsageError, EXIT };
