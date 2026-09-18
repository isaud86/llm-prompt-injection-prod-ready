/**
 * Provenance capture for the CEDA-1000 runner.
 *
 * Records the exact conditions of a run so results are reproducible and
 * auditable. Git facts are gathered with execFile + a FIXED argument vector
 * (never a shell string), so no dataset or user text is ever interpolated into
 * a command line. NO secrets are captured: environment variables are NOT
 * serialized; only a small allow-list of non-sensitive config values is
 * recorded.
 */

const os = require("os");
const { execFile } = require("child_process");

const REPO_ROOT = require("path").resolve(__dirname, "..", "..");

/** Run `git <args>` with a fixed arg vector; resolve trimmed stdout or null. */
function git(args) {
  return new Promise((resolve) => {
    execFile("git", args, { cwd: REPO_ROOT, timeout: 5000 }, (err, stdout) => {
      if (err) { resolve(null); return; }
      resolve(String(stdout).trim());
    });
  });
}

async function gitProvenance() {
  const [commit, branch, status, describe] = await Promise.all([
    git(["rev-parse", "HEAD"]),
    git(["rev-parse", "--abbrev-ref", "HEAD"]),
    git(["status", "--porcelain"]),
    git(["describe", "--tags", "--always", "--dirty"]),
  ]);
  return {
    commit: commit || "unknown",
    branch: branch || "unknown",
    describe: describe || "unknown",
    // Boolean only — we do NOT serialize the (potentially path-revealing) diff.
    dirty: status == null ? null : status.length > 0,
  };
}

/** Node + OS runtime facts (no hostname/user/env — avoid leaking identity). */
function runtimeProvenance() {
  return {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    osType: os.type(),
    osRelease: os.release(),
    cpuCount: os.cpus() ? os.cpus().length : null,
    totalMemBytes: os.totalmem(),
  };
}

/**
 * A curated, non-sensitive snapshot of the research-core config that affects
 * results. Deliberately excludes hosts/ports/paths and any secret material.
 */
function configProvenance(config) {
  if (!config) return null;
  return {
    mode: config.mode && config.mode.name,
    failOpenOnInferenceError: !!(config.mode && config.mode.failOpenOnInferenceError),
    ollamaModel: config.ollama && config.ollama.model,
    rateLimitMaxRequests: config.rateLimit && config.rateLimit.maxRequests,
    rateLimitWindowMs: config.rateLimit && config.rateLimit.windowMs,
    allowedCommands: config.command && config.command.allowedCommands,
    chromadbEnabled: config.chromadb && config.chromadb.enabled,
    sessionWindow: config.memory && config.memory.sessionWindow,
  };
}

/**
 * Build the full run manifest. Timestamps ARE permitted here (this is run
 * output, not dataset generation). Never include secrets.
 *
 * @param {object} p
 * @param {object} p.frozen         FROZEN dataset facts (configs.js)
 * @param {object} p.datasetInfo    { path, sha256, version, total }
 * @param {Array}  p.configs        resolved config objects
 * @param {object} p.cli            sanitized CLI options actually used
 * @param {object} p.preflight      preflight report (or null)
 * @param {object} p.git            git provenance
 * @param {object} p.config         research-core config (for configProvenance)
 * @param {string} p.status         VALID | INVALID | FAILED
 * @param {object} p.timing         { startedAt, finishedAt, durationMs }
 * @param {object} p.counts         summary counts
 * @param {Array}  p.invalidReasons why the run is INVALID/FAILED (if any)
 */
function buildRunManifest(p) {
  return {
    schema: "ceda-1000-run-manifest/v1",
    runner: {
      name: "runCEDA1000.js",
      note:
        "Dedicated CEDA-1000 v1.1 evaluation runner. Distinct from the historical " +
        "CEDA-215 runner (scripts/runAblation.js). Not a reproduction of the " +
        "original paper's runs.",
    },
    status: p.status,
    invalidReasons: p.invalidReasons || [],
    timing: p.timing || null,
    dataset: {
      path: p.datasetInfo && p.datasetInfo.path,
      sha256: p.datasetInfo && p.datasetInfo.sha256,
      expectedSha256: p.frozen && p.frozen.datasetSha256,
      version: p.datasetInfo && p.datasetInfo.version,
      total: p.datasetInfo && p.datasetInfo.total,
    },
    frozen: p.frozen || null,
    configs: (p.configs || []).map((c) => ({
      id: c.id, name: c.name, options: c.options,
      requiresSemantic: c.requiresSemantic, requiresRAG: c.requiresRAG,
      requiresRateLimit: c.requiresRateLimit, requiresMemory: c.requiresMemory,
    })),
    cli: p.cli || null,
    preflight: p.preflight || null,
    counts: p.counts || null,
    git: p.git || null,
    runtime: runtimeProvenance(),
    config: configProvenance(p.config),
  };
}

module.exports = {
  git,
  gitProvenance,
  runtimeProvenance,
  configProvenance,
  buildRunManifest,
};
