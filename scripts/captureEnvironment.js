#!/usr/bin/env node
/**
 * Capture environment provenance for a research/experiment run.
 *
 * Satisfies brief §3: records git commit, Node.js version, Ollama version,
 * model name + digest (if available), CUDA version, NVIDIA driver version,
 * dataset version, and the active experiment configuration.
 *
 * Fields that cannot be detected on this machine are recorded as `null` rather
 * than guessed. Output is written to provenance.local.json (git-ignored — it is
 * a per-run snapshot; archive a copy next to your results).
 *
 * Usage: node scripts/captureEnvironment.js   (or: npm run captureEnv)
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const OUTPUT = path.join(ROOT, "provenance.local.json");

/** Run a command safely; return trimmed stdout or null on any failure. */
function tryExec(bin, args, opts = {}) {
  try {
    return execFileSync(bin, args, {
      encoding: "utf8",
      timeout: 10000,
      stdio: ["ignore", "pipe", "ignore"],
      ...opts,
    }).trim();
  } catch {
    return null;
  }
}

function gitInfo() {
  return {
    commit: tryExec("git", ["rev-parse", "HEAD"]),
    shortCommit: tryExec("git", ["rev-parse", "--short", "HEAD"]),
    branch: tryExec("git", ["rev-parse", "--abbrev-ref", "HEAD"]),
    dirty: (() => {
      const status = tryExec("git", ["status", "--porcelain"]);
      return status === null ? null : status.length > 0;
    })(),
  };
}

function nodeInfo() {
  return {
    node: process.version,
    npm: tryExec("npm", ["--version"]),
    platform: process.platform,
    arch: process.arch,
  };
}

function ollamaInfo() {
  const version = tryExec("ollama", ["--version"]);
  // `ollama list` columns: NAME  ID(digest)  SIZE  MODIFIED
  const listRaw = tryExec("ollama", ["list"]);
  let models = null;
  if (listRaw) {
    const lines = listRaw.split("\n").slice(1).filter(Boolean); // drop header
    models = lines.map((line) => {
      const cols = line.split(/\s{2,}/).map((c) => c.trim());
      return { name: cols[0] || null, digest: cols[1] || null, size: cols[2] || null };
    });
  }
  return {
    version: version || null, // null => Ollama CLI not found on this host
    host: process.env.OLLAMA_HOST || "http://127.0.0.1:11434",
    configuredModel: process.env.OLLAMA_MODEL || "llama3.2:1b",
    models,
  };
}

function gpuInfo() {
  // nvidia-smi query; null when no NVIDIA GPU / driver present.
  const raw = tryExec("nvidia-smi", [
    "--query-gpu=name,driver_version,memory.total",
    "--format=csv,noheader",
  ]);
  const cuda = tryExec("nvcc", ["--version"]);
  let cudaVersion = null;
  if (cuda) {
    const m = cuda.match(/release\s+([\d.]+)/i);
    cudaVersion = m ? m[1] : null;
  }
  // nvidia-smi also reports a CUDA version in its header even without nvcc
  if (!cudaVersion) {
    const smiHeader = tryExec("nvidia-smi", []);
    if (smiHeader) {
      const m = smiHeader.match(/CUDA Version:\s*([\d.]+)/i);
      cudaVersion = m ? m[1] : null;
    }
  }
  let gpus = null;
  if (raw) {
    gpus = raw.split("\n").filter(Boolean).map((line) => {
      const [name, driver, mem] = line.split(",").map((c) => c.trim());
      return { name: name || null, driverVersion: driver || null, memoryTotal: mem || null };
    });
  }
  return {
    cudaVersion,
    driverVersion: gpus && gpus[0] ? gpus[0].driverVersion : null,
    gpus, // null => no NVIDIA GPU detected on this host
  };
}

function datasetInfo() {
  const datasetPath = path.join(ROOT, "data", "evaluation-dataset.json");
  if (!fs.existsSync(datasetPath)) {
    return { path: "data/evaluation-dataset.json", present: false };
  }
  const buf = fs.readFileSync(datasetPath);
  let entryCount = null;
  try {
    const parsed = JSON.parse(buf.toString("utf8"));
    entryCount = Array.isArray(parsed)
      ? parsed.length
      : Array.isArray(parsed.entries)
        ? parsed.entries.length
        : null;
  } catch {
    /* leave entryCount null */
  }
  return {
    path: "data/evaluation-dataset.json",
    present: true,
    sha256: crypto.createHash("sha256").update(buf).digest("hex"),
    bytes: buf.length,
    entryCount,
    name: "CEDA-215",
  };
}

function packageInfo() {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
    const hasLock = fs.existsSync(path.join(ROOT, "package-lock.json"));
    return { version: pkg.version, dependencies: pkg.dependencies, lockfileCommitted: hasLock };
  } catch {
    return null;
  }
}

const provenance = {
  capturedAt: new Date().toISOString(),
  git: gitInfo(),
  runtime: nodeInfo(),
  ollama: ollamaInfo(),
  gpu: gpuInfo(),
  dataset: datasetInfo(),
  package: packageInfo(),
  mode: {
    research: process.env.PRODUCTION_MODE === "true" ? false : true,
    production: process.env.PRODUCTION_MODE === "true",
  },
  note:
    "Fields recorded as null could not be detected on this host and were not guessed. " +
    "Archive a copy of this file alongside published results.",
};

fs.writeFileSync(OUTPUT, JSON.stringify(provenance, null, 2) + "\n");
console.log(`[provenance] wrote ${path.relative(ROOT, OUTPUT)}`);
console.log(JSON.stringify(provenance, null, 2));
