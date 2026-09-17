require("dotenv").config();

// --- Operating mode (brief §3; safety-gate task 4) ---
// A SINGLE validated mode is the source of truth: APP_MODE = research | production | test.
//   research   (default) : original experimental behavior — fail-OPEN semantic
//                          validation (rules-only on inference error), C1–C5, etc.
//   production            : fail-SAFE — inference errors do NOT fall through to
//                          command execution or conversational generation.
//   test                 : behaves like research (fail-open) for the unit suite.
//
// Backward-compatible migration: if APP_MODE is unset, the legacy PRODUCTION_MODE
// / RESEARCH_MODE flags are honored so existing setups and experiments are
// unchanged. The ambiguous combination PRODUCTION_MODE=true + RESEARCH_MODE=true
// resolves deterministically to production (the safer choice) with a warning.
const VALID_MODES = ["research", "production", "test"];

function resolveMode(env) {
  const raw = (env.APP_MODE || "").toLowerCase().trim();
  if (raw) {
    if (!VALID_MODES.includes(raw)) {
      throw new Error(
        `Invalid APP_MODE "${env.APP_MODE}". Expected one of: ${VALID_MODES.join(", ")}.`,
      );
    }
    return raw;
  }
  // Legacy fallback (deprecated — prefer APP_MODE).
  const prod = env.PRODUCTION_MODE === "true";
  const res = env.RESEARCH_MODE === "true";
  if (prod && res) {
    // eslint-disable-next-line no-console
    console.warn(
      "[config] Both PRODUCTION_MODE and RESEARCH_MODE are set; resolving to production. Prefer APP_MODE=production|research|test.",
    );
    return "production";
  }
  if (prod) return "production";
  return "research"; // default preserves original experimental behavior
}

const modeName = resolveMode(process.env);
const productionMode = modeName === "production";
const researchMode = modeName === "research";

const config = {
  mode: {
    // Single source of truth; provenance capture reports this exact value.
    name: modeName,
    research: researchMode,
    production: productionMode,
    test: modeName === "test",
    // Semantic validator + pipeline behavior when the LLM is unavailable:
    // production → fail SAFE; research/test → fail OPEN (rules only).
    failOpenOnInferenceError: !productionMode,
  },
  // In-memory context store safeguards (safety-gate task 2). These are DEVELOPMENT
  // safeguards to bound per-process state for session memory + rate limiters.
  // Redis remains the PRODUCTION implementation (Phase 4) — see docs.
  contexts: {
    maxContexts: parseInt(process.env.MAX_CONTEXTS, 10) || 10000,
    ttlMs: parseInt(process.env.CONTEXT_TTL_MS, 10) || 3600000, // 1 hour idle TTL
  },
  ollama: {
    host: process.env.OLLAMA_HOST || "http://127.0.0.1:11434",
    model: process.env.OLLAMA_MODEL || "llama3.2:1b",
  },
  rateLimit: {
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 20,
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 60000,
  },
  logging: {
    file: process.env.LOG_FILE || "logs/security.log",
    verbose: process.env.LOG_VERBOSE === "true",
  },
  command: {
    timeoutMs: parseInt(process.env.COMMAND_TIMEOUT_MS, 10) || 5000,
    allowedCommands: ["ls", "date"],
  },
  chromadb: {
    host: process.env.CHROMADB_HOST || "localhost",
    port: parseInt(process.env.CHROMADB_PORT, 10) || 8000,
    enabled: process.env.CHROMADB_ENABLED !== "false",
    nResults: parseInt(process.env.CHROMADB_N_RESULTS, 10) || 5,
    distanceThreshold:
      parseFloat(process.env.CHROMADB_DISTANCE_THRESHOLD) || 1.0,
  },
  memory: {
    sessionWindow:
      parseInt(process.env.SESSION_HISTORY_WINDOW, 10) || 5,
    longTermEnabled: process.env.LONG_TERM_MEMORY_ENABLED !== "false",
    warmupEntries:
      parseInt(process.env.MEMORY_WARMUP_ENTRIES, 10) || 10,
  },
};

module.exports = config;
