require("dotenv").config();

// --- Operating mode (brief §3) ---
// Research Mode (default) preserves original experimental behavior: fail-open
// semantic validation, shared session memory permitted, ChromaDB, command
// execution on. Production Mode enables fail-safe behavior, strict per-user
// isolation, and safe defaults. Setting PRODUCTION_MODE=true implies Research
// Mode is off unless RESEARCH_MODE=true is set explicitly (not recommended on a
// public production path). Defaulting to Research Mode guarantees that existing
// experiments and the C1–C5 ablation are unchanged when no env is provided.
const productionMode = process.env.PRODUCTION_MODE === "true";
const researchMode = productionMode
  ? process.env.RESEARCH_MODE === "true"
  : process.env.RESEARCH_MODE !== "false";

const config = {
  mode: {
    research: researchMode,
    production: productionMode,
    // Semantic validator behavior when the LLM is unavailable:
    // research → fail open (rules only); production → fail safe.
    failOpenOnInferenceError: researchMode && !productionMode,
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
