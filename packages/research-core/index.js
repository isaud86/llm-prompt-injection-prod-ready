/**
 * @llm-injection/research-core — public API.
 *
 * This barrel is the ONLY surface production apps (apps/api, apps/worker) should
 * depend on. The research core is framework-free: it has no HTTP server, auth,
 * billing, database, or cloud dependencies, and its scientific algorithms and
 * C1–C5 semantics are frozen (see docs/RESEARCH_REPRODUCIBILITY.md).
 *
 * The REPL research CLI remains at ./src/index.js and is run via `npm start`.
 */
const policemanAgent = require("./src/agents/policemanAgent");
const chatbotAgent = require("./src/agents/chatbotAgent");
const ruleBasedValidator = require("./src/validators/ruleBasedValidator");
const semanticValidator = require("./src/validators/semanticValidator");
const outputFilter = require("./src/validators/outputFilter");
const sessionMemory = require("./src/memory/sessionMemory");
const longTermMemory = require("./src/memory/longTermMemory");
const RateLimiter = require("./src/middleware/rateLimiter");
const config = require("./src/utils/config");
const logger = require("./src/utils/logger");
const providers = require("./src/providers");
const { PRESETS } = require("./src/presets");

module.exports = {
  // --- Pipeline (primary entry point) ---
  /** processInput(input, options) -> research result object (see policemanAgent) */
  processInput: policemanAgent.processInput,
  /** Reset all per-context rate limiters + session memory (tests / process reset) */
  resetPipeline: policemanAgent.resetRateLimiter,
  policemanAgent,
  chatbotAgent,

  // --- Validators ---
  ruleBasedValidator,
  semanticValidator,
  outputFilter,

  // --- Memory / middleware ---
  sessionMemory,
  longTermMemory,
  RateLimiter,

  // --- Infrastructure interfaces + defaults (injectable) ---
  providers,

  // --- Config, logging, experimental presets ---
  config,
  logger,
  PRESETS,
};
