/**
 * Thin indirection over the research-core public API. All API code reaches
 * research-core through this module so that (a) the dependency path lives in one
 * place and (b) tests can mock the research pipeline cleanly without touching the
 * package internals.
 */
const rc = require("../../../../packages/research-core");

module.exports = {
  /** processInput(message, options) -> research result object */
  processInput: rc.processInput,
  /** Reset per-context rate limiters + session memory (used by tests). */
  resetPipeline: rc.resetPipeline,
  /** C1–C5 presets (read-only; researcher-gated at the route level). */
  PRESETS: rc.PRESETS,
  /** Infrastructure providers (InferenceProvider / VectorStore defaults). */
  providers: rc.providers,
  /** Currently configured model name. */
  model: () => rc.config.ollama.model,
  /** Resolved research-core operating mode name ("research"|"production"|"test"). */
  modeName: () => rc.config.mode.name,
};
