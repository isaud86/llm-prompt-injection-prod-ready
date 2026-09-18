/**
 * InferenceProvider — abstraction over the LLM backend used by the research
 * pipeline (semantic validation + conversational responses).
 *
 * Keeps research-core decoupled from any specific model runtime (brief Phase 1b).
 * Implementations must have NO HTTP-server / auth / billing / cloud dependencies.
 * A future production deployment can inject an alternative provider (queued,
 * circuit-broken, remote) without touching the scientific algorithms.
 */
class InferenceProvider {
  /**
   * Chat completion. Parameters mirror the Ollama chat API shape so existing
   * callers are unchanged: { model, messages, format?, think?, options? }.
   * @returns {Promise<{ message: { content: string } }>}
   */
  async chat(_params) {
    throw new Error("InferenceProvider.chat() not implemented");
  }

  /** @returns {Promise<boolean>} whether the backend is reachable. */
  async isAvailable() {
    throw new Error("InferenceProvider.isAvailable() not implemented");
  }

  /**
   * @param {string} _model
   * @returns {Promise<boolean>} whether the model is available on the backend.
   */
  async hasModel(_model) {
    throw new Error("InferenceProvider.hasModel() not implemented");
  }
}

module.exports = InferenceProvider;
