const pipeline = require("./pipeline");

/**
 * Readiness checks (brief §26). Probes the dependencies required to serve
 * inference via research-core's provider interfaces. Returns booleans only; the
 * route decides the (minimal) public shape and logs detail server-side.
 *
 * Ollama + the configured model gate readiness (no model => cannot serve). The
 * vector store (RAG) is reported but does NOT gate readiness, because
 * research-core degrades gracefully without it (rules + semantic still run).
 */
async function checkReadiness() {
  const provider = pipeline.providers.defaultInferenceProvider;
  const vectorStore = pipeline.providers.defaultVectorStore;
  const model = pipeline.model();

  const [ollama, modelAvailable, vectorStoreUp] = await Promise.all([
    provider.isAvailable().catch(() => false),
    provider.hasModel(model).catch(() => false),
    vectorStore.isAvailable().catch(() => false),
  ]);

  const checks = { ollama, model: modelAvailable, vectorStore: vectorStoreUp };
  const ready = ollama && modelAvailable;
  return { ready, checks };
}

module.exports = { checkReadiness };
