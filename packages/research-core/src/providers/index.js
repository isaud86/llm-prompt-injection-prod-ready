const InferenceProvider = require("./InferenceProvider");
const OllamaInferenceProvider = require("./OllamaInferenceProvider");
const VectorStore = require("./VectorStore");
const ChromaVectorStore = require("./ChromaVectorStore");

/**
 * Default infrastructure providers used by the research pipeline. These preserve
 * the original behavior (local Ollama + ChromaDB). Production consumers (the API
 * / worker) may construct and inject alternative implementations of the same
 * interfaces without modifying the scientific code.
 */
const defaultInferenceProvider = new OllamaInferenceProvider();
const defaultVectorStore = new ChromaVectorStore();

module.exports = {
  InferenceProvider,
  OllamaInferenceProvider,
  VectorStore,
  ChromaVectorStore,
  defaultInferenceProvider,
  defaultVectorStore,
};
