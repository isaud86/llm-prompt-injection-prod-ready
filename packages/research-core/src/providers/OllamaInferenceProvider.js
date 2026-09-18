const { Ollama } = require("ollama");
const InferenceProvider = require("./InferenceProvider");
const config = require("../utils/config");

/**
 * OllamaInferenceProvider — the research backend (local Ollama). Wraps the
 * ollama client. Behavior is identical to the pre-extraction direct usage: the
 * client is created lazily on first use with the configured host.
 */
class OllamaInferenceProvider extends InferenceProvider {
  constructor(options = {}) {
    super();
    this.host = options.host || config.ollama.host;
    this._client = options.client || null; // injectable for tests
  }

  client() {
    if (!this._client) {
      this._client = new Ollama({ host: this.host });
    }
    return this._client;
  }

  async chat(params) {
    return this.client().chat(params);
  }

  async isAvailable() {
    try {
      await this.client().list();
      return true;
    } catch {
      return false;
    }
  }

  async hasModel(model) {
    if (!model) return false;
    try {
      const res = await this.client().list();
      const models = (res && res.models) || [];
      return models.some(
        (m) =>
          m.name === model ||
          m.model === model ||
          (typeof m.name === "string" && m.name.startsWith(model)),
      );
    } catch {
      return false;
    }
  }

  // ─── Read-only metadata (evaluation provenance; never runs inference) ─────────

  /** Raw installed-model list (metadata only). */
  async listModels() {
    const res = await this.client().list();
    return (res && res.models) || [];
  }

  /**
   * Resolve a model tag to a UNIQUE installed model using list metadata only.
   * Returns { name, digest } for an exact, unambiguous match; null when the
   * model is absent or the tag matches more than one entry. Unlike hasModel(),
   * this performs NO prefix matching — a scientific run must pin an exact model.
   */
  async resolveModel(model) {
    if (!model) return null;
    let models;
    try { models = await this.listModels(); } catch { return null; }
    const exact = models.filter((m) => m.name === model || m.model === model);
    if (exact.length !== 1) return null; // absent or ambiguous
    const m = exact[0];
    return { name: m.name || m.model, digest: m.digest || null };
  }

  /** Ollama server version via the non-inference /api/version endpoint. */
  async version() {
    try {
      const v = await this.client().version();
      if (v == null) return null;
      return typeof v === "string" ? v : (v.version || null);
    } catch {
      return null;
    }
  }
}

module.exports = OllamaInferenceProvider;
