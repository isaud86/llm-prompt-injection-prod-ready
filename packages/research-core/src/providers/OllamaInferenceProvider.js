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
}

module.exports = OllamaInferenceProvider;
