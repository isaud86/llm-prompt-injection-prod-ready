const VectorStore = require("./VectorStore");
const chromaClient = require("../rag/chromaClient");

/**
 * ChromaVectorStore — the canonical research vector store. Wraps the existing
 * chromaClient so behavior and graceful degradation are unchanged: when
 * ChromaDB is disabled/unavailable, getCollection() returns null and reads
 * return null / writes return false (never throw at this layer's callers'
 * expense — callers keep their own try/catch as before).
 */
class ChromaVectorStore extends VectorStore {
  async getCollection() {
    return chromaClient.getCollection();
  }

  async query({ queryTexts, nResults }) {
    const col = await this.getCollection();
    if (!col) return null;
    return col.query({ queryTexts, nResults });
  }

  async add(record) {
    const col = await this.getCollection();
    if (!col) return false;
    await col.add(record);
    return true;
  }

  async isAvailable() {
    return (await this.getCollection()) !== null;
  }
}

module.exports = ChromaVectorStore;
