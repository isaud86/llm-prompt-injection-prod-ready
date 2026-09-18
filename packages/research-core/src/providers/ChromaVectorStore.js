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

  /**
   * Read-only collection provenance: { name, count } or null when unavailable.
   * Uses the same collection handle the RAG read path already uses; does not
   * seed, mutate, reset or delete the collection.
   */
  async collectionInfo() {
    const col = await this.getCollection();
    if (!col) return null;
    let count = null;
    try { count = await col.count(); } catch { count = null; }
    return { name: col.name || null, count };
  }
}

module.exports = ChromaVectorStore;
