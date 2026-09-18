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

  // ─── STRICTLY READ-ONLY preflight/provenance (never creates a collection) ─────

  /** Existing collection handle, or null if absent. Throws on lookup error. */
  async getExistingCollection() {
    return chromaClient.getExistingCollection();
  }

  /** True iff the collection already exists. Swallows errors → false. */
  async isExistingCollectionAvailable() {
    try { return (await chromaClient.getExistingCollection()) !== null; }
    catch { return false; }
  }

  /**
   * Read-only collection provenance WITHOUT any create path. Returns
   * { exists, name, count }. `exists:false` means the collection is genuinely
   * absent. THROWS on a connection/lookup error so preflight can distinguish an
   * infrastructure failure from a missing collection. Never calls
   * getOrCreateCollection.
   */
  async collectionInfoReadOnly() {
    const col = await chromaClient.getExistingCollection(); // throws on error
    if (!col) return { exists: false, name: null, count: null };
    const count = await col.count(); // throws on error → treated as lookup failure
    return { exists: true, name: col.name || null, count };
  }
}

module.exports = ChromaVectorStore;
