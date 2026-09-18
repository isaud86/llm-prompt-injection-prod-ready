/**
 * VectorStore — abstraction over the vector database used by the RAG layer and
 * long-term memory (brief Phase 1b, §30).
 *
 * ChromaDB remains the canonical research implementation. A production
 * deployment may substitute pgvector or another store behind this same
 * interface WITHOUT changing research experiments (which must keep using
 * ChromaVectorStore — see docs/RESEARCH_REPRODUCIBILITY.md).
 */
class VectorStore {
  /**
   * @param {{ queryTexts: string[], nResults: number }} _params
   * @returns {Promise<null | { documents: any[][], distances: number[][], metadatas: any[][] }>}
   *   Chroma-shaped result, or null when the store is unavailable.
   */
  async query(_params) {
    throw new Error("VectorStore.query() not implemented");
  }

  /**
   * @param {{ ids: string[], documents: string[], metadatas: object[] }} _record
   * @returns {Promise<boolean>} true if written, false if the store is unavailable.
   */
  async add(_record) {
    throw new Error("VectorStore.add() not implemented");
  }

  /** @returns {Promise<boolean>} whether the store is reachable. */
  async isAvailable() {
    throw new Error("VectorStore.isAvailable() not implemented");
  }
}

module.exports = VectorStore;
