const { ChromaClient } = require("chromadb");
const config = require("../utils/config");

const COLLECTION_NAME = "security_patterns";

let client = null;
let collection = null;

/**
 * Get the ChromaDB collection handle.
 * Returns null if ChromaDB is disabled or unavailable (graceful degradation).
 * Embeddings are computed server-side by ChromaDB's built-in model.
 */
async function getCollection() {
  if (!config.chromadb.enabled) {
    return null;
  }

  if (collection) {
    return collection;
  }

  try {
    if (!client) {
      client = new ChromaClient({
        host: config.chromadb.host,
        port: config.chromadb.port,
      });
    }

    collection = await client.getOrCreateCollection({
      name: COLLECTION_NAME,
      metadata: { "hnsw:space": "cosine" },
    });

    return collection;
  } catch (err) {
    console.error(`[ChromaClient] Connection error: ${err.message}`);
    return null;
  }
}

// For testing — reset cached instances
function _reset() {
  client = null;
  collection = null;
}

module.exports = { getCollection, _reset, COLLECTION_NAME };
