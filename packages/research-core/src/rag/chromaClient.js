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

/**
 * STRICTLY READ-ONLY lookup of the security_patterns collection.
 *
 * Unlike getCollection() (which uses getOrCreateCollection and may CREATE the
 * collection), this NEVER creates, seeds, or mutates anything. It is used by the
 * scientific preflight, which must not alter a controlled Chroma instance.
 *
 * Uses listCollections() — a read-only API — to test existence, and returns the
 * matching collection handle (which supports .count()) or null when it does not
 * exist. It does NOT catch connection/lookup errors: it THROWS them so callers
 * can distinguish an absent collection (null) from an infrastructure failure.
 */
async function getExistingCollection() {
  if (!config.chromadb.enabled) {
    return null;
  }
  if (!client) {
    client = new ChromaClient({
      host: config.chromadb.host,
      port: config.chromadb.port,
    });
  }
  // listCollections is read-only and never creates a collection.
  const collections = await client.listCollections();
  const match = (collections || []).find((c) => c && c.name === COLLECTION_NAME);
  return match || null;
}

// For testing — reset cached instances
function _reset() {
  client = null;
  collection = null;
}

module.exports = { getCollection, getExistingCollection, _reset, COLLECTION_NAME };
