const config = require("../utils/config");
const { defaultVectorStore } = require("../providers");

/**
 * Retrieve similar security patterns from the vector store and format as
 * few-shot context. Returns a formatted string, or null if unavailable.
 * The vector store is injectable; it defaults to the research ChromaVectorStore.
 *
 * OBSERVABILITY (evaluation-only, decision-neutral): callers MAY pass a mutable
 * `diag` object as the third argument. When present, it is populated with the
 * infrastructure status of this query so an evaluation harness can distinguish
 * a legitimate "no similar patterns" result from a vector-store failure. The
 * RETURN VALUE and all retrieval behavior are unchanged whether or not `diag`
 * is supplied — this only records facts the function already computes.
 */
async function retrieveSimilarPatterns(input, vectorStore = defaultVectorStore, diag = null) {
  try {
    const results = await vectorStore.query({
      queryTexts: [input],
      nResults: config.chromadb.nResults,
    });

    // A null/empty result from the vector store means the collection was
    // unavailable (ChromaVectorStore.query() returns null when there is no
    // collection). This is infrastructure-unavailable, NOT "zero matches".
    if (!results || !results.documents || !results.documents[0]) {
      if (diag) { diag.ragQuerySucceeded = false; diag.ragUnavailable = true; }
      return null;
    }

    // The query itself succeeded; from here, an empty match set is legitimate.
    if (diag) diag.ragQuerySucceeded = true;

    const documents = results.documents[0];
    const distances = results.distances[0];
    const metadatas = results.metadatas[0];

    // Filter by distance threshold — lower distance = more similar
    const examples = [];
    for (let i = 0; i < documents.length; i++) {
      if (distances[i] <= config.chromadb.distanceThreshold) {
        const label = metadatas[i].safe === "true" ? "SAFE" : "UNSAFE";
        const category = metadatas[i].category || "unknown";
        examples.push(`- [${label}] (${category}) "${documents[i]}"`);
      }
    }

    if (examples.length === 0) {
      if (diag) diag.ragHadMatches = false;
      return null;
    }

    if (diag) diag.ragHadMatches = true;
    return `\n\nHere are similar known patterns for reference:\n${examples.join("\n")}`;
  } catch (err) {
    console.error(`[RAGRetriever] Error: ${err.message}`);
    if (diag) { diag.ragQuerySucceeded = false; diag.ragQueryFailed = true; }
    return null;
  }
}

module.exports = { retrieveSimilarPatterns };
