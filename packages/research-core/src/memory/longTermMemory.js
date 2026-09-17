const fs = require("fs");
const config = require("../utils/config");
const { defaultVectorStore } = require("../providers");

const ID_PREFIX = "rt-";

/**
 * Persist a blocked attack into the vector store for future RAG retrieval.
 * Skips rate_limit violations (behavioral, not semantic patterns).
 * Degrades gracefully — never throws. The vector store is injectable.
 */
async function storeBlockedPattern(
  input,
  violationType,
  confidence,
  vectorStore = defaultVectorStore,
) {
  if (!config.memory.longTermEnabled) return;
  if (violationType === "rate_limit") return;

  try {
    const id = `${ID_PREFIX}${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    await vectorStore.add({
      ids: [id],
      documents: [input.substring(0, 500)],
      metadatas: [
        {
          safe: "false",
          category: violationType,
          subcategory: "runtime_learned",
          confidence: confidence || "unknown",
          timestamp: new Date().toISOString(),
        },
      ],
    });
  } catch (err) {
    console.error(`[LongTermMemory] Failed to store pattern: ${err.message}`);
  }
}

/**
 * Read recent VIOLATION entries from the security log on startup.
 * Returns an array of log entry objects (oldest first), or [] on failure.
 */
function loadRecentViolations(maxEntries) {
  const limit = maxEntries || config.memory.warmupEntries;

  try {
    const logFile = config.logging.file;
    if (!fs.existsSync(logFile)) return [];

    const lines = fs.readFileSync(logFile, "utf8").split("\n").filter(Boolean);

    const violations = [];
    for (let i = lines.length - 1; i >= 0 && violations.length < limit; i--) {
      try {
        const entry = JSON.parse(lines[i]);
        if (entry.status === "VIOLATION" && entry.violationType !== "rate_limit") {
          violations.push(entry);
        }
      } catch {
        // skip malformed lines
      }
    }

    return violations.reverse();
  } catch (err) {
    console.error(
      `[LongTermMemory] Failed to load recent violations: ${err.message}`
    );
    return [];
  }
}

module.exports = { storeBlockedPattern, loadRecentViolations };
