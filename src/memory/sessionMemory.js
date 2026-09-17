const config = require("../utils/config");

const WINDOW = config.memory.sessionWindow;

// Context-keyed session history (brief §8: session isolation).
//
// History is stored per context id. A context id is intended to be
// `${userId}:${conversationId}` in a multi-user deployment. When no context id
// is supplied — which is the case for the research CLI, the evaluation scripts,
// and all existing tests — a single DEFAULT_CONTEXT is used, giving byte-for-byte
// the previous single-user behavior. This makes the change reproducibility-safe:
// one user's conversation/security history can never influence another user's
// requests, while the research path is unchanged (see
// docs/RESEARCH_REPRODUCIBILITY.md §5).
const DEFAULT_CONTEXT = "__research_default__";

// Map<contextId, Array<{ input, status, violationType, ts }>>
const store = new Map();

function historyFor(contextId) {
  const key = contextId || DEFAULT_CONTEXT;
  let history = store.get(key);
  if (!history) {
    history = [];
    store.set(key, history);
  }
  return history;
}

/**
 * Record the outcome of a processed turn for a given context.
 * @param {string} input
 * @param {string} status
 * @param {string} violationType
 * @param {string} [contextId] optional `${userId}:${conversationId}`
 */
function record(input, status, violationType, contextId) {
  const key = contextId || DEFAULT_CONTEXT;
  let history = historyFor(key);
  history.push({
    input: input.substring(0, 200),
    status,
    violationType,
    ts: Date.now(),
  });
  if (history.length > WINDOW) {
    history = history.slice(-WINDOW);
    store.set(key, history);
  }
}

/**
 * Return a copy of the current window (oldest first) for a context.
 */
function getHistory(contextId) {
  return [...historyFor(contextId)];
}

/**
 * Detect multi-turn escalation patterns in a context's history.
 * Returns { escalating: bool, reason: string|null }.
 *
 * Patterns:
 * 1. 2+ violations in window → persistent attacker
 * 2. Safe turns followed by a violation → reconnaissance then attack
 */
function detectEscalation(contextId) {
  const history = historyFor(contextId);
  if (history.length < 2) {
    return { escalating: false, reason: null };
  }

  const violations = history.filter((h) => h.status === "VIOLATION");
  if (violations.length >= 2) {
    return {
      escalating: true,
      reason: `Multi-turn attack: ${violations.length} violations in last ${history.length} turns`,
    };
  }

  const last = history[history.length - 1];
  if (
    last?.status === "VIOLATION" &&
    history.slice(0, -1).every((h) => h.status === "SAFE")
  ) {
    return {
      escalating: true,
      reason:
        "Escalation pattern: safe reconnaissance turns followed by attack",
    };
  }

  return { escalating: false, reason: null };
}

/**
 * Format a context's history as a compact context block for the semantic
 * validator prompt. Returns a string or null if history is empty.
 */
function formatContextBlock(contextId) {
  const history = historyFor(contextId);
  if (history.length === 0) {
    return null;
  }

  const lines = history.map((h, i) => {
    const snippet = h.input.replace(/\n/g, " ").substring(0, 80);
    const label =
      h.status === "VIOLATION"
        ? `VIOLATION[${h.violationType}]`
        : "SAFE";
    return `Turn ${i + 1}: "${snippet}" → ${label}`;
  });

  return `\n\nConversation history (${history.length} prior turns):\n${lines.join("\n")}`;
}

/**
 * Reset history. With a contextId, clears only that context; without one,
 * clears ALL contexts (used for test isolation, matching prior behavior).
 */
function reset(contextId) {
  if (contextId) {
    store.delete(contextId);
  } else {
    store.clear();
  }
}

module.exports = {
  record,
  getHistory,
  detectEscalation,
  formatContextBlock,
  reset,
  DEFAULT_CONTEXT,
};
