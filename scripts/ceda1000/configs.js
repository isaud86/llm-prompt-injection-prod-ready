/**
 * Frozen CEDA-1000 evaluation constants + C1–C5 configuration definitions.
 *
 * The C1–C5 research-layer semantics are IDENTICAL to the historical
 * scripts/runAblation.js. This module is the single canonical source; do not
 * redefine these meanings elsewhere.
 */

// Frozen CEDA-1000 v1.1 dataset facts (the runner refuses to run against anything else).
const FROZEN = {
  datasetSha256: "ae9e6f41d85bf1bcf2d7317efc0004eabb9f1ce95a004e4413e24121d22600d5",
  seedSha256: "d5edbb5f28d148a333fd0b14488bbe8cd4acf506821109c259d6cf6a70a1ebab",
  version: "1.1",
  total: 1000,
  safe: 500,
  unsafe: 500,
  categories: {
    prompt_injection: 100,
    command_injection: 100,
    path_traversal: 80,
    encoding_obfuscation: 80,
    semantic_manipulation: 80,
    rate_limit_evasion: 80,
    multi_turn_escalation: 80,
    output_probing: 50,
    benign: 350,
  },
};

// Canonical, frozen C1–C5 configurations (same layer meanings as runAblation.js).
const CONFIGS = [
  { id: "C1", name: "rules-only",
    options: { useRules: true, useSemantic: false, useRateLimit: false, useMemory: false, useRAG: false } },
  { id: "C2", name: "semantic-only",
    options: { useRules: false, useSemantic: true, useRateLimit: false, useMemory: false, useRAG: false } },
  { id: "C3", name: "rules+semantic",
    options: { useRules: true, useSemantic: true, useRateLimit: false, useMemory: false, useRAG: false } },
  { id: "C4", name: "rules+semantic+rate+memory",
    options: { useRules: true, useSemantic: true, useRateLimit: true, useMemory: true, useRAG: false } },
  { id: "C5", name: "full-pipeline",
    options: { useRules: true, useSemantic: true, useRateLimit: true, useMemory: true, useRAG: true } },
];

// Derived capability flags per config.
for (const c of CONFIGS) {
  c.requiresSemantic = c.options.useSemantic === true;
  c.requiresRAG = c.options.useRAG === true;
  c.requiresRateLimit = c.options.useRateLimit === true;
  c.requiresMemory = c.options.useMemory === true;
}

const BY_TOKEN = new Map();
for (const c of CONFIGS) {
  BY_TOKEN.set(c.id.toLowerCase(), c);
  BY_TOKEN.set(c.name.toLowerCase(), c);
}

/**
 * Resolve a --configs selection token string into an ordered, de-duplicated
 * list of config objects. Accepts "all", or a comma list of ids (c1..c5) and/or
 * names (rules-only, ...). Throws on an unknown token.
 */
function resolveConfigs(selection) {
  const raw = (selection == null || selection === "" || selection === "all")
    ? CONFIGS.map((c) => c.id)
    : String(selection).split(",").map((s) => s.trim()).filter(Boolean);
  const chosen = [];
  const seen = new Set();
  for (const tok of raw) {
    const c = BY_TOKEN.get(tok.toLowerCase());
    if (!c) {
      throw new Error(`Unknown config "${tok}". Valid: ${CONFIGS.map((x) => `${x.id}/${x.name}`).join(", ")}, or "all".`);
    }
    if (!seen.has(c.id)) { seen.add(c.id); chosen.push(c); }
  }
  // Preserve canonical C1..C5 order regardless of input order.
  return CONFIGS.filter((c) => seen.has(c.id));
}

module.exports = { FROZEN, CONFIGS, resolveConfigs };
