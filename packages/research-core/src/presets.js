/**
 * C1–C5 ablation presets — the single source of truth for the research
 * experimental configurations. Semantics are FROZEN (see
 * docs/RESEARCH_REPRODUCIBILITY.md §1). Consumed by the REPL, the evaluation
 * scripts, and (read-only, RESEARCHER-gated) the production API, so that no
 * consumer can silently redefine an experiment.
 */
const PRESETS = {
  c1: { useRules: true,  useSemantic: false, useRateLimit: false, useMemory: false, useRAG: false },
  c2: { useRules: false, useSemantic: true,  useRateLimit: false, useMemory: false, useRAG: false },
  c3: { useRules: true,  useSemantic: true,  useRateLimit: false, useMemory: false, useRAG: false },
  c4: { useRules: true,  useSemantic: true,  useRateLimit: true,  useMemory: true,  useRAG: false },
  c5: { useRules: true,  useSemantic: true,  useRateLimit: true,  useMemory: true,  useRAG: true  },
};

module.exports = { PRESETS };
