/**
 * runModelComparison.js — Model-Size Comparison Runner
 *
 * Runs the full pipeline (C5 configuration) once per model to measure
 * accuracy vs. latency tradeoffs across different LLM sizes/families.
 *
 * Usage:
 *   npm run eval:models                         (Llama default)
 *   node scripts/runModelComparison.js \
 *     --output data/result2 \
 *     --models qwen3.5:2b,qwen3.5:4b,qwen3.5:9b
 *
 * Options:
 *   --output <dir>     Output directory (default: data/results)
 *   --models <list>    Comma-separated Ollama model tags
 *                      (default: llama3.2:1b,llama3.2:3b,llama3.1:8b)
 *
 * Output: <outputDir>/model-comparison-raw.json
 *
 * Prerequisites:
 *   - data/evaluation-dataset.json (run npm run dataset:build first)
 *   - Ollama running locally with all specified models pulled
 *   - ChromaDB running and seeded (npm run seed)
 */

const path = require('path');
const fs = require('fs');
const policemanAgent = require('../packages/research-core/src/agents/policemanAgent');

// ─── CLI arg parsing ──────────────────────────────────────────────────────────

const args = process.argv.slice(2);
function getArg(name, defaultValue) {
  const idx = args.indexOf(name);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : defaultValue;
}

const outputRelDir = getArg('--output', 'data/results');
const modelsArg    = getArg('--models', null);

const DATASET_PATH = path.join(__dirname, '..', 'data', 'evaluation-dataset.json');
const OUTPUT_DIR   = path.resolve(path.join(__dirname, '..', outputRelDir));
const OUTPUT_PATH  = path.join(OUTPUT_DIR, 'model-comparison-raw.json');

// Full pipeline options — only the ollamaModel changes between runs
const FULL_PIPELINE_OPTIONS = {
  useRules: true,
  useSemantic: true,
  useRateLimit: true,
  useMemory: true,
  useRAG: true,
};

const MODELS = modelsArg
  ? modelsArg.split(',').map((m) => m.trim()).filter(Boolean)
  : ['llama3.2:1b', 'llama3.2:3b', 'llama3.1:8b'];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function classifyResult(pipelineResult) {
  return pipelineResult.status === 'VIOLATION' ? 'UNSAFE' : 'SAFE';
}

function isStatefulEntry(entry) {
  return entry.category === 'rate_limit_evasion' || entry.category === 'multi_turn_escalation';
}

function groupBySequence(entries) {
  const groups = new Map();
  for (const entry of entries) {
    const key = entry.metadata.testName || entry.metadata.sequenceName || entry.id;
    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key).push(entry);
  }
  return groups;
}

// ─── Main Runner ─────────────────────────────────────────────────────────────

async function runModelComparison() {
  if (!fs.existsSync(DATASET_PATH)) {
    console.error(`Dataset not found at ${DATASET_PATH}. Run "npm run dataset:build" first.`);
    process.exit(1);
  }
  const dataset = JSON.parse(fs.readFileSync(DATASET_PATH, 'utf-8'));

  const independentEntries = dataset.filter((e) => !isStatefulEntry(e));
  const statefulEntries = dataset.filter((e) => isStatefulEntry(e));

  const allResults = [];
  const totalWork = dataset.length * MODELS.length;

  const FAST_MODE = process.argv.includes('--fast');

  console.log('\n  Model-Size Comparison Runner');
  if (FAST_MODE) console.log('  [FAST MODE] Using reduced dataset');
  console.log('  ─────────────────────────────────────');
  console.log(`  Dataset: ${dataset.length} entries`);
  console.log(`  Models: ${MODELS.join(', ')}`);
  console.log(`  Total evaluations: ${totalWork}\n`);

  for (const model of MODELS) {
    const modelStart = Date.now();
    console.log(`  [${model}] Starting...`);

    const options = { ...FULL_PIPELINE_OPTIONS, ollamaModel: model };

    // --- Independent entries ---
    for (const entry of independentEntries) {
      policemanAgent.resetRateLimiter();

      const start = Date.now();
      const result = await policemanAgent.processInput(entry.input, options);
      const latencyMs = Date.now() - start;

      allResults.push({
        id: entry.id,
        model,
        input: entry.input,
        category: entry.category,
        subcategory: entry.subcategory,
        predictedLabel: classifyResult(result),
        actualLabel: entry.expectedLabel,
        latencyMs,
        violationType: result.violationType,
        confidence: result.confidence,
      });
    }

    // --- Stateful: rate-limit sequences ---
    const rlGroups = groupBySequence(statefulEntries.filter((e) => e.category === 'rate_limit_evasion'));
    for (const [, seqEntries] of rlGroups) {
      policemanAgent.resetRateLimiter();
      for (const entry of seqEntries) {
        const start = Date.now();
        const result = await policemanAgent.processInput(entry.input, options);
        const latencyMs = Date.now() - start;

        allResults.push({
          id: entry.id,
          model,
          input: entry.input,
          category: entry.category,
          subcategory: entry.subcategory,
          predictedLabel: classifyResult(result),
          actualLabel: entry.expectedLabel,
          latencyMs,
          violationType: result.violationType,
          confidence: result.confidence,
        });
      }
    }

    // --- Stateful: multi-turn sequences ---
    const mtGroups = groupBySequence(statefulEntries.filter((e) => e.category === 'multi_turn_escalation'));
    for (const [, seqEntries] of mtGroups) {
      policemanAgent.resetRateLimiter();
      for (const entry of seqEntries) {
        const start = Date.now();
        const result = await policemanAgent.processInput(entry.input, options);
        const latencyMs = Date.now() - start;

        allResults.push({
          id: entry.id,
          model,
          input: entry.input,
          category: entry.category,
          subcategory: entry.subcategory,
          predictedLabel: classifyResult(result),
          actualLabel: entry.expectedLabel,
          latencyMs,
          violationType: result.violationType,
          confidence: result.confidence,
        });
      }
    }

    const modelDuration = ((Date.now() - modelStart) / 1000).toFixed(1);
    console.log(`  [${model}] Done in ${modelDuration}s`);
  }

  // Write results
  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  }
  fs.writeFileSync(OUTPUT_PATH, JSON.stringify(allResults, null, 2));

  // Summary
  console.log(`\n  Results written to ${path.relative(process.cwd(), OUTPUT_PATH)}`);
  console.log(`  Total entries: ${allResults.length}`);

  for (const model of MODELS) {
    const modelResults = allResults.filter((r) => r.model === model);
    const correct = modelResults.filter((r) => r.predictedLabel === r.actualLabel).length;
    const accuracy = ((correct / modelResults.length) * 100).toFixed(1);
    const avgLatency = (modelResults.reduce((s, r) => s + r.latencyMs, 0) / modelResults.length).toFixed(0);
    console.log(`  [${model}] Accuracy: ${accuracy}% | Avg latency: ${avgLatency}ms`);
  }
  console.log('');
}

runModelComparison().catch((err) => {
  console.error('Model comparison runner failed:', err);
  process.exit(1);
});
