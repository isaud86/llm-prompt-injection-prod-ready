#!/usr/bin/env node

/**
 * hackerCli.js — CLI Entry Point for the Hacker Agent
 *
 * This is the command-line interface for running automated red team security tests.
 * It parses arguments from process.argv (no external arg-parsing dependencies)
 * and instantiates a HackerAgent with the appropriate configuration.
 *
 * Usage:
 *   npm run hack                                    — run all 8 attack categories
 *   npm run hack -- --category prompt_injection     — run a single category
 *   npm run hack -- --static-only                   — skip LLM-generated attacks
 *   npm run hack -- --dynamic-count 10              — more LLM attacks per category
 *   npm run hack -- --quiet                         — print summary only (no per-attack output)
 *   npm run hack -- --delay 200                     — slower attack cadence (ms between attacks)
 *
 * The double-dash (--) after `npm run hack` is required by npm to pass args
 * through to the script rather than interpreting them as npm flags.
 *
 * @see src/agents/hackerAgent.js — the HackerAgent class with all attack logic
 */

const HackerAgent = require('./agents/hackerAgent');

// ─── Arg Parsing ────────────────────────────────────────────────────────

/**
 * Parse CLI arguments from process.argv into an options object.
 * Uses a simple switch-based parser — no external dependencies needed.
 * @param {string[]} argv — process.argv (first 2 entries are node path and script path)
 */
function parseArgs(argv) {
  const args = argv.slice(2);
  const options = {
    categories: null,
    staticOnly: false,
    dynamicCount: 5,
    verbose: true,
    delayMs: 100,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--category':
      case '-c':
        if (args[i + 1]) {
          options.categories = [args[++i]];
        }
        break;
      case '--static-only':
        options.staticOnly = true;
        break;
      case '--dynamic-count':
        if (args[i + 1]) {
          options.dynamicCount = parseInt(args[++i], 10) || 5;
        }
        break;
      case '--quiet':
      case '-q':
        options.verbose = false;
        break;
      case '--delay':
        if (args[i + 1]) {
          options.delayMs = parseInt(args[++i], 10) || 100;
        }
        break;
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
        break;
      default:
        console.error(`Unknown argument: ${args[i]}`);
        printHelp();
        process.exit(1);
    }
  }

  return options;
}

function printHelp() {
  console.log(`
Usage: npm run hack [-- options]

Options:
  --category, -c <name>    Run a single category
                           Categories: prompt_injection, command_injection,
                           path_traversal, encoding_obfuscation, rate_limit_evasion,
                           semantic_manipulation, multi_turn_escalation, output_probing
  --static-only            Skip LLM-generated dynamic attacks
  --dynamic-count <n>      Number of LLM attacks per category (default: 5)
  --quiet, -q              Summary only (suppress per-attack output)
  --delay <ms>             Delay between attacks in ms (default: 100)
  --help, -h               Show this help message

Examples:
  npm run hack                                     Run all categories
  npm run hack -- --category prompt_injection      Run one category
  npm run hack -- --static-only                    No LLM-generated attacks
  npm run hack -- --dynamic-count 10 --quiet       More LLM attacks, summary only
`);
}

// ─── Main ───────────────────────────────────────────────────────────────

/**
 * Create a HackerAgent with parsed CLI options and run all selected categories.
 * The agent handles everything: attack execution, LLM generation, and reporting.
 */
async function main() {
  const options = parseArgs(process.argv);

  const agentOpts = {
    staticOnly: options.staticOnly,
    dynamicCount: options.dynamicCount,
    verbose: options.verbose,
    delayMs: options.delayMs,
  };

  if (options.categories) {
    agentOpts.categories = options.categories;
  }

  const agent = new HackerAgent(agentOpts);
  await agent.runAll();
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
