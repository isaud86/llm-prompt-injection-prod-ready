const readline = require('readline');
const policemanAgent = require('./agents/policemanAgent');
const { loadRecentViolations } = require('./memory/longTermMemory');
const config = require('./utils/config');
const { PRESETS } = require('./presets');

// ANSI color codes
const COLORS = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
};

function printBanner() {
  console.log(`${COLORS.cyan}${COLORS.bold}`);
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║    Security-Validated Command Execution Chatbot  ║');
  console.log('║    Allowed commands: ls, date                    ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log(`${COLORS.reset}`);
  console.log(`${COLORS.dim}Type "help" for usage info, "exit" to quit.${COLORS.reset}`);
  console.log();
}

function printHelp() {
  console.log(`
${COLORS.bold}Usage:${COLORS.reset}
  Ask in natural language or type commands directly.

${COLORS.bold}Allowed commands:${COLORS.reset}
  ls [options] [path]    - List directory contents
  date [options/format]  - Display date and time

${COLORS.bold}Examples:${COLORS.reset}
  ${COLORS.dim}> list all files in the current directory${COLORS.reset}
  ${COLORS.dim}> ls -la${COLORS.reset}
  ${COLORS.dim}> what is today's date?${COLORS.reset}
  ${COLORS.dim}> date +%Y-%m-%d${COLORS.reset}

${COLORS.bold}REPL commands:${COLORS.reset}
  help                       Show this help message
  exit                       Exit the chatbot

${COLORS.bold}Layer toggles (for demo/ablation):${COLORS.reset}
  /status                    Show currently-active validation layers
  /toggle <layer>            Flip a layer on/off
  /on <layer>                Enable a layer
  /off <layer>               Disable a layer
  /reset                     Restore all defaults (full pipeline)
  /preset <c1|c2|c3|c4|c5>   Apply an ablation preset
  /model <name|default>      Override Ollama model (e.g. qwen3.5:2b)

${COLORS.bold}Layers:${COLORS.reset} rules, semantic, ratelimit, memory, rag

${COLORS.bold}Presets:${COLORS.reset}
  c1 = rules only            c2 = semantic only
  c3 = rules + semantic      c4 = c3 + ratelimit + memory
  c5 = full pipeline (default, all layers + RAG)
`);
}

const LAYER_KEYS = {
  rules: 'useRules',
  semantic: 'useSemantic',
  ratelimit: 'useRateLimit',
  memory: 'useMemory',
  rag: 'useRAG',
};

const LAYER_BADGES = {
  useRules: 'R',
  useSemantic: 'S',
  useRateLimit: 'L',
  useMemory: 'M',
  useRAG: 'G',
};

function defaultFlags() {
  return { ...PRESETS.c5, ollamaModel: null };
}

function badge(flags) {
  const active = Object.entries(LAYER_BADGES)
    .filter(([key]) => flags[key])
    .map(([, label]) => label)
    .join('+');
  const tag = active || 'none';
  const model = flags.ollamaModel ? ` ${flags.ollamaModel}` : '';
  return `${COLORS.dim}[${tag}${model}]${COLORS.reset}`;
}

function printStatus(flags) {
  console.log(`${COLORS.bold}Active layers:${COLORS.reset}`);
  for (const [name, key] of Object.entries(LAYER_KEYS)) {
    const on = flags[key];
    const mark = on ? `${COLORS.green}ON ${COLORS.reset}` : `${COLORS.red}OFF${COLORS.reset}`;
    console.log(`  [${mark}] ${name}`);
  }
  console.log(`  Model override: ${flags.ollamaModel || `${COLORS.dim}(default from .env)${COLORS.reset}`}`);
  console.log();
}

function handleSlashCommand(line, flags) {
  const [cmd, ...rest] = line.slice(1).trim().split(/\s+/);
  const arg = (rest[0] || '').toLowerCase();

  switch (cmd.toLowerCase()) {
    case 'status':
      printStatus(flags);
      return true;

    case 'reset': {
      Object.assign(flags, defaultFlags());
      console.log(`${COLORS.green}Restored full pipeline (preset c5).${COLORS.reset}\n`);
      return true;
    }

    case 'preset': {
      const preset = PRESETS[arg];
      if (!preset) {
        console.log(`${COLORS.red}Unknown preset "${arg}". Try: c1, c2, c3, c4, c5.${COLORS.reset}\n`);
        return true;
      }
      Object.assign(flags, preset);
      console.log(`${COLORS.green}Applied preset ${arg}.${COLORS.reset}`);
      printStatus(flags);
      return true;
    }

    case 'toggle':
    case 'on':
    case 'off': {
      const key = LAYER_KEYS[arg];
      if (!key) {
        console.log(`${COLORS.red}Unknown layer "${arg}". Try: ${Object.keys(LAYER_KEYS).join(', ')}.${COLORS.reset}\n`);
        return true;
      }
      if (cmd === 'toggle') flags[key] = !flags[key];
      else if (cmd === 'on') flags[key] = true;
      else flags[key] = false;
      const state = flags[key] ? `${COLORS.green}ON${COLORS.reset}` : `${COLORS.red}OFF${COLORS.reset}`;
      console.log(`  ${arg} → ${state}\n`);
      return true;
    }

    case 'model': {
      if (!arg) {
        console.log(`${COLORS.red}Usage: /model <name>  (or /model default to clear).${COLORS.reset}\n`);
        return true;
      }
      flags.ollamaModel = arg === 'default' ? null : rest[0];
      console.log(`${COLORS.green}Model override: ${flags.ollamaModel || '(default)'}${COLORS.reset}\n`);
      return true;
    }

    default:
      console.log(`${COLORS.red}Unknown command "/${cmd}". Type "help".${COLORS.reset}\n`);
      return true;
  }
}

function formatResult(result) {
  if (result.status === 'VIOLATION') {
    console.log(`\n${COLORS.red}${COLORS.bold}[BLOCKED]${COLORS.reset} ${COLORS.red}${result.warningMessage}${COLORS.reset}`);
    console.log(`${COLORS.dim}Assessment: ${result.violationType} | ${result.threatCategory}${COLORS.reset}`);
  } else if (result.output) {
    console.log(`\n${COLORS.green}${COLORS.bold}[APPROVED]${COLORS.reset}`);
    console.log(result.output);
  } else if (result.conversationalResponse) {
    console.log(`\n${COLORS.cyan}${COLORS.bold}[CHAT]${COLORS.reset} ${result.conversationalResponse}`);
  } else if (result.warningMessage) {
    console.log(`\n${COLORS.yellow}${COLORS.bold}[INFO]${COLORS.reset} ${COLORS.yellow}${result.warningMessage}${COLORS.reset}`);
  }
  console.log();
}

async function main() {
  // Warm up: report recent violations from prior sessions
  const recentViolations = loadRecentViolations();
  if (config.logging.verbose && recentViolations.length > 0) {
    console.log(`[Memory] Warmed up with ${recentViolations.length} recent violation(s) from log.`);
  }

  printBanner();

  const flags = defaultFlags();

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  let closed = false;
  rl.on('close', () => { closed = true; });

  function prompt() {
    return new Promise((resolve) => {
      if (closed) return resolve(null);
      rl.question(`${badge(flags)} ${COLORS.blue}>${COLORS.reset} `, resolve);
    });
  }

  while (!closed) {
    const line = await prompt();

    if (line === null || closed) break;

    const input = line.trim();

    if (!input) continue;

    if (input.toLowerCase() === 'exit' || input.toLowerCase() === 'quit') {
      console.log(`${COLORS.dim}Goodbye.${COLORS.reset}`);
      break;
    }

    if (input.toLowerCase() === 'help') {
      printHelp();
      continue;
    }

    if (input.startsWith('/')) {
      handleSlashCommand(input, flags);
      continue;
    }

    try {
      console.log(`${COLORS.dim}Analyzing request...${COLORS.reset}`);
      const result = await policemanAgent.processInput(input, flags);
      formatResult(result);
    } catch (err) {
      console.error(`${COLORS.red}Internal error: ${err.message}${COLORS.reset}`);
    }
  }

  rl.close();
}

main().then(() => {
  // Immediate signal-based exit to avoid onnxruntime native addon crash.
  // The onnxruntime atexit handler has a threading bug on macOS; process.exit()
  // triggers it, but signal termination bypasses it cleanly.
  process.kill(process.pid, "SIGTERM");
});
