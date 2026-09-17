const ruleBasedValidator = require('../validators/ruleBasedValidator');
const semanticValidator = require('../validators/semanticValidator');
const outputFilter = require('../validators/outputFilter');
const chatbotAgent = require('./chatbotAgent');
const RateLimiter = require('../middleware/rateLimiter');
const { logSecurity } = require('../utils/logger');
const config = require('../utils/config');
const sessionMemory = require('../memory/sessionMemory');
const longTermMemory = require('../memory/longTermMemory');

// Per-context rate limiters (brief §8/§17: isolate rate budgets per user).
// A context id is intended to be `${userId}:${conversationId}`. When none is
// supplied (research CLI, evaluation scripts, existing tests), a single default
// context is used, preserving the original single-user behavior. NOTE: this
// in-process map is correct for a single node; the production API replaces it
// with a distributed Redis limiter (see docs/IMPLEMENTATION_PLAN.md Phase 4).
const DEFAULT_CONTEXT = sessionMemory.DEFAULT_CONTEXT;
const rateLimiters = new Map();

function getRateLimiter(contextId) {
  const key = contextId || DEFAULT_CONTEXT;
  let limiter = rateLimiters.get(key);
  if (!limiter) {
    limiter = new RateLimiter();
    rateLimiters.set(key, limiter);
  }
  return limiter;
}

/**
 * Determine the primary violation type from a list of violations.
 */
function getPrimaryViolationType(violations) {
  const typeOrder = ['prompt_injection', 'command_injection', 'forbidden_command', 'path_traversal', 'obfuscation'];
  for (const type of typeOrder) {
    if (violations.some((v) => v.type === type)) {
      return type;
    }
  }
  return violations[0]?.type || 'other';
}

/**
 * Map violation type to OWASP LLM threat category.
 */
function mapToOwaspCategory(violationType, threats) {
  // Check semantic threats first
  if (threats?.length > 0) {
    return threats[0].category;
  }

  const mapping = {
    prompt_injection: 'LLM01: Prompt Injection',
    command_injection: 'LLM07: Insecure Plugin Design',
    forbidden_command: 'LLM08: Excessive Agency',
    path_traversal: 'LLM06: Sensitive Information Disclosure',
    obfuscation: 'LLM01: Prompt Injection',
    social_engineering: 'LLM01: Prompt Injection',
    rate_limit: 'LLM04: Model Denial of Service',
  };

  return mapping[violationType] || 'none';
}

/**
 * Build a user-facing warning message without revealing security details.
 */
function buildWarningMessage(violationType) {
  const messages = {
    prompt_injection: 'Your request could not be processed. Please rephrase your request.',
    command_injection: 'Your request contains unsupported syntax. Please use simple ls or date commands.',
    forbidden_command: 'Only ls and date commands are supported. Please modify your request.',
    path_traversal: 'Access to the requested location is not permitted.',
    obfuscation: 'Your request could not be processed. Please use plain text commands.',
    social_engineering: 'Your request could not be processed. Please rephrase your request.',
    rate_limit: 'Too many requests. Please wait a moment before trying again.',
  };

  return messages[violationType] || 'Your request was blocked for security reasons.';
}

/**
 * Main validation pipeline.
 * Flow: Rate Limit → Rule-based → Semantic → Chatbot → Output Filter → Log
 *
 * Returns:
 * {
 *   status: 'SAFE' | 'VIOLATION',
 *   violationType: string,
 *   threatCategory: string,
 *   confidence: string,
 *   reasoning: string,
 *   output: string | null,
 *   warningMessage: string | null,
 *   logEntry: object
 * }
 */
async function processInput(input, options = {}) {
  const {
    useRules = true,
    useSemantic = true,
    useRateLimit = true,
    useMemory = true,
    useRAG = true,
    ollamaModel = null,
    contextId = null,
  } = options;

  // --- Step 1: Rate limit check ---
  if (useRateLimit) {
    const rateCheck = getRateLimiter(contextId).check(input);
    if (!rateCheck.allowed) {
      const result = {
        status: 'VIOLATION',
        violationType: 'rate_limit',
        threatCategory: 'LLM04: Model Denial of Service',
        confidence: 'high',
        reasoning: rateCheck.reason,
        output: null,
        warningMessage: buildWarningMessage('rate_limit'),
      };
      result.logEntry = logSecurity({
        input,
        status: 'VIOLATION',
        violationType: 'rate_limit',
        threatCategory: result.threatCategory,
        confidence: 'high',
        reasoning: rateCheck.reason,
        action: 'BLOCKED',
      });
      return result;
    }
  }

  // --- Step 1b: Session memory — escalation check + context ---
  let contextBlock = null;
  if (useMemory) {
    sessionMemory.detectEscalation(contextId);
    contextBlock = sessionMemory.formatContextBlock(contextId);
  }

  // --- Step 2: Rule-based validation ---
  const ruleResult = useRules
    ? ruleBasedValidator.validate(input)
    : { safe: true, violations: [], extractedCommands: ruleBasedValidator.extractCommands(input) };

  // --- Step 3: Semantic validation (Ollama) with session context ---
  let semanticResult;
  if (useSemantic) {
    semanticResult = await semanticValidator.analyze(input, contextBlock, { model: ollamaModel, useRAG });
  } else {
    semanticResult = { safe: true, threats: [], fallback: true };
  }

  // --- Step 4: Combine results (hybrid approach) ---
  const allViolations = [...ruleResult.violations];
  const semanticThreats = semanticResult.threats || [];

  if (!semanticResult.safe && semanticThreats.length > 0) {
    for (const threat of semanticThreats) {
      allViolations.push({
        type: threat.category?.includes('injection') ? 'prompt_injection' : 'social_engineering',
        detail: threat.reasoning,
        evidence: `Semantic analysis (confidence: ${threat.confidence})`,
      });
    }
  }

  const noCommandsExtracted = ruleResult.extractedCommands.length === 0;
  const semanticBlock = !semanticResult.safe && !semanticResult.fallback && noCommandsExtracted;
  const isSafe = ruleResult.safe && !semanticBlock;

  // --- If violations detected, BLOCK ---
  if (!isSafe && allViolations.length > 0) {
    const primaryType = getPrimaryViolationType(allViolations);
    const confidence = semanticThreats.length > 0 ? semanticThreats[0].confidence : 'high';
    const reasoning = allViolations.map((v) => `[${v.type}] ${v.detail}`).join('; ');

    const result = {
      status: 'VIOLATION',
      violationType: primaryType,
      threatCategory: mapToOwaspCategory(primaryType, semanticThreats),
      confidence,
      reasoning,
      output: null,
      warningMessage: buildWarningMessage(primaryType),
    };

    result.logEntry = logSecurity({
      input,
      status: 'VIOLATION',
      violationType: primaryType,
      threatCategory: result.threatCategory,
      confidence,
      reasoning,
      action: 'BLOCKED',
    });

    if (useMemory) {
      sessionMemory.record(input, 'VIOLATION', primaryType, contextId);
      await longTermMemory.storeBlockedPattern(input, primaryType, confidence);
    }

    return result;
  }

  // --- Step 5: Extract and execute commands ---
  const commands = ruleResult.extractedCommands;
  if (commands.length === 0) {
    // Try to generate a conversational response
    const chatResult = await chatbotAgent.chat(input, contextBlock);

    const conversationalResponse = (!chatResult.fallback && chatResult.response)
      ? outputFilter.filterOutput(chatResult.response)
      : null;

    const result = {
      status: 'SAFE',
      violationType: 'none',
      threatCategory: 'none',
      confidence: 'medium',
      reasoning: 'No executable commands detected; conversational response generated.',
      output: null,
      conversationalResponse,
      warningMessage: conversationalResponse
        ? null
        : 'No command detected. Please specify an ls or date command.',
    };

    result.logEntry = logSecurity({
      input,
      status: 'SAFE',
      violationType: 'none',
      reasoning: 'No commands extracted',
      action: 'NO_COMMAND',
    });

    if (useMemory) {
      sessionMemory.record(input, 'SAFE', 'none', contextId);
    }

    return result;
  }

  // Execute all extracted (safe) commands
  const outputs = [];
  for (const cmd of commands) {
    const base = ruleBasedValidator.getBaseCommand(cmd);
    if (config.command.allowedCommands.includes(base)) {
      const execResult = await chatbotAgent.execute(cmd);
      if (execResult.success) {
        outputs.push(`$ ${cmd}\n${execResult.output}`);
      } else {
        outputs.push(`$ ${cmd}\n[Error] ${outputFilter.sanitizeError(execResult.error)}`);
      }
    }
  }

  // --- Step 6: Filter output ---
  const rawOutput = outputs.join('\n');
  const filteredOutput = outputFilter.filterOutput(rawOutput);

  const result = {
    status: 'SAFE',
    violationType: 'none',
    threatCategory: 'none',
    confidence: 'high',
    reasoning: `Approved commands: ${commands.join(', ')}` +
      (semanticResult.fallback ? ' [Note: Semantic analysis unavailable, rule-based only]' : ''),
    output: filteredOutput,
    warningMessage: null,
  };

  result.logEntry = logSecurity({
    input,
    status: 'SAFE',
    violationType: 'none',
    reasoning: result.reasoning,
    action: 'APPROVED',
  });

  if (useMemory) {
    sessionMemory.record(input, 'SAFE', 'none', contextId);
  }

  return result;
}

/**
 * Reset all rate limiters and session memory (for tests / process reset).
 * Clears every context so test isolation matches prior behavior.
 */
function resetRateLimiter() {
  rateLimiters.clear();
  sessionMemory.reset();
}

module.exports = { processInput, resetRateLimiter };
