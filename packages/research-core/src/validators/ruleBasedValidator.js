const config = require('../utils/config');

const ALLOWED_COMMANDS = config.command.allowedCommands; // ['ls', 'date']

// Sensitive directories that require blocking
const SENSITIVE_PATHS = [
  '/etc/shadow', '/etc/passwd', '/etc/sudoers',
  '/root', '/proc', '/sys', '/boot',
  '/var/log', '/dev',
];

// Command chaining operators
const CHAINING_PATTERNS = [
  /;/,
  /&&/,
  /\|\|/,
  /\|/,
  /`[^`]*`/,        // backtick command substitution
  /\$\([^)]*\)/,     // $() command substitution
  /\$\{[^}]*\}/,     // ${} variable expansion
  /\n/,              // newline injection
  /\r/,              // carriage return
];

// Shell metacharacters that indicate malicious intent in command context
const DANGEROUS_METACHAR_PATTERNS = [
  />/,   // output redirection
  /</,   // input redirection
  /!!/,  // history expansion
  /&#/,  // background + comment (combined evasion)
];

// Prompt injection patterns
const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /ignore\s+(all\s+)?prior\s+instructions/i,
  /disregard\s+(all\s+)?previous/i,
  /you\s+are\s+now\s+/i,
  /new\s+role\s*:/i,
  /system\s*:/i,
  /admin\s+mode/i,
  /override\s+security/i,
  /bypass\s+(the\s+)?filter/i,
  /reveal\s+(your\s+)?(system\s+)?prompt/i,
  /show\s+(me\s+)?(your\s+)?instructions/i,
  /what\s+are\s+your\s+(system\s+)?instructions/i,
  /pretend\s+(you\s+are|to\s+be)/i,
  /act\s+as\s+(if|a|an)/i,
  /roleplay\s+as/i,
  /in\s+theory\s+could\s+you/i,
  /what\s+would\s+you\s+do\s+if/i,
  /hypothetically/i,
  /jailbreak/i,
  /DAN\s+mode/i,
];

// Known Unix commands for detection
const KNOWN_COMMANDS = [
  'ls', 'date',
  'rm', 'mv', 'cp', 'cat', 'chmod', 'chown', 'kill', 'sudo', 'su',
  'wget', 'curl', 'nc', 'bash', 'sh', 'python', 'node', 'npm',
  'apt', 'yum', 'systemctl', 'service', 'mkdir', 'rmdir', 'touch',
  'find', 'grep', 'awk', 'sed', 'dd', 'mount', 'umount', 'ssh',
  'scp', 'rsync', 'ping', 'netstat', 'ifconfig', 'ip', 'iptables',
  'docker', 'kubectl',
];

/**
 * Extract command-like strings from natural language input.
 * Looks for backtick-wrapped commands and bare command patterns.
 */
function extractCommands(input) {
  const commands = [];

  // 1. Match backtick-wrapped commands: `ls -la`
  const backtickMatches = input.match(/`([^`]+)`/g);
  if (backtickMatches) {
    for (const m of backtickMatches) {
      commands.push(m.replace(/`/g, '').trim());
    }
  }

  // 2. Match "run/execute <known_command> ..." patterns
  const cmdListPattern = KNOWN_COMMANDS.join('|');
  const runRegex = new RegExp(
    `(?:run|execute)\\s+((?:${cmdListPattern})(?:\\s+[^,.!?]+)*)`,
    'gi'
  );
  const runMatches = input.match(runRegex);
  if (runMatches) {
    for (const m of runMatches) {
      const cmd = m.replace(/^(?:run|execute)\s+/i, '').trim();
      // Trim trailing natural language (stop at sentence boundaries)
      const cleaned = cmd.replace(/\s+(to|so|and|for|in order|because|since|please)\s+.*/i, '').trim();
      commands.push(cleaned);
    }
  }

  // 3. Match bare allowed commands with flags/paths only (not greedy into English)
  //    ls followed by flags (-x) and/or paths (/foo, ~, .)
  const lsMatches = input.match(/\bls(?:\s+(?:-[\w]+|[~/.][\w./\-~]*))+/g);
  if (lsMatches) {
    commands.push(...lsMatches.map((m) => m.trim()));
  }

  //    date followed by format strings (+%...) or flags (-u, -R, etc.)
  const dateMatches = input.match(/\bdate(?:\s+(?:-[\w]+|[+][%\w\-_:.]+))+/g);
  if (dateMatches) {
    commands.push(...dateMatches.map((m) => m.trim()));
  }

  // 4. Detect bare forbidden commands (just the command word, for flagging)
  const forbiddenPattern = KNOWN_COMMANDS.filter((c) => !ALLOWED_COMMANDS.includes(c)).join('|');
  const forbiddenRegex = new RegExp(`\\b(${forbiddenPattern})\\b`, 'g');
  const forbiddenMatches = input.match(forbiddenRegex);
  if (forbiddenMatches) {
    for (const m of forbiddenMatches) {
      // Only add if not already captured in a longer command
      if (!commands.some((c) => c.includes(m))) {
        commands.push(m.trim());
      }
    }
  }

  return [...new Set(commands)];
}

/**
 * Get the base command (first word) from a command string.
 */
function getBaseCommand(cmdStr) {
  return cmdStr.trim().split(/\s+/)[0];
}

/**
 * Detect encoded/obfuscated content.
 */
function detectEncoding(input) {
  const findings = [];

  // Base64 pattern (long strings of base64 chars)
  if (/[A-Za-z0-9+/]{20,}={0,2}/.test(input)) {
    try {
      const matches = input.match(/[A-Za-z0-9+/]{20,}={0,2}/g);
      for (const m of matches) {
        const decoded = Buffer.from(m, 'base64').toString('utf-8');
        if (/^[\x20-\x7e\s]+$/.test(decoded) && decoded.length > 4) {
          findings.push({ type: 'base64', encoded: m, decoded });
        }
      }
    } catch { /* not valid base64 */ }
  }

  // Hex escape sequences
  if (/\\x[0-9a-fA-F]{2}/.test(input)) {
    findings.push({ type: 'hex_escape', evidence: input.match(/\\x[0-9a-fA-F]{2}/g) });
  }

  // Unicode escape sequences
  if (/\\u[0-9a-fA-F]{4}/.test(input)) {
    findings.push({ type: 'unicode_escape', evidence: input.match(/\\u[0-9a-fA-F]{4}/g) });
  }

  // URL encoding
  if (/%[0-9a-fA-F]{2}/.test(input)) {
    try {
      const decoded = decodeURIComponent(input);
      if (decoded !== input) {
        findings.push({ type: 'url_encoding', decoded });
      }
    } catch { /* invalid encoding */ }
  }

  return findings;
}

/**
 * Validate user input against all rule-based security policies.
 * Returns { safe: bool, violations: [{ type, detail, evidence }], extractedCommands: string[] }
 */
function validate(input) {
  const violations = [];
  const extractedCommands = extractCommands(input);

  // 1. Check for prompt injection patterns
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(input)) {
      violations.push({
        type: 'prompt_injection',
        detail: 'Prompt injection pattern detected',
        evidence: input.match(pattern)?.[0],
      });
    }
  }

  // 2. Check for command chaining in the raw input
  for (const pattern of CHAINING_PATTERNS) {
    // Skip pipe and semicolon check for natural language (only flag inside commands)
    if (pattern.source === ';' || pattern.source === '\\|\\|' || pattern.source === '\\|' || pattern.source === '&&') {
      // Check within extracted commands only
      for (const cmd of extractedCommands) {
        if (pattern.test(cmd)) {
          violations.push({
            type: 'command_injection',
            detail: `Command chaining operator detected in command: ${pattern.source}`,
            evidence: cmd,
          });
        }
      }
    } else if (pattern.test(input)) {
      // Backticks, $(), ${}, newlines — check full input
      // Backticks inside backtick-quoted commands are expected, skip
      if (pattern.source === '`[^`]*`') continue;
      violations.push({
        type: 'command_injection',
        detail: `Dangerous pattern detected: ${pattern.source}`,
        evidence: input.match(pattern)?.[0],
      });
    }
  }

  // 3. Check for dangerous metacharacters within extracted commands
  for (const cmd of extractedCommands) {
    for (const pattern of DANGEROUS_METACHAR_PATTERNS) {
      if (pattern.test(cmd)) {
        violations.push({
          type: 'command_injection',
          detail: 'Dangerous shell metacharacter in command',
          evidence: `${cmd} matched ${pattern.source}`,
        });
      }
    }
  }

  // 4. Whitelist validation — check extracted base commands
  const forbiddenCommands = [];
  for (const cmd of extractedCommands) {
    const base = getBaseCommand(cmd);
    if (!ALLOWED_COMMANDS.includes(base)) {
      forbiddenCommands.push(base);
    }
  }

  if (forbiddenCommands.length > 0) {
    violations.push({
      type: 'forbidden_command',
      detail: `Forbidden command(s) detected: ${[...new Set(forbiddenCommands)].join(', ')}`,
      evidence: forbiddenCommands.join(', '),
    });
  }

  // 5. Path traversal and sensitive path checks
  for (const cmd of extractedCommands) {
    // Path traversal
    if (/\.\.\//.test(cmd)) {
      violations.push({
        type: 'path_traversal',
        detail: 'Path traversal pattern detected',
        evidence: cmd,
      });
    }

    // Sensitive directories
    for (const sensitivePath of SENSITIVE_PATHS) {
      if (cmd.includes(sensitivePath)) {
        violations.push({
          type: 'path_traversal',
          detail: `Access to sensitive path: ${sensitivePath}`,
          evidence: cmd,
        });
      }
    }
  }

  // Also check raw input for sensitive paths mentioned outside commands
  for (const sensitivePath of SENSITIVE_PATHS) {
    if (input.includes(sensitivePath) && !violations.some(v => v.type === 'path_traversal' && v.evidence?.includes(sensitivePath))) {
      violations.push({
        type: 'path_traversal',
        detail: `Sensitive path referenced in input: ${sensitivePath}`,
        evidence: sensitivePath,
      });
    }
  }

  // 6. Encoding/obfuscation detection
  const encodings = detectEncoding(input);
  for (const enc of encodings) {
    violations.push({
      type: 'obfuscation',
      detail: `Encoded content detected (${enc.type})`,
      evidence: enc.decoded || JSON.stringify(enc.evidence),
    });
  }

  return {
    safe: violations.length === 0,
    violations,
    extractedCommands,
  };
}

module.exports = { validate, extractCommands, getBaseCommand, detectEncoding };
