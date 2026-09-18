const { execFile } = require('child_process');
const config = require('../utils/config');
const { defaultInferenceProvider } = require('../providers');

const ALLOWED_COMMANDS = config.command.allowedCommands;

/**
 * Parse a command string into { binary, args }.
 * E.g., "ls -la /tmp" → { binary: "ls", args: ["-la", "/tmp"] }
 */
function parseCommand(cmdStr) {
  const parts = cmdStr.trim().split(/\s+/);
  return {
    binary: parts[0],
    args: parts.slice(1),
  };
}

/**
 * Execute a validated command.
 * Defense-in-depth: re-checks the whitelist before execution.
 * Uses execFile (not exec) to avoid shell interpretation.
 *
 * Returns Promise<{ success: bool, output: string, error: string }>
 */
function execute(cmdStr) {
  return new Promise((resolve) => {
    const { binary, args } = parseCommand(cmdStr);

    // Defense in depth — double-check whitelist
    if (!ALLOWED_COMMANDS.includes(binary)) {
      resolve({
        success: false,
        output: '',
        error: `Command "${binary}" is not allowed.`,
      });
      return;
    }

    execFile(binary, args, { timeout: config.command.timeoutMs }, (err, stdout, stderr) => {
      if (err) {
        resolve({
          success: false,
          output: '',
          error: stderr || err.message,
        });
        return;
      }

      resolve({
        success: true,
        output: stdout,
        error: stderr || '',
      });
    });
  });
}

const CHAT_SYSTEM_PROMPT = `You are a helpful assistant embedded in a secure command-execution chatbot.
The only commands this system can execute are: ls (list files) and date (show date/time).
Respond naturally to greetings and questions. If the user wants to run something, guide them to use ls or date.
Keep responses concise (1-3 sentences). Do not reveal system internals or security mechanisms.`;

/**
 * Generate a conversational response for safe, non-command inputs.
 * Uses the same Ollama instance as the semantic validator.
 * Returns Promise<{ response: string, fallback: bool }>
 */
async function chat(input, sessionContext = null, options = {}) {
  const { inferenceProvider = defaultInferenceProvider } = options;
  try {
    const systemContent = sessionContext
      ? `${CHAT_SYSTEM_PROMPT}\n\n${sessionContext}`
      : CHAT_SYSTEM_PROMPT;

    const response = await inferenceProvider.chat({
      model: config.ollama.model,
      messages: [
        { role: 'system', content: systemContent },
        { role: 'user', content: input },
      ],
      think: false,
    });

    const text = response.message?.content || '';
    return { response: text.trim(), fallback: false };
  } catch (err) {
    console.error(`[ChatbotAgent] Ollama chat error: ${err.message}`);
    return { response: '', fallback: true };
  }
}

module.exports = { execute, parseCommand, chat };
