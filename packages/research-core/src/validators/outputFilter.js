/**
 * Patterns that indicate sensitive data in command output.
 * Each entry has a regex and a replacement label.
 */
const SENSITIVE_PATTERNS = [
  // Password hashes (e.g., /etc/shadow format)
  { pattern: /\$\d\$[^\s:]+/g, label: '[REDACTED_HASH]' },
  // Private keys
  { pattern: /-----BEGIN\s[\w\s]*PRIVATE KEY-----[\s\S]*?-----END\s[\w\s]*PRIVATE KEY-----/g, label: '[REDACTED_PRIVATE_KEY]' },
  // API keys / tokens (generic long hex/alphanum strings that look like tokens)
  { pattern: /(?:api[_-]?key|token|secret|password|passwd)\s*[=:]\s*\S+/gi, label: '[REDACTED_CREDENTIAL]' },
  // Internal/private IP addresses (10.x, 172.16-31.x, 192.168.x)
  { pattern: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g, label: '[REDACTED_IP]' },
  // AWS access keys
  { pattern: /AKIA[0-9A-Z]{16}/g, label: '[REDACTED_AWS_KEY]' },
  // Generic secrets in environment variable format
  { pattern: /\b[A-Z_]+_SECRET\s*=\s*\S+/g, label: '[REDACTED_SECRET]' },
];

/**
 * Filter command output to redact sensitive information.
 * Returns the sanitized output string.
 */
function filterOutput(output) {
  if (!output || typeof output !== 'string') {
    return output || '';
  }

  let filtered = output;

  for (const { pattern, label } of SENSITIVE_PATTERNS) {
    // Reset regex lastIndex for global patterns
    pattern.lastIndex = 0;
    filtered = filtered.replace(pattern, label);
  }

  return filtered;
}

/**
 * Sanitize error messages to avoid leaking security mechanism details.
 */
function sanitizeError(error) {
  if (!error) return 'An error occurred while processing your request.';

  // Strip internal paths, stack traces, etc.
  const generic = 'An error occurred while processing your request.';

  // Only pass through safe error messages
  const safePatterns = [
    /no such file or directory/i,
    /permission denied/i,
    /not a directory/i,
    /invalid.*option/i,
    /invalid date/i,
  ];

  for (const pattern of safePatterns) {
    if (pattern.test(error)) {
      // Return a cleaned version without internal paths
      return error.replace(/\/[\w/.\-]+/g, (match) => {
        // Keep the requested path but strip system internals
        if (match.startsWith('/usr/') || match.startsWith('/bin/') || match.startsWith('/lib/')) {
          return '[system_path]';
        }
        return match;
      });
    }
  }

  return generic;
}

module.exports = { filterOutput, sanitizeError };
