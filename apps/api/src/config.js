/**
 * API-level configuration (apps/api). Intentionally decoupled from research-core:
 * the model name and providers are reached via services/pipeline.js, so this
 * module has no research-core dependency and no load-order coupling.
 */
const env = process.env.NODE_ENV || "development";

module.exports = {
  env,
  isProd: env === "production",
  port: parseInt(process.env.API_PORT, 10) || 3001,
  // Strict CORS allowlist (comma-separated). Empty => only same-origin /
  // server-to-server (no Origin header) is allowed; all cross-origin is rejected.
  corsOrigins: (process.env.API_CORS_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
  // Request body size cap (mitigates oversized-payload abuse).
  bodyLimit: process.env.API_BODY_LIMIT || "32kb",
  // End-to-end inference timeout budget.
  requestTimeoutMs: parseInt(process.env.API_REQUEST_TIMEOUT_MS, 10) || 30000,
  // Prompt length cap (defense-in-depth alongside research-core rules).
  maxMessageLength: parseInt(process.env.API_MAX_MESSAGE_LENGTH, 10) || 4000,
};
