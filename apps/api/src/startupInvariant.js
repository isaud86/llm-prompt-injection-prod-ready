/**
 * Production startup invariant (pre-merge closure Task B).
 *
 * Eliminates the split-brain risk where the API layer runs as production
 * (NODE_ENV=production) while research-core silently defaults to research
 * (fail-open). Rule:
 *
 *   If NODE_ENV=production, the resolved research-core mode MUST be "production".
 *   Otherwise the API process MUST refuse to start.
 *
 * This explicitly rejects NODE_ENV=production with APP_MODE unset (defaults to
 * research), APP_MODE=research, or APP_MODE=test. Research CLI / evaluation runs
 * do not set NODE_ENV=production, so their behavior is unchanged.
 */
class FatalConfigurationError extends Error {
  constructor(message) {
    super(message);
    this.name = "FatalConfigurationError";
    this.code = "FATAL_CONFIGURATION_ERROR";
  }
}

/**
 * @param {{ nodeEnv?: string, appModeName?: string }} params
 *   nodeEnv     = process.env.NODE_ENV
 *   appModeName = the research-core RESOLVED mode (config.mode.name)
 * @throws {FatalConfigurationError} when the invariant is violated.
 */
function assertStartupInvariants({ nodeEnv, appModeName } = {}) {
  if (nodeEnv === "production" && appModeName !== "production") {
    throw new FatalConfigurationError(
      "FATAL_CONFIGURATION_ERROR: Production API requires APP_MODE=production. " +
        `NODE_ENV=production but the resolved research-core mode is "${appModeName || "(unset→research)"}". ` +
        "Refusing to start: production must be fail-safe, never fail-open. " +
        "Set APP_MODE=production.",
    );
  }
}

module.exports = { assertStartupInvariants, FatalConfigurationError };
