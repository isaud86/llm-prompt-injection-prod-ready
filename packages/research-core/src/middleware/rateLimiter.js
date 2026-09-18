const config = require("../utils/config");

class RateLimiter {
  constructor(options = {}) {
    this.maxRequests = options.maxRequests || config.rateLimit.maxRequests;
    this.windowMs = options.windowMs || config.rateLimit.windowMs;
    this.requests = [];
    this.recentInputs = [];
  }

  /**
   * Prune requests outside the current sliding window.
   */
  _prune() {
    const cutoff = Date.now() - this.windowMs;
    this.requests = this.requests.filter((ts) => ts > cutoff);
    this.recentInputs = this.recentInputs.filter((entry) => entry.ts > cutoff);
  }

  /**
   * Detect automated probing patterns:
   * - Rapid burst of requests in a short span
   * - Systematic path probing (many different paths in sequence)
   */
  _detectAbuse() {
    const burstWindow = 5000; // 5 seconds
    const burstThreshold = 10;
    const now = Date.now();
    const recentBurst = this.requests.filter((ts) => ts > now - burstWindow);
    if (recentBurst.length >= burstThreshold) {
      return {
        abuse: true,
        reason: "Burst rate exceeded: too many requests in a short period",
      };
    }

    // Check for systematic path probing (many unique paths in window)
    const uniquePaths = new Set();
    for (const entry of this.recentInputs) {
      const pathMatch = entry.input.match(/(?:\/[\w.\-]+)+/g);
      if (pathMatch) {
        pathMatch.forEach((p) => uniquePaths.add(p));
      }
    }
    if (uniquePaths.size > 15) {
      return {
        abuse: true,
        reason: "Systematic probing detected: too many unique paths queried",
      };
    }

    return { abuse: false, reason: null };
  }

  /**
   * Check if a request is allowed.
   * Returns { allowed: bool, reason: string }
   */
  check(input) {
    this._prune();

    // Check abuse patterns before rate limit
    const abuse = this._detectAbuse();
    if (abuse.abuse) {
      return { allowed: false, reason: abuse.reason };
    }

    if (this.requests.length >= this.maxRequests) {
      return {
        allowed: false,
        reason: `Rate limit exceeded: maximum ${this.maxRequests} requests per ${this.windowMs / 1000}s window`,
      };
    }

    this.requests.push(Date.now());
    this.recentInputs.push({ ts: Date.now(), input });

    return { allowed: true, reason: null };
  }

  /**
   * Reset the limiter (useful for tests).
   */
  reset() {
    this.requests = [];
    this.recentInputs = [];
  }
}

module.exports = RateLimiter;
