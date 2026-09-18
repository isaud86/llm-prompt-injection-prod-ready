const RateLimiter = require('../packages/research-core/src/middleware/rateLimiter');

describe('RateLimiter', () => {
  let limiter;

  beforeEach(() => {
    limiter = new RateLimiter({ maxRequests: 5, windowMs: 10000 });
  });

  test('allows requests within limit', () => {
    for (let i = 0; i < 5; i++) {
      const result = limiter.check('ls');
      expect(result.allowed).toBe(true);
    }
  });

  test('blocks requests over limit', () => {
    for (let i = 0; i < 5; i++) {
      limiter.check('ls');
    }
    const result = limiter.check('ls');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Rate limit exceeded');
  });

  test('reset clears all state', () => {
    for (let i = 0; i < 5; i++) {
      limiter.check('ls');
    }
    limiter.reset();
    const result = limiter.check('ls');
    expect(result.allowed).toBe(true);
  });

  test('detects probing patterns with many unique paths', () => {
    const probingLimiter = new RateLimiter({ maxRequests: 100, windowMs: 60000 });
    // Simulate probing many different paths
    for (let i = 0; i < 20; i++) {
      probingLimiter.check(`ls /path/number/${i}`);
    }
    const result = probingLimiter.check('ls /path/number/20');
    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/probing|Burst/);
  });
});
