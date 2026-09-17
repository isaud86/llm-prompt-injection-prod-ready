const policemanAgent = require("../src/agents/policemanAgent");

// Mock semantic validator so the pipeline runs offline (no Ollama needed).
jest.mock("../src/validators/semanticValidator", () => ({
  analyze: jest.fn().mockResolvedValue({ safe: true, threats: [], fallback: true }),
}));

/**
 * Rate-limit isolation (brief §8/§17, acceptance criteria "Rate limiting ...").
 * Each context id gets its own rate budget; one context exhausting its budget
 * must not throttle another. A command input ("ls -la ...") is used so commands
 * are extracted and executed locally without any model call.
 */
describe("rate-limit isolation across contexts", () => {
  beforeEach(() => {
    policemanAgent.resetRateLimiter(); // clears all per-context limiters
  });

  const CMD = "please run ls -la in the current directory";

  test("exhausting one context's budget does not affect another", async () => {
    const heavy = "heavyUser:conv1";
    const other = "quietUser:conv1";

    // Drive the heavy user well past the burst threshold (10 requests / 5s).
    const results = [];
    for (let i = 0; i < 15; i++) {
      results.push(
        await policemanAgent.processInput(CMD, {
          contextId: heavy,
          useMemory: false,
          useSemantic: false,
          useRAG: false,
        })
      );
    }

    const heavyBlocked = results.some(
      (r) => r.status === "VIOLATION" && r.violationType === "rate_limit"
    );
    expect(heavyBlocked).toBe(true);

    // A different context is completely unaffected on its first request.
    const otherResult = await policemanAgent.processInput(CMD, {
      contextId: other,
      useMemory: false,
      useSemantic: false,
      useRAG: false,
    });
    expect(otherResult.violationType).not.toBe("rate_limit");
    expect(otherResult.status).toBe("SAFE");
  });
});
