// Small bound so the flood is fast and the cap is observable (safety-gate task 3).
process.env.MAX_CONTEXTS = "100";

// Avoid Ollama/exec in the policeman path.
jest.mock("../packages/research-core/src/agents/chatbotAgent", () => ({
  chat: jest.fn().mockResolvedValue({ response: "", fallback: true }),
  execute: jest.fn().mockResolvedValue({ success: true, output: "ok" }),
  parseCommand: (s) => ({ binary: String(s).split(/\s+/)[0], args: [] }),
}));

const sessionMemory = require("../packages/research-core/src/memory/sessionMemory");
const policemanAgent = require("../packages/research-core/src/agents/policemanAgent");
const config = require("../packages/research-core/src/utils/config");

afterAll(() => {
  delete process.env.MAX_CONTEXTS;
});

describe("hostile high-cardinality context IDs cannot grow state unbounded", () => {
  beforeEach(() => {
    sessionMemory.reset();
    policemanAgent.resetRateLimiter();
  });

  test("config picked up the small bound", () => {
    expect(config.contexts.maxContexts).toBe(100);
  });

  test("session memory stays bounded across thousands of distinct contexts", () => {
    for (let i = 0; i < 5000; i++) {
      sessionMemory.record("ls", "SAFE", "none", `attacker:${i}`);
    }
    expect(sessionMemory.contextCount()).toBeLessThanOrEqual(100);
  });

  test("the research default context is pinned and survives a flood", () => {
    sessionMemory.record("baseline", "SAFE", "none"); // default context
    for (let i = 0; i < 5000; i++) {
      sessionMemory.record("ls", "SAFE", "none", `attacker:${i}`);
    }
    // Default context still holds its record (never evicted).
    expect(sessionMemory.getHistory()).toHaveLength(1);
    expect(sessionMemory.getHistory()[0].input).toBe("baseline");
  });

  test("reading unknown contexts does not create state", () => {
    for (let i = 0; i < 1000; i++) {
      sessionMemory.getHistory(`probe:${i}`);
      sessionMemory.detectEscalation(`probe:${i}`);
      sessionMemory.formatContextBlock(`probe:${i}`);
    }
    expect(sessionMemory.contextCount()).toBe(0);
  });

  test("rate-limiter map stays bounded across many distinct contexts", async () => {
    for (let i = 0; i < 1000; i++) {
      await policemanAgent.processInput("hello", {
        contextId: `attacker:${i}`,
        useSemantic: false,
        useMemory: false,
        useRAG: false,
      });
    }
    expect(policemanAgent.rateLimiterCount()).toBeLessThanOrEqual(100);
  });
});
