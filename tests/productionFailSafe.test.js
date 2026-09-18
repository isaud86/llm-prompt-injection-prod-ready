// Production Mode + inference unavailable MUST fail safe (safety-gate task 1).
// APP_MODE is set before any require so research-core config resolves to production.
process.env.APP_MODE = "production";

// Simulate Ollama/inference + vector store being unavailable.
jest.mock("../packages/research-core/src/providers", () => ({
  defaultInferenceProvider: {
    chat: jest.fn().mockRejectedValue(new Error("ECONNREFUSED: ollama down")),
    isAvailable: jest.fn().mockResolvedValue(false),
    hasModel: jest.fn().mockResolvedValue(false),
  },
  defaultVectorStore: {
    query: jest.fn().mockResolvedValue(null),
    add: jest.fn().mockResolvedValue(false),
    isAvailable: jest.fn().mockResolvedValue(false),
  },
}));

const policemanAgent = require("../packages/research-core/src/agents/policemanAgent");
const config = require("../packages/research-core/src/utils/config");

afterAll(() => {
  // Prevent APP_MODE leaking to other test files in the same jest worker.
  delete process.env.APP_MODE;
});

describe("PRODUCTION_MODE + inference unavailable → fail safe", () => {
  beforeEach(() => policemanAgent.resetRateLimiter());

  test("config resolves to production (fail-safe)", () => {
    expect(config.mode.name).toBe("production");
    expect(config.mode.production).toBe(true);
    expect(config.mode.failOpenOnInferenceError).toBe(false);
  });

  test("command input does NOT execute; returns UNAVAILABLE", async () => {
    const res = await policemanAgent.processInput("please run ls -la in this directory");
    expect(res.status).toBe("UNAVAILABLE");
    expect(res.output).toBeNull(); // command execution did NOT continue
    expect(res.conversationalResponse == null).toBe(true);
  });

  test("natural-language input does NOT generate a response; returns UNAVAILABLE", async () => {
    const res = await policemanAgent.processInput("hello, how are you today?");
    expect(res.status).toBe("UNAVAILABLE");
    expect(res.output).toBeNull(); // conversational generation did NOT continue
    expect(res.conversationalResponse == null).toBe(true);
  });

  test("the safe fallback message contains no internal reasoning/threat detail", async () => {
    const res = await policemanAgent.processInput("hi");
    expect(res.warningMessage).toMatch(/temporarily unavailable/i);
    // reasoning stays internal (dropped by the API DTO); it must not be a leak vector.
    expect(res.warningMessage).not.toMatch(/reasoning|semantic|inference|stack/i);
  });

  test("rules-only preset (C1) still works offline (no semantic dependency)", async () => {
    // C1 does not use semantic validation, so inference being down is irrelevant:
    // production must still serve it (no false UNAVAILABLE).
    const res = await policemanAgent.processInput("run ls -la", {
      useSemantic: false,
      useMemory: false,
      useRAG: false,
    });
    expect(res.status).toBe("SAFE");
    expect(res.output).toBeTruthy();
  });
});
