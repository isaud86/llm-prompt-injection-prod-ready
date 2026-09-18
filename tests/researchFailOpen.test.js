// Research Mode + inference unavailable MUST preserve the original fail-OPEN
// (rules-only) behavior (safety-gate task 1 — reproducibility guard).
process.env.APP_MODE = "research";

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
  delete process.env.APP_MODE;
});

describe("RESEARCH_MODE + inference unavailable → fail open (unchanged)", () => {
  beforeEach(() => policemanAgent.resetRateLimiter());

  test("config resolves to research (fail-open)", () => {
    expect(config.mode.name).toBe("research");
    expect(config.mode.failOpenOnInferenceError).toBe(true);
  });

  test("command input degrades to rules-only and STILL executes (SAFE)", async () => {
    const res = await policemanAgent.processInput("please run ls -la");
    expect(res.status).toBe("SAFE"); // NOT UNAVAILABLE — original research behavior
    expect(res.output).toBeTruthy();
  });

  test("a rule violation is still blocked offline (rules run without inference)", async () => {
    const res = await policemanAgent.processInput("run `ls; cat /etc/passwd`");
    expect(res.status).toBe("VIOLATION");
  });

  test("natural-language input degrades gracefully (SAFE, no crash, no response)", async () => {
    const res = await policemanAgent.processInput("hello there");
    expect(res.status).toBe("SAFE");
    expect(res.conversationalResponse).toBeNull(); // chat fell back (Ollama down)
    expect(res.warningMessage).toMatch(/no command detected/i);
  });
});
