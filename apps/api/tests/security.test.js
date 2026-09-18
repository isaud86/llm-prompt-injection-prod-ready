// Mock the pipeline so we can drive the UNAVAILABLE fail-safe path deterministically.
jest.mock("../src/services/pipeline", () => ({
  processInput: jest.fn(),
  resetPipeline: jest.fn(),
  PRESETS: require("../../../packages/research-core/src/presets").PRESETS,
  providers: {},
  model: () => "qwen3.5:2b",
}));

const request = require("supertest");
const { createApp } = require("../src/app");
const pipeline = require("../src/services/pipeline");
const { buildRequestContext } = require("../src/context/requestContext");

const app = createApp();
const CHAT = "/api/v1/chat";

describe("Production fail-safe surfaces as MODEL_UNAVAILABLE (no leak)", () => {
  afterEach(() => jest.clearAllMocks());

  test("UNAVAILABLE pipeline result -> 503 MODEL_UNAVAILABLE", async () => {
    pipeline.processInput.mockResolvedValue({
      status: "UNAVAILABLE",
      reasoning: "Semantic inference unavailable; failing safe (production mode).",
      warningMessage: "The AI service is temporarily unavailable. Please try again shortly.",
    });
    const res = await request(app).post(CHAT).send({ message: "hello" });
    expect(res.status).toBe(503);
    expect(res.body.error.code).toBe("MODEL_UNAVAILABLE");
    const raw = JSON.stringify(res.body);
    expect(raw).not.toMatch(/reasoning|semantic|failing safe|stack/i);
  });
});

describe("Client cannot supply an authenticated identity", () => {
  afterEach(() => jest.clearAllMocks());

  test("body userId is rejected (strict schema, mass-assignment defense)", async () => {
    pipeline.processInput.mockResolvedValue({ status: "SAFE", output: "ok" });
    const res = await request(app).post(CHAT).send({ message: "ls", userId: "attacker-controlled" });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("INVALID_REQUEST");
  });

  test("even if a userId slips through validation, contextId is derived from auth only", async () => {
    pipeline.processInput.mockResolvedValue({ status: "SAFE", output: "ok" });
    const conversationId = "22222222-2222-4222-8222-222222222222";
    await request(app).post(CHAT).send({ message: "ls", conversationId });
    // Auth is anonymous in this phase -> contextId must be anon-scoped, never
    // taking a client-supplied identity.
    const opts = pipeline.processInput.mock.calls[0][1];
    expect(opts.contextId).toBe(`anon:${conversationId}`);
  });
});

describe("buildRequestContext identity rules (userId from auth, conversationId separate)", () => {
  test("authenticated userId comes only from the verified auth context", () => {
    const ctx = buildRequestContext({
      requestId: "req-1",
      auth: { userId: "cognito-sub-123", roles: ["user"], authenticated: true },
      conversationId: "33333333-3333-4333-8333-333333333333",
    });
    expect(ctx.userId).toBe("cognito-sub-123");
    expect(ctx.contextId).toBe("cognito-sub-123:33333333-3333-4333-8333-333333333333");
    expect(ctx.isResearcher).toBe(false);
  });

  test("anonymous auth yields a null userId and anon-scoped context", () => {
    const ctx = buildRequestContext({
      requestId: "req-2",
      auth: { userId: null, roles: ["anonymous"], authenticated: false },
      conversationId: "44444444-4444-4444-8444-444444444444",
    });
    expect(ctx.userId).toBeNull();
    expect(ctx.contextId.startsWith("anon:")).toBe(true);
  });

  test("researcher/admin roles are recognized for preset gating", () => {
    expect(buildRequestContext({ requestId: "r", auth: { userId: "u", roles: ["researcher"] } }).isResearcher).toBe(true);
    expect(buildRequestContext({ requestId: "r", auth: { userId: "u", roles: ["admin"] } }).isResearcher).toBe(true);
    expect(buildRequestContext({ requestId: "r", auth: { userId: "u", roles: ["user"] } }).isResearcher).toBe(false);
  });

  test("conversationId is validated/handled separately from identity", () => {
    // No conversationId supplied -> a fresh unguessable UUID is generated,
    // independent of userId.
    const ctx = buildRequestContext({ requestId: "r", auth: { userId: "u", roles: [] } });
    expect(ctx.conversationId).toMatch(/^[0-9a-f-]{36}$/i);
    expect(ctx.contextId).toBe(`u:${ctx.conversationId}`);
  });
});
