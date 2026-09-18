// Readiness is mocked so we can assert the endpoint's behavior on dependency
// success AND failure without a live Ollama/ChromaDB.
jest.mock("../src/services/readiness", () => ({
  checkReadiness: jest.fn(),
}));

const request = require("supertest");
const { createApp } = require("../src/app");
const { checkReadiness } = require("../src/services/readiness");

describe("health endpoints", () => {
  const app = createApp();

  afterEach(() => jest.clearAllMocks());

  test("GET /healthz returns 200 ok (liveness)", async () => {
    const res = await request(app).get("/healthz");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ok" });
  });

  test("GET /readyz returns 200 ready when dependencies are up", async () => {
    checkReadiness.mockResolvedValue({
      ready: true,
      checks: { ollama: true, model: true, vectorStore: true },
    });
    const res = await request(app).get("/readyz");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ready" });
  });

  test("GET /readyz returns 503 not_ready when a dependency fails", async () => {
    checkReadiness.mockResolvedValue({
      ready: false,
      checks: { ollama: false, model: false, vectorStore: false },
    });
    const res = await request(app).get("/readyz");
    expect(res.status).toBe(503);
    expect(res.body).toEqual({ status: "not_ready" });
  });

  test("GET /readyz does not leak dependency detail publicly", async () => {
    checkReadiness.mockResolvedValue({
      ready: false,
      checks: { ollama: false, model: false, vectorStore: true },
    });
    const res = await request(app).get("/readyz");
    // Only the minimal status is exposed — no per-check infra detail.
    expect(Object.keys(res.body)).toEqual(["status"]);
  });
});
