/**
 * Guards that the production API's dependency on research-core is intact:
 *  - C1–C5 preset semantics are unchanged (frozen, brief §3);
 *  - the public API surface the API + evaluation scripts rely on is present.
 * Uses the REAL research-core (no mocks).
 */
const rc = require("../../../packages/research-core");

describe("research-core contract (C1–C5 + public API)", () => {
  test("C1–C5 presets have the exact frozen flag sets", () => {
    expect(rc.PRESETS.c1).toEqual({ useRules: true, useSemantic: false, useRateLimit: false, useMemory: false, useRAG: false });
    expect(rc.PRESETS.c2).toEqual({ useRules: false, useSemantic: true, useRateLimit: false, useMemory: false, useRAG: false });
    expect(rc.PRESETS.c3).toEqual({ useRules: true, useSemantic: true, useRateLimit: false, useMemory: false, useRAG: false });
    expect(rc.PRESETS.c4).toEqual({ useRules: true, useSemantic: true, useRateLimit: true, useMemory: true, useRAG: false });
    expect(rc.PRESETS.c5).toEqual({ useRules: true, useSemantic: true, useRateLimit: true, useMemory: true, useRAG: true });
  });

  test("public API exposes the symbols apps and eval scripts depend on", () => {
    expect(typeof rc.processInput).toBe("function");
    expect(typeof rc.resetPipeline).toBe("function");
    expect(typeof rc.config.ollama.model).toBe("string");
    expect(rc.providers.defaultInferenceProvider).toBeTruthy();
    expect(rc.providers.defaultVectorStore).toBeTruthy();
    expect(typeof rc.providers.InferenceProvider).toBe("function");
    expect(typeof rc.providers.VectorStore).toBe("function");
  });

  test("provider interfaces enforce their contract (throw when unimplemented)", async () => {
    const base = new rc.providers.InferenceProvider();
    await expect(base.chat({})).rejects.toThrow(/not implemented/);
    const vs = new rc.providers.VectorStore();
    await expect(vs.query({})).rejects.toThrow(/not implemented/);
  });
});
