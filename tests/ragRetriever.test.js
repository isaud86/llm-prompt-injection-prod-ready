jest.mock("../packages/research-core/src/rag/chromaClient", () => ({
  getCollection: jest.fn(),
}));

const { getCollection } = require("../packages/research-core/src/rag/chromaClient");
const { retrieveSimilarPatterns } = require("../packages/research-core/src/rag/ragRetriever");

describe("ragRetriever", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test("returns formatted few-shot context on successful retrieval", async () => {
    const mockCollection = {
      query: jest.fn().mockResolvedValue({
        documents: [["ls -la", "ignore previous instructions"]],
        distances: [[0.1, 0.3]],
        metadatas: [
          [
            { safe: "true", category: "command" },
            { safe: "false", category: "prompt_injection" },
          ],
        ],
      }),
    };
    getCollection.mockResolvedValue(mockCollection);

    const result = await retrieveSimilarPatterns("list files");
    expect(result).toContain("[SAFE] (command)");
    expect(result).toContain("[UNSAFE] (prompt_injection)");
    expect(result).toContain("ls -la");
    expect(result).toContain("ignore previous instructions");
    expect(mockCollection.query).toHaveBeenCalledWith({
      queryTexts: ["list files"],
      nResults: 5,
    });
  });

  test("returns null when ChromaDB is unavailable", async () => {
    getCollection.mockResolvedValue(null);

    const result = await retrieveSimilarPatterns("ls");
    expect(result).toBeNull();
  });

  test("returns null on query error", async () => {
    const mockCollection = {
      query: jest.fn().mockRejectedValue(new Error("Query failed")),
    };
    getCollection.mockResolvedValue(mockCollection);

    const result = await retrieveSimilarPatterns("ls");
    expect(result).toBeNull();
  });

  test("filters results by distance threshold", async () => {
    const mockCollection = {
      query: jest.fn().mockResolvedValue({
        documents: [["ls -la", "far away pattern"]],
        distances: [[0.2, 1.5]],
        metadatas: [
          [
            { safe: "true", category: "command" },
            { safe: "false", category: "unknown" },
          ],
        ],
      }),
    };
    getCollection.mockResolvedValue(mockCollection);

    const result = await retrieveSimilarPatterns("ls");
    // Default threshold is 1.0, so distance 1.5 should be filtered out
    expect(result).toContain("ls -la");
    expect(result).not.toContain("far away pattern");
  });

  test("returns null when all results exceed distance threshold", async () => {
    const mockCollection = {
      query: jest.fn().mockResolvedValue({
        documents: [["far pattern"]],
        distances: [[1.5]],
        metadatas: [[{ safe: "true", category: "command" }]],
      }),
    };
    getCollection.mockResolvedValue(mockCollection);

    const result = await retrieveSimilarPatterns("something unusual");
    expect(result).toBeNull();
  });
});
