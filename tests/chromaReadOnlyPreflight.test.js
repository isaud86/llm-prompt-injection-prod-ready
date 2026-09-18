/**
 * Proves chromaClient.getExistingCollection() is STRICTLY READ-ONLY: it uses the
 * read-only listCollections() API and NEVER calls getOrCreateCollection (which
 * would create the collection). Uses a mocked chromadb module — no real Chroma.
 */

// Must be enabled for the read-only path to attempt a lookup (setup.js disables it).
process.env.CHROMADB_ENABLED = "true";

const mockListCollections = jest.fn();
const mockGetOrCreateCollection = jest.fn(() => {
  throw new Error("getOrCreateCollection MUST NOT be called by the read-only lookup");
});
const mockGetCollection = jest.fn(() => {
  throw new Error("getCollection MUST NOT be called by the read-only lookup");
});

jest.mock("chromadb", () => ({
  ChromaClient: jest.fn().mockImplementation(() => ({
    listCollections: mockListCollections,
    getOrCreateCollection: mockGetOrCreateCollection,
    getCollection: mockGetCollection,
  })),
}));

const chromaClient = require("../packages/research-core/src/rag/chromaClient");

describe("chromaClient.getExistingCollection (read-only)", () => {
  beforeEach(() => {
    mockListCollections.mockReset();
    mockGetOrCreateCollection.mockReset();
    mockGetOrCreateCollection.mockImplementation(() => { throw new Error("must not create"); });
    mockGetCollection.mockReset();
    chromaClient._reset();
  });

  test("existing collection: returns it via listCollections; never creates", async () => {
    const col = { name: "security_patterns", count: async () => 215 };
    mockListCollections.mockResolvedValue([{ name: "other" }, col]);
    const result = await chromaClient.getExistingCollection();
    expect(result).toBe(col);
    expect(await result.count()).toBe(215);
    expect(mockListCollections).toHaveBeenCalledTimes(1);
    expect(mockGetOrCreateCollection).toHaveBeenCalledTimes(0);
    expect(mockGetCollection).toHaveBeenCalledTimes(0);
  });

  test("missing collection: returns null; never creates", async () => {
    mockListCollections.mockResolvedValue([{ name: "something_else" }]);
    const result = await chromaClient.getExistingCollection();
    expect(result).toBeNull();
    expect(mockGetOrCreateCollection).toHaveBeenCalledTimes(0);
  });

  test("lookup error: throws; never creates", async () => {
    mockListCollections.mockRejectedValue(new Error("connection refused"));
    await expect(chromaClient.getExistingCollection()).rejects.toThrow(/connection refused/);
    expect(mockGetOrCreateCollection).toHaveBeenCalledTimes(0);
  });
});
