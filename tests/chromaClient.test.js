process.env.CHROMADB_ENABLED = "true";
jest.mock("chromadb", () => {
  const mockCollection = { name: "security_patterns" };
  const mockClient = {
    getOrCreateCollection: jest.fn().mockResolvedValue(mockCollection),
  };
  return {
    ChromaClient: jest.fn(() => mockClient),
    __mockClient: mockClient,
    __mockCollection: mockCollection,
  };
});

const { ChromaClient, __mockClient, __mockCollection } = require("chromadb");
const { getCollection, _reset } = require("../packages/research-core/src/rag/chromaClient");

describe("chromaClient", () => {
  beforeEach(() => {
    _reset();
    jest.clearAllMocks();
  });

  test("returns collection on successful connection", async () => {
    const col = await getCollection();
    expect(col).toBe(__mockCollection);
    expect(__mockClient.getOrCreateCollection).toHaveBeenCalledWith({
      name: "security_patterns",
      metadata: { "hnsw:space": "cosine" },
    });
  });

  test("caches collection on subsequent calls (singleton)", async () => {
    const col1 = await getCollection();
    const col2 = await getCollection();
    expect(col1).toBe(col2);
    // ChromaClient constructor called only once
    expect(ChromaClient).toHaveBeenCalledTimes(1);
    // getOrCreateCollection called only once
    expect(__mockClient.getOrCreateCollection).toHaveBeenCalledTimes(1);
  });

  test("returns null on connection failure", async () => {
    __mockClient.getOrCreateCollection.mockRejectedValueOnce(
      new Error("Connection refused"),
    );
    const col = await getCollection();
    expect(col).toBeNull();
  });
});
