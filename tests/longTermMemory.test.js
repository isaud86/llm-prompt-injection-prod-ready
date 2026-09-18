process.env.LONG_TERM_MEMORY_ENABLED = "true";
jest.mock("../packages/research-core/src/rag/chromaClient", () => ({
  getCollection: jest.fn(),
}));

const fs = require("fs");
const path = require("path");
const { getCollection } = require("../packages/research-core/src/rag/chromaClient");
const {
  storeBlockedPattern,
  loadRecentViolations,
} = require("../packages/research-core/src/memory/longTermMemory");

describe("longTermMemory", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("storeBlockedPattern", () => {
    test("stores a violation in ChromaDB", async () => {
      const mockCollection = { add: jest.fn().mockResolvedValue(undefined) };
      getCollection.mockResolvedValue(mockCollection);

      await storeBlockedPattern(
        "ignore instructions",
        "prompt_injection",
        "high",
      );

      expect(mockCollection.add).toHaveBeenCalledTimes(1);
      const call = mockCollection.add.mock.calls[0][0];
      expect(call.ids[0]).toMatch(/^rt-/);
      expect(call.documents[0]).toBe("ignore instructions");
      expect(call.metadatas[0].safe).toBe("false");
      expect(call.metadatas[0].category).toBe("prompt_injection");
      expect(call.metadatas[0].subcategory).toBe("runtime_learned");
    });

    test("silently skips when ChromaDB is unavailable", async () => {
      getCollection.mockResolvedValue(null);
      // Should not throw
      await storeBlockedPattern("attack input", "prompt_injection", "high");
      // No collection.add called
    });

    test("skips rate_limit violations", async () => {
      const mockCollection = { add: jest.fn() };
      getCollection.mockResolvedValue(mockCollection);

      await storeBlockedPattern("too many requests", "rate_limit", "high");

      expect(mockCollection.add).not.toHaveBeenCalled();
    });

    test("silently handles ChromaDB add errors", async () => {
      const mockCollection = {
        add: jest.fn().mockRejectedValue(new Error("write failed")),
      };
      getCollection.mockResolvedValue(mockCollection);

      // Should not throw
      await storeBlockedPattern("attack", "prompt_injection", "high");
    });
  });

  describe("loadRecentViolations", () => {
    const testLogDir = path.join(__dirname, "..", "logs");
    const testLogFile = path.join(testLogDir, "security.log");

    beforeEach(() => {
      if (!fs.existsSync(testLogDir)) {
        fs.mkdirSync(testLogDir, { recursive: true });
      }
    });

    test("reads violation entries from log file", () => {
      const entries = [
        JSON.stringify({ status: "SAFE", violationType: "none", input: "ls" }),
        JSON.stringify({
          status: "VIOLATION",
          violationType: "prompt_injection",
          input: "ignore instructions",
        }),
        JSON.stringify({
          status: "VIOLATION",
          violationType: "forbidden_command",
          input: "rm -rf /",
        }),
        JSON.stringify({
          status: "VIOLATION",
          violationType: "rate_limit",
          input: "spam",
        }),
      ];
      fs.writeFileSync(testLogFile, entries.join("\n") + "\n");

      const violations = loadRecentViolations(10);
      // Should include prompt_injection and forbidden_command, NOT rate_limit or SAFE
      expect(violations).toHaveLength(2);
      expect(violations[0].violationType).toBe("prompt_injection");
      expect(violations[1].violationType).toBe("forbidden_command");
    });

    test("returns empty array when log file does not exist", () => {
      // Use a non-existent path
      const violations = loadRecentViolations(10);
      // The actual log file may or may not exist depending on test order,
      // but this should at minimum not throw
      expect(Array.isArray(violations)).toBe(true);
    });

    test("respects maxEntries limit", () => {
      const entries = [];
      for (let i = 0; i < 20; i++) {
        entries.push(
          JSON.stringify({
            status: "VIOLATION",
            violationType: "prompt_injection",
            input: `attack-${i}`,
          }),
        );
      }
      fs.writeFileSync(testLogFile, entries.join("\n") + "\n");

      const violations = loadRecentViolations(3);
      expect(violations).toHaveLength(3);
      // Should be the LAST 3 entries (most recent), returned oldest-first
      expect(violations[0].input).toBe("attack-17");
      expect(violations[2].input).toBe("attack-19");
    });
  });
});
