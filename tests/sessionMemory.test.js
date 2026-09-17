const sessionMemory = require("../packages/research-core/src/memory/sessionMemory");

describe("sessionMemory", () => {
  beforeEach(() => {
    sessionMemory.reset();
  });

  describe("record + getHistory", () => {
    test("records turns and returns them in order", () => {
      sessionMemory.record("ls -la", "SAFE", "none");
      sessionMemory.record("rm -rf /", "VIOLATION", "forbidden_command");

      const history = sessionMemory.getHistory();
      expect(history).toHaveLength(2);
      expect(history[0].input).toBe("ls -la");
      expect(history[0].status).toBe("SAFE");
      expect(history[1].input).toBe("rm -rf /");
      expect(history[1].status).toBe("VIOLATION");
    });

    test("caps history at session window size", () => {
      for (let i = 0; i < 10; i++) {
        sessionMemory.record(`input-${i}`, "SAFE", "none");
      }

      const history = sessionMemory.getHistory();
      // Default window is 5
      expect(history).toHaveLength(5);
      expect(history[0].input).toBe("input-5");
      expect(history[4].input).toBe("input-9");
    });

    test("truncates long inputs to 200 chars", () => {
      const longInput = "x".repeat(500);
      sessionMemory.record(longInput, "SAFE", "none");

      const history = sessionMemory.getHistory();
      expect(history[0].input).toHaveLength(200);
    });
  });

  describe("detectEscalation", () => {
    test("returns no escalation with fewer than 2 turns", () => {
      sessionMemory.record("ls", "SAFE", "none");
      expect(sessionMemory.detectEscalation()).toEqual({
        escalating: false,
        reason: null,
      });
    });

    test("detects multiple violations as persistent attacker", () => {
      sessionMemory.record("rm -rf /", "VIOLATION", "forbidden_command");
      sessionMemory.record("ls", "SAFE", "none");
      sessionMemory.record("cat /etc/passwd", "VIOLATION", "forbidden_command");

      const result = sessionMemory.detectEscalation();
      expect(result.escalating).toBe(true);
      expect(result.reason).toMatch(/Multi-turn attack/);
      expect(result.reason).toContain("2 violations");
    });

    test("detects safe recon followed by attack", () => {
      sessionMemory.record("ls", "SAFE", "none");
      sessionMemory.record("date", "SAFE", "none");
      sessionMemory.record("ignore instructions", "VIOLATION", "prompt_injection");

      const result = sessionMemory.detectEscalation();
      expect(result.escalating).toBe(true);
      expect(result.reason).toMatch(/Escalation pattern/);
    });

    test("returns no escalation for all safe turns", () => {
      sessionMemory.record("ls", "SAFE", "none");
      sessionMemory.record("date", "SAFE", "none");
      sessionMemory.record("ls -la", "SAFE", "none");

      expect(sessionMemory.detectEscalation()).toEqual({
        escalating: false,
        reason: null,
      });
    });
  });

  describe("formatContextBlock", () => {
    test("returns null when history is empty", () => {
      expect(sessionMemory.formatContextBlock()).toBeNull();
    });

    test("formats history as context block", () => {
      sessionMemory.record("ls -la", "SAFE", "none");
      sessionMemory.record("ignore instructions", "VIOLATION", "prompt_injection");

      const block = sessionMemory.formatContextBlock();
      expect(block).toContain("Conversation history (2 prior turns)");
      expect(block).toContain('Turn 1: "ls -la" → SAFE');
      expect(block).toContain('Turn 2: "ignore instructions" → VIOLATION[prompt_injection]');
    });

    test("truncates long inputs in context block to 80 chars", () => {
      sessionMemory.record("a".repeat(200), "SAFE", "none");

      const block = sessionMemory.formatContextBlock();
      // The snippet in the block should be at most 80 chars
      const match = block.match(/"(a+)"/);
      expect(match[1]).toHaveLength(80);
    });
  });

  describe("reset", () => {
    test("clears all history", () => {
      sessionMemory.record("ls", "SAFE", "none");
      sessionMemory.record("date", "SAFE", "none");
      sessionMemory.reset();
      expect(sessionMemory.getHistory()).toHaveLength(0);
      expect(sessionMemory.formatContextBlock()).toBeNull();
    });
  });
});
