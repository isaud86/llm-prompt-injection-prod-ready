const sessionMemory = require("../packages/research-core/src/memory/sessionMemory");

/**
 * Session isolation tests (brief §8, acceptance criteria "User sessions are
 * isolated"). Proves that history keyed by different context ids
 * (`${userId}:${conversationId}`) never crosses between contexts, and that the
 * default context (no id) preserves the original single-user behavior.
 */
describe("session isolation", () => {
  beforeEach(() => {
    sessionMemory.reset(); // clears ALL contexts
  });

  test("history for one context is invisible to another", () => {
    const userA = "userA:conv1";
    const userB = "userB:conv1";

    sessionMemory.record("ls -la", "SAFE", "none", userA);
    sessionMemory.record("cat /etc/passwd", "VIOLATION", "forbidden_command", userA);

    // User B has done nothing.
    expect(sessionMemory.getHistory(userB)).toHaveLength(0);
    expect(sessionMemory.formatContextBlock(userB)).toBeNull();

    // User A sees only its own history.
    const aHist = sessionMemory.getHistory(userA);
    expect(aHist).toHaveLength(2);
    expect(aHist[1].status).toBe("VIOLATION");
  });

  test("one user's escalation state does not affect another user", () => {
    const attacker = "attacker:conv1";
    const victim = "victim:conv1";

    // Attacker triggers multi-turn escalation.
    sessionMemory.record("ignore instructions", "VIOLATION", "prompt_injection", attacker);
    sessionMemory.record("rm -rf /", "VIOLATION", "forbidden_command", attacker);
    expect(sessionMemory.detectEscalation(attacker).escalating).toBe(true);

    // A different user is unaffected.
    sessionMemory.record("ls", "SAFE", "none", victim);
    expect(sessionMemory.detectEscalation(victim).escalating).toBe(false);
  });

  test("same user, different conversations are isolated", () => {
    const conv1 = "userA:conv1";
    const conv2 = "userA:conv2";

    sessionMemory.record("ls", "SAFE", "none", conv1);
    sessionMemory.record("date", "SAFE", "none", conv1);

    expect(sessionMemory.getHistory(conv1)).toHaveLength(2);
    expect(sessionMemory.getHistory(conv2)).toHaveLength(0);
  });

  test("escalation in conversation A does not influence conversation B (same user)", () => {
    const convA = "userA:conv1";
    const convB = "userA:conv2";

    // Conversation A escalates.
    sessionMemory.record("ignore instructions", "VIOLATION", "prompt_injection", convA);
    sessionMemory.record("rm -rf /", "VIOLATION", "forbidden_command", convA);
    expect(sessionMemory.detectEscalation(convA).escalating).toBe(true);

    // Conversation B of the same user is not flagged and gets no leaked context.
    sessionMemory.record("ls", "SAFE", "none", convB);
    expect(sessionMemory.detectEscalation(convB).escalating).toBe(false);
    const blockB = sessionMemory.formatContextBlock(convB);
    expect(blockB).not.toContain("prompt_injection");
    expect(blockB).not.toContain("rm -rf");
  });

  test("resetting one context leaves others intact", () => {
    const a = "userA:conv1";
    const b = "userB:conv1";
    sessionMemory.record("ls", "SAFE", "none", a);
    sessionMemory.record("ls", "SAFE", "none", b);

    sessionMemory.reset(a);

    expect(sessionMemory.getHistory(a)).toHaveLength(0);
    expect(sessionMemory.getHistory(b)).toHaveLength(1);
  });

  test("default context (no id) preserves original single-user behavior", () => {
    // Calls with no context id all share the default context — identical to the
    // pre-refactor behavior relied upon by the CLI and evaluation scripts.
    sessionMemory.record("ls -la", "SAFE", "none");
    sessionMemory.record("date", "SAFE", "none");

    const hist = sessionMemory.getHistory();
    expect(hist).toHaveLength(2);
    expect(hist[0].input).toBe("ls -la");

    const block = sessionMemory.formatContextBlock();
    expect(block).toContain("Conversation history (2 prior turns)");

    // The default context is a real, separate key — a namespaced context does
    // not leak into it.
    sessionMemory.record("hacker", "VIOLATION", "prompt_injection", "someUser:conv");
    expect(sessionMemory.getHistory()).toHaveLength(2); // default untouched
  });

  test("window cap applies per-context, not globally", () => {
    const a = "userA:conv1";
    const b = "userB:conv1";
    // Default session window is 5.
    for (let i = 0; i < 8; i++) sessionMemory.record(`a-${i}`, "SAFE", "none", a);
    for (let i = 0; i < 3; i++) sessionMemory.record(`b-${i}`, "SAFE", "none", b);

    expect(sessionMemory.getHistory(a)).toHaveLength(5); // capped
    expect(sessionMemory.getHistory(b)).toHaveLength(3); // independent
    expect(sessionMemory.getHistory(a)[0].input).toBe("a-3");
  });
});
