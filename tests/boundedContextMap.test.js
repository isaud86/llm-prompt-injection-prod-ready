const BoundedContextMap = require("../packages/research-core/src/utils/boundedContextMap");

/**
 * Proves the in-memory context-store safeguards (safety-gate tasks 2 & 3):
 * bounded size, LRU eviction, idle TTL, reads never allocate, pinned key exempt.
 */
describe("BoundedContextMap", () => {
  test("never exceeds maxContexts (evicts on insert)", () => {
    const m = new BoundedContextMap({ maxContexts: 3, ttlMs: 0 });
    for (let i = 0; i < 100; i++) m.getOrCreate(`k${i}`, () => i);
    expect(m.size).toBe(3);
  });

  test("evicts least-recently-used entry when full", () => {
    let t = 1000;
    const now = () => t;
    const m = new BoundedContextMap({ maxContexts: 2, ttlMs: 0, now });
    m.getOrCreate("a", () => "A"); t += 1;
    m.getOrCreate("b", () => "B"); t += 1;
    m.get("a"); t += 1; // touch a -> b is now LRU
    m.getOrCreate("c", () => "C"); // full -> evict b
    expect(m.has("a")).toBe(true);
    expect(m.has("b")).toBe(false);
    expect(m.has("c")).toBe(true);
  });

  test("reads never create a context", () => {
    const m = new BoundedContextMap({ maxContexts: 10 });
    expect(m.get("missing")).toBeUndefined();
    expect(m.has("missing")).toBe(false);
    expect(m.size).toBe(0);
  });

  test("sweeps entries idle beyond ttl (pinned key exempt)", () => {
    let t = 0;
    const now = () => t;
    const m = new BoundedContextMap({ maxContexts: 100, ttlMs: 1000, pinnedKey: "PIN", now });
    m.getOrCreate("PIN", () => "pinned");
    m.getOrCreate("temp", () => "x");
    t = 2000; // advance past ttl
    const removed = m.sweep();
    expect(removed).toBe(1);
    expect(m.has("temp")).toBe(false);
    expect(m.has("PIN")).toBe(true); // pinned survives forever
  });

  test("pinned key is never evicted even under size pressure", () => {
    const m = new BoundedContextMap({ maxContexts: 2, ttlMs: 0, pinnedKey: "PIN" });
    m.getOrCreate("PIN", () => "pinned");
    for (let i = 0; i < 50; i++) m.getOrCreate(`k${i}`, () => i);
    expect(m.has("PIN")).toBe(true);
    expect(m.size).toBeLessThanOrEqual(2);
  });
});
