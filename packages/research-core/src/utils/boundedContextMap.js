/**
 * BoundedContextMap — a development safeguard for the in-process, context-keyed
 * state used by session memory and rate limiters (safety-gate task 2).
 *
 * Guarantees:
 *  - **Bounded size:** never holds more than `maxContexts` entries; when full, the
 *    least-recently-used entry is evicted on insert.
 *  - **Idle TTL:** entries untouched for `ttlMs` are swept lazily (on insert and
 *    on demand). No background timers (keeps tests deterministic and avoids
 *    keeping the event loop alive).
 *  - **Reads never create:** `get()` returns `undefined` for a missing key and
 *    does NOT allocate an entry (prevents hostile read traffic from growing state).
 *  - **Pinned key:** an optional `pinnedKey` (the research DEFAULT_CONTEXT) is
 *    never evicted and never expires, protecting reproducibility.
 *
 * This is NOT the production implementation. Redis is the production store for
 * session/rate state (Phase 4); see docs/IMPLEMENTATION_PLAN.md.
 */
class BoundedContextMap {
  constructor({ maxContexts = 10000, ttlMs = 3600000, pinnedKey = null, now = Date.now } = {}) {
    this.maxContexts = maxContexts;
    this.ttlMs = ttlMs;
    this.pinnedKey = pinnedKey;
    this._now = now; // injectable clock for tests
    this._map = new Map(); // key -> { value, lastAccess }
  }

  /** Remove entries whose idle time exceeds ttlMs (pinned key exempt). */
  sweep() {
    if (!this.ttlMs || this.ttlMs <= 0) return 0;
    const cutoff = this._now() - this.ttlMs;
    let removed = 0;
    for (const [key, entry] of this._map) {
      if (key === this.pinnedKey) continue;
      if (entry.lastAccess <= cutoff) {
        this._map.delete(key);
        removed++;
      }
    }
    return removed;
  }

  /** Evict the least-recently-used non-pinned entry. */
  _evictLRU() {
    let oldestKey = null;
    let oldestAt = Infinity;
    for (const [key, entry] of this._map) {
      if (key === this.pinnedKey) continue;
      if (entry.lastAccess < oldestAt) {
        oldestAt = entry.lastAccess;
        oldestKey = key;
      }
    }
    if (oldestKey !== null) this._map.delete(oldestKey);
  }

  /**
   * Read without creating. Returns the stored value or undefined. Refreshes
   * lastAccess only when the entry already exists.
   */
  get(key) {
    const entry = this._map.get(key);
    if (!entry) return undefined;
    entry.lastAccess = this._now();
    return entry.value;
  }

  /**
   * Get the value for key, creating it via `factory()` if absent. This is the
   * WRITE path — it sweeps expired entries and enforces the size bound.
   */
  getOrCreate(key, factory) {
    const existing = this._map.get(key);
    if (existing) {
      existing.lastAccess = this._now();
      return existing.value;
    }
    this.sweep();
    if (this._map.size >= this.maxContexts) this._evictLRU();
    const value = factory();
    this._map.set(key, { value, lastAccess: this._now() });
    return value;
  }

  has(key) {
    return this._map.has(key);
  }

  delete(key) {
    return this._map.delete(key);
  }

  clear() {
    this._map.clear();
  }

  get size() {
    return this._map.size;
  }
}

module.exports = BoundedContextMap;
