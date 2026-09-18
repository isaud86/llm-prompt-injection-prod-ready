const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const b = require("../scripts/buildCEDA1000");

const ROOT = path.resolve(__dirname, "..");
const BUILDER = path.join(ROOT, "scripts", "buildCEDA1000.js");
const OUT = path.join(ROOT, "data", "ceda-1000.json");

const EXPECTED_CATEGORIES = {
  prompt_injection: 100, command_injection: 100, path_traversal: 80,
  encoding_obfuscation: 80, semantic_manipulation: 80, rate_limit_evasion: 80,
  multi_turn_escalation: 80, output_probing: 50, benign: 350,
};

function freshBuild() {
  const seed = b.loadSeed();
  b.verifySeed(seed);
  return { seed, dataset: b.buildDataset(seed) };
}

describe("CEDA-1000 builder", () => {
  const { seed, dataset } = freshBuild();

  test("seed is the validated CEDA-215", () => {
    expect(seed.sha256).toBe(b.EXPECTED_SEED_SHA);
    expect(seed.records).toHaveLength(215);
  });

  test("build returns exactly 1000 records", () => {
    expect(dataset).toHaveLength(1000);
  });

  test("500 SAFE / 500 UNSAFE", () => {
    const c = { SAFE: 0, UNSAFE: 0 };
    for (const r of dataset) c[r.expectedLabel]++;
    expect(c).toEqual({ SAFE: 500, UNSAFE: 500 });
  });

  test("category totals exact", () => {
    const c = {};
    for (const r of dataset) c[r.category] = (c[r.category] || 0) + 1;
    expect(c).toEqual(EXPECTED_CATEGORIES);
  });

  test("original 215 records preserved (deep-equal) and in order", () => {
    expect(dataset.slice(0, 215)).toEqual(seed.records);
  });

  test("IDs unique (1000)", () => {
    expect(new Set(dataset.map((r) => r.id)).size).toBe(1000);
  });

  test("extension size is exactly 785", () => {
    expect(b.generateExtension(seed)).toHaveLength(785);
  });

  test("deterministic generation (two in-memory builds are byte-identical)", () => {
    const s2 = b.loadSeed();
    expect(JSON.stringify(b.buildDataset(seed))).toBe(JSON.stringify(b.buildDataset(s2)));
  });

  test("every new record has required provenance metadata", () => {
    for (const r of dataset.slice(215)) {
      expect(r.metadata.cedaVersion).toBe("1.1");
      expect(r.metadata.source).toBe("ceda-1000-extension");
      expect(typeof r.metadata.generationMethod).toBe("string");
      expect(typeof r.metadata.familyId).toBe("string");
      expect(typeof r.metadata.variantIndex).toBe("number");
    }
  });

  test("duplicate detection: new independent inputs canonical-unique", () => {
    const legacyCanon = new Set(seed.records.map((r) => b.canonical(r.input)));
    const indep = dataset.slice(215).filter(
      (r) => r.category !== "rate_limit_evasion" && r.category !== "multi_turn_escalation");
    const seen = new Set();
    for (const r of indep) {
      const c = b.canonical(r.input);
      expect(legacyCanon.has(c)).toBe(false);
      expect(seen.has(c)).toBe(false);
      seen.add(c);
    }
  });

  test("rate-limit sequence is correct (21 records, 20 SAFE + 1 UNSAFE, expectBlockAfter=20)", () => {
    const rl = dataset.slice(215).filter((r) => r.category === "rate_limit_evasion");
    expect(rl).toHaveLength(21);
    expect(new Set(rl.map((r) => r.metadata.testName)).size).toBe(1);
    rl.forEach((r, i) => {
      expect(r.metadata.sequenceIndex).toBe(i);
      expect(r.metadata.sequenceLength).toBe(21);
      expect(r.metadata.expectBlockAfter).toBe(20);
      expect(r.expectedLabel).toBe(i < 20 ? "SAFE" : "UNSAFE");
    });
    expect(rl.filter((r) => r.expectedLabel === "SAFE")).toHaveLength(20);
    expect(rl.filter((r) => r.expectedLabel === "UNSAFE")).toHaveLength(1);
  });

  test("multi-turn structure is correct (11 sequences x 6 turns; 8x2/4, 3x1/5)", () => {
    const mt = dataset.slice(215).filter((r) => r.category === "multi_turn_escalation");
    expect(mt).toHaveLength(66);
    const groups = {};
    for (const r of mt) (groups[r.metadata.sequenceName] ||= []).push(r);
    expect(Object.keys(groups)).toHaveLength(11);
    let twoFour = 0, oneFive = 0;
    for (const name of Object.keys(groups)) {
      const turns = groups[name].sort((a, x) => a.metadata.turnIndex - x.metadata.turnIndex);
      expect(turns).toHaveLength(6);
      turns.forEach((r, i) => {
        expect(r.metadata.turnIndex).toBe(i);
        expect(r.metadata.totalTurns).toBe(6);
        expect(r.expectedLabel === "SAFE").toBe(r.metadata.expectSafe);
      });
      const safe = turns.filter((r) => r.expectedLabel === "SAFE").length;
      if (safe === 2) twoFour++; else if (safe === 1) oneFive++;
      // SAFE turns precede UNSAFE turns.
      const firstUnsafe = turns.findIndex((r) => r.expectedLabel === "UNSAFE");
      const lastSafe = turns.map((r) => r.expectedLabel).lastIndexOf("SAFE");
      if (firstUnsafe !== -1 && lastSafe !== -1) expect(lastSafe).toBeLessThan(firstUnsafe);
    }
    expect(twoFour).toBe(8);
    expect(oneFive).toBe(3);
    expect(mt.filter((r) => r.expectedLabel === "SAFE")).toHaveLength(19);
    expect(mt.filter((r) => r.expectedLabel === "UNSAFE")).toHaveLength(47);
  });

  test("extension introduces no destructive templates / real network targets", () => {
    const IP = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
    const DOM = new RegExp("\\b[a-z0-9-]+\\.(" + b.REAL_TLDS.join("|") + ")\\b", "i");
    for (const r of dataset.slice(215)) {
      expect(b.DESTRUCTIVE_PATTERNS.some((re) => re.test(r.input))).toBe(false);
      expect(IP.test(r.input)).toBe(false);
      expect(DOM.test(r.input)).toBe(false);
    }
  });

  test("actual builder run twice produces byte-identical data/ceda-1000.json", () => {
    execFileSync("node", [BUILDER], { cwd: ROOT, stdio: "ignore" });
    const sha1 = crypto.createHash("sha256").update(fs.readFileSync(OUT)).digest("hex");
    execFileSync("node", [BUILDER], { cwd: ROOT, stdio: "ignore" });
    const sha2 = crypto.createHash("sha256").update(fs.readFileSync(OUT)).digest("hex");
    expect(sha1).toBe(sha2);
  });
});

// ─── v1.1 methodology refinements ────────────────────────────────────────────
const ruleValidator = require("../packages/research-core/src/validators/ruleBasedValidator");
const FORBIDDEN_CMD_RE = /\b(rm|mv|cp|cat|chmod|chown|kill|sudo|su|wget|curl|nc|bash|sh|python|node|npm|apt|yum|systemctl|service|mkdir|rmdir|touch|find|grep|awk|sed|dd|mount|umount|ssh|scp|rsync|ping|netstat|ifconfig|ip|iptables|docker|kubectl|whoami|id|pwd|uname)\b/;

describe("CEDA-1000 v1.1 methodology", () => {
  const { seed, dataset } = freshBuild();
  const ext = dataset.slice(215);
  const byCat = (c) => ext.filter((r) => r.category === c);

  test("dataset version is 1.1 on all new records", () => {
    expect(ext.every((r) => r.metadata.cedaVersion === "1.1")).toBe(true);
    expect(seed.records.every((r) => r.metadata.cedaVersion === undefined)).toBe(true); // legacy untouched
  });

  describe("path_traversal (Issue 1)", () => {
    const path = byCat("path_traversal");
    test("70 new records, all use ls", () => {
      expect(path).toHaveLength(70);
      expect(path.every((r) => /^ls\b/.test(r.input.trim()))).toBe(true);
    });
    test("no forbidden command word present", () => {
      expect(path.every((r) => !FORBIDDEN_CMD_RE.test(r.input))).toBe(true);
    });
    test("no record is rejected by the rule layer as forbidden_command", () => {
      for (const r of path) {
        const v = ruleValidator.validate(r.input).violations || [];
        expect(v.some((x) => x.type === "forbidden_command")).toBe(false);
      }
    });
    test("family count >= 7", () => {
      expect(new Set(path.map((r) => r.metadata.familyId)).size).toBeGreaterThanOrEqual(7);
    });
  });

  describe("output_probing (Issue 2)", () => {
    const op = byCat("output_probing");
    test("45 new records, all SAFE input label", () => {
      expect(op).toHaveLength(45);
      expect(op.every((r) => r.expectedLabel === "SAFE")).toBe(true);
    });
    test("correct fixture/output metadata on every record", () => {
      for (const r of op) {
        expect(r.metadata.checkOutput).toBe(true);
        expect(r.metadata.outputExpectation).toBe("NO_SENSITIVE_PATTERN");
        expect(r.metadata.fixtureStrategy).toBe("synthetic-temp-fixture");
        expect(typeof r.metadata.fixtureId).toBe("string");
        expect(Array.isArray(r.metadata.sensitivePatterns)).toBe(true);
        expect(r.metadata.sensitivePatterns.length).toBeGreaterThan(0);
        expect(r.metadata.sensitivePatterns.every((p) => /^(CEDA_TEST_|CEDA_SYNTHETIC_|api_key=CEDA_TEST_)/.test(p))).toBe(true);
      }
    });
    test("family count >= 5", () => {
      expect(new Set(op.map((r) => r.metadata.familyId)).size).toBeGreaterThanOrEqual(5);
    });
  });

  describe("semantic_manipulation (Issue 3)", () => {
    const sm = byCat("semantic_manipulation");
    const so = sm.filter((r) => r.metadata.challengeType === "semantic_only");
    const mx = sm.filter((r) => r.metadata.challengeType === "mixed");
    test("70 new records; semantic_only >= 50; total split correct", () => {
      expect(sm).toHaveLength(70);
      expect(so.length).toBeGreaterThanOrEqual(50);
      expect(so.length + mx.length).toBe(70);
      expect(sm.every((r) => r.expectedLabel === "UNSAFE")).toBe(true);
    });
    test("every semantic_only record SURVIVES the deterministic rule-only layer", () => {
      for (const r of so) {
        expect(ruleValidator.validate(r.input).safe).toBe(true);
      }
    });
    test("family count >= 7", () => {
      expect(new Set(sm.map((r) => r.metadata.familyId)).size).toBeGreaterThanOrEqual(7);
    });
  });

  test("new extension inputs remain duplicate-free (canonical) vs legacy + each other", () => {
    const legacyCanon = new Set(seed.records.map((r) => b.canonical(r.input)));
    const seen = new Set();
    for (const r of ext) {
      const c = b.canonical(r.input);
      expect(legacyCanon.has(c)).toBe(false);
      expect(seen.has(c)).toBe(false);
      seen.add(c);
    }
  });
});
