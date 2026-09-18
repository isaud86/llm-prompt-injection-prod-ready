#!/usr/bin/env node
/**
 * validateCEDA1000.js — independent invariant checker for the CEDA-1000 corpus.
 *
 * Exits non-zero if ANY invariant fails. Does not modify any file. Reads:
 *   data/ceda-1000.json          (built corpus)
 *   data/evaluation-dataset.json (CEDA-215 seed, read-only reference)
 *   data/ceda-1000.manifest.json (optional; validated if present)
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.resolve(__dirname, "..");
const SEED_PATH = path.join(ROOT, "data", "evaluation-dataset.json");
const OUT_PATH = path.join(ROOT, "data", "ceda-1000.json");
const MANIFEST_PATH = path.join(ROOT, "data", "ceda-1000.manifest.json");

const EXPECTED_SEED_SHA =
  "d5edbb5f28d148a333fd0b14488bbe8cd4acf506821109c259d6cf6a70a1ebab";

const EXPECTED_CATEGORIES = {
  prompt_injection: 100,
  command_injection: 100,
  path_traversal: 80,
  encoding_obfuscation: 80,
  semantic_manipulation: 80,
  rate_limit_evasion: 80,
  multi_turn_escalation: 80,
  output_probing: 50,
  benign: 350,
};
const VALID_CATEGORIES = new Set(Object.keys(EXPECTED_CATEGORIES));
const VALID_LABELS = new Set(["SAFE", "UNSAFE"]);

const DESTRUCTIVE_PATTERNS = [
  /\brm\s+-\w*r/i, /\brm\s+-\w*f/i, /\brm\s+\//i, /\brmdir\b/i,
  /\bmkfs\b/i, /\bdd\s+if=/i, /\bshutdown\b/i, /\breboot\b/i, /\bhalt\b/i,
  /\bpoweroff\b/i, /:\(\)\s*\{/, /\bchmod\s+(-\w*\s+)?777/i, /\bchmod\s+-R/i,
  /\bchown\s+-R/i, /\bmv\s+\/\s/i, /\bmkfs\./i, /\btruncate\s+-s/i,
  /\bformat\s+[a-z]:/i, />\s*\/dev\/sd/i, />\s*\/etc\//i,
  /\bcurl\b[^\n]*\|\s*sh\b/i, /\bwget\b[^\n]*\|\s*sh\b/i,
];
const REAL_TLDS = [
  "com", "net", "org", "io", "gov", "edu", "co", "ai", "dev", "app", "xyz",
  "info", "biz", "ru", "cn", "uk", "de", "fr", "jp", "us", "ca", "au", "cloud",
  "sh", "me", "tv",
];
const IP_RE = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
const DOMAIN_RE = new RegExp("\\b[a-z0-9-]+\\.(" + REAL_TLDS.join("|") + ")\\b", "i");

const META_KEYS = {
  independent: ["cedaVersion", "source", "generationMethod", "familyId", "variantIndex"],
  rate_limit_evasion: [
    "cedaVersion", "source", "generationMethod", "familyId", "variantIndex",
    "type", "sequenceIndex", "sequenceLength", "expectBlockAfter", "testName",
  ],
  multi_turn_escalation: [
    "cedaVersion", "source", "generationMethod", "familyId", "variantIndex",
    "turnIndex", "totalTurns", "expectSafe", "sequenceName",
  ],
};
const NONDETERMINISM_KEY_RE = /(timestamp|createdat|updatedat|generatedat|random|uuid|epoch|\bnow\b)/i;

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}
function canonical(s) {
  return String(s).trim().replace(/\s+/g, " ").toLowerCase();
}

const results = [];
function check(name, cond, detail) {
  results.push({ name, pass: !!cond, detail: cond ? "" : detail || "" });
}

function main() {
  if (!fs.existsSync(OUT_PATH)) {
    console.error(`FAIL: ${OUT_PATH} not found. Run "npm run dataset:build:ceda1000" first.`);
    process.exit(1);
  }
  const seedBuf = fs.readFileSync(SEED_PATH);
  const seed = JSON.parse(seedBuf.toString("utf8"));
  const outBuf = fs.readFileSync(OUT_PATH);
  const records = JSON.parse(outBuf.toString("utf8"));

  // Seed integrity (must be untouched CEDA-215).
  check("seed SHA256 == CEDA-215", sha256Hex(seedBuf) === EXPECTED_SEED_SHA,
    `got ${sha256Hex(seedBuf)}`);
  check("seed length == 215", Array.isArray(seed) && seed.length === 215);

  // Totals + labels.
  check("total == 1000", records.length === 1000, `got ${records.length}`);
  const labelCounts = { SAFE: 0, UNSAFE: 0 };
  for (const r of records) labelCounts[r.expectedLabel] = (labelCounts[r.expectedLabel] || 0) + 1;
  check("SAFE == 500", labelCounts.SAFE === 500, `got ${labelCounts.SAFE}`);
  check("UNSAFE == 500", labelCounts.UNSAFE === 500, `got ${labelCounts.UNSAFE}`);

  // Category counts.
  const catCounts = {};
  for (const r of records) catCounts[r.category] = (catCounts[r.category] || 0) + 1;
  for (const [cat, exp] of Object.entries(EXPECTED_CATEGORIES)) {
    check(`category ${cat} == ${exp}`, catCounts[cat] === exp, `got ${catCounts[cat]}`);
  }
  check("no unexpected categories",
    Object.keys(catCounts).every((c) => VALID_CATEGORIES.has(c)),
    `got ${Object.keys(catCounts).join(",")}`);

  // Legacy preservation (first 215 deep-equal seed, in order).
  const legacy = records.slice(0, 215);
  const extension = records.slice(215);
  check("legacy count == 215", legacy.length === 215);
  check("extension count == 785", extension.length === 785, `got ${extension.length}`);
  check("legacy deep-equal seed (order preserved)",
    JSON.stringify(legacy) === JSON.stringify(seed));
  check("legacy records carry NO extension source flag",
    legacy.every((r) => !(r.metadata && r.metadata.source === "ceda-1000-extension")));
  check("every extension record has source=ceda-1000-extension",
    extension.every((r) => r.metadata && r.metadata.source === "ceda-1000-extension"));

  // IDs unique.
  const ids = records.map((r) => r.id);
  check("IDs unique (1000)", new Set(ids).size === 1000, `unique=${new Set(ids).size}`);

  // Required fields present + valid on ALL records. `input` must be PRESENT as a
  // string (legacy CEDA-215 intentionally includes one empty-string minimal_input
  // case, which is valid and immutable); extension inputs must be non-empty.
  check("all records have id/input(string)/category/subcategory/expectedLabel",
    records.every((r) => r.id && typeof r.input === "string" &&
      r.category && r.subcategory && r.expectedLabel));
  check("all extension inputs non-empty",
    records.slice(215).every((r) => typeof r.input === "string" && r.input.length > 0));
  check("all expectedLabel values valid", records.every((r) => VALID_LABELS.has(r.expectedLabel)));
  check("all categories valid", records.every((r) => VALID_CATEGORIES.has(r.category)));

  // Extension metadata: exact key sets (enforces required metadata AND no stray/
  // nondeterministic fields) + provenance values.
  let metaOk = true, provenanceOk = true, nondetOk = true, detMeta = "";
  for (const r of extension) {
    const m = r.metadata || {};
    const type = r.category === "rate_limit_evasion" ? "rate_limit_evasion"
      : r.category === "multi_turn_escalation" ? "multi_turn_escalation" : "independent";
    const expectedKeys = META_KEYS[type].slice().sort();
    const actualKeys = Object.keys(m).sort();
    if (JSON.stringify(expectedKeys) !== JSON.stringify(actualKeys)) {
      metaOk = false; if (!detMeta) detMeta = `${r.id}: keys ${actualKeys.join(",")}`;
    }
    if (m.cedaVersion !== "1.0" || m.source !== "ceda-1000-extension" ||
        typeof m.generationMethod !== "string" || typeof m.familyId !== "string" ||
        typeof m.variantIndex !== "number") provenanceOk = false;
    for (const k of actualKeys) if (NONDETERMINISM_KEY_RE.test(k)) nondetOk = false;
  }
  check("extension metadata key sets exact per type", metaOk, detMeta);
  check("extension provenance fields present + correct", provenanceOk);
  check("no nondeterminism-related metadata keys", nondetOk);

  // Independent-new inputs canonical-unique vs legacy and each other.
  const legacyCanon = new Set(seed.map((r) => canonical(r.input)));
  const independentNew = extension.filter(
    (r) => r.category !== "rate_limit_evasion" && r.category !== "multi_turn_escalation");
  const seenNew = new Set();
  let dupVsLegacy = 0, dupVsNew = 0;
  for (const r of independentNew) {
    const c = canonical(r.input);
    if (legacyCanon.has(c)) dupVsLegacy++;
    if (seenNew.has(c)) dupVsNew++; else seenNew.add(c);
  }
  check("new independent inputs unique vs legacy", dupVsLegacy === 0, `dups=${dupVsLegacy}`);
  check("new independent inputs unique vs each other", dupVsNew === 0, `dups=${dupVsNew}`);

  // Safety: no destructive templates / real network targets in NEW records.
  let destr = 0, ipHit = 0, domHit = 0, dEx = "";
  for (const r of extension) {
    if (DESTRUCTIVE_PATTERNS.some((re) => re.test(r.input))) { destr++; if (!dEx) dEx = r.id; }
    if (IP_RE.test(r.input)) ipHit++;
    if (DOMAIN_RE.test(r.input)) domHit++;
  }
  check("no destructive command templates in extension", destr === 0, `count=${destr} e.g. ${dEx}`);
  check("no real IPs in extension inputs", ipHit === 0, `count=${ipHit}`);
  check("no real domains in extension inputs", domHit === 0, `count=${domHit}`);

  // Rate-limit sequence integrity (exactly ONE new sequence).
  const rlNew = extension.filter((r) => r.category === "rate_limit_evasion");
  const rlSeqNames = [...new Set(rlNew.map((r) => r.metadata.testName))];
  check("exactly 1 new rate-limit sequence", rlSeqNames.length === 1, `got ${rlSeqNames.length}`);
  check("rate-limit sequence has 21 records", rlNew.length === 21, `got ${rlNew.length}`);
  const rlSorted = rlNew.slice().sort((a, b) => a.metadata.sequenceIndex - b.metadata.sequenceIndex);
  let rlOk = true;
  rlSorted.forEach((r, i) => {
    const expLabel = i < 20 ? "SAFE" : "UNSAFE";
    if (r.metadata.sequenceIndex !== i || r.metadata.sequenceLength !== 21 ||
        r.metadata.expectBlockAfter !== 20 || r.expectedLabel !== expLabel) rlOk = false;
  });
  check("rate-limit indices/labels/expectBlockAfter correct", rlOk);
  check("rate-limit: 20 SAFE + 1 UNSAFE",
    rlNew.filter((r) => r.expectedLabel === "SAFE").length === 20 &&
    rlNew.filter((r) => r.expectedLabel === "UNSAFE").length === 1);
  check("rate-limit inputs unique (21)", new Set(rlNew.map((r) => canonical(r.input))).size === 21);

  // Multi-turn sequence integrity (exactly 11 new sequences of 6 turns).
  const mtNew = extension.filter((r) => r.category === "multi_turn_escalation");
  const mtGroups = {};
  for (const r of mtNew) (mtGroups[r.metadata.sequenceName] ||= []).push(r);
  const seqNames = Object.keys(mtGroups);
  check("exactly 11 new multi-turn sequences", seqNames.length === 11, `got ${seqNames.length}`);
  check("multi-turn total 66 records", mtNew.length === 66, `got ${mtNew.length}`);
  let mtStructOk = true, twoFour = 0, oneFive = 0;
  for (const name of seqNames) {
    const turns = mtGroups[name].slice().sort((a, b) => a.metadata.turnIndex - b.metadata.turnIndex);
    if (turns.length !== 6) mtStructOk = false;
    turns.forEach((r, i) => {
      if (r.metadata.turnIndex !== i || r.metadata.totalTurns !== 6) mtStructOk = false;
      if ((r.expectedLabel === "SAFE") !== r.metadata.expectSafe) mtStructOk = false;
    });
    const safe = turns.filter((r) => r.expectedLabel === "SAFE").length;
    const unsafe = turns.filter((r) => r.expectedLabel === "UNSAFE").length;
    if (safe === 2 && unsafe === 4) twoFour++;
    else if (safe === 1 && unsafe === 5) oneFive++;
    else mtStructOk = false;
    // SAFE turns must precede UNSAFE turns (realistic escalation).
    const firstUnsafe = turns.findIndex((r) => r.expectedLabel === "UNSAFE");
    const lastSafe = turns.map((r) => r.expectedLabel).lastIndexOf("SAFE");
    if (firstUnsafe !== -1 && lastSafe !== -1 && lastSafe > firstUnsafe) mtStructOk = false;
  }
  check("multi-turn: each 6 turns, indices+expectSafe consistent, SAFE before UNSAFE", mtStructOk);
  check("multi-turn: 8 sequences 2SAFE/4UNSAFE", twoFour === 8, `got ${twoFour}`);
  check("multi-turn: 3 sequences 1SAFE/5UNSAFE", oneFive === 3, `got ${oneFive}`);
  check("multi-turn: 19 SAFE + 47 UNSAFE",
    mtNew.filter((r) => r.expectedLabel === "SAFE").length === 19 &&
    mtNew.filter((r) => r.expectedLabel === "UNSAFE").length === 47);

  // Manifest (optional but validated when present).
  if (fs.existsSync(MANIFEST_PATH)) {
    const man = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
    check("manifest seedSha256 == CEDA-215", man.seedSha256 === EXPECTED_SEED_SHA);
    check("manifest datasetSha256 == file sha", man.datasetSha256 === sha256Hex(outBuf),
      `manifest=${man.datasetSha256} file=${sha256Hex(outBuf)}`);
    check("manifest counts correct",
      man.totalRecords === 1000 && man.safe === 500 && man.unsafe === 500 &&
      man.legacyRecords === 215 && man.extensionRecords === 785);
    check("manifest has no timestamp field",
      !Object.keys(man).some((k) => NONDETERMINISM_KEY_RE.test(k)));
  }

  // Report.
  const failed = results.filter((r) => !r.pass);
  console.log("\nCEDA-1000 VALIDATION REPORT");
  console.log("===========================");
  for (const r of results) {
    console.log(`  [${r.pass ? "PASS" : "FAIL"}] ${r.name}${r.pass ? "" : "  -> " + r.detail}`);
  }
  console.log("===========================");
  console.log(`  ${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length > 0) {
    console.log(`\nRESULT: FAIL (${failed.length} failing)\n`);
    process.exit(1);
  }
  console.log("\nRESULT: PASS\n");
}

main();
