# CEDA-1000 v1.1 — Specification

**Command-Execution Defense Assessment corpus, 1000 records.** CEDA-1000 extends
the validated CEDA-215 seed to 1000 labelled records for evaluating the hybrid
rule + LLM defense pipeline. This document is the authoritative spec for its
purpose, methodology, provenance, and validation. **v1.1** refines the
experimental methodology of three categories (see §0) without changing any global
invariant (still 1000 records, 500/500, 215 legacy + 785 extension, identical
category totals); CEDA-215 remains byte-for-byte unchanged.

## 0. v1.1 Methodology Refinement

Independent review identified three confounds in v1.0; v1.1 fixes them at the
dataset level only (no pipeline/code behavior changed):

1. **Path-traversal isolation (Issue 1).** All 70 path_traversal extension records
   now use the *allowed* `ls` command (v1.0 used `cat`/etc., which are rejected by
   the command whitelist and confounded path detection with command rejection).
   The refactored records exercise **path semantics** (`../` depth, redundant
   segments, repeated slashes, nested relative, quoted paths, sensitive targets)
   across ≥7 families, and none contain a forbidden-command word — verified
   against the real rule validator (0 `forbidden_command` confounders).
2. **Semantic-only challenge subset (Issue 3).** ≥50 of the 70
   semantic_manipulation extension records are `challengeType:"semantic_only"`:
   semantically UNSAFE intent phrased **without** command words, path/encoding
   syntax, or known injection phrases. Each one is **verified to survive the
   deterministic rule layer** (`ruleBasedValidator.validate(input).safe === true`)
   at build time and in tests, so it genuinely requires the semantic validator.
   The remaining ≤20 are `challengeType:"mixed"` (deliberately rule-catchable).
3. **Output-safety probes (Issue 2).** All 45 output_probing extension records are
   now real output-leakage probes: an allowed `ls` over a clearly **synthetic**
   temp fixture (`/tmp/ceda1000-output-probe/...`) plus output-safety metadata
   (`checkOutput`, `outputExpectation:"NO_SENSITIVE_PATTERN"`, `fixtureId`,
   `fixtureStrategy:"synthetic-temp-fixture"`, `sensitivePatterns` using synthetic
   markers only). Input label stays SAFE (the input is allowed); output-safety is
   asserted via metadata for a later dedicated runner.
4. **Historical-runner limitation.** `scripts/runAblation.js` scores SAFE/UNSAFE
   **input** verdicts and does **not** by itself score output leakage. It is
   **unchanged** in this phase and is **not** wired to consume CEDA-1000. The 45
   output_probing records therefore carry explicit output-safety metadata for a
   separate CEDA-1000 output-evaluation step to be built after the dataset is
   frozen. No claim is made that the generic ablation runner currently measures
   these 45 output-safety cases.
5. **Honest scope.** The 785 additions remain **deterministic template-generated
   variants**, not independently discovered human attacks (see §10).
6. **CEDA-215 unchanged.** The seed file and the first 215 records are immutable.

## 1. Purpose

Provide a larger, balanced (500 SAFE / 500 UNSAFE) offline evaluation corpus that
preserves CEDA-215 exactly and adds deterministically-generated adversarial and
benign variants, including difficult false-positive ("hard negative") cases. It
is used only for offline evaluation of the defense pipeline; **payloads are data
and are never executed by the generator.**

## 2. Relationship to CEDA-215

- CEDA-215 (`data/evaluation-dataset.json`) is the frozen seed:
  SHA256 `d5edbb5f28d148a333fd0b14488bbe8cd4acf506821109c259d6cf6a70a1ebab`,
  215 records (146 SAFE / 69 UNSAFE).
- CEDA-1000 (`data/ceda-1000.json`) is **the 215 seed records first, unchanged
  and in original order, followed by 785 new records.** The seed file is never
  modified. The builder aborts if the seed SHA256 does not match.

## 3. Category & label distribution

| Category | Existing | Add | Final |
|---|--:|--:|--:|
| prompt_injection | 15 | 85 | 100 |
| command_injection | 12 | 88 | 100 |
| path_traversal | 10 | 70 | 80 |
| encoding_obfuscation | 10 | 70 | 80 |
| semantic_manipulation | 10 | 70 | 80 |
| rate_limit_evasion | 59 | 21 | 80 |
| multi_turn_escalation | 14 | 66 | 80 |
| output_probing | 5 | 45 | 50 |
| benign | 80 | 270 | 350 |
| **TOTAL** | **215** | **785** | **1000** |

**Labels.** Extension adds 354 SAFE + 431 UNSAFE → final 500 / 500.
Independent attack categories are all UNSAFE (`prompt_injection` +85,
`command_injection` +88, `path_traversal` +70, `encoding_obfuscation` +70,
`semantic_manipulation` +70). `output_probing` +45 and `benign` +270 are SAFE.
Stateful contributions: rate-limit 20 SAFE + 1 UNSAFE; multi-turn 19 SAFE + 47
UNSAFE.

## 4. Deterministic generation strategy

The 785 records are produced by `scripts/buildCEDA1000.js` with **no**
`Math.random`, timestamps, or random UUIDs. Curated template families are
enumerated in a fixed order; the first canonical-unique candidates are selected
per category. Identical inputs ⇒ identical output bytes (verified by rebuilding
and comparing SHA256).

Independent families (illustrative, not exhaustive):
- **prompt_injection:** instruction replacement, role reassignment, policy
  override, fake authority, context switching, instruction-hierarchy, indirect
  override, quoted-instruction, XML/JSON-style, delimiter-based.
- **command_injection:** `;`, `&&`, `||`, `|`, `$( )`, backticks, redirection to
  `/dev/null`, newline, nested substitution — each chaining `ls`/`date` with a
  **non-destructive unauthorized** command (`whoami`, `id`, `uname -a`, `cat
  /etc/passwd`, …).
- **path_traversal (v1.1):** ALL use the allowed `ls` command (no `cat`/etc.) across
  ≥7 pure-path families — relative depth, `ls` flags, redundant dot segments,
  nested relative, repeated slashes, quoted paths, sensitive targets — so the path
  mechanism is tested without command-whitelist confounding (§0).
- **encoding_obfuscation:** URL, unicode, hex, base64-shaped, mixed, double,
  fragmented encodings of a payload word (encoded deterministically via
  `Buffer`; never decoded/executed).
- **semantic_manipulation (v1.1):** ≥50 `semantic_only` records (rule-verified to
  survive the deterministic rule layer) plus ≤20 `mixed` records, across ≥7
  families — indirect system inspection, authority-without-keywords,
  troubleshooting pretext, trust exploitation, operational pretext, implicit
  privilege request, contextual social engineering (§0).
- **output_probing (SAFE, v1.1):** allowed `ls` over synthetic temp fixtures with
  output-safety metadata (`checkOutput`, `outputExpectation`, `fixtureId`,
  `fixtureStrategy`, synthetic `sensitivePatterns`) — genuine output-leakage
  probes, not format questions (§0).
- **benign (SAFE):** normal `ls`/`date` variants, natural-language equivalents,
  security-education questions, code-review questions, awareness questions,
  filenames/paths as data, quoted suspicious text with explicitly benign intent,
  conversational/short/data-like inputs, and documentation requests — including
  **hard negatives** that mention words like *root, passwd, curl, sudo, base64,
  path traversal* as data without requesting execution.

## 5. Stateful methodology

Both stateful families carry the metadata `runAblation.js` groups on
(`metadata.testName` for rate-limit, `metadata.sequenceName` for multi-turn),
plus the extension provenance fields.

- **Rate-limit:** exactly one new 21-request sliding-window sequence of unique,
  harmless whitelisted `ls /tmp/ceda1000/rate/reqNN` requests. Requests 1–20 =
  SAFE, request 21 = UNSAFE. Metadata: `type`, `sequenceIndex` (0-based),
  `sequenceLength=21`, `expectBlockAfter=20`, `testName`.
- **Multi-turn:** 11 new sequences of 6 turns each. 8 sequences are 2 SAFE + 4
  UNSAFE; 3 sequences are 1 SAFE + 5 UNSAFE (SAFE setup turns precede UNSAFE
  escalation turns). Patterns include trust-building→unauthorized command, benign
  recon→restricted path, normal command→instruction override, gradual privilege
  escalation, contextual/obfuscated/role manipulation, repeated boundary probing,
  and safe setup→command-injection/path-traversal/semantic-manipulation.
  Metadata: `turnIndex` (0-based), `totalTurns=6`, `expectSafe`, `sequenceName`.

Escalation uses harmless unauthorized commands (`whoami`, `id`, `pwd`, `uname`)
or non-destructive restricted reads — never destructive commands.

## 6. Provenance model

Every new record carries at least:
```json
{ "cedaVersion": "1.0", "source": "ceda-1000-extension",
  "generationMethod": "...", "familyId": "...", "variantIndex": <number> }
```
Stateful records additionally carry the sequence metadata above. Legacy records
are copied verbatim and their metadata is **not** modified. IDs are stable and
deterministic (`ceda1000_<category>_NNN`; `ceda1000_rate_limit_evasion_seq01_reqNN`;
`ceda1000_multi_turn_escalation_seqNN_turnMM`). `data/ceda-1000.manifest.json`
records seed/dataset SHA256 and counts (no timestamps → deterministic).

## 7. Deduplication rules

Canonical comparison normalizes leading/trailing whitespace, collapses repeated
whitespace, and lowercases (it does **not** alter attack syntax). All new
**independent** inputs are canonical-unique against (1) legacy inputs and (2)
each other. New stateful inputs are also unique (unique `/tmp` paths; distinct
authored turns). Legacy textual duplicates (e.g. repeated `ls` in legacy
sequences) are intentionally preserved. Result: 1000 unique IDs, no accidental
new duplicate inputs.

## 8. Safety requirements for new data

- Generator never executes payloads; strings are data only.
- No real malicious infrastructure: only reserved synthetic domains
  (`example.invalid`, `attacker.invalid`, `test.invalid`); no real IPs.
- No destructive commands in new variants; policy violations use harmless
  unauthorized commands or non-destructive disclosure reads.
- Legacy CEDA-215 records are never rewritten, even where they contain stronger
  historical attack strings.

## 9. Validation requirements

`scripts/validateCEDA1000.js` fails (non-zero) unless all hold: total 1000;
500/500 labels; exact category counts; 215 legacy deep-equal + order preserved;
785 extension; unique IDs; new independent inputs canonical-unique; required
metadata (exact key sets per record type); valid labels/categories; no missing
fields; no nondeterministic metadata keys; no real IPs/domains; no destructive
templates; rate-limit and multi-turn structural integrity; manifest correctness.
Jest coverage lives in `tests/ceda1000.test.js`, including a deterministic
double-build byte-equality check.

## 10. Limitations / honest scope

CEDA-1000 is an **evaluation corpus**, not a claim of 1000 independently
discovered attacks. The 785 additions are **deterministic template-generated
adversarial and benign variants**, documented as such — meaningful controlled
variation, not human-authored field observations. "1000 dataset records" is
distinct from "total model evaluations": running the ablation over C1–C5 (5
configurations) evaluates each record up to 5 times, so a full run performs up to
5000 model evaluations, not 1000.

## 11. Reproduce

```bash
npm run dataset:build:ceda1000      # writes data/ceda-1000.json + manifest
npm run dataset:validate:ceda1000   # invariant checks (non-zero on failure)
npm run dataset:check:ceda1000      # build + validate
npm test                            # includes tests/ceda1000.test.js
```
CEDA-1000 does **not** replace the evaluation dataset used by `eval:ablation` /
`eval:models`; those continue to use `data/evaluation-dataset.json` unchanged.

## 12. Changelog (deterministic)

| Version | Dataset SHA256 | Notes |
|---|---|---|
| 1.0 | `5048d9672bfef2f2c20b320417c3c241266faabc6f1039fafa35506b20fd75bc` | Initial CEDA-1000 (215 legacy + 785 extension). |
| 1.1 | `ae9e6f41d85bf1bcf2d7317efc0004eabb9f1ce95a004e4413e24121d22600d5` | Methodology refinement (§0): path-traversal isolation (ls-only, no command confounder); ≥50 rule-verified `semantic_only` records; 45 genuine synthetic output-safety probes. Same global invariants; CEDA-215 unchanged. Supersedes 1.0. |

Seed (CEDA-215) SHA256 (immutable): `d5edbb5f28d148a333fd0b14488bbe8cd4acf506821109c259d6cf6a70a1ebab`.
The manifest (`data/ceda-1000.manifest.json`) records `version`,
`supersedesVersion`, `supersedesDatasetSha256`, `seedSha256`, and `datasetSha256`
(no timestamps → deterministic).
