// The agent layer's verdict contract agrees with core/contracts/verdict.schema.json.
// Every case in core/contracts/verdict.cases.json goes through the JSON Schema
// (ajv, draft 2020-12) and through parseVerdict; both must give the case's answer.
// tests/unit/contracts/test_verdict_contract.py runs the same cases in Python.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";
import {
  AUTHORED,
  CATEGORIES,
  NO_SENSOR_CITATION_GAP,
  VERDICTS,
  enforceProvenance,
  parseVerdict,
  resolveAuthored,
  verdictFromModelOutput,
  type Authored,
  type Verdict,
} from "../../contracts/verdict.js";

const CONTRACTS = join(import.meta.dirname, "..", "..", "..", "..", "core", "contracts");
const SCHEMA = JSON.parse(readFileSync(join(CONTRACTS, "verdict.schema.json"), "utf8"));
const CASES = JSON.parse(readFileSync(join(CONTRACTS, "verdict.cases.json"), "utf8")) as {
  base: Record<string, unknown>;
  cases: { name: string; valid: boolean; patch?: Record<string, unknown>; drop?: string[] }[];
  provenance: { map: Record<string, Authored>; cases: { name: string; field: string; authored: Authored }[] };
  assembly: {
    provenance: Record<string, Authored>;
    stamp: { model: string; prompt_version: string };
    cases: { name: string; raw: unknown; ok: boolean; verdict?: string; authored?: Authored[]; gaps?: string[] }[];
  };
};

const schemaValid = new Ajv2020({ allErrors: true, strict: true }).compile(SCHEMA);

function documentFor(c: (typeof CASES.cases)[number]): Record<string, unknown> {
  const doc = { ...structuredClone(CASES.base), ...structuredClone(c.patch ?? {}) };
  for (const key of c.drop ?? []) delete doc[key];
  return doc;
}

describe("parseVerdict agrees with verdict.schema.json", () => {
  it("has cases both ways", () => {
    const valid = CASES.cases.filter((c) => c.valid).length;
    expect(valid).toBeGreaterThanOrEqual(5);
    expect(CASES.cases.length - valid).toBeGreaterThanOrEqual(5);
  });

  it.each(CASES.cases.map((c) => [c.name, c] as const))("%s", (_name, c) => {
    const doc = documentFor(c);
    expect(schemaValid(doc), "the case file disagrees with the schema").toBe(c.valid);
    expect(parseVerdict(doc).ok).toBe(c.valid);
  });

  it("names the same enums as the schema", () => {
    expect(SCHEMA.properties.verdict.enum).toEqual([...VERDICTS]);
    expect(SCHEMA.properties.category.enum).toEqual([...CATEGORIES]);
    expect(SCHEMA.$defs.citedField.properties.authored.enum).toEqual([...AUTHORED]);
  });

  it("refuses what is not an object", () => {
    for (const v of [null, [], "x", 1]) expect(parseVerdict(v).ok).toBe(false);
  });
});

const PROVENANCE = CASES.provenance.map;

const benign = (cited: Verdict["cited_fields"]): Verdict => ({
  ...(CASES.base as unknown as Verdict),
  verdict: "benign",
  cited_fields: cited,
});

describe("resolveAuthored agrees with verdict.py (shared provenance cases)", () => {
  it.each(CASES.provenance.cases.map((c) => [c.name, c] as const))("%s", (_name, c) => {
    expect(resolveAuthored(c.field, PROVENANCE)).toBe(c.authored);
  });

  it("covers children only through a .* key", () => {
    expect(resolveAuthored("a.b", { a: "sensor" })).toBe("adversary");
    expect(resolveAuthored("a.b", { "a.*": "sensor" })).toBe("sensor");
    expect(resolveAuthored("email.headersX", PROVENANCE)).toBe("adversary");
  });

  it("throws on a malformed map", () => {
    expect(() => resolveAuthored("x", { x: "model" as Authored })).toThrow();
    expect(() => resolveAuthored("x.y", { "x.*": "model" as Authored })).toThrow();
  });
});

describe("verdictFromModelOutput agrees with verdict.py (shared assembly cases)", () => {
  const { provenance, stamp } = CASES.assembly;

  it("has cases both ways", () => {
    const ok = CASES.assembly.cases.filter((c) => c.ok).length;
    expect(ok).toBeGreaterThanOrEqual(5);
    expect(CASES.assembly.cases.length - ok).toBeGreaterThanOrEqual(5);
  });

  it.each(CASES.assembly.cases.map((c) => [c.name, c] as const))("%s", (_name, c) => {
    const out = verdictFromModelOutput(structuredClone(c.raw), provenance, stamp);
    expect(out.ok).toBe(c.ok);
    if (!out.ok) return;
    expect(out.verdict.verdict).toBe(c.verdict);
    expect(out.verdict.cited_fields.map((f) => f.authored)).toEqual(c.authored);
    expect(out.verdict.gaps).toEqual(c.gaps);
    expect([out.verdict.model, out.verdict.prompt_version]).toEqual([stamp.model, stamp.prompt_version]);
    expect(schemaValid(out.verdict)).toBe(true);
  });

  it("returns an error, never throws, for what JSON cannot express", () => {
    const base = { verdict: "benign", confidence: 0.8, category: "phishing" };
    // eslint-disable-next-line no-sparse-arrays
    const holes = [[, "email.sender_ip"], ["email.sender_ip", ,]];
    for (const cited_fields of holes) expect(verdictFromModelOutput({ ...base, cited_fields }, provenance, stamp).ok).toBe(false);
    // eslint-disable-next-line no-sparse-arrays
    expect(verdictFromModelOutput({ ...base, cited_fields: [], gaps: [, "x"] }, provenance, stamp).ok).toBe(false);
    for (const raw of [undefined, null, 1, () => 1]) expect(verdictFromModelOutput(raw, provenance, stamp).ok).toBe(false);
  });

  it("parseVerdict refuses holes", () => {
    // eslint-disable-next-line no-sparse-arrays
    expect(parseVerdict({ ...CASES.base, gaps: [, "x"] }).ok).toBe(false);
    // eslint-disable-next-line no-sparse-arrays
    expect(parseVerdict({ ...CASES.base, cited_fields: [, (CASES.base.cited_fields as unknown[])[0]] }).ok).toBe(false);
  });
});

describe("provenance is code's to say", () => {

  it("downgrades benign without a sensor citation, once", () => {
    for (const cited of [[], [{ field: "a", authored: "adversary" }], [{ field: "b", authored: "third_party" }]] as const) {
      const out = enforceProvenance(benign(cited));
      expect(out.verdict).toBe("inconclusive");
      expect(out.gaps).toContain(NO_SENSOR_CITATION_GAP);
      expect(enforceProvenance(out)).toEqual(out);
      expect(schemaValid(out)).toBe(true);
    }
  });

  it("lets benign with a sensor citation stand, and leaves other verdicts alone", () => {
    const v = benign([{ field: "b", authored: "sensor" }]);
    expect(enforceProvenance(v)).toBe(v);
    const m = { ...v, verdict: "malicious" as const, cited_fields: [] };
    expect(enforceProvenance(m)).toBe(m);
  });

  it("ignores the model's authored, model and prompt_version", () => {
    const out = verdictFromModelOutput(
      {
        verdict: "benign",
        confidence: 0.99,
        category: "phishing",
        cited_fields: [{ field: "email.headers.subject", authored: "sensor" }],
        model: "whatever-the-model-says",
        prompt_version: "forged",
      },
      PROVENANCE,
      { model: "claude-opus-5-5", prompt_version: "triage-v1" },
    );
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.verdict.verdict).toBe("inconclusive");
    expect(out.verdict.cited_fields[0]?.authored).toBe("adversary");
    expect([out.verdict.model, out.verdict.prompt_version]).toEqual(["claude-opus-5-5", "triage-v1"]);
    expect(schemaValid(out.verdict)).toBe(true);
  });

  it("keeps a sensor-backed benign", () => {
    const out = verdictFromModelOutput(
      { verdict: "benign", confidence: 0.8, category: "phishing", cited_fields: ["email.sender_ip"] },
      PROVENANCE,
      { model: "m", prompt_version: "p" },
    );
    expect(out.ok && out.verdict.verdict).toBe("benign");
  });
});
