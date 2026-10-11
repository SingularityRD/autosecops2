// The triage verdict contract (W0.5). The source of truth is
// core/contracts/verdict.schema.json; core/contracts/verdict.py is its Python
// form and this is the agent layer's. tests/core/verdict-contract.test.ts loads
// that schema and runs core/contracts/verdict.cases.json through it and through
// parseVerdict, so the two cannot disagree silently. The schema is not imported
// here: the agent image is built from services/agent alone.
//
// cited_fields[].authored is filled by code from the subject's provenance map,
// never taken from the model. A model reading adversary-controlled text can be
// told to call that text sensor data; taking its word would let a phishing email
// cite itself as proof it is benign. verdictFromModelOutput discards whatever
// authored the model wrote, resolves each field against the map (a field the map
// does not cover is "adversary", the least trusted), stamps model and
// prompt_version from the caller, and applies enforceProvenance.
//
// The map matches exactly: a key "email.sender_ip" covers that field and nothing
// under it. A key ending in ".*" ("edr.process.*") covers every child of its
// prefix, a child being one or more non-empty dotted segments of [A-Za-z0-9_-].
// The longest declared prefix wins and an exact key beats any prefix. Made-up
// children, trailing dots and empty segments resolve to "adversary".
//
// verdict.cases.json "provenance" and "assembly" pin resolveAuthored and
// verdictFromModelOutput to core/contracts/verdict.py case by case.

export const VERDICTS = ["malicious", "benign", "inconclusive"] as const;
export type VerdictValue = (typeof VERDICTS)[number];

export const CATEGORIES = ["phishing", "malware", "identity", "network", "cloud", "other"] as const;
export type Category = (typeof CATEGORIES)[number];

// sensor: our instrumentation observed it. adversary: the party under suspicion
// controls it. third_party: someone else asserted it (intel feed, reputation).
export const AUTHORED = ["sensor", "adversary", "third_party"] as const;
export type Authored = (typeof AUTHORED)[number];

export const UNKNOWN_FIELD_AUTHOR: Authored = "adversary";

export const NO_SENSOR_CITATION_GAP = "benign verdict cited no sensor-authored field; downgraded to inconclusive";

export interface CitedField {
  readonly field: string;
  readonly authored: Authored;
}

export interface RecommendedAction {
  readonly type: string;
  readonly target: string;
}

export interface Verdict {
  readonly verdict: VerdictValue;
  readonly confidence: number;
  readonly category: Category;
  readonly cited_fields: readonly CitedField[];
  readonly gaps: readonly string[];
  readonly recommended_action?: RecommendedAction | null;
  readonly model: string;
  readonly prompt_version: string;
}

export type ProvenanceMap = Readonly<Record<string, Authored>>;

// A value, never a throw, like the rest of the contracts: callers decide what an
// unparseable verdict means for their run.
export type VerdictParse = { ok: true; verdict: Verdict } | { ok: false; errors: string[] };

const KEYS = new Set([
  "verdict",
  "confidence",
  "category",
  "cited_fields",
  "gaps",
  "recommended_action",
  "model",
  "prompt_version",
]);

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const oneOf = <T extends string>(list: readonly T[], v: unknown): v is T =>
  typeof v === "string" && (list as readonly string[]).includes(v);

function onlyKeys(obj: Record<string, unknown>, allowed: readonly string[], at: string, errors: string[]): void {
  for (const key of Object.keys(obj)) if (!allowed.includes(key)) errors.push(`${at}: unknown key ${key}`);
}

export function parseVerdict(value: unknown): VerdictParse {
  const errors: string[] = [];
  if (!isObject(value)) return { ok: false, errors: ["verdict must be an object"] };
  for (const key of Object.keys(value)) if (!KEYS.has(key)) errors.push(`unknown key ${key}`);

  if (!oneOf(VERDICTS, value.verdict)) errors.push(`verdict must be one of ${VERDICTS.join(", ")}`);
  const c = value.confidence;
  if (typeof c !== "number" || !Number.isFinite(c) || c < 0 || c > 1) errors.push("confidence must be a number in [0, 1]");
  if (!oneOf(CATEGORIES, value.category)) errors.push(`category must be one of ${CATEGORIES.join(", ")}`);

  // Array.from, not forEach: forEach skips the holes of a sparse array, which
  // would let [ , x] through.
  if (!Array.isArray(value.cited_fields)) errors.push("cited_fields must be an array");
  else
    Array.from(value.cited_fields as unknown[]).forEach((item, i) => {
      const at = `cited_fields[${i}]`;
      if (!isObject(item)) return void errors.push(`${at} must be an object`);
      onlyKeys(item, ["field", "authored"], at, errors);
      if (!nonEmpty(item.field)) errors.push(`${at}.field must be a non-empty string`);
      if (!oneOf(AUTHORED, item.authored)) errors.push(`${at}.authored must be one of ${AUTHORED.join(", ")}`);
    });

  if (!Array.isArray(value.gaps)) errors.push("gaps must be an array");
  else Array.from(value.gaps as unknown[]).forEach((g, i) => nonEmpty(g) || errors.push(`gaps[${i}] must be a non-empty string`));

  const action = value.recommended_action;
  if (action !== undefined && action !== null) {
    if (!isObject(action)) errors.push("recommended_action must be an object or null");
    else {
      onlyKeys(action, ["type", "target"], "recommended_action", errors);
      if (!nonEmpty(action.type)) errors.push("recommended_action.type must be a non-empty string");
      if (!nonEmpty(action.target)) errors.push("recommended_action.target must be a non-empty string");
    }
  }

  if (!nonEmpty(value.model)) errors.push("model must be a non-empty string");
  if (!nonEmpty(value.prompt_version)) errors.push("prompt_version must be a non-empty string");

  return errors.length ? { ok: false, errors } : { ok: true, verdict: value as unknown as Verdict };
}

// A provenance-map key ending in this covers every child of its prefix.
export const CHILDREN_SUFFIX = ".*";
const SEGMENT = /^[A-Za-z0-9_-]+$/;

const own = (map: ProvenanceMap, key: string): boolean => Object.prototype.hasOwnProperty.call(map, key);

function checked(key: string, authored: unknown): Authored {
  if (!oneOf(AUTHORED, authored)) throw new Error(`provenance map gives ${key} unknown author ${String(authored)}`);
  return authored;
}

// An exact key, else the longest "prefix.*" key, else adversary. A malformed map
// (an author outside AUTHORED) throws: that is the caller's bug, not the model's.
export function resolveAuthored(field: string, provenance: ProvenanceMap): Authored {
  if (!field.endsWith(CHILDREN_SUFFIX) && own(provenance, field)) return checked(field, provenance[field]);
  const segments = field.split(".");
  if (!segments.every((s) => SEGMENT.test(s))) return UNKNOWN_FIELD_AUTHOR;
  for (let end = segments.length - 1; end > 0; end--) {
    const key = segments.slice(0, end).join(".") + CHILDREN_SUFFIX;
    if (own(provenance, key)) return checked(key, provenance[key]);
  }
  return UNKNOWN_FIELD_AUTHOR;
}

// Each item is a field name or an object with a field; any authored it carries is ignored.
export function attachProvenance(cited: readonly unknown[], provenance: ProvenanceMap): CitedField[] {
  return Array.from(cited).map((item) => {
    const field = isObject(item) ? item.field : item;
    if (!nonEmpty(field)) throw new Error(`cited field must be a non-empty string, got ${JSON.stringify(field)}`);
    return { field, authored: resolveAuthored(field, provenance) };
  });
}

// Benign without any sensor-authored citation becomes inconclusive.
export function enforceProvenance(v: Verdict): Verdict {
  if (v.verdict !== "benign") return v;
  if (v.cited_fields.some((c) => c.authored === "sensor")) return v;
  const gaps = v.gaps.includes(NO_SENSOR_CITATION_GAP) ? v.gaps : [...v.gaps, NO_SENSOR_CITATION_GAP];
  return { ...v, verdict: "inconclusive", gaps };
}

// One model citation with authored set by code. Anything that is not a non-empty
// field name (or an object holding one) is passed on for parseVerdict to refuse,
// as verdict.py's _cite passes it on for pydantic to refuse.
function cite(item: unknown, provenance: ProvenanceMap): unknown {
  const field = isObject(item) ? item.field : item;
  if (nonEmpty(field)) return { field, authored: resolveAuthored(field, provenance) };
  if (isObject(item) || typeof item === "string") return { field, authored: UNKNOWN_FIELD_AUTHOR };
  return item;
}

// Never throws on what the model wrote: gaps and cited_fields that are absent or
// null mean none, and anything else wrong (raw not an object, cited_fields not an
// array, a citation without a field name, a hole in an array, ...) is
// {ok: false}. verdict_from_model_output raises pydantic.ValidationError for
// exactly the same inputs. A malformed provenance map throws in both.
export function verdictFromModelOutput(
  raw: unknown,
  provenance: ProvenanceMap,
  stamp: { model: string; prompt_version: string },
): VerdictParse {
  if (!isObject(raw)) return { ok: false, errors: ["model output must be an object"] };
  const rawCited = raw.cited_fields ?? [];
  const cited_fields = Array.isArray(rawCited) ? Array.from(rawCited as unknown[], (c) => cite(c, provenance)) : rawCited;
  const parsed = parseVerdict({
    ...raw,
    cited_fields,
    gaps: raw.gaps ?? [],
    model: stamp.model,
    prompt_version: stamp.prompt_version,
  });
  return parsed.ok ? { ok: true, verdict: enforceProvenance(parsed.verdict) } : parsed;
}
