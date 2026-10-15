import { displaySafe, forPeople, SubjectValues, type RunValues, type SubjectValueRow } from "./guards.js";
import { errorFields, logger } from "./log.js";
import type { State } from "./seams.js";

const log = logger("agent.outbound");

// W0.30 round 3: the one choke point every body the agent layer posts to the backend
// passes through (core/checkpoints.ts httpAnnounce, workflows/compose/mirror.ts
// httpMirror). A guarded run's model-written text can carry handles ({{h:...}});
// here each becomes a "[subject value N]" marker and the value travels beside the
// prose in subject_values, before a backend or a person sees it. A handle the run
// holds no value for becomes a neutral marker. Nothing posted ever carries {{h:...}},
// and no prose carries subject text.
//
// The values are what the run's ledger journaled: any event payload, or patch
// fields, carrying a `handles` map (key -> value). The ledger is set by the worker
// for the process; without one every handle becomes the marker.

let ledger: State | null = null;

export function outboundLedger(state: State | null): void {
  ledger = state;
}

const HANDLE_TEXT = "{{h:";

// Single-line display fields: escaped whole (newlines too), as the backend's
// display_safe does for a title. Other strings (markdown bodies) keep their layout;
// the substituted values are escaped either way.
const DISPLAY_KEYS: ReadonlySet<string> = new Set(["question", "reason", "title", "rationale", "statement", "parked_reason"]);

function handlesIn(payload: unknown, into: Map<string, string>): void {
  if (typeof payload !== "object" || payload === null) return;
  const record = payload as Record<string, unknown>;
  for (const holder of [record, record["fields"]]) {
    const handles = typeof holder === "object" && holder !== null ? (holder as Record<string, unknown>)["handles"] : undefined;
    if (typeof handles !== "object" || handles === null) continue;
    for (const [key, value] of Object.entries(handles)) if (typeof value === "string") into.set(key, value);
  }
}

export async function outboundValues(runId: string, state: State | null = ledger): Promise<RunValues> {
  const byKey = new Map<string, string>();
  if (state !== null) {
    try {
      for (const event of await state.read(runId)) handlesIn(event.payload, byKey);
    } catch (error) {
      log.warn("could not read the run's handle values; handles go out as markers", { run_id: runId, ...errorFields(error) });
    }
  }
  return { byKey, byRef: new Map() };
}

function convert(value: unknown, values: RunValues, key: string | null, collected: SubjectValues): unknown {
  if (typeof value === "string") {
    if (!value.includes(HANDLE_TEXT)) return value;
    const filled = forPeople(value, values, collected);
    return key !== null && DISPLAY_KEYS.has(key) ? displaySafe(filled) : filled;
  }
  if (Array.isArray(value)) return value.map((one) => convert(one, values, key, collected));
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, convert(v, values, k, collected)]));
  }
  return value;
}

// body unchanged (the same object) when nothing in it names a handle. Otherwise every
// handle in its prose is a "[subject value N]" marker and, for an object body, the
// values ride beside it as subject_values ({ref, field, value}); a consumer renders
// those as plain text (W0.30 round 6).
export async function outbound<T>(runId: string, body: T, state: State | null = ledger): Promise<T> {
  if (!(JSON.stringify(body) ?? "").includes(HANDLE_TEXT)) return body;
  const collected = new SubjectValues();
  const converted = convert(body, await outboundValues(runId, state), null, collected);
  if (collected.rows.length === 0 || typeof converted !== "object" || converted === null || Array.isArray(converted)) return converted as T;
  const prior = (converted as { subject_values?: SubjectValueRow[] }).subject_values ?? [];
  return { ...(converted as object), subject_values: [...prior, ...collected.rows] } as T;
}
