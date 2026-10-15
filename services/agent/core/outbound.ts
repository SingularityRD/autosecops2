import { displaySafe, forPeople, type RunValues } from "./guards.js";
import { errorFields, logger } from "./log.js";
import type { State } from "./seams.js";

const log = logger("agent.outbound");

// W0.30 round 3: the one choke point every body the agent layer posts to the backend
// passes through (core/checkpoints.ts httpAnnounce, workflows/compose/mirror.ts
// httpMirror). A guarded run's model-written text can carry handles ({{h:...}});
// here each becomes the value it stands for, escaped and marked as the subject's,
// before a backend or a person sees it. A handle the run holds no value for becomes
// a neutral marker. Nothing posted ever carries {{h:...}}.
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

function convert(value: unknown, values: RunValues, key: string | null): unknown {
  if (typeof value === "string") {
    if (!value.includes(HANDLE_TEXT)) return value;
    const filled = forPeople(value, values);
    return key !== null && DISPLAY_KEYS.has(key) ? displaySafe(filled) : filled;
  }
  if (Array.isArray(value)) return value.map((one) => convert(one, values, key));
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, convert(v, values, k)]));
  }
  return value;
}

// body unchanged (the same object) when nothing in it names a handle.
export async function outbound<T>(runId: string, body: T, state: State | null = ledger): Promise<T> {
  if (!(JSON.stringify(body) ?? "").includes(HANDLE_TEXT)) return body;
  return convert(body, await outboundValues(runId, state), null) as T;
}
