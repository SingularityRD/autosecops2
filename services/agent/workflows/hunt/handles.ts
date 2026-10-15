import { type RunValues } from "../../core/guards.js";

// Guards (W0.30): the values a hunt's guarded dispatches journaled. citedFindings
// resolves the alert ids it links with them; every other exit converts handles in
// core/outbound.ts (markers in prose, values in subject_values).

// Every value the run's guarded dispatches journaled, by handle key. Keys carry their
// dispatch's scope (quarantine.ts scopeToken), so the union is unambiguous.
export function runValuesOf(dispatches: Iterable<{ handles?: Record<string, string> }>): RunValues {
  const byKey = new Map<string, string>();
  for (const dispatch of dispatches) for (const [key, value] of Object.entries(dispatch.handles ?? {})) byKey.set(key, value);
  return { byKey, byRef: new Map() };
}

