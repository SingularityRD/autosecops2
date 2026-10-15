import { forModelsDeep, forPeople, forPeopleDeep, type RunValues } from "../../core/guards.js";

// Guards (W0.30 round 2): the values a hunt's guarded dispatches journaled, and the
// one conversion every exit from the agent layer goes through. A handle means
// something only inside the run; a person (report, case file, projection) is shown
// the value marked as written by the subject, and a handle the run cannot fill is
// shown as a neutral marker -- never as {{h:...}} text.

// Every value the run's guarded dispatches journaled, by handle key. Keys carry their
// dispatch's scope (quarantine.ts scopeToken), so the union is unambiguous.
export function runValuesOf(dispatches: Iterable<{ handles?: Record<string, string> }>): RunValues {
  const byKey = new Map<string, string>();
  for (const dispatch of dispatches) for (const [key, value] of Object.entries(dispatch.handles ?? {})) byKey.set(key, value);
  return { byKey, byRef: new Map() };
}

export const peopleText = (text: string, dispatches: Iterable<{ handles?: Record<string, string> }>): string => forPeople(text, runValuesOf(dispatches));

// Untouched when nothing in it names a handle, so a run without guards is served the
// same object it always was.
export function forPeopleOf<T>(value: T, dispatches: Iterable<{ handles?: Record<string, string> }>): T {
  if (!(JSON.stringify(value) ?? "").includes("{{h:")) return value;
  return forPeopleDeep(value, runValuesOf(dispatches));
}

export { forModelsDeep };
