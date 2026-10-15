import { hasHandle, resolveExact, type RunValues } from "../../core/guards.js";
import { logger } from "../../core/log.js";
import type { Projection } from "./ledger.js";
import { runValuesOf } from "./handles.js";

const log = logger("hunt.findings");

// Deep enough for a salvaged record ({ gathered: [{ rows: [{ finding_id }] }] }) and
// no deeper: the payload is attacker-reachable, so a walk over it stays bounded.
const MAX_DEPTH = 6;

function collect(value: unknown, depth: number, into: Set<string>, values: RunValues, dropped: string[]): void {
  if (depth > MAX_DEPTH || typeof value !== "object" || value === null) return;
  if (Array.isArray(value)) {
    for (const item of value) collect(item, depth + 1, into, values, dropped);
    return;
  }
  for (const [key, inner] of Object.entries(value)) {
    if (key === "finding_id" && typeof inner === "string" && inner.trim() !== "") {
      // Guards (W0.30): a worker that only saw a handle cites the handle. It is
      // filled from the dispatch's journaled values; one the run cannot fill never
      // leaves the agent layer as {{h:...}} text.
      const id = hasHandle(inner) ? resolveExact(inner, values) : inner;
      if (id === null || id.trim() === "") dropped.push(inner.trim());
      else into.add(id.trim());
    } else collect(inner, depth + 1, into, values, dropped);
  }
}

// The alerts the hunt's evidence cites: rows carrying a finding_id, as findings_search
// and get_finding return them. One that only turned up in a search result and never
// became evidence is not here, so it is not linked to the case.
export function citedFindings(projection: Projection): string[] {
  const ids = new Set<string>();
  const values = runValuesOf(projection.dispatches.values());
  const dropped: string[] = [];
  for (const record of projection.evidence.values()) collect(record.payload, 0, ids, values, dropped);
  if (dropped.length > 0) log.warn("cited finding ids named handles the run holds no value for; not linked", { count: dropped.length });
  return [...ids];
}
