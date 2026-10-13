import { defineTool, type Effect, type RegisteredTool, type ToolBounds, type ToolResult } from "../contracts/tool.js";
import { EFFECTS, TOOL_EFFECTS } from "../contracts/tool-effects.js";
import { SpecError, type ToolSpec } from "../core/spec.js";
import { LOCAL, localTool, type LocalExecutor } from "./local.js";

export const REMOTE = "remote";

const DEFAULT_BOUNDS: ToolBounds = { maxRows: 200, timeoutMs: 30_000 };

// Never reached: a remote tool is resolved by remoteDispatch, which posts the id
// rather than calling this. Present because RegisteredTool cannot be built without it.
function unreachable(id: string): ToolResult {
  return { ok: false, failure: { kind: "unavailable", detail: `${id} has no local implementation; it resolves remotely` } };
}

// A local whose answer needs the run in hand, which harnessFor does not have: the
// workflow that owns one rebuilds the registry once it does. Registered rather than
// refused so the run reaches that rebuild, and failing rather than silent if it never does.
function unsupplied(id: string): ToolResult {
  return { ok: false, failure: { kind: "unavailable", detail: `${id} is local and this registry supplied no implementation for it` } };
}

// The far side owns the implementation, so this carries only what the registry and
// the model need: what it is called, what it does, and what it takes.
export function remoteTool(spec: ToolSpec): RegisteredTool {
  const description = typeof spec["description"] === "string" ? spec["description"] : "";
  if (description.trim() === "") throw new SpecError(`tool ${spec.id} needs a description; a model cannot choose between two blank tools`);

  const parameters = spec["parameters"];
  if (typeof parameters !== "object" || parameters === null) throw new SpecError(`tool ${spec.id} needs a parameters schema`);

  return defineTool(
    {
      id: spec.id,
      description,
      parameters: parameters as Record<string, unknown>,
      execute: async () => unreachable(spec.id),
    },
    boundsOf(spec),
    false,
    effectOf(spec),
  );
}

// What a declared tool does to the world. The far side stamps every spec it
// writes with the class from its table; a spec without one (hand-written
// config) is looked up in the mirrored table, and a name neither knows is
// taken as destructive -- the restrictive end -- so it parks for a person.
export function effectOf(spec: ToolSpec): Effect {
  const stated = spec["effect"];
  if (stated !== undefined) {
    if (typeof stated !== "string" || !(EFFECTS as readonly string[]).includes(stated)) {
      throw new SpecError(`tool ${spec.id} declares effect ${String(stated)}; expected one of ${EFFECTS.join(", ")}`);
    }
    return stated as Effect;
  }
  return TOOL_EFFECTS[spec.id] ?? "destructive";
}

export function boundsOf(spec: ToolSpec): ToolBounds {
  return {
    maxRows: typeof spec["max_rows"] === "number" ? spec["max_rows"] : DEFAULT_BOUNDS.maxRows,
    timeoutMs: typeof spec["timeout_ms"] === "number" ? spec["timeout_ms"] : DEFAULT_BOUNDS.timeoutMs,
  };
}

// One place a declared tool becomes a registered one. An unimplemented kind, or a
// local one nothing supplied, throws here rather than answering nothing later.
export function toolsFrom(
  specs: readonly ToolSpec[],
  locals: Readonly<Record<string, LocalExecutor>> = {},
): RegisteredTool[] {
  return specs.map((spec) => {
    if (spec.kind === REMOTE) return remoteTool(spec);
    if (spec.kind === LOCAL) {
      const execute = locals[spec.id] ?? (async () => unsupplied(spec.id));
      return localTool(spec, execute, boundsOf(spec), effectOf(spec));
    }
    throw new SpecError(`tool ${spec.id} declares kind ${spec.kind}, which no adapter implements`);
  });
}
