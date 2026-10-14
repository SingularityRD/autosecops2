import { GATED, HUMAN_ONLY, type Effect } from "./tool-effects.js";

export type { Effect } from "./tool-effects.js";

// One of the four Phase-0 contracts. Consumed by the registry and dispatch, the
// query port and its SIEM adapters, and the hunt workflow's tools.

export interface ToolBounds {
  readonly maxRows: number;
  readonly timeoutMs: number;
}

// Opaque to this layer: the API signs it for a session's user, InvokeRequest.principal
// verifies it. Absent means no person is behind the run, and tools record "agent".
export type ToolPrincipal = string;

// The approved checkpoint a gated call carries to the far side: the run that
// parked on it and the checkpoint a person answered. InvokeRequest.approval.
export interface ToolApproval {
  run_id: string;
  checkpoint_id: string;
}

// timeout and unavailable are genuine visibility gaps; refused and invalid_args
// are defects and must never be recorded as one (CONTEXT.md, Visibility gap).
export type ToolFailure =
  | { kind: "invalid_args"; detail: string }
  | { kind: "refused"; detail: string }
  | { kind: "timeout"; timeoutMs: number }
  | { kind: "unavailable"; detail: string }
  | { kind: "backend_error"; detail: string };

export type ToolResult =
  | { ok: true; rows: readonly unknown[]; rowCount: number; capped: boolean; sourceSystem: string }
  | { ok: false; failure: ToolFailure };

// What an adapter author writes. Receives the bounds and must enforce them at
// the source: capping a serialised result afterwards yields malformed data.
export interface ToolAdapter {
  readonly id: string;
  readonly description: string;
  readonly parameters: Record<string, unknown>;
  execute(args: Record<string, unknown>, bounds: ToolBounds, signal: AbortSignal): Promise<ToolResult>;
  close?(): Promise<void>;
}

declare const registered: unique symbol;

// The only tool shape the registry and the harness ever hold. Unconstructable
// outside defineTool, which is how a caller is prevented from opting out of bounds.
export interface RegisteredTool {
  readonly [registered]: true;
  readonly id: string;
  readonly description: string;
  readonly parameters: Record<string, unknown>;
  readonly bounds: ToolBounds;
  // Whether this tool answers in this process. Dispatch reads it: the remote one
  // posts an id to a backend that has never heard of the run's own ledger.
  readonly local: boolean;
  // What calling it does to the world, from the one table (core/llm/tool_effects.py,
  // mirrored in tool-effects.ts). A gated effect parks the call for a person
  // whatever the run's approvals list says. Absent only for a tool built by hand
  // in-process, which the approvals list alone then governs.
  readonly effect?: Effect;
  invoke(args: Record<string, unknown>): Promise<ToolResult>;
  close(): Promise<void>;
}

// Whether a call to this tool may run only once a person approves it.
export function isGated(tool: Pick<RegisteredTool, "effect">): boolean {
  return tool.effect !== undefined && GATED.has(tool.effect);
}

// Whether a tool decides an approval: never on a model's tool list, approved or
// not (W1.7b). A person decides those on the approvals screen, over HTTP.
export function isHumanOnly(tool: Pick<RegisteredTool, "effect">): boolean {
  return tool.effect !== undefined && HUMAN_ONLY.has(tool.effect);
}

// An adapter returning more rows than it was told to is a defect in the adapter,
// so it throws rather than resolving; truncating here would malform the result.
export class ToolBoundsViolation extends Error {}

// The brand is type-only and is never materialised, so the cast is the whole
// mechanism: an object literal cannot satisfy RegisteredTool on its own.
export function defineTool(adapter: ToolAdapter, bounds: ToolBounds, local = false, effect?: Effect): RegisteredTool {
  return {
    id: adapter.id,
    description: adapter.description,
    parameters: adapter.parameters,
    bounds,
    local,
    ...(effect === undefined ? {} : { effect }),
    invoke: (args) => invokeBounded(adapter, bounds, args),
    close: async () => void (await adapter.close?.()),
  } as RegisteredTool;
}

async function invokeBounded(
  adapter: ToolAdapter,
  bounds: ToolBounds,
  args: Record<string, unknown>,
): Promise<ToolResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), bounds.timeoutMs);
  try {
    const result = await adapter.execute(args, bounds, controller.signal);
    if (result.ok && result.rowCount > bounds.maxRows) {
      throw new ToolBoundsViolation(
        `${adapter.id} returned ${result.rowCount} rows against a cap of ${bounds.maxRows}`,
      );
    }
    return result;
  } catch (error) {
    if (error instanceof ToolBoundsViolation) throw error;
    if (controller.signal.aborted) return { ok: false, failure: { kind: "timeout", timeoutMs: bounds.timeoutMs } };
    return { ok: false, failure: { kind: "backend_error", detail: messageOf(error) } };
  } finally {
    clearTimeout(timer);
  }
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
