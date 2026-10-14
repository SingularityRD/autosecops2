import { describe, expect, it } from "vitest";
import { approvalId, TOOL_CALL, type Harness, type TurnConfig } from "../../core/loop.js";
import { drain, streamTurn } from "../../core/stream.js";
import { budgetOf, FRESH, unmeteredQuota } from "../../core/budget.js";
import { registryOf } from "../../core/registry.js";
import { InProcessState } from "../../core/state.js";
import { nullMemory } from "../../core/memory.js";
import { remoteDispatch } from "../../core/remote.js";
import { SpecError, DEFAULT_BUDGETS, DEFAULT_DISPATCH, DEFAULT_RUNTIME, type RunSpec, type ToolSpec } from "../../core/spec.js";
import { isGated, isHumanOnly, type RegisteredTool, type ToolApproval, type ToolResult } from "../../contracts/tool.js";
import { EFFECTS, GATED, HUMAN_ONLY, TOOL_EFFECTS } from "../../contracts/tool-effects.js";
import type { ToolDispatch } from "../../core/seams.js";
import type { CheckpointPayload } from "../../contracts/events.js";
import { toolsFrom, effectOf } from "../../tools/remote.js";
import { grantsOf, runCompose } from "../../workflows/compose/workflow.js";
import type { Mirror, PhaseUpdate } from "../../workflows/compose/mirror.js";
import type { ComposeKinds } from "../../workflows/compose/vocabulary.js";
import { scriptedProvider, type ScriptedTurn } from "../support/scripted-provider.js";

// W1.7: a tool that changes the world runs only once a person approves the call,
// on every surface. The class comes from one table (core/llm/tool_effects.py,
// mirrored in contracts/tool-effects.ts); the run's approvals list can add a
// gate but can no longer leave one off.

const RUN = "7a170000-0000-4000-8000-000000000017";
const ROLE = "actor";
const ARGS = '{"target":"10.0.0.1"}';

function spec(id: string, extra: Record<string, unknown> = {}): ToolSpec {
  return { id, kind: "remote", description: `the ${id} tool`, parameters: { type: "object" }, ...extra };
}

// Counts every call that would leave the process, and what rode with it.
function counting(): ToolDispatch & { calls: { tool: string; approval?: ToolApproval }[] } {
  const calls: { tool: string; approval?: ToolApproval }[] = [];
  return {
    calls,
    invoke: async (tool, _args, _signal, _agent, approval): Promise<ToolResult> => {
      calls.push({ tool: tool.id, ...(approval === undefined ? {} : { approval }) });
      return { ok: true, rows: [{ done: true }], rowCount: 1, capped: false, sourceSystem: "test" };
    },
  };
}

function harnessOf(tools: readonly RegisteredTool[], script: readonly ScriptedTurn[], dispatch: ToolDispatch, state = new InProcessState()): Harness {
  return {
    provider: scriptedProvider(script),
    registry: registryOf(tools, { [ROLE]: tools.map((tool) => tool.id) }),
    dispatch,
    budget: budgetOf({ ...DEFAULT_BUDGETS, max_calls: 50 }, unmeteredQuota, Date.now, FRESH),
    memory: nullMemory,
    state,
  };
}

function turn(approvals: readonly string[] = []): TurnConfig {
  return {
    run_id: RUN,
    run_kind: "tally",
    role: ROLE,
    system: "act",
    task: "act once",
    schema: null,
    max_turns: 3,
    approvals: new Set(approvals),
    verbs: [],
    result_cap: 4_000,
    recall_limit: 0,
  };
}

const GATED_IDS = Object.entries(TOOL_EFFECTS)
  .filter(([, effect]) => GATED.has(effect))
  .map(([id]) => id)
  .sort();

describe("the mirrored effect table", () => {
  it("classifies every tool into a known class", () => {
    for (const [id, effect] of Object.entries(TOOL_EFFECTS)) expect(EFFECTS, id).toContain(effect);
  });

  it("gates write and destructive, and nothing else", () => {
    expect([...GATED].sort()).toEqual(["destructive", "write"]);
  });

  // A vacuous pass is the one way the ratchet below fails silently.
  it("holds the EDR, IdP and firewall actions the compose catalog could grant", () => {
    for (const id of ["mde_isolate", "cb_quarantine", "aad_disable_user", "pan_block_ip", "cf_waf_block_ip", "atomic_red_team_execute"]) {
      expect(GATED_IDS).toContain(id);
    }
    expect(GATED_IDS.length).toBeGreaterThanOrEqual(20);
  });
});

describe("a declared tool's effect", () => {
  it("is what the spec states", () => {
    expect(effectOf(spec("mde_isolate", { effect: "destructive" }))).toBe("destructive");
    expect(effectOf(spec("anything", { effect: "read_only" }))).toBe("read_only");
  });

  it("is the table's when the spec states none", () => {
    expect(effectOf(spec("cb_quarantine"))).toBe("destructive");
    expect(effectOf(spec("search_findings"))).toBe("read_only");
  });

  // The restrictive end: a name nobody classified parks rather than runs.
  it("is destructive for a name neither the spec nor the table knows", () => {
    expect(effectOf(spec("acme_frobnicate"))).toBe("destructive");
  });

  it("refuses a class that does not exist", () => {
    expect(() => effectOf(spec("x", { effect: "harmless" }))).toThrow(SpecError);
  });

  it("rides every tool toolsFrom builds, local ones included", () => {
    const [remote, local] = toolsFrom([spec("pan_block_ip"), { ...spec("expand"), kind: "local" }]);
    expect(remote?.effect).toBe("destructive");
    expect(local?.effect).toBe("read_only");
  });
});

// The ratchet: every gated tool in the table, granted with an empty approvals
// list, parks the call for a person and never reaches the dispatch.
describe("no gated tool runs without a person", () => {
  it.each(GATED_IDS)("%s parks and is not dispatched", async (id) => {
    const tools = toolsFrom([spec(id)]);
    expect(isGated(tools[0] as RegisteredTool)).toBe(true);
    const dispatch = counting();
    const outcome = await drain(streamTurn(turn(), harnessOf(tools, [{ calls: [{ tool: id, args: ARGS }] }], dispatch)));

    expect(outcome.status).toBe("waiting_approval");
    expect(outcome.pending).toEqual({ checkpoint_id: approvalId(RUN, id, ARGS), tool: id, args: ARGS });
    expect(dispatch.calls).toEqual([]);
  });

  it("counts zero ungated write tools", async () => {
    let ungated = 0;
    for (const id of GATED_IDS) {
      const dispatch = counting();
      await drain(streamTurn(turn(), harnessOf(toolsFrom([spec(id)]), [{ calls: [{ tool: id, args: ARGS }] }], dispatch)));
      if (dispatch.calls.length > 0) ungated += 1;
    }
    expect(ungated).toBe(0);
  });

  it("still runs a read tool unasked", async () => {
    const dispatch = counting();
    const outcome = await drain(
      streamTurn(turn(), harnessOf(toolsFrom([spec("search_findings")]), [{ calls: [{ tool: "search_findings", args: "{}" }] }, { content: "ok" }], dispatch)),
    );
    expect(outcome.status).toBe("completed");
    expect(dispatch.calls).toEqual([{ tool: "search_findings" }]);
  });

  it("carries the approved checkpoint to the dispatch once a person approved", async () => {
    const state = new InProcessState();
    const checkpoint_id = approvalId(RUN, "mde_isolate", ARGS);
    await state.append(RUN, [
      {
        run_id: RUN,
        run_kind: "tally",
        kind: "resolution",
        payload: { checkpoint_id, actor: "analyst", answer: "approve", text: "", resolved_at: new Date().toISOString() },
      },
    ]);
    const dispatch = counting();
    const outcome = await drain(
      streamTurn(turn(), harnessOf(toolsFrom([spec("mde_isolate")]), [{ calls: [{ tool: "mde_isolate", args: ARGS }] }, { content: "done" }], dispatch, state)),
    );
    expect(outcome.status).toBe("completed");
    expect(dispatch.calls).toEqual([{ tool: "mde_isolate", approval: { run_id: RUN, checkpoint_id } }]);
  });
});

describe("the remote dispatch", () => {
  async function bodyOf(approval?: ToolApproval): Promise<Record<string, unknown>> {
    let sent: Record<string, unknown> = {};
    const fetch = (async (_url: string, init: RequestInit) => {
      sent = JSON.parse(String(init.body)) as Record<string, unknown>;
      return new Response(JSON.stringify({ ok: true, rows: [], rowCount: 0, capped: false, sourceSystem: "t" }), { status: 200 });
    }) as unknown as typeof globalThis.fetch;
    const [tool] = toolsFrom([spec("mde_isolate")]);
    await remoteDispatch({ url: "http://far/invoke", token: "t", fetch }).invoke(tool as RegisteredTool, {}, undefined, undefined, approval);
    return sent;
  }

  it("sends the approval the far side checks", async () => {
    expect((await bodyOf({ run_id: RUN, checkpoint_id: "apr-1" }))["approval"]).toEqual({ run_id: RUN, checkpoint_id: "apr-1" });
  });

  it("sends none for a call nobody approved", async () => {
    expect(await bodyOf()).not.toHaveProperty("approval");
  });
});

// The compose surface: a phase granted an EDR action by its playbook, with a
// config whose approvals list is empty, parks the step instead of running it.
describe("a compose phase granted a destructive tool", () => {
  function composeSpec(tool: string): RunSpec {
    return {
      sections: {},
      model: "scripted",
      budgets: DEFAULT_BUDGETS,
      runtime: DEFAULT_RUNTIME,
      tools: [spec(tool)],
      approvals: [],
      thresholds: {},
      arch: "compose",
      name: "contain",
      description: "",
      use_case: "",
      trigger_examples: [],
      objectives: [],
      scope: {},
      narrative: "",
      prompt: "",
      phases: [{ id: "act", agent: "auto_responder", name: "Contain", instructions: "contain", approval_required: false, tools: [tool], prompt: "" }],
      roles: { workers: {} },
      dispatch: DEFAULT_DISPATCH,
      digest: {},
    };
  }

  function mirror(): Mirror & { updates: PhaseUpdate[] } {
    const updates: PhaseUpdate[] = [];
    return {
      answerable: true,
      updates,
      phase: async (_run, update) => void updates.push(update),
      terminal: async () => {},
      status: async () => true,
      handoff: async () => true,
      findings: async () => true,
      decisions: async () => [],
    };
  }

  it.each(["mde_isolate", "cb_quarantine", "aad_disable_user", "pan_block_ip", "cloudflare_cf_waf_block_ip"])(
    "parks on %s for a person",
    async (tool) => {
      const run = composeSpec(tool);
      const dispatch = counting();
      const state = new InProcessState<ComposeKinds>();
      const harness: Harness<ComposeKinds> = {
        provider: scriptedProvider([{ calls: [{ tool, args: ARGS }] }]),
        registry: registryOf(toolsFrom(run.tools), grantsOf(run)),
        dispatch,
        budget: budgetOf(run.budgets, unmeteredQuota, Date.now, FRESH),
        memory: nullMemory,
        state,
      };
      const watched = mirror();
      const report = await runCompose(harness, { run_id: RUN, spec: run, mirror: watched });

      expect(report.status).toBe("waiting_approval");
      expect(dispatch.calls).toEqual([]);
      const parked = watched.updates.at(-1);
      expect(parked?.status).toBe("pending_approval");
      // The question names the tool: the far side checks an approval is about it.
      expect(parked?.question).toContain(tool);
      // And the call itself rides along: the approval is bound to these arguments
      // and the person is shown them (W1.7b).
      expect(parked?.tool).toBe(tool);
      expect(parked?.args).toEqual(JSON.parse(ARGS));
    },
  );
});

// W1.7b: a decision on the approval queue is a person's, never a model's.
describe("a tool that decides an approval", () => {
  it("is the human-only class, and the table's approve/reject are in it", () => {
    expect([...HUMAN_ONLY]).toEqual(["decision"]);
    expect(TOOL_EFFECTS["approve_action"]).toBe("decision");
    expect(TOOL_EFFECTS["reject_action"]).toBe("decision");
  });

  it.each(["approve_action", "reject_action"])("%s is never declared to the model nor dispatched", async (id) => {
    const tools = toolsFrom([spec(id), spec("search_findings")]);
    expect(isHumanOnly(tools[0] as RegisteredTool)).toBe(true);
    const dispatch = counting();
    const provider = scriptedProvider([{ calls: [{ tool: id, args: '{"action_id":"a"}' }] }, { content: "ok" }]);
    const harness = { ...harnessOf(tools, [], dispatch), provider };
    // Even with the run's approvals list naming it.
    const outcome = await drain(streamTurn(turn([id]), harness));
    const declared = provider.requests[0]?.tools.map((tool) => tool.id);

    expect(declared).toEqual(["search_findings"]);
    expect(outcome.status).toBe("completed");
    expect(dispatch.calls).toEqual([]);
  });
});

describe("a parked call's checkpoint", () => {
  it("names the call and its parsed arguments for the backend to bind", async () => {
    const state = new InProcessState();
    const dispatch = counting();
    await drain(streamTurn(turn(), harnessOf(toolsFrom([spec("mde_isolate")]), [{ calls: [{ tool: "mde_isolate", args: ARGS }] }], dispatch, state)));
    const raised = (await state.read(RUN)).find((event) => event.kind === "checkpoint");
    const payload = raised?.payload as CheckpointPayload;
    expect(payload.context).toEqual({ [TOOL_CALL]: { tool: "mde_isolate", args: { target: "10.0.0.1" } } });
    expect(payload.question).toContain(ARGS);
  });
});
