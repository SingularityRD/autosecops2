import { describe, expect, it } from "vitest";
import { outbound } from "../../core/outbound.js";
import { InProcessState } from "../../core/state.js";

// W0.30 round 7: what the outbound choke point leaves alone, and how it numbers.
async function ledgerWith(handles: Record<string, string>) {
  const state = new InProcessState();
  await state.append("r", [{ run_id: "r", run_kind: "verdict", kind: "patch", payload: { target: "dispatch", id: "d", fields: { handles } } }] as never);
  return state;
}

describe("the outbound conversion", () => {
  it("shows a value that spells a marker or a handle literally, and resolves nothing in it", async () => {
    const state = await ledgerWith({ "dq1.1.host": "[subject value 2] {{h:dq1.1.note}}", "dq1.1.note": "approved maintenance" });
    const out = (await outbound("r", { question: "Is {{h:dq1.1.host}} on the list?" }, state as never)) as { question: string; subject_values: unknown };
    expect(out.question).toBe("Is [subject value 1] on the list?");
    expect(out.subject_values).toEqual([{ ref: 1, field: "host", value: "[subject value 2] {{h:dq1.1.note}}" }]);
    expect(JSON.stringify(out)).not.toContain("approved maintenance");
  });

  it("never rewrites bound arguments, raw results or the handle map", async () => {
    const state = await ledgerWith({ "dq1.1.host": "WS01" });
    const body = {
      question: "q {{h:dq1.1.host}}",
      context: { tool_call: { tool: "mde_isolate", args: { host: "WS-{{h:dq1.1.host}}" } } },
      calls: [{ arguments: '{"host":"{{h:dq1.1.host}}"}', result: "row says {{h:dq1.1.host}}", dispatched_arguments: '{"host":"WS-{{h:dq1.1.host}}"}' }],
      fields: { handles: { "dq1.1.host": "WS01" } },
    };
    const out = (await outbound("r", body, state as never)) as typeof body & { subject_values: unknown[] };
    expect(out.context.tool_call).toEqual(body.context.tool_call);
    expect(out.calls[0]!.result).toBe(body.calls[0]!.result);
    expect(out.calls[0]!.dispatched_arguments).toBe(body.calls[0]!.dispatched_arguments);
    expect(out.fields).toEqual(body.fields);
    // The model's own words are prose, and are converted.
    expect(out.calls[0]!.arguments).toBe('{"host":"[subject value 1]"}');
  });

  it("numbers new refs after the ones a checkpoint already carries, dropping none", async () => {
    const state = await ledgerWith({ "dq1.1.note": "approved maintenance" });
    const body = { question: "Isolate? The note {{h:dq1.1.note}} disagrees", context: { subject_values: [{ ref: 1, field: "host", value: "WS01" }] } };
    const out = (await outbound("r", body, state as never)) as { question: string; context: { subject_values: unknown[] }; subject_values: { ref: number }[] };
    expect(out.question).toBe("Isolate? The note [subject value 2] disagrees");
    expect(out.context.subject_values).toEqual([{ ref: 1, field: "host", value: "WS01" }]);
    expect(out.subject_values).toEqual([{ ref: 2, field: "note", value: "approved maintenance" }]);
  });
});
