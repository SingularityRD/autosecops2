import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FRESH, budgetOf, unmeteredQuota } from "../../core/budget.js";
import { ZERO_TOKENS } from "../../contracts/budget.js";
import type { RunJob } from "../../contracts/job.js";
import type { ToolResult } from "../../contracts/tool.js";
import { announceOpen, httpAnnounce } from "../../core/checkpoints.js";
import { nullMemory } from "../../core/memory.js";
import { outboundLedger } from "../../core/outbound.js";
import type { Provider, ProviderEvent, TurnRequest } from "../../core/provider.js";
import { registryOf } from "../../core/registry.js";
import type { ToolDispatch } from "../../core/seams.js";
import { InProcessState } from "../../core/state.js";
import type { HarnessFactory } from "../../harness.js";
import { handle } from "../../worker.js";
import { InProcessDirectiveQueue } from "../../workflows/hunt/directives.js";
import { InProcessLeases } from "../support/in-process-leases.js";

// W0.30 round 3: every body the agent layer posts to the backend goes through one
// choke point (core/outbound.ts) that turns a guarded run's handles back into their
// values, escaped and marked as the subject's. Swept here over a real worker run with
// guards ON and budget_anomaly=ask: the lead writes a handle into its checkpoint, and
// the checkpoint, the paused status and every other post must carry the real value.

const FIXTURES = join(import.meta.dirname, "..", "fixtures");
const LEGACY_ID = "demo2-ts-009";
const RLO = String.fromCharCode(0x202e);
// Subject-written, with a bidi override in it: shown escaped, never raw.
const HOST = `WS${RLO}EVIL`;

const dispatch: ToolDispatch = {
  invoke: async (tool): Promise<ToolResult> =>
    tool.id === "search_findings"
      ? { ok: true, rows: [{ finding_id: LEGACY_ID, host: HOST }], rowCount: 1, capped: false, sourceSystem: "findings" }
      : { ok: true, rows: [], rowCount: 0, capped: false, sourceSystem: "none" },
};

const text = (request: TurnRequest) => JSON.stringify(request.messages);
const has = (schema: Record<string, unknown>, key: string) => key in ((schema["properties"] as Record<string, unknown>) ?? {});

function provider(): Provider {
  let leads = 0;
  return {
    model: "scripted/model",
    provider_type: "scripted",
    stream: async function* (request: TurnRequest): AsyncGenerator<ProviderEvent> {
      const schema = request.emit;
      if (schema !== undefined) {
        let answer: unknown;
        if (has(schema, "action")) {
          leads += 1;
          const seen = text(request);
          const hypothesis = /\bh-[0-9a-f]{8}\b/.exec(seen)?.[0] ?? "";
          const handle = /\{\{h:[A-Za-z0-9_.:-]+host\}\}/.exec(seen)?.[0] ?? "NO-HANDLE";
          answer =
            leads === 1
              ? { action: "INVESTIGATE", rationale: "look at the alerts", query_intent: "which alerts fired", ...(hypothesis === "" ? {} : { target_hypothesis_id: hypothesis }), worker_agent_id: "threat_hunter", evidence_citations: [] }
              : { action: "CHECKPOINT", rationale: `Is ${handle} on the change list?`, evidence_citations: [] };
        } else if (has(schema, "addressed_to_reader")) {
          answer = {
            findings: [{ source_system: "findings", summary: "an alert fired", values: [{ field: "finding_id", value: LEGACY_ID, authored: "subject" }, { field: "host", value: HOST, authored: "subject" }] }],
            addressed_to_reader: false,
          };
        } else {
          const seen = text(request);
          const handles = [...seen.matchAll(/\{\{h:[A-Za-z0-9_.:-]+\}\}/g)].map((m) => m[0]);
          answer = {
            results: [{ source_system: "findings", summary: `alert on ${handles.join(" ")}`, salience: "notable", why_notable: "x", payload: JSON.stringify({ cited: handles.filter((h) => h.includes("finding_id")).map((h) => ({ finding_id: h })) }) }],
          };
        }
        yield { type: "text_delta", text: JSON.stringify(answer) };
        yield { type: "usage", tokens: ZERO_TOKENS };
        return;
      }
      yield { type: "usage", tokens: ZERO_TOKENS };
      const isWorker = request.tools.some((tool) => tool.id === "search_findings");
      if (isWorker && !request.messages.some((m) => m.role === "tool")) yield { type: "tool_call", call: { id: "c1", tool: "search_findings", args: '{"query":"x"}' } };
    },
  };
}

const build: HarnessFactory = (_kind, spec, state, memory = nullMemory, seed = FRESH) => ({
  provider: provider(),
  registry: registryOf([], {}),
  dispatch,
  budget: budgetOf({ ...spec.budgets, max_calls: 40 }, unmeteredQuota, Date.now, seed),
  memory,
  state,
});

function config(): string {
  const dir = mkdtempSync(join(tmpdir(), "w030-"));
  const path = join(dir, "hunt.config.yaml");
  writeFileSync(path, `${readFileSync(join(FIXTURES, "hunt.config.yaml"), "utf8")}\ncheckpoints:\n  budget_anomaly: ask\n`);
  return path;
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  outboundLedger(null);
});

describe("everything a guarded run posts to the backend", () => {
  it("carries the real (escaped) values and never {{h:", async () => {
    vi.stubEnv("AUTOSECOPS_GUARDS", "on");
    vi.stubEnv("VIGIL_RUNS_URL", "http://backend.test/internal/runs");
    vi.stubEnv("AGENT_INTERNAL_TOKEN", "t");
    const posts: { url: string; body: string }[] = [];
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      posts.push({ url: String(url), body: String(init?.body ?? "") });
      return new Response(init?.method === "POST" ? "{}" : "[]", { status: 200, headers: { "content-type": "application/json" } });
    });

    const job: RunJob = {
      schema_version: 1,
      run_id: "5a2c2d3e-0000-4000-8000-0000000003a0",
      run_kind: "hunt",
      tenant_id: null,
      enqueued_at: new Date().toISOString(),
      enqueued_by: "test",
      reason: "start",
      request: { arch: "", playbook: join(FIXTURES, "hunt.playbook.yaml"), config: config(), prompt: "go" },
    };
    const state = new InProcessState();
    await handle(state, new InProcessLeases(), job, new InProcessDirectiveQueue(), build);

    const outbound = posts.filter((post) => post.body !== "");
    expect(outbound.length).toBeGreaterThan(0);
    for (const post of outbound) expect(post.body, post.url).not.toContain("{{h:");
    for (const post of outbound) expect(post.body, post.url).not.toContain(RLO);

    // The lead's checkpoint reached the backend with the real value, escaped.
    const announced = outbound.find((post) => post.url.endsWith("/checkpoints") && post.body.includes("budget_anomaly"));
    expect(announced).toBeDefined();
    const question = (JSON.parse(announced!.body) as { question: string }).question;
    expect(question).toContain("WS\\u202eEVIL");
    expect(question).toContain("(written by the subject)");
    expect(question).not.toContain("withheld");
    // The paused status carries the lead's reason with the real value too.
    const paused = outbound.find((post) => post.url.endsWith("/status") && post.body.includes('"paused"'));
    expect(paused).toBeDefined();
    expect((JSON.parse(paused!.body) as { reason: string }).reason).toContain("WS\\u202eEVIL");
    // The alert was linked by its real id.
    const findings = outbound.find((post) => post.url.endsWith("/findings"));
    expect(JSON.parse(findings!.body)).toEqual({ finding_ids: [LEGACY_ID] });
    // And the run really did journal the handle: the conversion is what removed it.
    const raised = (await state.read(job.run_id)).find((event) => event.kind === "checkpoint" && (event.payload as { checkpoint_class: string }).checkpoint_class === "budget_anomaly");
    expect(JSON.stringify(raised?.payload)).toContain("{{h:");
  });
});

describe("the outbound choke point, for a verdict_review question", () => {
  it("resolves the hypothesis statement's handle to the escaped real value", async () => {
    const state = new InProcessState();
    const runId = "run-verdict-review";
    await state.append(runId, [
      { run_id: runId, run_kind: "verdict", kind: "patch", payload: { target: "dispatch", id: "dsp-1", fields: { handles: { "dabcq1.1.host": HOST } } } },
      {
        run_id: runId,
        run_kind: "verdict",
        kind: "checkpoint",
        payload: { checkpoint_id: "cp-1", checkpoint_class: "verdict_review", question: "Mark h-1 proven? {{h:dabcq1.1.host}} beacons", raised_at: new Date().toISOString(), context: { hypothesis_id: "h-1" } },
      },
    ] as never);
    const sent: string[] = [];
    const fetch = (async (_url: string, init: RequestInit) => {
      sent.push(String(init.body));
      return new Response("{}", { status: 200 });
    }) as unknown as typeof globalThis.fetch;
    outboundLedger(state);
    await announceOpen(state, runId, "verdict", "cp-1", httpAnnounce({ url: "http://backend.test/runs", token: "t", fetch }));

    const body = JSON.parse(sent[0]!) as { question: string };
    expect(body.question).toBe('Mark h-1 proven? `"WS\\u202eEVIL"` (written by the subject) beacons');
  });
});
