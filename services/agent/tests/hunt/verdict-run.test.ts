import { readFileSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { Ajv } from "ajv";
import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";
import { archFor } from "../../arch/registry.js";
import type { AgentEvent } from "../../contracts/events.js";
import { NO_SENSOR_CITATION_GAP, parseVerdict, type Verdict } from "../../contracts/verdict.js";
import { budgetOf, FRESH, unmeteredQuota } from "../../core/budget.js";
import { localDispatch } from "../../core/dispatch.js";
import type { Harness } from "../../core/loop.js";
import { nullMemory } from "../../core/memory.js";
import type { Provider, ProviderEvent, TurnRequest } from "../../core/provider.js";
import { registryOf } from "../../core/registry.js";
import { buildSpec, type RunSpec } from "../../core/spec.js";
import { InProcessState } from "../../core/state.js";
import { BASE_RATE_PROVENANCE, startHunt } from "../../workflows/hunt/controller.js";
import { InProcessDirectiveQueue } from "../../workflows/hunt/directives.js";
import { newId } from "../../workflows/hunt/ids.js";
import type { HuntEvent, HuntKinds, Journal } from "../../workflows/hunt/journal.js";
import { fold } from "../../workflows/hunt/ledger.js";
import { replay } from "../../workflows/hunt/replay.js";
import { DEFAULT_BUDGETS, type Decision, type DispatchResult } from "../../workflows/hunt/types.js";
import {
  BENIGN_UNARGUED_GAP,
  BENIGN_WHILE_PROVEN_GAP,
  criticGate,
  journaledVerdict,
  journalVerdict,
  ledgerProvenance,
  MALICIOUS_UNPROVEN_GAP,
  NO_CONCLUDE_GAP,
  NO_VERDICT_GAP,
  VERDICT_PROMPT_VERSION,
  verdictOf,
  verdictProjection,
} from "../../workflows/hunt/verdict.js";
import { runHunt } from "../../workflows/hunt/workflow.js";
import { SCRIPTED_MODEL_ID, ScriptedDisconfirmationCritic, ScriptedWorkerDispatcher } from "../support/scripted-hunt.js";
import { controllerFor, huntSpecFor, ruled, spender, validateOn } from "../support/hunt.js";

// The verdict run kind (W2.1): the hunt loop at triage scale, ending in one contract
// verdict derived by code from the ledger. Nothing here is verdict-specific loop code
// -- HUNT_LOOP is shared -- so what is tested is the arch the lead is handed, the
// on_budget section, and verdict.ts: the critic gate, the provenance the citations
// resolve through, and the verdict journaled before the terminal.

const FIXTURES = join(import.meta.dirname, "..", "fixtures");
const CONTRACTS = join(import.meta.dirname, "..", "..", "..", "..", "core", "contracts");
const SCHEMA = JSON.parse(readFileSync(join(CONTRACTS, "verdict.schema.json"), "utf8"));
const schemaValid = new Ajv2020({ allErrors: true, strict: true }).compile(SCHEMA);

const ALERT = "alert f-4821 is adversary activity rather than benign behaviour";

// A verdict run's small ceiling, everything else the hunt default.
const budgets = (max_iterations: number, max_cost_usd = 5) => ({ ...DEFAULT_BUDGETS, max_iterations, max_cost_usd });

function verdictSpec(): RunSpec {
  const entry = archFor("verdict");
  return buildSpec(
    { arch: entry.arch, playbook: join(FIXTURES, "hunt.playbook.yaml"), config: join(FIXTURES, "hunt.config.yaml") },
    entry.actions,
  );
}

const leadSchema = () => new Ajv({ allErrors: true, strict: false }).compile(verdictSpec().roles.lead!.output_schema!);

// Sensor-attested beacon telemetry, the shape a worker returns it in.
const beaconFor = (intentId: string): DispatchResult["evidence"] => [
  {
    source_system: "net_flow",
    summary: `10.128.0.5 -> 198.51.100.7: 412 connections, 300s +/- 4s`,
    payload: { conn_count: 412, interval_s: 300 },
    salience: "anomalous",
    why_notable: "regular interval with low variance",
    provenance: "worker",
    attacker_influenceable: false,
    instruction_like: false,
    supports: [intentId],
    rests_on: [
      { field: "conn_count", authored: "sensor" },
      { field: "user_agent", authored: "adversary" },
    ],
  },
  {
    source_system: "dns",
    summary: `198.51.100.7 resolved from a domain registered 2 days ago`,
    payload: { first_seen_days: 2 },
    salience: "notable",
    why_notable: "young domain",
    provenance: "worker",
    attacker_influenceable: false,
    instruction_like: false,
    supports: [intentId],
    rests_on: [{ field: "first_seen_days", authored: "sensor" }],
  },
];

interface Run {
  state: InProcessState<HuntKinds>;
  runId: string;
  ledger: Journal;
  intentId: string;
}

async function verdictRun(overrides: Parameters<typeof huntSpecFor>[0] = {}, onBudget: "park" | "terminate" = "terminate"): Promise<Run> {
  const state = new InProcessState<HuntKinds>();
  const runId = newId("run");
  const spec = { ...huntSpecFor({ hypotheses: [ALERT], hypothesisLoop: true, ...overrides }), arch: "verdict", on_budget: onBudget };
  const ledger = await startHunt(state, new InProcessDirectiveQueue(), runId, spec, "test", "verdict");
  const [intent] = [...ledger.projection.hypotheses.values()].filter((h) => h.provenance !== BASE_RATE_PROVENANCE);
  return { state, runId, ledger, intentId: intent!.hypothesis_id };
}

const evidenceIds = (ledger: Journal) =>
  [...ledger.projection.evidence.values()].filter((record) => record.provenance === "worker").map((record) => record.evidence_id);

async function investigate(run: Run): Promise<string[]> {
  await controllerFor(run.ledger, [{ action: "INVESTIGATE", rationale: "look", query_intent: "characterise the beacon", target_hypothesis_id: run.intentId }], {
    dispatcher: new ScriptedWorkerDispatcher(beaconFor(run.intentId)),
  }).advanceIteration();
  return evidenceIds(run.ledger);
}

async function validate(run: Run, cited: string[], survives: boolean): Promise<void> {
  await controllerFor(run.ledger, [ruled(run.ledger, validateOn(run.intentId, cited))], {
    critic: new ScriptedDisconfirmationCritic(survives),
  }).advanceIteration();
}

async function abandon(run: Run, cited: string): Promise<void> {
  await controllerFor(run.ledger, [
    ruled(run.ledger, { action: "ABANDON", rationale: "the backup schedule explains it", target_hypothesis_id: run.intentId, evidence_citations: [cited] }),
  ]).advanceIteration();
}

function concluding(verdict: Record<string, unknown> | null): Decision {
  return { action: "CONCLUDE", rationale: "the verdict is in", evidence_citations: [], verdict } as Decision;
}

async function conclude(run: Run, verdict: Record<string, unknown> | null) {
  return controllerFor(run.ledger, [ruled(run.ledger, concluding(verdict))]).advanceIteration();
}

// What workflow.ts end() does after the terminal patch: the verdict, then the terminal.
async function finish(run: Run): Promise<{ events: readonly HuntEvent[]; verdict: Verdict | null }> {
  await run.ledger.flush();
  const verdict = await journalVerdict(run.state, run.runId, "verdict", run.ledger.projection);
  return { events: await run.state.read(run.runId), verdict };
}

function expectValid(verdict: Verdict | null): asserts verdict is Verdict {
  expect(verdict).not.toBeNull();
  expect(schemaValid(verdict)).toBe(true);
  expect(parseVerdict(verdict).ok).toBe(true);
}

describe("what the verdict lead is told", () => {
  const spec = verdictSpec();
  const lead = spec.roles.lead!.prompt;

  it("makes the critic mandatory before a malicious or benign verdict", () => {
    expect(lead).toContain("VALIDATE is mandatory before a malicious or benign verdict");
    expect(lead.replace(/\s+/g, " ")).toContain("without that critic result on the ledger is recorded as inconclusive");
    expect(spec.roles.critic?.prompt.replace(/\s+/g, " ")).toContain("Your job is to argue the null");
  });

  it("says authorship is decided by code from the ledger, never by the lead", () => {
    const flat = lead.replace(/\s+/g, " ");
    expect(flat).toContain("Who authored each field is decided by code from the ledger, never by you");
    expect(flat).toContain("adversary-authored");
    expect(flat).toContain("A benign verdict that cites no sensor-attested field is recorded as inconclusive");
  });

  it("seeds the benign account at its base rate as the claim to beat", () => {
    expect(lead.replace(/\s+/g, " ")).toContain("the benign explanation is the claim to beat");
  });

  it("carries a verdict on CONCLUDE without authored, and refuses HANDOFF_IR", () => {
    const valid = leadSchema();
    const verdict = { verdict: "malicious", confidence: 0.8, category: "network", cited_fields: ["ev-1.conn_count"], gaps: [] };
    expect(valid({ ...concluding(verdict) })).toBe(true);
    expect(valid({ ...concluding(null) })).toBe(true);
    // Authorship is not the model's to write.
    expect(valid({ ...concluding({ ...verdict, cited_fields: [{ field: "ev-1.conn_count", authored: "sensor" }] }) })).toBe(false);
    expect(valid({ ...concluding({ ...verdict, model: "m" }) })).toBe(false);
    expect(valid({ action: "HANDOFF_IR", rationale: "escalate", evidence_citations: [], target_hypothesis_id: "h-1" })).toBe(false);
  });
});

describe("a malicious verdict through the critic", () => {
  it("is recorded malicious when the alert's claim was proven, with authorship from the ledger", async () => {
    const run = await verdictRun();
    const [beacon, dns] = await investigate(run);
    await validate(run, [beacon!, dns!], true);
    expect(run.ledger.projection.hypotheses.get(run.intentId)?.status).toBe("proven");

    const ended = await conclude(run, {
      verdict: "malicious",
      confidence: 0.85,
      category: "network",
      cited_fields: [`${beacon}.conn_count`, `${beacon}.user_agent`, `${dns}.first_seen_days`, "f-4821.title"],
      gaps: [],
      recommended_action: { type: "isolate_host", target: "10.128.0.5" },
    });
    expect(ended.hunt_status).toBe("terminal");

    const { events, verdict } = await finish(run);
    expectValid(verdict);
    expect(verdict.verdict).toBe("malicious");
    expect(verdict.cited_fields).toEqual([
      { field: `${beacon}.conn_count`, authored: "sensor" },
      { field: `${beacon}.user_agent`, authored: "adversary" },
      { field: `${dns}.first_seen_days`, authored: "sensor" },
      // The alert's own text attests nothing.
      { field: "f-4821.title", authored: "adversary" },
    ]);
    expect(verdict.recommended_action).toEqual({ type: "isolate_host", target: "10.128.0.5" });
    expect(verdict.model).toBe(SCRIPTED_MODEL_ID);
    expect(verdict.prompt_version).toBe(VERDICT_PROMPT_VERSION);

    // Journaled once, as the projection reports it, and the fold is blind to it.
    expect(events.filter((event) => event.kind === "verdict")).toHaveLength(1);
    const erased = events as unknown as readonly AgentEvent<Record<never, never>>[];
    const view = archFor("verdict").projection?.(run.runId, erased) as ReturnType<typeof verdictProjection>;
    expect(view.verdict).toEqual(verdict);
    expect(view.status).toBe("terminal");
    expect(fold(events)).toEqual(fold(events.filter((event) => event.kind !== "verdict")));

    // A second write (a resumed end()) writes nothing new.
    await journalVerdict(run.state, run.runId, "verdict", fold(await run.state.read(run.runId)));
    expect((await run.state.read(run.runId)).filter((event) => event.kind === "verdict")).toHaveLength(1);
  });

  it("ignores whatever authorship the lead wrote", async () => {
    const run = await verdictRun();
    const [beacon, dns] = await investigate(run);
    await validate(run, [beacon!, dns!], true);
    await conclude(run, {
      verdict: "malicious",
      confidence: 0.9,
      category: "network",
      cited_fields: [{ field: `${beacon}.user_agent`, authored: "sensor" }],
      gaps: [],
    });
    const { verdict } = await finish(run);
    expectValid(verdict);
    expect(verdict.cited_fields).toEqual([{ field: `${beacon}.user_agent`, authored: "adversary" }]);
  });
});

describe("the critic is mandatory", () => {
  // CONCLUDE with the claim still active is refused by the controller; with a ceiling
  // of one iteration the run ends there, and what the lead wrote is held to the gate.
  it("records a malicious verdict with no VALIDATE behind it as inconclusive", async () => {
    const run = await verdictRun({ budgets: budgets(1, 5) });
    await conclude(run, { verdict: "malicious", confidence: 0.95, category: "malware", cited_fields: [], gaps: [] });
    expect(run.ledger.projection.hunt.status).toBe("terminal");

    const { verdict } = await finish(run);
    expectValid(verdict);
    expect(verdict.verdict).toBe("inconclusive");
    expect(verdict.gaps).toContain(MALICIOUS_UNPROVEN_GAP);
    expect(verdict.recommended_action).toBeNull();
  });

  it("refuses benign until the critic has argued the claim and its benign explanation stood", async () => {
    const run = await verdictRun();
    await investigate(run);
    expect(criticGate(run.ledger.projection, "benign")).toBe(BENIGN_UNARGUED_GAP);
    expect(criticGate(run.ledger.projection, "malicious")).toBe(MALICIOUS_UNPROVEN_GAP);
    expect(criticGate(run.ledger.projection, "inconclusive")).toBeNull();
  });

  it("refuses benign when the critic argued but its benign explanation did not stand", async () => {
    const run = await verdictRun();
    const [beacon] = await investigate(run);
    // One domain: survives, but not enough corroboration to be proven.
    await controllerFor(run.ledger, [ruled(run.ledger, validateOn(run.intentId, [beacon!]))], {
      critic: new ScriptedDisconfirmationCritic(true),
    }).advanceIteration();
    expect(criticGate(run.ledger.projection, "benign")).not.toBeNull();
  });

  it("refuses benign while the claim stands proven", async () => {
    const run = await verdictRun();
    const [beacon, dns] = await investigate(run);
    await validate(run, [beacon!, dns!], true);
    expect(criticGate(run.ledger.projection, "benign")).toBe(BENIGN_WHILE_PROVEN_GAP);
    expect(criticGate(run.ledger.projection, "malicious")).toBeNull();
  });

  it("records benign once the critic's explanation stood and the claim was abandoned on sensor evidence", async () => {
    const run = await verdictRun();
    const [beacon, dns] = await investigate(run);
    await validate(run, [beacon!, dns!], false);
    expect(criticGate(run.ledger.projection, "benign")).toBeNull();

    await abandon(run, beacon!);
    await conclude(run, {
      verdict: "benign",
      confidence: 0.7,
      category: "network",
      cited_fields: [`${beacon}.conn_count`],
      gaps: ["no endpoint telemetry for 10.128.0.5"],
      recommended_action: null,
    });
    expect(run.ledger.projection.hunt.status).toBe("terminal");

    const { verdict } = await finish(run);
    expectValid(verdict);
    expect(verdict.verdict).toBe("benign");
    expect(verdict.cited_fields).toEqual([{ field: `${beacon}.conn_count`, authored: "sensor" }]);
    expect(verdict.gaps).toEqual(["no endpoint telemetry for 10.128.0.5"]);
  });
});

describe("provenance comes from the ledger", () => {
  it("resolves worker rests_on as written, enrichment as third_party, and instruction-like records as adversary", async () => {
    const run = await verdictRun();
    const [beacon] = await investigate(run);
    const capture = new Date().toISOString();
    const record = (evidence_id: string, provenance: string, instruction_like: boolean) =>
      run.ledger.append({
        kind: "evidence",
        payload: {
          evidence_id,
          dispatch_id: null,
          iteration: 1,
          source_system: "net_flow",
          summary: "s",
          payload: {},
          salience: "routine",
          why_notable: "",
          provenance,
          attacker_influenceable: false,
          instruction_like,
          rests_on: [{ field: "bytes", authored: "sensor" }],
          entities: [],
          captured_at: capture,
        },
      });
    record("ev-feed", "enrichment:intel", false);
    record("ev-told", "worker", true);
    record("ev-null", "null_check", false);

    const map = ledgerProvenance(run.ledger.projection);
    expect(map[`${beacon}.conn_count`]).toBe("sensor");
    expect(map[`${beacon}.user_agent`]).toBe("adversary");
    expect(map["ev-feed.bytes"]).toBe("third_party");
    expect(map["ev-told.bytes"]).toBe("adversary");
    expect(map["ev-null.bytes"]).toBeUndefined();
  });

  it("downgrades a benign verdict citing nothing sensor-attested", async () => {
    const run = await verdictRun();
    const [beacon, dns] = await investigate(run);
    await validate(run, [beacon!, dns!], false);
    await abandon(run, beacon!);
    await conclude(run, { verdict: "benign", confidence: 0.6, category: "network", cited_fields: [`${beacon}.user_agent`, "f-4821.description"], gaps: [] });
    expect(run.ledger.projection.hunt.status).toBe("terminal");

    const { verdict } = await finish(run);
    expectValid(verdict);
    expect(verdict.verdict).toBe("inconclusive");
    expect(verdict.gaps).toContain(NO_SENSOR_CITATION_GAP);
  });

  it("records a malformed verdict as inconclusive, never a crash", async () => {
    const run = await verdictRun({ budgets: budgets(1, 5) });
    await conclude(run, { verdict: "certainly", confidence: 7 });
    const { verdict } = await finish(run);
    expectValid(verdict);
    expect(verdict.verdict).toBe("inconclusive");
    expect(verdict.gaps[0]).toContain(NO_VERDICT_GAP);
    // The model's words are not echoed into the record.
    expect(JSON.stringify(verdict)).not.toContain("certainly");
  });
});

describe("a verdict run stops at its small ceiling and says inconclusive", () => {
  it("ends on iterations rather than parking", async () => {
    const run = await verdictRun({ budgets: budgets(1, 5) });
    await investigate(run);
    expect(run.ledger.projection.hunt.status).toBe("terminal");
    expect(run.ledger.projection.hunt.outcome).toBe("budget_terminated");

    const { verdict } = await finish(run);
    expectValid(verdict);
    expect(verdict).toMatchObject({ verdict: "inconclusive", confidence: 0, category: "other", cited_fields: [] });
    expect(verdict.gaps[0]).toContain(NO_CONCLUDE_GAP);
  });

  it("ends on cost rather than parking", async () => {
    const run = await verdictRun({ budgets: budgets(4, 0.5) });
    await controllerFor(run.ledger, [{ action: "INVESTIGATE", rationale: "look", query_intent: "q", target_hypothesis_id: run.intentId }], {
      dispatcher: new ScriptedWorkerDispatcher(beaconFor(run.intentId)),
      costPerDecision: 1,
      spend: spender(run.state, run.runId),
    }).advanceIteration();
    expect(run.ledger.projection.hunt.status).toBe("terminal");
    expect(run.ledger.projection.hunt.outcome).toBe("budget_terminated");
    const { verdict } = await finish(run);
    expectValid(verdict);
    expect(verdict.verdict).toBe("inconclusive");
  });

  // The default, every hunt's: a run without on_budget parks at the same ceiling.
  it("leaves a run without on_budget parking at its ceiling, as a hunt does", async () => {
    const run = await verdictRun({ budgets: budgets(1, 5) }, "park");
    await investigate(run);
    expect(run.ledger.projection.hunt.status).toBe("parked");
    expect(verdictOf(run.ledger.projection)).toBeNull();
  });

  // The wall clock is the harness's ceiling, not the controller's: a refused call
  // ends the run through workflow.ts, which journals the verdict before the terminal.
  it("ends on the wall clock through the workflow, with the verdict before the terminal", async () => {
    const state = new InProcessState<HuntKinds>();
    const base = verdictSpec();
    const spec: RunSpec = {
      ...base,
      budgets: { ...base.budgets, max_wall_ms: 1_000 },
      sections: { ...base.sections, hypotheses: [ALERT], on_budget: "terminate" },
    };
    let clock = 0;
    const never: Provider = {
      model: "m",
      provider_type: "test",
      // eslint-disable-next-line require-yield
      async *stream(_request: TurnRequest): AsyncGenerator<ProviderEvent> {
        throw new Error("the wall clock should have refused this call");
      },
    };
    const harness: Harness<HuntKinds> = {
      provider: never,
      registry: registryOf([], {}),
      dispatch: localDispatch,
      budget: budgetOf(spec.budgets, unmeteredQuota, () => (clock += 10_000), FRESH),
      memory: nullMemory,
      state,
    };
    const report = await runHunt(harness, {
      run_id: "run-wall",
      run_kind: "verdict",
      spec,
      actions: archFor("verdict").actions,
      queue: new InProcessDirectiveQueue(),
    });

    expect(report.status).toBe("budget_exhausted");
    const terminal = await state.terminal("run-wall");
    expect(terminal?.outcome).toBe("budget_exhausted");
    const events = await state.read("run-wall");
    const verdict = journaledVerdict(events);
    expectValid(verdict);
    expect(verdict.verdict).toBe("inconclusive");
    expect(verdict.gaps[0]).toContain(NO_CONCLUDE_GAP);
    expect(events.findIndex((event) => event.kind === "verdict")).toBeLessThan(events.findIndex((event) => (event.kind as string) === "terminal"));
  });
});

describe("the recorded verdict run replays", () => {
  // Written by scripts/record-verdict-run.ts: a regression snapshot of the harness's
  // own verdict path, not a Golden (ADR 0012), like hunt-recall.
  const REPLAY = join(FIXTURES, "replay");
  const LOG = gunzipSync(readFileSync(join(REPLAY, "verdict-malicious.jsonl.gz")))
    .toString("utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line) as HuntEvent);
  const GOLDEN = JSON.parse(readFileSync(join(REPLAY, "verdict-malicious.golden.json"), "utf8")) as { verdict: Verdict };

  it("journals exactly one verdict, schema-valid, before its terminal", () => {
    const written = LOG.filter((event) => event.kind === "verdict");
    expect(written).toHaveLength(1);
    expectValid(journaledVerdict(LOG));
    expect(LOG.at(-1)?.kind).not.toBe("verdict");
  });

  it("projects the verdict the golden holds", () => {
    expect(verdictProjection("verdict-malicious", LOG).verdict).toEqual(GOLDEN.verdict);
  });

  // Fold equivalence: the verdict is a deliverable, never a belief, and deriving it
  // again from the fold reaches what was journaled.
  it("folds to the same projection with the verdict event and without it", () => {
    expect(fold(LOG)).toEqual(fold(LOG.filter((event) => event.kind !== "verdict")));
    expect(verdictOf(fold(LOG))).toEqual(GOLDEN.verdict);
  });

  it("reproduces every digest the run decided against", () => {
    const report = replay(LOG);
    expect(report.decisions.map((decision) => decision.action)).toEqual(["INVESTIGATE", "VALIDATE", "CONCLUDE"]);
    expect(report.decisions.filter((decision) => decision.mismatch !== null)).toEqual([]);
    expect(report.reproduced).toBe(report.decisions.length);
  });
});
