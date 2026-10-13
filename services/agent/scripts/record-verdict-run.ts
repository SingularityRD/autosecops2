import { gzipSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { InProcessState } from "../core/state.js";
import { BASE_RATE_PROVENANCE, startHunt } from "../workflows/hunt/controller.js";
import { InProcessDirectiveQueue } from "../workflows/hunt/directives.js";
import type { HuntKinds } from "../workflows/hunt/journal.js";
import { journaledVerdict, journalVerdict } from "../workflows/hunt/verdict.js";
import type { Decision } from "../workflows/hunt/types.js";
import { ScriptedDisconfirmationCritic, ScriptedWorkerDispatcher } from "../tests/support/scripted-hunt.js";
import { controllerFor, huntSpecFor, ruled, validateOn } from "../tests/support/hunt.js";

// Records the fixture tests/hunt/verdict-run.test.ts replays: one verdict run, driven
// by current code through the hunt controller with scripted doubles, that investigates,
// puts the alert's claim to the critic, concludes malicious, and journals its verdict
// the way workflow.ts end() does. Like hunt-recall, a regression snapshot of the
// harness's own path rather than a Golden (ADR 0012).
//
// Run: npx tsx scripts/record-verdict-run.ts

const OUT = join(import.meta.dirname, "..", "tests", "fixtures", "replay");
const NAME = "verdict-malicious";
const RUN = "verdict-malicious-0001";
const ALERT = "alert f-4821 is adversary activity rather than benign behaviour";

const main = async (): Promise<void> => {
  const state = new InProcessState<HuntKinds>();
  const spec = { ...huntSpecFor({ hypotheses: [ALERT], hypothesisLoop: true }), arch: "verdict", on_budget: "terminate" as const };
  const ledger = await startHunt(state, new InProcessDirectiveQueue(), RUN, spec, "record", "verdict");
  const [intent] = [...ledger.projection.hypotheses.values()].filter((h) => h.provenance !== BASE_RATE_PROVENANCE);
  const intentId = intent!.hypothesis_id;

  await controllerFor(ledger, [{ action: "INVESTIGATE", rationale: "characterise the beacon", query_intent: "beacon cadence", target_hypothesis_id: intentId }], {
    dispatcher: new ScriptedWorkerDispatcher([
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
    ]),
  }).advanceIteration();

  const [beacon, dns] = [...ledger.projection.evidence.values()].filter((r) => r.provenance === "worker").map((r) => r.evidence_id);
  await controllerFor(ledger, [ruled(ledger, validateOn(intentId, [beacon!, dns!]))], {
    critic: new ScriptedDisconfirmationCritic(true),
  }).advanceIteration();

  const conclude = {
    action: "CONCLUDE",
    rationale: "the cadence survived the benign account across two domains",
    evidence_citations: [],
    verdict: {
      verdict: "malicious",
      confidence: 0.85,
      category: "network",
      cited_fields: [`${beacon}.conn_count`, `${beacon}.user_agent`, `${dns}.first_seen_days`],
      gaps: ["no endpoint telemetry for 10.128.0.5"],
      recommended_action: { type: "isolate_host", target: "10.128.0.5" },
    },
  } as Decision;
  const ended = await controllerFor(ledger, [ruled(ledger, conclude)]).advanceIteration();
  if (ended.hunt_status !== "terminal") throw new Error(`the run did not end on CONCLUDE: ${ended.note}`);
  await ledger.flush();

  const verdict = await journalVerdict(state, RUN, "verdict", ledger.projection);
  if (verdict?.verdict !== "malicious") throw new Error(`the run recorded ${JSON.stringify(verdict)}`);
  // The terminal workflow.ts writes after the verdict, so the fixture ends the way a run does.
  await state.append(RUN, [
    { run_id: RUN, run_kind: "verdict", kind: "terminal", payload: { outcome: "completed", reason: ended.note, summary: "" } } as never,
  ]);

  const events = await state.read(RUN, { snapshots: true });
  mkdirSync(OUT, { recursive: true });
  const jsonl = events.map((event) => JSON.stringify(event)).join("\n");
  writeFileSync(join(OUT, `${NAME}.jsonl.gz`), gzipSync(Buffer.from(`${jsonl}\n`, "utf8")));
  writeFileSync(join(OUT, `${NAME}.golden.json`), `${JSON.stringify({ verdict: journaledVerdict(events) }, null, 2)}\n`);
  console.log(`${NAME}: ${events.length} events, verdict ${verdict.verdict}`);
};

await main();
