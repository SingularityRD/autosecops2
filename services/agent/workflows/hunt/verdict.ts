import type { AgentEvent, RunKind } from "../../contracts/events.js";
import type { State } from "../../core/seams.js";
import {
  verdictFromModelOutput,
  type Authored,
  type ProvenanceMap,
  type Verdict,
  type VerdictValue,
} from "../../contracts/verdict.js";
import { BASE_RATE_PROVENANCE } from "./controller.js";
import { fold, type HuntEvent, type HuntKinds, type Projection } from "./ledger.js";
import { huntProjection, type HuntProjection } from "./projection.js";
import { forPeopleOf } from "./handles.js";
import { NULL_CHECK_PROVENANCE } from "./strength.js";
import type { DecisionRecord, EvidenceRecord, Hypothesis, HuntOutcome } from "./types.js";

// The verdict run kind's answer: one contract verdict (contracts/verdict.ts) about
// one uncertain alert, derived from the hunt ledger by code. The lead proposes it on
// CONCLUDE; what is recorded is what the ledger can stand behind:
//
//   - authored on every citation comes from the ledger's own provenance map, never
//     from the lead (verdictFromModelOutput discards whatever it wrote);
//   - malicious and benign each need the critic to have argued the alert's claim,
//     with the matching result -- otherwise the verdict is inconclusive and says why;
//   - a benign verdict citing nothing sensor-attested is inconclusive
//     (enforceProvenance, the contract's own rule).
//
// Derived rather than trusted, so a lead that names a verdict its ledger does not
// support -- by mistake or because an alert's text told it to -- is recorded as
// what the evidence supports, and a replay of the ledger reaches the same verdict.

export const VERDICT_RUN_KIND: RunKind = "verdict";

// Stamped as every verdict's prompt_version. Bump it with any change to
// arch/verdict.yaml's prompts or to the rules below, so verdicts written under
// different rules are never compared as one population.
export const VERDICT_PROMPT_VERSION = "verdict-run.v1";

// A field the run's own instrumentation never names. Used only when no decision was
// ever journaled, so the verdict still satisfies the contract's non-empty model.
export const UNKNOWN_MODEL = "unknown";

// The gaps the gate writes. Exported so tests and readers match on them, not on prose.
export const NO_CONCLUDE_GAP = "the run ended before the lead concluded";
export const CONCLUDE_REFUSED_GAP =
  "the controller refused the lead's CONCLUDE and the run ended without concluding; its proposed verdict is not recorded";
export const OPERATOR_CONCLUDE_GAP =
  "an operator concluded the hunt on what it had before the lead concluded; no verdict of the lead's is recorded";
export const OPERATOR_CONCLUDE_REFUSED_GAP =
  "an operator concluded the hunt on what it had; the controller never accepted the lead's CONCLUDE, so its refused draft verdict is not recorded";
export const NO_VERDICT_GAP = "the lead concluded without a well-formed verdict";
export const MALICIOUS_UNPROVEN_GAP =
  "malicious verdict without the alert's hypothesis proven through the critic (VALIDATE); downgraded to inconclusive";
export const BENIGN_UNARGUED_GAP =
  "benign verdict without the critic's benign explanation standing against every claim (VALIDATE); downgraded to inconclusive";
export const BENIGN_WHILE_PROVEN_GAP = "benign verdict while a claim of adversary activity stands proven; downgraded to inconclusive";

// Whether a run of this kind journals a verdict before its terminal. One place, so
// the workflow does not compare kinds inline.
export function journalsVerdict(kind: RunKind): boolean {
  return kind === VERDICT_RUN_KIND;
}

// The claims of adversary activity: everything on the board but the seeded null.
function contenders(projection: Projection): Hypothesis[] {
  return [...projection.hypotheses.values()].filter((hypothesis) => hypothesis.provenance !== BASE_RATE_PROVENANCE);
}

const settled = (hypothesis: Hypothesis) => hypothesis.status === "proven" || hypothesis.status === "handed_off";

// The critic's latest argument against one hypothesis, read off the ledger the way
// strength.ts reads it, so the gate and the proven predicate see the same record.
function latestNullCheck(projection: Projection, hypothesisId: string): EvidenceRecord | undefined {
  return [...projection.evidence.values()]
    .filter((record) => record.provenance === NULL_CHECK_PROVENANCE && record.payload["hypothesis_id"] === hypothesisId)
    .at(-1);
}

// Who authored each field the ledger can attest, keyed <evidence_id>.<field>. Built by
// code from the records the workers returned: a worker's rests_on is the hunt's own
// attestation (it is what ABANDON and the proven predicate already gate on), an
// enrichment is somebody else's claim, and a record that read like instructions is
// treated as the adversary's whatever it says it rests on. Critic arguments, tool
// failures and deployment gaps attest no field, so citing them resolves to adversary.
export function ledgerProvenance(projection: Projection): ProvenanceMap {
  const map: Record<string, Authored> = {};
  for (const record of projection.evidence.values()) {
    const enrichment = record.provenance.startsWith("enrichment:");
    if (record.provenance !== "worker" && !enrichment) continue;
    for (const basis of record.rests_on ?? []) {
      if (typeof basis.field !== "string" || basis.field === "") continue;
      const authored: Authored = record.instruction_like ? "adversary" : enrichment ? "third_party" : basis.authored;
      map[`${record.evidence_id}.${basis.field}`] = authored;
    }
  }
  return map;
}

// The CONCLUDE the controller accepted, if it accepted one: its termination predicate
// passed on that decision, directly or past an approved verdict review, and the
// controller journaled the decision's id as it concluded (hunt.accepted_conclude).
// Nothing else counts. A CONCLUDE the controller refused is a draft the evidence did
// not yet support -- when the run then ends on its budget, fails, is aborted, or an
// operator's conclude directive ends it on what it had (completed, without the
// predicate), the draft is not a verdict, even when it was the last decision the lead
// made.
function lastConclude(projection: Projection): DecisionRecord | undefined {
  const accepted = projection.hunt.accepted_conclude;
  if (typeof accepted !== "string" || accepted === "") return undefined;
  const outcome = projection.hunt.outcome;
  if (outcome === null || !CONCLUDED.has(outcome)) return undefined;
  const decision = projection.decisions.find((record) => record.decision_id === accepted);
  return decision?.decision.action === "CONCLUDE" ? decision : undefined;
}

// The outcomes a concluding run ends on. Every other ending -- budget_terminated on
// iterations, cost or the wall clock, failed, aborted -- stopped without concluding.
const CONCLUDED: ReadonlySet<HuntOutcome> = new Set<HuntOutcome>(["completed", "data_starved"]);

// Why the run has no verdict of the lead's to record, naming how it ended.
function unconcludedGap(projection: Projection): string {
  const outcome = projection.hunt.outcome ?? "ended";
  const why = projection.hunt.termination_reason || outcome || "no conclusion";
  const drafted = projection.decisions.some((record) => record.decision.action === "CONCLUDE");
  if (projection.hunt.operator_concluded === true) {
    return `${drafted ? OPERATOR_CONCLUDE_REFUSED_GAP : OPERATOR_CONCLUDE_GAP} (${outcome}): ${why}`;
  }
  const refused = projection.decisions.at(-1)?.decision.action === "CONCLUDE";
  return `${refused ? CONCLUDE_REFUSED_GAP : NO_CONCLUDE_GAP} (${outcome}): ${why}`;
}

function stampOf(projection: Projection, conclude: DecisionRecord | undefined): { model: string; prompt_version: string } {
  const model = conclude?.model_id || projection.decisions.at(-1)?.model_id || projection.hunt.spec?.model || UNKNOWN_MODEL;
  return { model, prompt_version: VERDICT_PROMPT_VERSION };
}

// Why the critic gate refuses this verdict, or null when it stands.
export function criticGate(projection: Projection, verdict: VerdictValue): string | null {
  if (verdict === "inconclusive") return null;
  const claims = contenders(projection);
  if (verdict === "malicious") return claims.some(settled) ? null : MALICIOUS_UNPROVEN_GAP;

  // benign: nothing stands proven, and the critic argued every claim and its benign
  // explanation stood (survives false) on the latest argument it made.
  if (claims.some(settled)) return BENIGN_WHILE_PROVEN_GAP;
  if (claims.length === 0) return BENIGN_UNARGUED_GAP;
  const argued = claims.every((claim) => latestNullCheck(projection, claim.hypothesis_id)?.payload["survives"] === false);
  return argued ? null : BENIGN_UNARGUED_GAP;
}

const withGap = (gaps: readonly string[], gap: string): string[] => (gaps.includes(gap) ? [...gaps] : [...gaps, gap]);

// The verdict a terminal run's ledger supports. Null while the run is still going:
// a verdict is an ending, and one read mid-run would be the lead's draft.
export function verdictOf(projection: Projection): Verdict | null {
  if (projection.hunt.status !== "terminal") return null;
  const conclude = lastConclude(projection);
  const stamp = stampOf(projection, conclude);

  if (conclude === undefined) {
    return {
      verdict: "inconclusive",
      confidence: 0,
      category: "other",
      cited_fields: [],
      gaps: [unconcludedGap(projection)],
      recommended_action: null,
      ...stamp,
    };
  }

  const raw = (conclude.decision as { verdict?: unknown }).verdict;
  const parsed = verdictFromModelOutput(raw, ledgerProvenance(projection), stamp);
  if (!parsed.ok) {
    // The errors name keys and rules, never the values the model wrote.
    return {
      verdict: "inconclusive",
      confidence: 0,
      category: "other",
      cited_fields: [],
      gaps: [`${NO_VERDICT_GAP} (${parsed.errors.length} problem(s))`],
      recommended_action: null,
      ...stamp,
    };
  }

  const verdict = parsed.verdict;
  const refused = criticGate(projection, verdict.verdict);
  if (refused === null) return verdict;
  // Downgraded, so no response follows from it: an inconclusive verdict acts on nothing.
  return { ...verdict, verdict: "inconclusive", gaps: withGap(verdict.gaps, refused), recommended_action: null };
}

// The journaled verdict when there is one (written once, before the terminal), so a
// rule changed after the run cannot rewrite what it decided; derived otherwise, which
// is what a run that ended without reaching the write looks like.
export function journaledVerdict(events: readonly HuntEvent[]): Verdict | null {
  const written = events.filter((event) => event.kind === "verdict").at(-1);
  return written === undefined ? null : (written.payload as Verdict);
}

// Written once per run, from the fold: a resume past a written verdict writes no
// second. A no-op for every kind but verdict, and while the run is not terminal.
export async function journalVerdict(
  state: State<HuntKinds>,
  runId: string,
  runKind: RunKind,
  projection: Projection,
): Promise<Verdict | null> {
  if (!journalsVerdict(runKind)) return null;
  const held = journaledVerdict(await state.read(runId));
  if (held !== null) return held;
  const raw = verdictOf(projection);
  if (raw === null) return null;
  // Guards (W0.30): the verdict leaves the agent layer, so it carries no handles.
  const verdict = forPeopleOf(raw, projection.dispatches.values());
  await state.append(runId, [{ run_id: runId, run_kind: runKind, kind: "verdict", payload: verdict }]);
  return verdict;
}

export interface VerdictProjection extends HuntProjection {
  verdict: Verdict | null;
}

export function verdictProjection(runId: string, events: readonly AgentEvent<HuntKinds>[]): VerdictProjection {
  const hunt = huntProjection(runId, events);
  const view = fold(events);
  const verdict = journaledVerdict(events) ?? verdictOf(view);
  return { ...hunt, verdict: verdict === null ? null : forPeopleOf(verdict, view.dispatches.values()) };
}
