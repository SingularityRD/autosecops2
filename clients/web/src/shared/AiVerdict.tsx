import type { ReactNode } from 'react'
import type { TriageVerdict } from '../services/api'

/* The structured triage verdict (W1.2) for the analyst (W0.45): the triage
   queue and the finding popup. Styles: .tq-pill.v-*, .tq-cite (styles.css). */

const BLANK = '—'

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="tq-row">
      <span>{label}</span>
      <span className="tq-val">{children}</span>
    </div>
  )
}

const VERDICT_WORD: Record<'malicious' | 'benign' | 'inconclusive', string> = {
  malicious: 'Malicious',
  benign: 'Benign',
  inconclusive: 'Inconclusive',
}

const AUTHORED_WORD: Record<'sensor' | 'adversary' | 'third_party', string> = {
  sensor: 'from the sensor',
  adversary: 'attacker-controlled',
  third_party: 'third party',
}

const pct = (value: number) => `${Math.round(value * 100)}%`

/** The verdict's one-line pill: the queue column and the panel heading. */
export function VerdictPill({ verdict }: { verdict: TriageVerdict | null | undefined }) {
  if (!verdict) return <>{BLANK}</>
  if (verdict.state === 'failed') return <span className="tq-pill v-failed" title={verdict.error}>Triage failed</span>
  if (verdict.state === 'unreadable') return <span className="tq-pill v-unreadable">Unreadable</span>
  return (
    <span className={`tq-pill v-${verdict.verdict}`}>
      {VERDICT_WORD[verdict.verdict]} · {pct(verdict.confidence)}
    </span>
  )
}

export function VerdictBody({ verdict }: { verdict: TriageVerdict | null | undefined }) {
  if (!verdict) return <p className="tq-meta">Not triaged by AI yet.</p>
  if (verdict.state === 'failed') return <p className="tq-meta">Triage failed: {verdict.error}</p>
  if (verdict.state === 'unreadable') {
    return <p className="tq-meta">The stored verdict does not match the verdict contract, so it is not shown.</p>
  }
  return (
    <div className="tq-verdict">
      <Row label="Verdict"><VerdictPill verdict={verdict} /></Row>
      <Row label="Category">{verdict.category}</Row>
      <Row label="Recommended action">
        {verdict.recommended_action
          ? `${verdict.recommended_action.type} → ${verdict.recommended_action.target} (needs approval)`
          : 'None'}
      </Row>
      <span className="tq-h">What it cites</span>
      {verdict.cited_fields.length ? (
        <div className="tq-cites">
          {verdict.cited_fields.map((c) => (
            <span key={c.field} className={`tq-cite ${c.authored}`}>
              <code>{c.field}</code>
              <span className="by">{AUTHORED_WORD[c.authored]}</span>
            </span>
          ))}
        </div>
      ) : (
        <p className="tq-meta">Cites no field.</p>
      )}
      <p className="tq-meta">
        Who wrote each field is worked out by AutoSecOps from the source, not taken from the model. A benign verdict needs a field from the sensor.
      </p>
      {verdict.gaps.length > 0 && (
        <>
          <span className="tq-h">What it could not see</span>
          <ul className="tq-meta">
            {verdict.gaps.map((g) => <li key={g}>{g}</li>)}
          </ul>
        </>
      )}
      <p className="tq-meta">
        {verdict.model} · prompt {verdict.prompt_version}{verdict.at ? ` · ${verdict.at.slice(0, 16).replace('T', ' ')} UTC` : ''}
      </p>
    </div>
  )
}

