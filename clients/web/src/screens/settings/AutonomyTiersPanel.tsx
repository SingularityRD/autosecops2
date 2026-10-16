// W3.1: how far AutoSecOps may act alone, per alert category and action class.
// Approve is the default. Autonomous needs a reversible action class, a TTL, a
// confidence floor, an evidence link and a category whose QA bound holds; the
// server checks all of it and demotes a tier when the bound breaks.
import { useCallback, useEffect, useState } from 'react'
import { autonomyApi } from '../../services/api'
import type { Schema } from '../../services/apiTypes'
import { ALWAYS_HUMAN_ACTIONS, ALWAYS_HUMAN_SUMMARY } from '../../shared/autonomy'
import { Field, SettingsCard, TextInput } from '../../shared/ui'
import type { SectionProps } from './types'

const ALWAYS_HUMAN: ReadonlySet<string> = new Set(ALWAYS_HUMAN_ACTIONS.map((a) => a.id))

type Matrix = Schema<'AutonomyMatrix'>
type Entry = Schema<'TierEntryModel'>
type AuditEntry = Schema<'AutonomyAuditEntry'>

const TIER_LABELS: Record<string, string> = {
  watch: 'Watch',
  suggest: 'Suggest',
  approve: 'Approve',
  autonomous: 'Autonomous (reversible)',
}
const TIER_ORDER = ['watch', 'suggest', 'approve', 'autonomous']
const CATEGORY_LABELS: Record<string, string> = { '*': 'Any other category' }
const label = (s: string) => CATEGORY_LABELS[s] ?? s.charAt(0).toUpperCase() + s.slice(1)
const actionLabel = (s: string) => s.replace(/_/g, ' ')

interface Draft {
  entry: Entry
  tier: string
  reason: string
  evidence: string
  ttlHours: string
  floor: string
}

function errText(e: unknown, fallback: string): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  return (e as { message?: string })?.message || fallback
}

export default function AutonomyTiersPanel({ notify }: SectionProps) {
  const [matrix, setMatrix] = useState<Matrix | null>(null)
  const [audit, setAudit] = useState<AuditEntry[]>([])
  const [failed, setFailed] = useState(false)
  const [category, setCategory] = useState('phishing')
  const [draft, setDraft] = useState<Draft | null>(null)
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState('')

  const load = useCallback(async () => {
    try {
      const [tiers, log] = await Promise.all([autonomyApi.tiers(), autonomyApi.audit(10)])
      setMatrix(tiers.data)
      setAudit(log.data.entries ?? [])
      setFailed(false)
    } catch {
      setFailed(true)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  if (failed) {
    return (
      <SettingsCard title="Autonomy by alert category" wide>
        <p className="text-sm text-tx-2">Could not load autonomy tiers.</p>
      </SettingsCard>
    )
  }
  if (!matrix) {
    return (
      <SettingsCard title="Autonomy by alert category" wide>
        <p className="text-sm text-tx-3">Loading autonomy tiers…</p>
      </SettingsCard>
    )
  }

  const rows = (matrix.entries ?? []).filter((e) => e.category === category)
  const bound = matrix.bounds?.[category]
  const raising = (d: Draft) => TIER_ORDER.indexOf(d.tier) > TIER_ORDER.indexOf(d.entry.tier)

  const openDraft = (entry: Entry, tier: string) => {
    if (tier === entry.tier) return
    setFormError('')
    setDraft({ entry, tier, reason: '', evidence: '', ttlHours: '24', floor: '0.9' })
  }

  const save = async () => {
    if (!draft) return
    if (!draft.reason.trim()) { setFormError('A reason is required'); return }
    const needsEvidence = raising(draft) || draft.tier === 'autonomous'
    if (needsEvidence && !/^https:\/\/[^\s/@]+(\/\S*)?$/.test(draft.evidence.trim())) {
      setFormError('Raising a tier needs an https evidence link')
      return
    }
    const body: Schema<'TierUpdate'> = {
      tier: draft.tier as Schema<'TierUpdate'>['tier'],
      reason: draft.reason.trim(),
      evidence_url: needsEvidence ? draft.evidence.trim() : null,
    }
    if (draft.tier === 'autonomous') {
      body.max_ttl_seconds = Math.round(Number(draft.ttlHours) * 3600)
      body.min_confidence = Number(draft.floor)
    }
    setSaving(true)
    setFormError('')
    try {
      await autonomyApi.setTier(draft.entry.category, draft.entry.action_type, body)
      notify('ok', `${actionLabel(draft.entry.action_type)} on ${label(draft.entry.category)}: ${TIER_LABELS[draft.tier]}`)
      setDraft(null)
      await load()
    } catch (e) {
      setFormError(errText(e, 'Could not save the tier'))
    } finally {
      setSaving(false)
    }
  }

  const runCheck = async () => {
    try {
      const res = await autonomyApi.check()
      const n = res.data.demoted?.length ?? 0
      notify(n ? 'info' : 'ok', n ? `${n} tier(s) demoted to Approve` : 'Every autonomous tier still holds')
      await load()
    } catch (e) {
      notify('err', errText(e, 'Check failed'))
    }
  }

  return (
    <SettingsCard
      title="Autonomy by alert category"
      desc={`Approve is the default. Autonomous runs a reversible action without a person, undoes it after its TTL, and only while the category's sampled false-negative bound stays at or under ${(matrix.fn_bound_target * 100).toFixed(0)}% from at least ${matrix.fn_bound_min_reviews} reviews. Containment (${ALWAYS_HUMAN_SUMMARY.toLowerCase()}) is never autonomous, and every action still passes the response policy.`}
      actions={<button className="btn ghost" onClick={runCheck}>Check bounds now</button>}
      wide
    >
      <div className="tabs" style={{ gap: 4 }} role="tablist" aria-label="Alert category">
        {matrix.categories.map((c) => (
          <button
            key={c}
            role="tab"
            aria-selected={c === category}
            className={`tab${c === category ? ' active' : ''}`}
            onClick={() => { setCategory(c); setDraft(null) }}
          >
            {label(c)}
          </button>
        ))}
      </div>

      {category !== '*' && (
        <p className="text-xs text-tx-3 my-2" data-testid="autonomy-bound">
          {!matrix.bounds_readable
            ? 'QA bound unreadable: autonomy is refused until it can be read.'
            : bound
              ? `QA bound: ${bound.holds ? 'holds' : 'does not hold'} (${bound.reason})`
              : 'No QA data for this category.'}
        </p>
      )}

      <table className="tbl">
        <thead>
          <tr><th>Action</th><th>Tier</th><th>Set by</th></tr>
        </thead>
        <tbody>
          {rows.map((entry) => (
            <tr key={entry.action_type}>
              <td>{actionLabel(entry.action_type)}</td>
              <td>
                <select
                  className="field-input"
                  aria-label={`Tier for ${actionLabel(entry.action_type)}`}
                  value={draft?.entry.action_type === entry.action_type ? draft.tier : entry.tier}
                  onChange={(ev) => openDraft(entry, ev.target.value)}
                >
                  {matrix.tiers
                    .filter((t) => t !== 'autonomous' || entry.eligible || entry.tier === 'autonomous')
                    .map((t) => (
                      <option key={t} value={t}>{TIER_LABELS[t] ?? t}</option>
                    ))}
                </select>
              </td>
              <td className="text-xs text-tx-3">
                {entry.explicit ? entry.updated_by ?? '' : 'default'}
                {entry.tier === 'autonomous' && entry.max_ttl_seconds
                  ? ` · TTL ${Math.round(entry.max_ttl_seconds / 3600)}h · floor ${entry.min_confidence}`
                  : ''}
                {ALWAYS_HUMAN.has(entry.action_type) ? ' · containment: always a person' : ''}
                {entry.tier === 'autonomous' && !entry.eligible ? ' · not applied: a person approves' : ''}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {draft && (
        <div className="settings-banner info mt-3" role="form" aria-label="Change tier">
          <div className="flex flex-col gap-2 w-full">
            <strong>
              {actionLabel(draft.entry.action_type)} on {label(draft.entry.category)}: {TIER_LABELS[draft.entry.tier]} → {TIER_LABELS[draft.tier]}
            </strong>
            <Field label="Reason">
              <TextInput value={draft.reason} onChange={(e) => setDraft({ ...draft, reason: e.target.value })} />
            </Field>
            {(raising(draft) || draft.tier === 'autonomous') && (
              <Field label="Evidence link" hint="Scorecard, eval run or review that supports raising this tier">
                <TextInput value={draft.evidence} placeholder="https://" onChange={(e) => setDraft({ ...draft, evidence: e.target.value })} />
              </Field>
            )}
            {draft.tier === 'autonomous' && (
              <>
                <Field label="Undo after (hours)">
                  <TextInput type="number" min={1} max={168} value={draft.ttlHours} onChange={(e) => setDraft({ ...draft, ttlHours: e.target.value })} />
                </Field>
                <Field label="Minimum confidence (0 to 1)">
                  <TextInput type="number" min={0} max={1} step={0.01} value={draft.floor} onChange={(e) => setDraft({ ...draft, floor: e.target.value })} />
                </Field>
              </>
            )}
            {formError && <p className="text-sm text-red" role="alert">{formError}</p>}
            <div className="flex gap-2">
              <button className="btn primary" disabled={saving} onClick={save}>Save</button>
              <button className="btn ghost" disabled={saving} onClick={() => setDraft(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {audit.length > 0 && (
        <details className="mt-3">
          <summary className="text-sm">Recent tier changes</summary>
          <ul className="text-xs text-tx-3 mt-2" data-testid="autonomy-audit">
            {audit.map((a) => (
              <li key={a.id}>
                {a.at ? new Date(a.at).toLocaleString() : ''} · {a.key} · {a.action} by {a.changed_by}
                {a.reason ? ` — ${a.reason}` : ''}
              </li>
            ))}
          </ul>
        </details>
      )}
    </SettingsCard>
  )
}
