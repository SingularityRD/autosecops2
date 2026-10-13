import { useCallback, useEffect, useRef, useState } from 'react'
import { casesApi, responseActionsApi, type CaseActionItem } from '../../services/api'
import { utcDayClock } from '../../shared/utc'
import { InfoTip } from '../../shared/InfoTip'
import { EmptyState } from '../../shared/ui'
import { useToast } from '../../shell/toast'
import type { Phase } from './useCases'

type Tone = 'good' | 'fair' | 'poor' | 'ac' | 'muted'
type Chip = { text: string; tone: Tone; title?: string }

/** Re-render the countdowns this often while an expiry is on screen. */
const TICK_MS = 30_000

const EVENT_LABEL: Record<string, string> = {
  proposed: 'Proposed',
  approved: 'Approved',
  rejected: 'Rejected',
  executed: 'Executed',
  failed: 'Failed',
  verified: 'Verified',
  reversed: 'Reverted',
}

const VERIFY: Record<string, Chip> = {
  verified: { text: 'Verified', tone: 'good', title: 'The executor checked the change is in place.' },
  failed: { text: 'Verify failed', tone: 'poor', title: 'The executor checked and the change is not in place.' },
  unknown: { text: 'Couldn’t verify', tone: 'fair', title: 'The executor could not look. This is not a failure.' },
}

/** "4 min", "7 h", "3 d" (DESIGN.md §2). */
function span(ms: number): string {
  const min = Math.max(0, Math.round(ms / 60_000))
  return min < 60 ? `${min} min` : min < 48 * 60 ? `${Math.round(min / 60)} h` : `${Math.round(min / 1440)} d`
}

/** Where the action stands, one chip. */
export function statusChip(item: CaseActionItem): Chip {
  if (item.reversed_at) return { text: 'Reverted', tone: 'muted' }
  switch (item.status) {
    case 'pending':
      return item.policy.requires_approval ? { text: 'Needs you', tone: 'poor' } : { text: 'Proposed', tone: 'ac' }
    case 'approved':
      return { text: 'Approved', tone: 'ac' }
    case 'executed':
      return { text: 'Executed', tone: 'good' }
    case 'rejected':
      return { text: 'Rejected', tone: 'muted' }
    case 'failed':
      return { text: 'Failed', tone: 'poor' }
    default:
      return { text: item.status, tone: 'muted' }
  }
}

/** The expiry countdown, only while the change stands. */
export function expiryChip(item: CaseActionItem, now: number): Chip | null {
  if (!item.expires_at || item.reversed_at || item.status !== 'executed') return null
  const at = new Date(item.expires_at).getTime()
  if (Number.isNaN(at)) return null
  const title = `Reverts on its own at ${utcDayClock(item.expires_at)} UTC`
  return at > now ? { text: `Reverts in ${span(at - now)}`, tone: 'fair', title } : { text: 'Expiry due', tone: 'muted', title }
}

function Pill({ chip }: { chip: Chip }) {
  return (
    <span className={`case-expl-pill ${chip.tone}`} title={chip.title}>
      {chip.text}
    </span>
  )
}

function detailOf(error: unknown, fallback: string): string {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string' && detail.trim()) return detail
  // The revert route answers 502 with an object: {message, reverse_action_id, verify_status}.
  if (detail && typeof detail === 'object' && !Array.isArray(detail)) {
    const { message, verify_status: verify } = detail as { message?: unknown; verify_status?: unknown }
    if (typeof message === 'string' && message.trim()) {
      return typeof verify === 'string' && verify ? `${message} (verify: ${verify})` : message
    }
  }
  return (error as { message?: string })?.message || fallback
}

function statusOf(error: unknown): number | undefined {
  return (error as { response?: { status?: number } })?.response?.status
}

/** The case's actions, read once per case and again when `refreshKey` moves. */
export function useCaseActions(caseId: string, refreshKey: number) {
  const [actions, setActions] = useState<CaseActionItem[]>([])
  const [phase, setPhase] = useState<Phase>('loading')
  const [error, setError] = useState<string | null>(null)
  const [own, setOwn] = useState(0)
  const shownFor = useRef<string | null>(null)

  useEffect(() => {
    let cancelled = false
    // A re-read of the case on screen keeps its rows; a new case starts blank.
    if (shownFor.current !== caseId) {
      setActions([])
      setPhase('loading')
    }
    setError(null)
    casesApi
      .getActionTimeline(caseId)
      .then((res) => {
        if (cancelled) return
        shownFor.current = caseId
        setActions(res.data.actions ?? [])
        setPhase('ready')
      })
      .catch((e) => {
        if (cancelled) return
        if (shownFor.current === caseId) return // a failed re-read keeps what is shown
        setError(detailOf(e, 'Couldn’t load the actions'))
        setPhase('error')
      })
    return () => {
      cancelled = true
    }
  }, [caseId, refreshKey, own])

  const reload = useCallback(() => setOwn((n) => n + 1), [])
  return { actions, phase, error, reload }
}

function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!active) return
    setNow(Date.now())
    const timer = window.setInterval(() => setNow(Date.now()), TICK_MS)
    return () => window.clearInterval(timer)
  }, [active])
  return now
}

function StateList({ label, rows }: { label: string; rows: CaseActionItem['before_state'] }) {
  if (!rows?.length) return null
  return (
    <div className="act-state">
      <span className="act-state-label">{label}</span>
      <dl>
        {rows.map((row) => (
          <div key={row.key}>
            <dt className="mono">{row.key}</dt>
            <dd className="mono" title={row.value}>{row.value}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

function ActionRow({ item, now, canRevert, onReverted }: { item: CaseActionItem; now: number; canRevert: boolean; onReverted: () => void }) {
  const { notify } = useToast()
  const [open, setOpen] = useState(false)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const verify = item.verify_status ? VERIFY[item.verify_status] ?? { text: item.verify_status, tone: 'muted' as const } : null
  const expiry = expiryChip(item, now)
  const offered = canRevert && item.can_revert
  const rule = item.policy.decision_rule
  const proposed = [
    item.proposed_by && `Proposed by ${item.proposed_by}`,
    item.policy.requires_approval ? 'Needed a person' : 'Approved by policy',
    item.confidence != null && `confidence ${Math.round(item.confidence * 100)}%`,
  ].filter(Boolean).join(' · ')

  const submit = async () => {
    const text = reason.trim()
    if (!text || busy) return
    setBusy(true)
    try {
      await responseActionsApi.revert(item.action_id, text)
      notify('ok', `Revert requested: ${item.title}`)
      setOpen(false)
      setReason('')
      onReverted()
    } catch (e) {
      const status = statusOf(e)
      if (status === 404 || status === 501) notify('info', 'Revert is not available on this AutoSecOps server yet.')
      else {
        notify('err', detailOf(e, 'Could not revert that action'))
        if (status === 502) {
          // The reverse ran and failed: its row is on the record now, so re-read
          // the timeline to show it.
          setOpen(false)
          setReason('')
          onReverted()
        }
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <li className="act-row" aria-label={item.title}>
      <div className="act-head">
        <div className="act-chips">
          <Pill chip={statusChip(item)} />
          {verify && <Pill chip={verify} />}
          {expiry && <Pill chip={expiry} />}
          {item.reversibility !== 'reversible' && <Pill chip={{ text: 'Cannot be undone', tone: 'muted' }} />}
        </div>
        <div className="act-title">
          <b className="clamp2" title={item.title}>{item.title}</b>
          <span className="act-target mono" title={item.target}>{item.action_type} · {item.target}</span>
        </div>
        {offered && (
          <button type="button" className="btn act-revert" aria-expanded={open} disabled={busy} onClick={() => setOpen((v) => !v)}>
            Revert
          </button>
        )}
      </div>
      <div className="act-meta">
        {proposed}
        {rule && <span className="mono act-rule" title="The approval gate's rule">{rule}</span>}
        {item.reverse_of && <span>Reverts <span className="mono">{item.reverse_of}</span></span>}
        {item.reverted_by && <span>Reverted by <span className="mono">{item.reverted_by}</span></span>}
      </div>
      {item.reason && <p className="act-reason clamp2" title={item.reason}>{item.reason}</p>}
      <ol className="act-events" aria-label="Lifecycle">
        {item.events.map((event, i) => (
          <li key={`${event.kind}-${i}`} className={`act-event ${event.kind}`}>
            <span className="act-dot" aria-hidden="true" />
            <span className="act-when mono">{utcDayClock(event.at) ?? '—'}</span>
            <span className="act-kind">{EVENT_LABEL[event.kind] ?? event.kind}</span>
            {event.actor && <span className="act-actor">{event.actor}</span>}
            {event.detail && <span className="act-detail clamp2" title={event.detail}>{event.detail}</span>}
          </li>
        ))}
      </ol>
      {(item.before_state?.length || item.after_state?.length) ? (
        <details className="act-states">
          <summary>Before and after</summary>
          <div className="act-state-grid">
            <StateList label="Before" rows={item.before_state} />
            <StateList label="After" rows={item.after_state} />
          </div>
        </details>
      ) : null}
      {open && offered && (
        <form
          className="act-revert-form"
          onSubmit={(event) => {
            event.preventDefault()
            void submit()
          }}
        >
          <label htmlFor={`revert-${item.action_id}`}>Why revert? The reason is kept on the record.</label>
          <textarea
            id={`revert-${item.action_id}`}
            className="feedback-box"
            aria-label="Revert reason"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Why is this change being reverted?"
            autoFocus
          />
          <div className="act-revert-actions">
            <button type="submit" className="btn act-confirm" disabled={busy || !reason.trim()}>
              {busy ? 'Reverting…' : 'Confirm revert'}
            </button>
            <button type="button" className="btn neutral" disabled={busy} onClick={() => setOpen(false)}>
              Cancel
            </button>
          </div>
        </form>
      )}
    </li>
  )
}

/** The Actions tab: every response action on the case and where each one stands. */
export function CaseActions({
  actions,
  phase,
  error,
  canRevert,
  onRetry,
  onReverted,
}: {
  actions: CaseActionItem[]
  phase: Phase
  error: string | null
  /** The viewer may revert (RBAC); each row also has to be revertible. */
  canRevert: boolean
  onRetry: () => void
  onReverted: () => void
}) {
  const now = useNow(actions.some((item) => item.expires_at && !item.reversed_at))
  if (phase === 'loading') return <EmptyState loading compact icon="bolt" title="Loading the actions…" />
  if (phase === 'error') {
    return (
      <EmptyState
        error
        compact
        icon="alert"
        title="Couldn’t load the actions"
        body={error || undefined}
        primary={{ label: 'Retry', onClick: onRetry, icon: 'refresh' }}
      />
    )
  }
  if (actions.length === 0) {
    return <EmptyState compact icon="bolt" title="No actions on this case" body="Changes AutoSecOps proposes or makes for this case show here." />
  }
  return (
    <section className="case-card act-card" aria-label="Actions">
      <h3>
        Actions on this case · {actions.length}
        <InfoTip
          label="About actions"
          align="start"
          source="Response actions linked to this case, newest first."
          calculation="Each shows who proposed it, who approved it, when it ran, whether it was verified, when it expires and whether it was reverted."
          limit="Revert is offered only on an executed change that can be undone and has not been reverted."
        />
      </h3>
      <ul className="act-rows">
        {actions.map((item) => (
          <ActionRow key={item.action_id} item={item} now={now} canRevert={canRevert} onReverted={onReverted} />
        ))}
      </ul>
    </section>
  )
}
