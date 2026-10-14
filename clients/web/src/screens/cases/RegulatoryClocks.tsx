import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../../contexts/AuthContext'
import { regulatoryApi, type RegulatoryClock, type RegulatoryDraft, type RegulatoryStatus } from '../../services/regulatoryApi'
import { when } from './caseFormat'
import { countdown, INSTANTS, liveState, type Regime } from './regulatoryFormat'

const REGIMES: { id: Regime; label: string }[] = [
  { id: 'dora', label: 'DORA' },
  { id: 'nis2', label: 'NIS2' },
]

const KINDS: Record<Regime, { id: 'initial' | 'intermediate' | 'final' | 'early_warning' | 'notification'; label: string }[]> = {
  dora: [
    { id: 'initial', label: 'Initial' },
    { id: 'intermediate', label: 'Intermediate' },
    { id: 'final', label: 'Final' },
  ],
  nis2: [
    { id: 'early_warning', label: 'Early warning' },
    { id: 'notification', label: 'Notification' },
    { id: 'intermediate', label: 'Intermediate' },
    { id: 'final', label: 'Final' },
  ],
}

const TICK_MS = 15_000

const TONE: Record<RegulatoryClock['state'], string> = {
  not_started: 'muted',
  running: 'fair',
  overdue: 'poor',
  met: 'good',
  met_late: 'poor',
}

const STATE_WORD: Record<RegulatoryClock['state'], string> = {
  not_started: 'Not started',
  running: 'Running',
  overdue: 'Overdue',
  met: 'Met',
  met_late: 'Met late',
}

function instantLabel(regime: Regime, id: string | null | undefined): string {
  return INSTANTS[regime].find((i) => i.id === id)?.label.toLowerCase() ?? id ?? ''
}

function detailOf(error: unknown, fallback: string): string {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

/** A UTC datetime-local value ("2026-03-02T08:00") as ISO with an offset. */
function utcIso(local: string): string | null {
  if (!local) return null
  const t = new Date(`${local}:00Z`)
  return Number.isNaN(t.getTime()) ? null : t.toISOString()
}

function ClockRow({ clock, regime, nowMs }: { clock: RegulatoryClock; regime: Regime; nowMs: number }) {
  const state = liveState(clock, nowMs)
  const left = countdown(clock, nowMs)
  return (
    <li className={`reg-clock ${TONE[state]}`} data-state={state}>
      <div className="reg-clock-head">
        <span className="reg-clock-label">{clock.label}</span>
        <span className={`reg-state ${TONE[state]}`}>{STATE_WORD[state]}</span>
      </div>
      {clock.due_at ? (
        <div className="side-meta">
          Due {when(clock.due_at)} UTC · from {instantLabel(regime, clock.bound_to)}
          {left && state !== 'met' && state !== 'met_late' && (
            <>
              {' · '}
              <span className={`reg-left ${TONE[state]}`}>{left}</span>
            </>
          )}
        </div>
      ) : (
        <div className="side-meta">
          {state === 'met' ? `Met ${when(clock.met_at)} UTC` : `Starts when ${instantLabel(regime, clock.waiting_for)} is recorded`}
        </div>
      )}
    </li>
  )
}

function InstantRow({ caseId, regime, id, label, source, canWrite, onSaved }: {
  caseId: string
  regime: Regime
  id: string
  label: string
  source?: RegulatoryStatus['instants'][string][string]
  canWrite: boolean
  onSaved: (status: RegulatoryStatus) => void
}) {
  const [editing, setEditing] = useState(false)
  const [value, setValue] = useState('')
  const [reason, setReason] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const recorded = !!source?.value
  const needsReason = recorded

  const save = (clear: boolean) => {
    const iso = clear ? null : utcIso(value)
    if (!clear && !iso) return setError('Pick a date and time (UTC).')
    if (needsReason && !reason.trim()) return setError('Say why this recorded instant changes.')
    setBusy(true)
    setError(null)
    regulatoryApi
      .record(caseId, { regime, instant: id, value: iso, reason: reason.trim() || null })
      .then((res) => {
        onSaved(res.data.status)
        setEditing(false)
        setReason('')
      })
      .catch((e) => setError(detailOf(e, 'The instant could not be recorded.')))
      .finally(() => setBusy(false))
  }

  return (
    <div className="reg-instant">
      <dt>{label}</dt>
      <dd>
        {recorded ? (
          <>
            {when(source?.value)} UTC
            <span className="side-meta"> · {source?.actor}</span>
          </>
        ) : (
          '—'
        )}
        {canWrite && !editing && (
          <button
            type="button"
            className="reg-link"
            aria-label={`${recorded ? 'Change' : 'Record'} ${label}`}
            onClick={() => {
              setEditing(true)
              setValue(new Date().toISOString().slice(0, 16))
            }}
          >
            {recorded ? 'Change' : 'Record'}
          </button>
        )}
        {editing && (
          <div className="reg-form">
            <label>
              <span className="side-meta">Time (UTC)</span>
              <input type="datetime-local" value={value} onChange={(e) => setValue(e.target.value)} aria-label={`${label} time (UTC)`} />
            </label>
            {needsReason && (
              <label>
                <span className="side-meta">Reason (kept in the audit record)</span>
                <input type="text" value={reason} maxLength={1000} onChange={(e) => setReason(e.target.value)} aria-label={`Reason for changing ${label}`} />
              </label>
            )}
            {error && <p className="reg-error" role="alert">{error}</p>}
            <div className="reg-actions">
              <button type="button" className="btn" disabled={busy} onClick={() => save(false)}>Save</button>
              {recorded && <button type="button" className="btn" disabled={busy} onClick={() => save(true)}>Clear</button>}
              <button type="button" className="btn" disabled={busy} onClick={() => { setEditing(false); setError(null) }}>Cancel</button>
            </div>
          </div>
        )}
      </dd>
    </div>
  )
}

function Drafts({ caseId, regime, canWrite }: { caseId: string; regime: Regime; canWrite: boolean }) {
  const [draft, setDraft] = useState<RegulatoryDraft | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  if (!canWrite) return null
  const make = (kind: (typeof KINDS)[Regime][number]['id']) => {
    setBusy(true)
    setError(null)
    regulatoryApi
      .draft(caseId, { regime, kind })
      .then((res) => setDraft(res.data))
      .catch((e) => setError(detailOf(e, 'The draft could not be generated.')))
      .finally(() => setBusy(false))
  }
  return (
    <div className="reg-drafts">
      <div className="reg-actions">
        <span className="side-meta">Draft from the evidence pack:</span>
        {KINDS[regime].map((k) => (
          <button key={k.id} type="button" className="btn" disabled={busy} onClick={() => make(k.id)}>
            {k.label}
          </button>
        ))}
      </div>
      {error && <p className="reg-error" role="alert">{error}</p>}
      {draft && (
        <details open className="reg-draft">
          <summary>
            {draft.title} · cites {draft.cited_ids.length} item{draft.cited_ids.length === 1 ? '' : 's'}
          </summary>
          <pre>{draft.markdown}</pre>
        </details>
      )}
    </div>
  )
}

/** The case's DORA and NIS2 notification clocks, their start instants, and report drafts. */
export function RegulatoryClocks({ caseId }: { caseId: string }) {
  const { hasPermission } = useAuth()
  const canWrite = hasPermission('cases.write')
  const [status, setStatus] = useState<RegulatoryStatus | null>(null)
  const [phase, setPhase] = useState<'loading' | 'ready' | 'error'>('loading')
  const [skew, setSkew] = useState(0)
  const [nowMs, setNowMs] = useState(() => Date.now())
  const [regime, setRegime] = useState<Regime>('dora')

  const take = useCallback((next: RegulatoryStatus | undefined) => {
    // An answer without clocks or a chain verdict is not one to show.
    if (!next || !Array.isArray(next.clocks) || !next.chain || !next.instants) {
      setPhase('error')
      return
    }
    setStatus(next)
    // Count down on the server's clock, not the browser's.
    const server = new Date(next.now).getTime()
    const local = Date.now()
    setSkew(Number.isNaN(server) ? 0 : server - local)
    setNowMs(local)
    setPhase('ready')
  }, [])

  useEffect(() => {
    let cancelled = false
    setPhase('loading')
    Promise.resolve()
      .then(() => regulatoryApi.clocks(caseId))
      .then((res) => { if (!cancelled) take(res.data) })
      .catch(() => { if (!cancelled) setPhase('error') })
    return () => { cancelled = true }
  }, [caseId, take])

  useEffect(() => {
    const timer = window.setInterval(() => setNowMs(Date.now()), TICK_MS)
    return () => window.clearInterval(timer)
  }, [])

  const now = nowMs + skew
  const clocks = (status?.clocks ?? []).filter((c) => c.regime === regime)
  const overdue = (status?.clocks ?? []).filter((c) => liveState(c, now) === 'overdue').length

  return (
    <section className="side-block reg-block" aria-label="Regulatory clocks">
      <h3 className="side-title">
        Regulatory clocks
        {overdue > 0 && <span className="reg-state poor"> {overdue} overdue</span>}
      </h3>
      {phase === 'loading' && <p className="muted">Loading clocks…</p>}
      {phase === 'error' && <p className="muted">Couldn’t load the regulatory clocks.</p>}
      {phase === 'ready' && status && (
        <>
          <div className="reg-tabs" role="tablist" aria-label="Regime">
            {REGIMES.map((r) => (
              <button key={r.id} type="button" role="tab" aria-selected={regime === r.id} className={`reg-tab${regime === r.id ? ' on' : ''}`} onClick={() => setRegime(r.id)}>
                {r.label}
              </button>
            ))}
          </div>
          {!status.chain.ok && (
            <p className="reg-error" role="alert">
              The instant history does not verify ({status.chain.broken_at != null ? `row ${status.chain.broken_at}: ` : ''}{status.chain.why}). Treat these clocks as unreliable.
            </p>
          )}
          {status.chain.ok && status.chain.anchored === false && (
            <p className="muted reg-unanchored">
              The instant history verifies row by row, but no chain head was checked, so deleted latest entries would not show.
            </p>
          )}
          <ul className="reg-clocks">
            {clocks.map((clock) => <ClockRow key={clock.key} clock={clock} regime={regime} nowMs={now} />)}
          </ul>
          <dl className="side-kv reg-instants">
            {INSTANTS[regime].map((i) => (
              <InstantRow
                key={`${regime}.${i.id}`}
                caseId={caseId}
                regime={regime}
                id={i.id}
                label={i.label}
                source={status.instants[regime]?.[i.id]}
                canWrite={canWrite}
                onSaved={take}
              />
            ))}
          </dl>
          <Drafts caseId={caseId} regime={regime} canWrite={canWrite} />
          <div className="side-meta">Months count in {status.timezone}. Every change is kept, with who and why.</div>
        </>
      )}
    </section>
  )
}
