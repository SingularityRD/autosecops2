import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { useAuth } from '../../contexts/AuthContext'
import { lessonsApi, type Lesson } from '../../services/lessonsApi'
import { Icon } from '../../shared/icons'
import { EmptyState, Field, Popup } from '../../shared/ui'
import { useToast } from '../../shell/toast'
import { apiErr, type Phase } from './useScorecard'

const PROMOTE_PERMISSION = 'ai_decisions.approve'
const WRITE_PERMISSION = 'findings.write'

const EFFECT_LABEL: Record<string, string> = {
  benign_hint: 'Benign hint',
  escalate: 'Escalate',
}

const STATUS_COLOR: Record<Lesson['status'], string> = {
  proposed: 'var(--tx-2)',
  active: 'var(--ok)',
  retired: 'var(--tx-faint)',
}

type Replay = {
  passed?: boolean
  improvements?: number
  regressions?: number
  cases?: number
  baseline?: { fp?: number; tp?: number }
  with_lesson?: { fp?: number; tp?: number }
  reasons?: string[]
}

function useLessons() {
  const [lessons, setLessons] = useState<Lesson[]>([])
  const [phase, setPhase] = useState<Phase>('loading')
  const [error, setError] = useState<string | null>(null)
  const [reloadKey, setReloadKey] = useState(0)
  const reload = useCallback(() => setReloadKey((k) => k + 1), [])
  useEffect(() => {
    let cancelled = false
    lessonsApi
      .list()
      .then((res) => {
        if (cancelled) return
        setLessons(res.data.lessons)
        setError(null)
        setPhase('ready')
      })
      .catch((e) => {
        if (cancelled) return
        setError(apiErr(e, 'Failed to load lessons'))
        setPhase((p) => (p === 'ready' ? 'ready' : 'error'))
      })
    return () => {
      cancelled = true
    }
  }, [reloadKey])
  return { lessons, phase, error, reload }
}

function scopeText(scope: Record<string, unknown>): string {
  return Object.entries(scope)
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(', ') : String(v)}`)
    .join(' · ')
}

function replaySummary(r: Replay | null | undefined): string {
  if (!r) return 'Not replayed'
  const fp = `FP ${r.baseline?.fp ?? '?'} → ${r.with_lesson?.fp ?? '?'}`
  const tp = `TP ${r.baseline?.tp ?? '?'} → ${r.with_lesson?.tp ?? '?'}`
  return `${r.passed ? 'Passed' : 'Failed'} · ${fp} · ${tp} · ${r.regressions ?? 0} regressions`
}

const day = (iso?: string | null) => (iso ? iso.slice(0, 10) : '—')

/** Lessons learned from analyst corrections. A lesson is promoted only when a
 *  replay over labelled historical alerts shows no verdict got worse; rollback
 *  retires it at once. */
export default function LessonsTab() {
  const { user, hasPermission } = useAuth()
  // Two-person rule: the API refuses a promotion by the lesson's proposer.
  const me = [user?.username, user?.user_id].filter(Boolean).map((v) => String(v).trim().toLowerCase())
  const proposedByMe = (l: Lesson) => me.includes(String(l.created_by ?? '').trim().toLowerCase())
  const { notify } = useToast()
  const canPromote = hasPermission(PROMOTE_PERMISSION)
  const canWrite = hasPermission(WRITE_PERMISSION)
  const state = useLessons()
  const [busy, setBusy] = useState<string | null>(null)
  const [rollbackOf, setRollbackOf] = useState<Lesson | null>(null)

  const promote = async (lesson: Lesson) => {
    setBusy(lesson.id)
    try {
      await lessonsApi.promote(lesson.id)
      notify('ok', 'Replay passed: the lesson is active')
    } catch (e) {
      notify('err', apiErr(e, 'Promotion failed'))
    } finally {
      setBusy(null)
      state.reload()
    }
  }

  if (state.phase === 'loading') return <div className="p-[22px]"><EmptyState loading icon="brain" title="Loading lessons…" /></div>
  if (state.phase === 'error') {
    return (
      <div className="p-[22px]">
        <EmptyState error icon="alert" title="Couldn’t load lessons" body={state.error} primary={{ label: 'Retry', onClick: state.reload, icon: 'refresh' }} />
      </div>
    )
  }
  if (state.lessons.length === 0) {
    return (
      <div className="p-[22px]">
        <EmptyState icon="brain" title="No lessons yet" body="A lesson is proposed from an analyst correction and does nothing until a replay over historical alerts promotes it." />
      </div>
    )
  }

  return (
    <div className="px-[22px] py-5">
      {state.error && <p className="text-xs text-high pb-3" role="status">Last refresh failed — showing the previous list.</p>}
      <section className="card card-sq">
        <div className="card-b">
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Lesson</th>
                  <th>Effect</th>
                  <th>Status</th>
                  <th>Provenance</th>
                  <th>Replay</th>
                  <th>Expires</th>
                  <th aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {state.lessons.map((l) => {
                  const trusted = l.provenance === 'analyst'
                  const promotable = l.status === 'proposed' && trusted && !l.expired
                  return (
                    <tr key={l.id} data-lesson={l.id}>
                      <td>
                        <div className="font-semibold">{l.lesson}</div>
                        <div className="text-xs text-tx-3 font-mono">{scopeText(l.applies_to)}</div>
                        <div className="text-xs text-tx-3">by {l.created_by}{l.approved_by ? ` · promoted by ${l.approved_by}` : ''}{l.retired_by ? ` · rolled back by ${l.retired_by}: ${l.retire_reason ?? ''}` : ''}</div>
                      </td>
                      <td>{EFFECT_LABEL[l.effect] ?? l.effect}</td>
                      <td><span className="chip" style={{ color: STATUS_COLOR[l.status] }}>{l.expired && l.status !== 'retired' ? `${l.status} · expired` : l.status}</span></td>
                      <td>
                        {trusted ? 'Analyst' : (
                          <span className="chip" style={{ color: 'var(--crit)' }} title="Traced to text the alert’s author controls, or written by automation: it never applies.">
                            {l.provenance === 'adversary_text' ? 'Alert text — blocked' : 'System — blocked'}
                          </span>
                        )}
                      </td>
                      <td className="text-xs">{replaySummary(l.replay as Replay | null)}</td>
                      <td className="font-mono text-xs">{day(l.expires_at)}</td>
                      <td>
                        <div className="flex gap-2 justify-end">
                          {canPromote && promotable && proposedByMe(l) && (
                            <span className="text-xs text-tx-3" title="The person who proposed a lesson cannot promote it.">Needs a second analyst</span>
                          )}
                          {canPromote && promotable && !proposedByMe(l) && (
                            <button className="btn primary" disabled={busy === l.id} onClick={() => promote(l)}>
                              <Icon name="check" /> Promote
                            </button>
                          )}
                          {canWrite && l.status !== 'retired' && (
                            <button className="btn ghost" disabled={busy === l.id} onClick={() => setRollbackOf(l)}>
                              <Icon name="stop" /> Roll back
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-tx-3 mt-3 max-w-[900px] leading-relaxed">
            Promote replays the lesson over labelled historical alerts first and refuses if any verdict gets worse.
            A lesson never applies to a critical alert, never closes anything, and expires on its date.
          </p>
        </div>
      </section>
      <RollbackDialog
        lesson={rollbackOf}
        onClose={() => setRollbackOf(null)}
        onDone={(msg, ok) => {
          setRollbackOf(null)
          notify(ok ? 'ok' : 'err', msg)
          state.reload()
        }}
      />
    </div>
  )
}

function RollbackDialog({
  lesson,
  onClose,
  onDone,
}: {
  lesson: Lesson | null
  onClose: () => void
  onDone: (msg: string, ok: boolean) => void
}) {
  const [reason, setReason] = useState('')
  const [saving, setSaving] = useState(false)
  useEffect(() => setReason(''), [lesson])
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!lesson || !reason.trim()) return
    setSaving(true)
    try {
      await lessonsApi.rollback(lesson.id, reason.trim())
      onDone('Lesson rolled back', true)
    } catch (err) {
      onDone(apiErr(err, 'Rollback failed'), false)
    } finally {
      setSaving(false)
    }
  }
  return (
    <Popup open={lesson !== null} onClose={onClose} title="Roll back lesson" width={460}>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <p className="text-sm">{lesson?.lesson}</p>
        <Field label="Reason">
          <input className="field-input" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1000} autoFocus />
        </Field>
        <div className="flex gap-2 justify-end">
          <button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn primary" disabled={saving || !reason.trim()}>Roll back</button>
        </div>
      </form>
    </Popup>
  )
}
