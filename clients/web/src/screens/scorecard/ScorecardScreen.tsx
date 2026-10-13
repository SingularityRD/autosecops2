import { useCallback, useState, type CSSProperties, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useAuth } from '../../contexts/AuthContext'
import { qaApi } from '../../services/api'
import { Icon } from '../../shared/icons'
import { TabStrip } from '../../shared/TabStrip'
import { EmptyState, Field, NumberInput, Popup } from '../../shared/ui'
import { utcDayClock } from '../../shared/utc'
import { useToast } from '../../shell/toast'
import {
  apiErr, useReviewQueue, useScorecard,
  type CategoryScore, type QASample, type Scorecard,
} from './useScorecard'
import { fmtBound, fmtTarget, plural, titleCase } from './format'
import LessonsTab from './LessonsTab'

// One list, so an unknown ?tab= falls back to the scorecard rather than a blank page.
const TABS = ['scorecard', 'queue', 'lessons'] as const
type Tab = (typeof TABS)[number]
const TAB_LABEL: Record<Tab, string> = { scorecard: 'Scorecard', queue: 'Review queue', lessons: 'Lessons' }

const DRAW_PERMISSION = 'ai_decisions.approve'
const REVIEW_PERMISSION = 'findings.write'

// The bar's scale runs to three times the target, so the target sits a third in.
const SCALE_TIMES_TARGET = 3

const KIND_LABEL: Record<QASample['sampling_kind'], string> = {
  simple_random: 'Random',
  risk_weighted: 'Risk-weighted',
}

const STATUS: Record<CategoryScore['status'], { label: string; color: string }> = {
  meets: { label: 'Meets target', color: 'var(--ok)' },
  not_met: { label: 'Above target', color: 'var(--crit)' },
  no_data: { label: 'No reviews yet', color: 'var(--tx-faint)' },
}

/** QA sampling of verdicts handled without a person: per-category false-negative
 *  upper bounds from simple random reviews, and the queue analysts review. */
export default function ScorecardScreen() {
  const { hasPermission } = useAuth()
  const { notify } = useToast()
  const canDraw = hasPermission(DRAW_PERMISSION)
  const canReview = hasPermission(REVIEW_PERMISSION)

  const [searchParams, setSearchParams] = useSearchParams()
  const tabParam = searchParams.get('tab')
  const tab: Tab = tabParam && (TABS as readonly string[]).includes(tabParam) ? (tabParam as Tab) : 'scorecard'
  // replace, not push: a tab is view state, not a navigation step
  const setTab = useCallback(
    (next: Tab) => {
      const params = new URLSearchParams(searchParams)
      params.set('tab', next)
      setSearchParams(params, { replace: true })
    },
    [searchParams, setSearchParams],
  )

  const card = useScorecard()
  const queue = useReviewQueue()
  const [drawOpen, setDrawOpen] = useState(false)
  const reloadAll = () => { card.reload(); queue.reload() }

  return (
    <>
      <div className="flex items-center gap-3 px-[22px] border-b border-line">
        <TabStrip label="Scorecard sections" tabs={TABS.map((id) => ({ id, label: TAB_LABEL[id] }))} active={tab} onChange={setTab} className="border-b-0" />
        <div className="flex-1" />
        {canDraw && (
          <button className="btn primary" onClick={() => setDrawOpen(true)}>
            <Icon name="target" /> Draw samples
          </button>
        )}
        <button className="btn ghost icon" title="Refresh" aria-label="Refresh" onClick={reloadAll}>
          <Icon name="refresh" />
        </button>
      </div>

      {tab === 'scorecard' && <ScorecardTab state={card} />}
      {tab === 'lessons' && <LessonsTab />}
      {tab === 'queue' && (
        <QueueTab
          state={queue}
          canReview={canReview}
          canDraw={canDraw}
          onDraw={() => setDrawOpen(true)}
          onReviewed={(msg) => { notify('ok', msg); reloadAll() }}
          onError={(msg) => notify('err', msg)}
        />
      )}

      <DrawDialog
        open={drawOpen}
        onClose={() => setDrawOpen(false)}
        onDrawn={(msg) => {
          setDrawOpen(false)
          notify('ok', msg)
          reloadAll()
          setTab('queue')
        }}
      />
    </>
  )
}

// ---------------------------------------------------------------- scorecard

function ScorecardTab({ state }: { state: ReturnType<typeof useScorecard> }) {
  if (state.phase === 'loading') return <div className="p-[22px]"><EmptyState loading icon="target" title="Loading the scorecard…" /></div>
  if (state.phase === 'error' || !state.data) {
    return (
      <div className="p-[22px]">
        <EmptyState error icon="alert" title="Couldn’t load the scorecard" body={state.error} primary={{ label: 'Retry', onClick: state.reload, icon: 'refresh' }} />
      </div>
    )
  }
  return <ScorecardBody data={state.data} staleError={state.error} />
}

function ScorecardBody({ data, staleError }: { data: Scorecard; staleError: string | null }) {
  const cats = data.categories
  const meets = cats.filter((c) => c.status === 'meets').length
  const reviewed = cats.reduce((n, c) => n + c.reviewed, 0)
  const misses = cats.reduce((n, c) => n + c.misses, 0)
  const pending = cats.reduce((n, c) => n + c.pending + c.risk_weighted.pending, 0)
  const target = fmtTarget(data.target)
  const conf = `${Math.round(data.confidence * 100)}%`

  return (
    <>
      {staleError && <p className="text-xs text-high px-[22px] pt-3" role="status">Last refresh failed — showing the previous scorecard.</p>}
      <div className="kpi-strip">
        <Kpi label="Categories at target" value={`${meets} / ${cats.length}`} note={`upper bound ≤ ${target}`} color={meets === cats.length ? 'var(--ok)' : undefined} />
        <Kpi label="Reviewed" value={reviewed.toLocaleString()} note="simple random samples" />
        <Kpi label="Misses" value={misses.toLocaleString()} note="closed as benign, found malicious" color={misses > 0 ? 'var(--crit)' : undefined} />
        <Kpi label="Waiting for review" value={pending.toLocaleString()} note="in the review queue" />
      </div>

      <div className="px-[22px] py-5">
        <section className="card card-sq">
          <div className="card-h">
            <h3 className="text-[14.5px]">False-negative rate by category</h3>
            <span className="flex-1" />
            <span className="text-xs text-tx-3 inline-flex items-center gap-2">
              <span aria-hidden="true" className="inline-block w-[2px] h-3" style={{ background: 'var(--tx-2)' }} />
              target {target} · {conf} one-sided upper bound
            </span>
          </div>
          <div className="card-b">
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Category</th>
                    <th style={{ textAlign: 'right' }}>Reviewed</th>
                    <th style={{ textAlign: 'right' }}>Misses</th>
                    <th>Upper bound vs target</th>
                    <th>Status</th>
                    <th>To reach target</th>
                    <th>Risk-weighted</th>
                  </tr>
                </thead>
                <tbody>
                  {cats.map((c) => <CategoryRow key={c.category} c={c} target={data.target} />)}
                </tbody>
              </table>
            </div>
            <p className="text-xs text-tx-3 mt-3 max-w-[900px] leading-relaxed">
              Each category’s bound is the exact one-sided {conf} Clopper–Pearson upper limit on the share of
              verdicts AutoSecOps handled without a person (closed as benign) that were really malicious, computed
              from simple random reviews only. Risk-weighted reviews over-sample low-confidence and high-severity
              closures; they are counted beside the bound, never in it.
            </p>
          </div>
        </section>
      </div>
    </>
  )
}

function CategoryRow({ c, target }: { c: CategoryScore; target: number }) {
  const status = STATUS[c.status]
  const rw = c.risk_weighted
  return (
    <tr data-category={c.category}>
      <td className="font-semibold">{titleCase(c.category)}</td>
      <td className="font-mono" style={{ textAlign: 'right' }}>{c.reviewed.toLocaleString()}</td>
      <td className="font-mono" style={{ textAlign: 'right', color: c.misses > 0 ? 'var(--crit)' : undefined }}>{c.misses.toLocaleString()}</td>
      <td><BoundBar c={c} target={target} /></td>
      <td><span className="chip" style={{ color: status.color }}>{status.label}</span></td>
      <td className="muted">{toTarget(c)}</td>
      <td className="muted">
        {rw.reviewed + rw.pending === 0 ? '—' : `${plural(rw.reviewed, 'reviewed', 'reviewed')} · ${plural(rw.misses, 'miss', 'misses')}`}
      </td>
    </tr>
  )
}

function toTarget(c: CategoryScore): string {
  if (c.status === 'meets') return 'Met'
  if (c.reviews_needed == null) return 'Out of reach at this miss count'
  return `${plural(c.reviews_needed, 'more review')}, all agreeing`
}

/** The bound as a bar on a 0–3×target scale with a tick at the target. */
function BoundBar({ c, target }: { c: CategoryScore; target: number }) {
  const max = target * SCALE_TIMES_TARGET
  if (c.status === 'no_data') {
    return <span className="text-tx-faint">—</span>
  }
  const over = c.fn_upper_bound > max
  const width = `${Math.min(c.fn_upper_bound / max, 1) * 100}%`
  const color = c.fn_upper_bound <= target ? 'var(--ok)' : 'var(--crit)'
  const track: CSSProperties = { position: 'relative', width: 180, height: 8, borderRadius: 999, background: 'var(--bg-3)', overflow: 'visible' }
  return (
    <span className="inline-flex items-center gap-3">
      <span style={track} role="img" aria-label={`upper bound ${fmtBound(c.fn_upper_bound)}, target ${fmtTarget(target)}`}>
        <span style={{ position: 'absolute', inset: 0, width, background: color, borderRadius: 999 }} />
        <span style={{ position: 'absolute', top: -3, bottom: -3, left: `${100 / SCALE_TIMES_TARGET}%`, width: 2, background: 'var(--tx-2)' }} />
      </span>
      <span className="font-mono text-xs" style={{ color }}>
        {over ? '> ' : ''}{fmtBound(over ? max : c.fn_upper_bound)}
      </span>
    </span>
  )
}

function Kpi({ label, value, note, color }: { label: string; value: string; note: string; color?: string }) {
  return (
    <div className="kpi">
      <div className="k-label">{label}</div>
      <div className="k-row"><span className="k-val" style={color ? { color } : undefined}>{value}</span></div>
      <div className="k-note">{note}</div>
    </div>
  )
}

// ---------------------------------------------------------------- review queue

function QueueTab({
  state, canReview, canDraw, onDraw, onReviewed, onError,
}: {
  state: ReturnType<typeof useReviewQueue>
  canReview: boolean
  canDraw: boolean
  onDraw: () => void
  onReviewed: (msg: string) => void
  onError: (msg: string) => void
}) {
  const [busy, setBusy] = useState<number | null>(null)
  const [disagreeWith, setDisagreeWith] = useState<QASample | null>(null)

  const submit = async (s: QASample, body: { agrees: boolean; review_verdict?: 'malicious' | 'inconclusive'; notes?: string }) => {
    setBusy(s.id)
    try {
      await qaApi.review(s.id, { agrees: body.agrees, review_verdict: body.review_verdict ?? null, notes: body.notes || null })
      setDisagreeWith(null)
      onReviewed(body.agrees ? 'Review saved: the verdict was right' : `Review saved: should have been ${body.review_verdict}`)
    } catch (e) {
      onError(apiErr(e, 'Couldn’t save the review'))
    } finally {
      setBusy(null)
    }
  }

  if (state.phase === 'loading') return <div className="p-[22px]"><EmptyState loading icon="check" title="Loading the review queue…" /></div>
  if (state.phase === 'error') {
    return (
      <div className="p-[22px]">
        <EmptyState error icon="alert" title="Couldn’t load the review queue" body={state.error} primary={{ label: 'Retry', onClick: state.reload, icon: 'refresh' }} />
      </div>
    )
  }
  if (state.samples.length === 0) {
    return (
      <div className="p-[22px]">
        <EmptyState
          icon="check"
          title="Nothing to review"
          body="Draw samples of the verdicts AutoSecOps handled without a person to fill the queue."
          primary={canDraw ? { label: 'Draw samples', onClick: onDraw, icon: 'target' } : undefined}
        />
      </div>
    )
  }

  return (
    <div className="px-[22px] py-5">
      {!canReview && (
        <p className="text-xs text-tx-3 mb-3" role="note">Your role can see the queue but not review it.</p>
      )}
      {state.error && <p className="text-xs text-high mb-3" role="status">Last refresh failed — showing the previous queue.</p>}
      <section className="card card-sq">
        <div className="card-h">
          <h3 className="text-[14.5px]">Closed as benign — was it?</h3>
          <span className="flex-1" />
          <span className="text-xs text-tx-3">{plural(state.samples.length, 'sample')} waiting, oldest first</span>
        </div>
        <div className="card-b">
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Decision</th>
                  <th>Category</th>
                  <th>Sample</th>
                  <th style={{ textAlign: 'right' }}>AI confidence</th>
                  <th>Why it was closed</th>
                  <th>Sampled</th>
                  {canReview && <th style={{ textAlign: 'right' }}>Review</th>}
                </tr>
              </thead>
              <tbody>
                {state.samples.map((s) => (
                  <tr key={s.id} data-sample={s.id}>
                    <td className="font-mono text-xs">{s.subject_id}</td>
                    <td>{titleCase(s.category)}</td>
                    <td>
                      <span className="chip" title={`inclusion probability ${s.inclusion_probability.toFixed(3)}`}>{KIND_LABEL[s.sampling_kind]}</span>
                    </td>
                    <td className="font-mono" style={{ textAlign: 'right' }}>{s.ai_confidence == null ? '—' : `${Math.round(s.ai_confidence * 100)}%`}</td>
                    <td style={{ whiteSpace: 'normal', minWidth: 260 }}>
                      <Clamp text={s.reasoning || s.decision_type || '—'} />
                    </td>
                    <td className="muted">{utcDayClock(s.sampled_at) ?? '—'}</td>
                    {canReview && (
                      <td style={{ textAlign: 'right' }}>
                        <span className="inline-flex gap-2">
                          <button className="btn" disabled={busy === s.id} onClick={() => submit(s, { agrees: true })}>
                            <Icon name="check" /> Agree
                          </button>
                          <button className="btn" disabled={busy === s.id} onClick={() => setDisagreeWith(s)}>
                            <Icon name="close" /> Disagree
                          </button>
                        </span>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <DisagreeDialog
        sample={disagreeWith}
        busy={disagreeWith != null && busy === disagreeWith.id}
        onClose={() => setDisagreeWith(null)}
        onSubmit={(verdict, notes) => disagreeWith && submit(disagreeWith, { agrees: false, review_verdict: verdict, notes })}
      />
    </div>
  )
}

function Clamp({ text }: { text: string }) {
  const style: CSSProperties = { display: '-webkit-box', WebkitBoxOrient: 'vertical', WebkitLineClamp: 2, overflow: 'hidden' }
  return <span style={style} title={text}>{text}</span>
}

function DisagreeDialog({
  sample, busy, onClose, onSubmit,
}: {
  sample: QASample | null
  busy: boolean
  onClose: () => void
  onSubmit: (verdict: 'malicious' | 'inconclusive', notes: string) => void
}) {
  const [verdict, setVerdict] = useState<'malicious' | 'inconclusive'>('malicious')
  const [notes, setNotes] = useState('')
  const submit = (e: FormEvent) => {
    e.preventDefault()
    onSubmit(verdict, notes.trim())
  }
  return (
    <Popup open={sample != null} onClose={onClose} title="What should the verdict have been?" width={480}>
      {sample && (
        <form onSubmit={submit} className="flex flex-col gap-4">
          <p className="text-[13px] text-tx-2">
            AutoSecOps closed <span className="font-mono">{sample.subject_id}</span> as benign.{' '}
            {sample.sampling_kind === 'simple_random'
              ? `Malicious counts as a miss against the ${titleCase(sample.category).toLowerCase()} bound; inconclusive counts as a disagreement, not a miss.`
              : `This is a risk-weighted extra: it is reported on its own and never enters the ${titleCase(sample.category).toLowerCase()} bound, whatever the verdict.`}
          </p>
          <Field label="Correct verdict">
            <div className="range-tabs" role="radiogroup" aria-label="Correct verdict">
              {(['malicious', 'inconclusive'] as const).map((v) => (
                <button key={v} type="button" role="radio" aria-checked={verdict === v} className={verdict === v ? 'active' : ''} onClick={() => setVerdict(v)}>
                  {titleCase(v)}
                </button>
              ))}
            </div>
          </Field>
          <Field label="Notes" hint="Optional. What the AI missed.">
            <textarea className="feedback-box" aria-label="Notes" value={notes} onChange={(e) => setNotes(e.target.value)} maxLength={4000} />
          </Field>
          <div className="flex justify-end gap-2">
            <button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy}>Save review</button>
          </div>
        </form>
      )}
    </Popup>
  )
}

// ---------------------------------------------------------------- draw

function DrawDialog({ open, onClose, onDrawn }: { open: boolean; onClose: () => void; onDrawn: (msg: string) => void }) {
  const [days, setDays] = useState(7)
  const [perCategory, setPerCategory] = useState(30)
  const [extra, setExtra] = useState(0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const res = await qaApi.draw({ days, per_category: perCategory, risk_weighted_extra: extra })
      const random = Object.values(res.data.categories).reduce((n, c) => n + c.drawn, 0)
      const rw = res.data.risk_weighted.drawn
      onDrawn(`Drew ${plural(random, 'random sample')}${rw ? ` and ${plural(rw, 'risk-weighted extra', 'risk-weighted extras')}` : ''}`)
    } catch (err) {
      setError(apiErr(err, 'Couldn’t draw samples'))
    } finally {
      setBusy(false)
    }
  }

  const num = (set: (n: number) => void) => (e: { target: { value: string } }) => set(Math.max(0, parseInt(e.target.value, 10) || 0))

  return (
    <Popup open={open} onClose={onClose} title="Draw review samples" width={480}>
      <form onSubmit={submit} className="flex flex-col gap-4">
        <p className="text-[13px] text-tx-2">
          Takes a simple random sample, per category, of the verdicts AutoSecOps handled without a person in the window. Decisions already sampled are not drawn again.
        </p>
        <Field label="Window (days)"><NumberInput min={1} max={365} value={days} onChange={num(setDays)} aria-label="Window (days)" /></Field>
        <Field label="Per category" hint="Simple random sample size. These are the reviews the bound is computed from.">
          <NumberInput min={0} max={1000} value={perCategory} onChange={num(setPerCategory)} aria-label="Per category" />
        </Field>
        <Field label="Risk-weighted extras" hint="About this many more, favouring low confidence and high severity. Counted separately, never in the bound.">
          <NumberInput min={0} max={1000} value={extra} onChange={num(setExtra)} aria-label="Risk-weighted extras" />
        </Field>
        {error && <p className="text-xs text-crit" role="alert">{error}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn primary" disabled={busy || days < 1}>Draw</button>
        </div>
      </form>
    </Popup>
  )
}

