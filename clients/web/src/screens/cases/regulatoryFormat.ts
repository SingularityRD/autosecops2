import type { RegulatoryClock } from '../../services/regulatoryApi'

export type Regime = 'dora' | 'nis2'

/** The instants each regime records, in the order they happen. */
export const INSTANTS: Record<Regime, { id: string; label: string }[]> = {
  dora: [
    { id: 'aware_at', label: 'Became aware' },
    { id: 'classification_at', label: 'Classified as major' },
    { id: 'notified_at', label: 'Initial notification sent' },
    { id: 'last_intermediate_at', label: 'Last intermediate report sent' },
    { id: 'final_at', label: 'Final report sent' },
  ],
  nis2: [
    { id: 'aware_at', label: 'Became aware' },
    { id: 'early_warning_at', label: 'Early warning sent' },
    { id: 'notified_at', label: 'Incident notification sent' },
    { id: 'final_at', label: 'Final report sent' },
  ],
}

function span(ms: number): string {
  const min = Math.round(Math.abs(ms) / 60_000)
  if (min < 60) return `${min} min`
  const h = Math.floor(min / 60)
  if (h < 48) return `${h} h ${min % 60} min`
  return `${Math.floor(h / 24)} d ${h % 24} h`
}

/** "3 h 12 min left", "overdue by 1 h 5 min", or the met state; '' while not started. */
export function countdown(clock: RegulatoryClock, nowMs: number): string {
  if (clock.state === 'met') return 'Met'
  if (clock.state === 'met_late') return 'Met late'
  if (!clock.due_at) return ''
  const ms = new Date(clock.due_at).getTime() - nowMs
  if (Number.isNaN(ms)) return ''
  return ms < 0 ? `overdue by ${span(ms)}` : `${span(ms)} left`
}

/** The clock's state at `nowMs`: a running clock turns overdue in the browser without a reload. */
export function liveState(clock: RegulatoryClock, nowMs: number): RegulatoryClock['state'] {
  if (clock.state !== 'running' || !clock.due_at) return clock.state
  return new Date(clock.due_at).getTime() < nowMs ? 'overdue' : 'running'
}
