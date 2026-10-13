import { useCallback, useEffect, useState } from 'react'
import { qaApi } from '../../services/api'
import type { Schema } from '../../services/apiTypes'

export type Phase = 'loading' | 'ready' | 'error'
export type Scorecard = Schema<'QAScorecardResponse'>
export type CategoryScore = Schema<'QACategoryScore'>
export type QASample = Schema<'QASample'>

export function apiErr(e: unknown, fallback: string): string {
  const r = e as { response?: { data?: { detail?: unknown } }; message?: string }
  const detail = r?.response?.data?.detail
  return (typeof detail === 'string' && detail) || r?.message || fallback
}

/** Per-category FN upper bounds against the target. */
export function useScorecard() {
  const [data, setData] = useState<Scorecard | null>(null)
  const [phase, setPhase] = useState<Phase>('loading')
  const [error, setError] = useState<string | null>(null)
  const [reloadKey, setReloadKey] = useState(0)
  const reload = useCallback(() => setReloadKey((k) => k + 1), [])

  useEffect(() => {
    let cancelled = false
    setError(null)
    qaApi
      .scorecard()
      .then((res) => {
        if (cancelled) return
        setData(res.data)
        setPhase('ready')
      })
      .catch((e) => {
        if (cancelled) return
        setError(apiErr(e, 'Failed to load the scorecard'))
        // keep the last good card on a failed refresh
        setPhase((p) => (p === 'ready' ? 'ready' : 'error'))
      })
    return () => {
      cancelled = true
    }
  }, [reloadKey])

  return { data, phase, error, reload }
}

/** Samples waiting for a review, oldest first. */
export function useReviewQueue() {
  const [samples, setSamples] = useState<QASample[]>([])
  const [phase, setPhase] = useState<Phase>('loading')
  const [error, setError] = useState<string | null>(null)
  const [reloadKey, setReloadKey] = useState(0)
  const reload = useCallback(() => setReloadKey((k) => k + 1), [])

  useEffect(() => {
    let cancelled = false
    setError(null)
    qaApi
      .samples({ status: 'pending', limit: 500 })
      .then((res) => {
        if (cancelled) return
        setSamples(res.data.samples)
        setPhase('ready')
      })
      .catch((e) => {
        if (cancelled) return
        setError(apiErr(e, 'Failed to load the review queue'))
        setPhase((p) => (p === 'ready' ? 'ready' : 'error'))
      })
    return () => {
      cancelled = true
    }
  }, [reloadKey])

  return { samples, phase, error, reload }
}
