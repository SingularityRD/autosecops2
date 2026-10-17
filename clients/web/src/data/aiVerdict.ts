import type { TriageVerdict } from '../services/api'

const VERDICTS = new Set(['malicious', 'benign', 'inconclusive'])
const AUTHORS = new Set(['sensor', 'adversary', 'third_party'])

/** The stored verdict in a finding's ai_enrichment, if it has the contract's shape. */
export function verdictFromEnrichment(enrichment: unknown): TriageVerdict | null {
  if (!enrichment || typeof enrichment !== 'object') return null
  const e = enrichment as Record<string, unknown>
  const triage = e.ai_triage as Record<string, unknown> | undefined
  if (!triage || typeof triage !== 'object') {
    return typeof e.ai_triage_error === 'string' && e.ai_triage_error
      ? { state: 'failed', error: e.ai_triage_error.slice(0, 300) }
      : null
  }
  const v = triage.verdict as Record<string, unknown> | undefined
  const cited = Array.isArray(v?.cited_fields) ? v.cited_fields : null
  if (
    !v ||
    typeof v.verdict !== 'string' ||
    !VERDICTS.has(v.verdict) ||
    typeof v.confidence !== 'number' ||
    typeof v.category !== 'string' ||
    !cited ||
    !cited.every((c) => c && typeof c.field === 'string' && AUTHORS.has(c.authored)) ||
    !Array.isArray(v.gaps)
  ) {
    return { state: 'unreadable' }
  }
  const action = v.recommended_action as { type?: unknown; target?: unknown } | undefined
  return {
    state: 'verdict',
    verdict: v.verdict as 'malicious' | 'benign' | 'inconclusive',
    confidence: v.confidence,
    category: v.category,
    cited_fields: cited as { field: string; authored: 'sensor' | 'adversary' | 'third_party' }[],
    gaps: (v.gaps as unknown[]).filter((g): g is string => typeof g === 'string'),
    recommended_action:
      action && typeof action.type === 'string' && typeof action.target === 'string'
        ? { type: action.type, target: action.target }
        : null,
    model: typeof v.model === 'string' ? v.model : '',
    prompt_version: typeof v.prompt_version === 'string' ? v.prompt_version : '',
    at: typeof triage.timestamp === 'string' ? triage.timestamp : null,
  }
}
