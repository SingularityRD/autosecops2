// W0.36: the response policy as the Settings form edits it, and back.
import type { Schema } from '../../services/apiTypes'

type Policy = Schema<'ResponsePolicyView'>
type Update = Schema<'ResponsePolicyUpdate'>

export interface Draft {
  targets: string
  assetTags: string
  tags: string
  limits: Record<string, string>
  defaultLimit: string
  fourEyes: Set<string>
}

export const pretty = (s: string) => s.replace(/_/g, ' ')

const lines = (text: string) =>
  text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)

const words = (text: string) =>
  text
    .split(/[,\s]+/)
    .map((w) => w.trim())
    .filter(Boolean)

/** "dc01.corp.local: tier0, domain_controller" per line -> {target: [tags]} */
export function parseAssetTags(text: string): Record<string, string[]> {
  const out: Record<string, string[]> = {}
  for (const line of lines(text)) {
    const at = line.lastIndexOf(':')
    // An IPv6 address carries colons of its own: the tags follow the last ": ".
    const sep = line.lastIndexOf(': ') >= 0 ? line.lastIndexOf(': ') : at
    const target = (sep > 0 ? line.slice(0, sep) : line).trim()
    const tags = sep > 0 ? words(line.slice(sep + 1)) : []
    out[target] = [...(out[target] ?? []), ...tags]
  }
  return out
}

export function toDraft(p: Policy): Draft {
  return {
    targets: p.protected_targets.join('\n'),
    assetTags: Object.entries(p.asset_tags)
      .map(([t, tags]) => `${t}: ${tags.join(', ')}`)
      .join('\n'),
    tags: p.protected_tags.join(', '),
    limits: Object.fromEntries(Object.entries(p.hourly_limits).map(([k, v]) => [k, String(v)])),
    defaultLimit: String(p.default_hourly_limit),
    fourEyes: new Set(p.four_eyes_types),
  }
}

export function toUpdate(d: Draft, reason: string, version: string): Update | string {
  const limits: Record<string, number> = {}
  for (const [k, v] of Object.entries(d.limits)) {
    if (v.trim() === '') continue
    const n = Number(v)
    if (!Number.isInteger(n) || n < 0 || n > 1000) return `${pretty(k)}: limit must be a whole number from 0 to 1000`
    limits[k] = n
  }
  const def = Number(d.defaultLimit)
  if (!Number.isInteger(def) || def < 0 || def > 1000) return 'Default limit must be a whole number from 0 to 1000'
  return {
    protected_targets: lines(d.targets),
    asset_tags: parseAssetTags(d.assetTags),
    protected_tags: words(d.tags),
    hourly_limits: limits,
    default_hourly_limit: def,
    four_eyes_types: [...d.fourEyes].sort(),
    reason,
    version,
  }
}
