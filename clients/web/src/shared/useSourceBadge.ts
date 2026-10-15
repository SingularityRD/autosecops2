import { sourceBadge, type SourceBadge } from '../config/sourceBadges'

/** Resolves a data_source to its chip badge from the static map. */
export function useSourceBadge(): (source?: string | null) => SourceBadge {
  return sourceBadge
}
