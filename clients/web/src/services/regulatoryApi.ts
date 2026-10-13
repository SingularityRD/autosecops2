import api from './api'
import type { Schema } from './apiTypes'

export type RegulatoryStatus = Schema<'RegulatoryStatusResponse'>
export type RegulatoryClock = Schema<'ClockStatusResponse'>
export type RegulatoryDraft = Schema<'DraftResponse'>
export type RecordInstant = Schema<'RecordInstantRequest'>
export type DraftRequest = Schema<'GenerateDraftRequest'>

/** DORA / NIS2 notification clocks on a case (W3.8). */
export const regulatoryApi = {
  clocks: (caseId: string) =>
    api.get<RegulatoryStatus>(`/cases/${encodeURIComponent(caseId)}/regulatory/clocks`),
  record: (caseId: string, body: RecordInstant) =>
    api.post<Schema<'RecordInstantResponse'>>(`/cases/${encodeURIComponent(caseId)}/regulatory/events`, body),
  drafts: (caseId: string) =>
    api.get<Schema<'DraftsResponse'>>(`/cases/${encodeURIComponent(caseId)}/regulatory/drafts`),
  draft: (caseId: string, body: DraftRequest) =>
    api.post<RegulatoryDraft>(`/cases/${encodeURIComponent(caseId)}/regulatory/drafts`, body),
}
