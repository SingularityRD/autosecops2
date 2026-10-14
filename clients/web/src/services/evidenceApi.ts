import api from './api'

/** A case's signed evidence pack (W3.7): a ZIP the recipient verifies offline. */
export const evidenceApi = {
  pack: (caseId: string) =>
    api.get<Blob>(`/cases/${encodeURIComponent(caseId)}/evidence-pack`, {
      responseType: 'blob',
      timeout: 120_000,
    }),
}

/** The file name the server chose, from Content-Disposition; a fallback when absent. */
export function packFilename(disposition: unknown, caseId: string): string {
  if (typeof disposition === 'string') {
    const match = /filename="?([^";]+)"?/i.exec(disposition)
    if (match?.[1]) return match[1]
  }
  return `evidence-pack-${caseId}.zip`
}
