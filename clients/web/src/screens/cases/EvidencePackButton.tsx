import { useState } from 'react'
import type { Level } from '../../shared/LevelBadge'
import { InfoTip } from '../../shared/InfoTip'
import { evidenceApi, packFilename } from '../../services/evidenceApi'

export type PackStatus = { level: Level; text: string } | null

function blobText(blob: Blob): Promise<string> {
  if (typeof blob.text === 'function') return blob.text()
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result ?? ''))
    reader.onerror = () => reject(reader.error)
    reader.readAsText(blob)
  })
}

/** The error's detail; a blob error body (responseType blob) is read as JSON first. */
async function failure(error: unknown): Promise<string> {
  const data = (error as { response?: { data?: unknown } })?.response?.data
  let detail: unknown = (data as { detail?: unknown } | undefined)?.detail
  if (data instanceof Blob) {
    try {
      detail = (JSON.parse(await blobText(data)) as { detail?: unknown }).detail
    } catch {
      detail = undefined
    }
  }
  if (typeof detail === 'string' && detail.trim()) return detail
  return (error as { message?: string })?.message || 'Evidence pack failed'
}

/**
 * Downloads the case's signed evidence pack. Progress and failure go to `report`
 * (the Record header's status line).
 */
export function EvidencePackButton({ caseId, report }: { caseId: string; report: (s: PackStatus) => void }) {
  const [busy, setBusy] = useState(false)

  const download = async () => {
    setBusy(true)
    report({ level: null, text: 'Building evidence pack…' })
    try {
      const res = await evidenceApi.pack(caseId)
      const blob = res.data instanceof Blob ? res.data : new Blob([res.data as BlobPart], { type: 'application/zip' })
      const name = packFilename(res.headers?.['content-disposition'], caseId)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = name
      a.click()
      URL.revokeObjectURL(url)
      const ephemeral = res.headers?.['x-evidence-pack-key-source'] === 'ephemeral'
      report(
        ephemeral
          ? { level: 'fair', text: `Evidence pack saved · signed with a one-off key (no signing key configured)` }
          : { level: 'good', text: `Evidence pack saved · ${name}` },
      )
    } catch (e) {
      report({ level: 'poor', text: await failure(e) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <button type="button" className="rec-btn" onClick={download} disabled={busy}>
        Evidence pack
      </button>
      <InfoTip
        label="About the evidence pack"
        align="end"
        source="The case, findings, evidence, audit log, response actions with before/after state, the runs’ hash-chained ledger, AI verdicts and regulatory clock events, as a signed ZIP."
        calculation="Every file’s sha256 is in a manifest signed with Ed25519; the ledger and clock chains are recomputed by the verifier."
        limit="Verify offline with `autosecops verify-bundle <file> --public-key <key>` or the verify_bundle.py inside the pack."
      />
    </>
  )
}
