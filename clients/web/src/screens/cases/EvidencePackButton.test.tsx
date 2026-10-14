import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../../services/evidenceApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../services/evidenceApi')>()),
  evidenceApi: { pack: vi.fn() },
}))

import { evidenceApi, packFilename } from '../../services/evidenceApi'
import { EvidencePackButton } from './EvidencePackButton'

const pack = vi.mocked(evidenceApi.pack)

describe('EvidencePackButton', () => {
  let click: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    pack.mockReset()
    URL.createObjectURL = vi.fn(() => 'blob:pack')
    URL.revokeObjectURL = vi.fn()
    click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  })
  afterEach(() => click.mockRestore())

  it('downloads the pack under the server file name', async () => {
    pack.mockResolvedValue({
      data: new Blob(['zip'], { type: 'application/zip' }),
      headers: {
        'content-disposition': 'attachment; filename="evidence-pack-c-1-20260302T120000Z.zip"',
        'x-evidence-pack-key-source': 'configured',
      },
    } as never)
    const report = vi.fn()
    render(<EvidencePackButton caseId="c-1" report={report} />)
    fireEvent.click(screen.getByRole('button', { name: 'Evidence pack' }))
    await waitFor(() => expect(report).toHaveBeenLastCalledWith({
      level: 'good',
      text: 'Evidence pack saved · evidence-pack-c-1-20260302T120000Z.zip',
    }))
    expect(pack).toHaveBeenCalledWith('c-1')
    expect(click).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('button', { name: 'Evidence pack' })).not.toBeDisabled()
  })

  it('says when the pack was signed with a one-off key', async () => {
    pack.mockResolvedValue({
      data: new Blob(['zip']),
      headers: { 'x-evidence-pack-key-source': 'ephemeral' },
    } as never)
    const report = vi.fn()
    render(<EvidencePackButton caseId="c-1" report={report} />)
    fireEvent.click(screen.getByRole('button', { name: 'Evidence pack' }))
    await waitFor(() => expect(report.mock.lastCall?.[0]?.level).toBe('fair'))
    expect(report.mock.lastCall?.[0]?.text).toMatch(/one-off key/)
  })

  it('reports the server detail from a blob error body', async () => {
    pack.mockRejectedValue({
      response: { data: new Blob([JSON.stringify({ detail: 'Missing permission: cases.read' })]) },
    })
    const report = vi.fn()
    render(<EvidencePackButton caseId="c-1" report={report} />)
    fireEvent.click(screen.getByRole('button', { name: 'Evidence pack' }))
    await waitFor(() => expect(report).toHaveBeenLastCalledWith({ level: 'poor', text: 'Missing permission: cases.read' }))
    expect(click).not.toHaveBeenCalled()
  })

  it('falls back to a file name when the header is missing', () => {
    expect(packFilename(undefined, 'c-9')).toBe('evidence-pack-c-9.zip')
    expect(packFilename('attachment; filename=x.zip', 'c-9')).toBe('x.zip')
  })
})
