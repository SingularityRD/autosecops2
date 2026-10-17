import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../services/api', () => ({ qaApi: { pocReport: vi.fn() } }))

import { qaApi } from '../services/api'
import { daysForRange, downloadPocReport } from './pocReport'

describe('POC report download (W0.49)', () => {
  beforeEach(() => {
    vi.mocked(qaApi.pocReport).mockReset()
    URL.createObjectURL = vi.fn(() => 'blob:x')
    URL.revokeObjectURL = vi.fn()
  })

  it('maps the analytics ranges to days', () => {
    expect(daysForRange('24h')).toBe(1)
    expect(daysForRange('7d')).toBe(7)
    expect(daysForRange('30d')).toBe(30)
    expect(daysForRange('all')).toBe(365)
    expect(daysForRange('weird')).toBe(30)
  })

  it('asks for the window, clamped, and saves a Markdown file', async () => {
    vi.mocked(qaApi.pocReport).mockResolvedValue({ data: new Blob(['# r']) } as never)
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    await downloadPocReport(9999)
    expect(qaApi.pocReport).toHaveBeenCalledWith(365)
    expect(click).toHaveBeenCalled()
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:x')
  })

  it('says so when the report cannot be made', async () => {
    vi.mocked(qaApi.pocReport).mockRejectedValue(new Error('403'))
    const alert = vi.spyOn(window, 'alert').mockImplementation(() => {})
    await downloadPocReport(30)
    expect(alert).toHaveBeenCalledWith(expect.stringContaining('settings.read'))
  })
})
