import { qaApi } from '../services/api'

/** Save the POC report (W0.49) for the last `days` days; a failure is shown, not swallowed. */
export async function downloadPocReport(days: number): Promise<void> {
  try {
    const res = await qaApi.pocReport(Math.max(1, Math.min(365, Math.round(days))))
    const url = URL.createObjectURL(res.data)
    const a = document.createElement('a')
    a.href = url
    a.download = `autosecops-poc-report-${days}d.md`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  } catch {
    window.alert('The report could not be generated. You need the settings.read permission; otherwise check the server log.')
  }
}

const RANGE_DAYS: Record<string, number> = { '24h': 1, '7d': 7, '30d': 30, all: 365 }

export const daysForRange = (range: string): number => RANGE_DAYS[range] ?? 30
