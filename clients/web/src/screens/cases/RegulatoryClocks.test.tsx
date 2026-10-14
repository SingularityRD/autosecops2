import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { RegulatoryClock, RegulatoryStatus } from '../../services/regulatoryApi'

const auth = vi.hoisted(() => ({ canWrite: true }))

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => p !== 'cases.write' || auth.canWrite }),
}))

vi.mock('../../services/regulatoryApi', () => ({
  regulatoryApi: {
    clocks: vi.fn(),
    record: vi.fn(),
    drafts: vi.fn(),
    draft: vi.fn(),
  },
}))

import { regulatoryApi } from '../../services/regulatoryApi'
import { RegulatoryClocks } from './RegulatoryClocks'
import { countdown, liveState } from './regulatoryFormat'

const NOW = '2026-03-03T09:00:00+00:00'

function clock(over: Partial<RegulatoryClock>): RegulatoryClock {
  return {
    key: 'nis2.early_warning',
    regime: 'nis2',
    label: 'NIS2 early warning',
    state: 'not_started',
    met_by: 'early_warning_at',
    overdue: false,
    due_at: null,
    bound_to: null,
    started_at: null,
    met_at: null,
    waiting_for: 'aware_at',
    remaining_seconds: null,
    ...over,
  }
}

function status(over: Partial<RegulatoryStatus> = {}): RegulatoryStatus {
  return {
    case_id: 'c-1',
    now: NOW,
    timezone: 'Europe/Istanbul',
    durations: {},
    events: 2,
    chain: { ok: true, broken_at: null, why: null, rows: 2 },
    instants: {
      dora: {
        classification_at: { value: '2026-03-03T06:00:00+00:00', actor: 'ayse', recorded_at: NOW, seq: 2, reason: null },
      },
      nis2: {},
    },
    clocks: [
      clock({
        key: 'dora.initial',
        regime: 'dora',
        label: 'DORA initial notification',
        state: 'overdue',
        due_at: '2026-03-03T08:00:00+00:00',
        bound_to: 'aware_at',
        overdue: true,
        remaining_seconds: -3600,
      }),
      clock({
        key: 'dora.intermediate',
        regime: 'dora',
        label: 'DORA intermediate report',
        waiting_for: 'notified_at',
      }),
      clock({
        key: 'nis2.notification',
        regime: 'nis2',
        label: 'NIS2 incident notification',
        state: 'running',
        due_at: '2026-03-05T08:00:00+00:00',
        bound_to: 'aware_at',
        remaining_seconds: 47 * 3600,
      }),
    ],
    ...over,
  }
}

beforeEach(() => {
  auth.canWrite = true
  vi.mocked(regulatoryApi.clocks).mockReset()
  vi.mocked(regulatoryApi.record).mockReset()
  vi.mocked(regulatoryApi.draft).mockReset()
  vi.mocked(regulatoryApi.clocks).mockResolvedValue({ data: status() } as never)
})

describe('countdown', () => {
  const at = new Date('2026-03-03T09:00:00Z').getTime()
  it('counts down, then over', () => {
    expect(countdown(clock({ state: 'running', due_at: '2026-03-03T12:12:00Z' }), at)).toBe('3 h 12 min left')
    expect(countdown(clock({ state: 'running', due_at: '2026-03-03T08:55:00Z' }), at)).toBe('overdue by 5 min')
    expect(countdown(clock({ state: 'running', due_at: '2026-03-06T11:00:00Z' }), at)).toBe('3 d 2 h left')
    expect(countdown(clock({ state: 'met', due_at: '2026-03-03T08:55:00Z' }), at)).toBe('Met')
    expect(countdown(clock({}), at)).toBe('')
  })
  it('turns a running clock overdue without a reload', () => {
    expect(liveState(clock({ state: 'running', due_at: '2026-03-03T08:59:00Z' }), at)).toBe('overdue')
    expect(liveState(clock({ state: 'running', due_at: '2026-03-03T09:01:00Z' }), at)).toBe('running')
    expect(liveState(clock({ state: 'met_late', due_at: '2026-03-03T08:00:00Z' }), at)).toBe('met_late')
  })
})

describe('RegulatoryClocks', () => {
  it('shows the DORA clocks with due, binding instant and overdue state', async () => {
    render(<RegulatoryClocks caseId="c-1" />)
    expect(await screen.findByText('DORA initial notification')).toBeInTheDocument()
    expect(screen.getByText('1 overdue', { exact: false })).toBeInTheDocument()
    const row = screen.getByText('DORA initial notification').closest('li')!
    expect(row).toHaveAttribute('data-state', 'overdue')
    expect(row.textContent).toContain('from became aware')
    expect(row.textContent).toContain('overdue by 1 h 0 min')
    expect(screen.getByText('Starts when initial notification sent is recorded')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: 'NIS2' }))
    expect(screen.getByText('NIS2 incident notification').closest('li')).toHaveAttribute('data-state', 'running')
  })

  it('asks for a reason before changing a recorded instant', async () => {
    vi.mocked(regulatoryApi.record).mockResolvedValue({ data: { changed: true, event: null, status: status() } } as never)
    render(<RegulatoryClocks caseId="c-1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Change Classified as major' }))
    fireEvent.change(screen.getByLabelText('Classified as major time (UTC)'), { target: { value: '2026-03-03T05:00' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Say why')
    expect(regulatoryApi.record).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText('Reason for changing Classified as major'), { target: { value: 'board call moved' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(regulatoryApi.record).toHaveBeenCalledWith('c-1', {
        regime: 'dora',
        instant: 'classification_at',
        value: '2026-03-03T05:00:00.000Z',
        reason: 'board call moved',
      }),
    )
  })

  it('records a first instant without a reason', async () => {
    vi.mocked(regulatoryApi.record).mockResolvedValue({ data: { changed: true, event: null, status: status() } } as never)
    render(<RegulatoryClocks caseId="c-1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Record Became aware' }))
    expect(screen.queryByLabelText('Reason for changing Became aware')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Became aware time (UTC)'), { target: { value: '2026-03-03T04:00' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(regulatoryApi.record).toHaveBeenCalledWith('c-1', {
      regime: 'dora', instant: 'aware_at', value: '2026-03-03T04:00:00.000Z', reason: null,
    }))
  })

  it('a viewer sees the clocks but cannot record or draft', async () => {
    auth.canWrite = false
    render(<RegulatoryClocks caseId="c-1" />)
    expect(await screen.findByText('DORA initial notification')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^(Record|Change) / })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Initial' })).not.toBeInTheDocument()
  })

  it('generates a draft and shows what it cites', async () => {
    vi.mocked(regulatoryApi.draft).mockResolvedValue({
      data: { title: 'DORA initial notification of a major ICT-related incident', cited_ids: ['case:c-1', 'finding:f-1'], markdown: '# Draft\n- Beacon [finding:f-1]\n' },
    } as never)
    render(<RegulatoryClocks caseId="c-1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Initial' }))
    expect(await screen.findByText(/cites 2 items/)).toBeInTheDocument()
    expect(screen.getByText(/Beacon \[finding:f-1\]/)).toBeInTheDocument()
    expect(regulatoryApi.draft).toHaveBeenCalledWith('c-1', { regime: 'dora', kind: 'initial' })
  })

  it('warns when the instant history does not verify', async () => {
    vi.mocked(regulatoryApi.clocks).mockResolvedValue({ data: status({ chain: { ok: false, broken_at: 2, why: 'hash mismatch', rows: null } }) } as never)
    render(<RegulatoryClocks caseId="c-1" />)
    expect(await screen.findByRole('alert')).toHaveTextContent('row 2: hash mismatch')
  })

  it('warns when the chain head is unavailable, without a row number', async () => {
    vi.mocked(regulatoryApi.clocks).mockResolvedValue({ data: status({ chain: { ok: false, broken_at: null, why: 'chain head unavailable', rows: null } }) } as never)
    render(<RegulatoryClocks caseId="c-1" />)
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('does not verify (chain head unavailable)')
    expect(alert).not.toHaveTextContent('row')
  })

  it('says when a verified history was not checked against a chain head', async () => {
    vi.mocked(regulatoryApi.clocks).mockResolvedValue({ data: status({ chain: { ok: true, broken_at: null, why: null, rows: 2, anchored: false } }) } as never)
    render(<RegulatoryClocks caseId="c-1" />)
    expect(await screen.findByText(/no chain head was checked/)).toBeInTheDocument()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('shows no head note for an anchored chain', async () => {
    vi.mocked(regulatoryApi.clocks).mockResolvedValue({ data: status({ chain: { ok: true, broken_at: null, why: null, rows: 2, anchored: true } }) } as never)
    render(<RegulatoryClocks caseId="c-1" />)
    await screen.findByRole('tablist')
    expect(screen.queryByText(/no chain head was checked/)).toBeNull()
  })

  it('says so when the clocks cannot be read', async () => {
    vi.mocked(regulatoryApi.clocks).mockRejectedValue(new Error('down'))
    render(<RegulatoryClocks caseId="c-1" />)
    expect(await screen.findByText('Couldn’t load the regulatory clocks.')).toBeInTheDocument()
  })
})
