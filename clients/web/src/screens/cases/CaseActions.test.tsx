import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { CaseActions, expiryChip, statusChip, useCaseActions } from './CaseActions'
import { ToastProvider } from '../../shell/toast'
import { casesApi, responseActionsApi, type CaseActionItem } from '../../services/api'

vi.mock('../../services/api', () => ({
  casesApi: { getActionTimeline: vi.fn() },
  responseActionsApi: { revert: vi.fn() },
}))

const NOW = Date.parse('2026-10-12T12:00:00Z')

function item(over: Partial<CaseActionItem> = {}): CaseActionItem {
  return {
    action_id: 'act-1',
    action_type: 'block_ip',
    title: 'Block 203.0.113.9 at the edge',
    target: '203.0.113.9',
    status: 'executed',
    reversibility: 'reversible',
    can_revert: true,
    proposed_at: '2026-10-12T10:00:00Z',
    proposed_by: 'responder-agent',
    confidence: 0.92,
    reason: 'Beaconing to a known C2 host.',
    policy: { requires_approval: true, decision_rule: 'severity=high [met]' },
    approved_at: '2026-10-12T10:05:00Z',
    approved_by: 'alice',
    second_approver: 'bob',
    rejection_reason: null,
    executed_at: '2026-10-12T10:06:00Z',
    execution: { success: true, status: 'done', message: 'Rule added', error: null },
    verified_at: '2026-10-12T10:07:00Z',
    verify_status: 'verified',
    expires_at: '2026-10-12T14:00:00Z',
    reversed_at: null,
    reverse_of: null,
    reverted_by: null,
    before_state: [{ key: 'blocked', value: 'false' }],
    after_state: [{ key: 'blocked', value: 'true' }],
    events: [
      { kind: 'proposed', at: '2026-10-12T10:00:00Z', actor: 'responder-agent', detail: null },
      { kind: 'approved', at: '2026-10-12T10:05:00Z', actor: 'alice + bob', detail: null },
      { kind: 'executed', at: '2026-10-12T10:06:00Z', actor: null, detail: 'Rule added' },
      { kind: 'verified', at: '2026-10-12T10:07:00Z', actor: null, detail: 'verified' },
    ],
    ...over,
  }
}

function show(actions: CaseActionItem[], canRevert = true, onReverted = vi.fn()) {
  render(
    <ToastProvider>
      <div className="case-page">
        <CaseActions actions={actions} phase="ready" error={null} canRevert={canRevert} onRetry={vi.fn()} onReverted={onReverted} />
      </div>
    </ToastProvider>,
  )
  return onReverted
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] })
  vi.setSystemTime(NOW)
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.clearAllMocks()
})

describe('chips', () => {
  it('names where each action stands', () => {
    expect(statusChip(item()).text).toBe('Executed')
    expect(statusChip(item({ status: 'pending' })).text).toBe('Needs you')
    expect(statusChip(item({ status: 'pending', policy: { requires_approval: false, decision_rule: null } })).text).toBe('Proposed')
    expect(statusChip(item({ status: 'rejected' })).text).toBe('Rejected')
    expect(statusChip(item({ status: 'failed' })).tone).toBe('poor')
    expect(statusChip(item({ reversed_at: '2026-10-12T11:00:00Z' })).text).toBe('Reverted')
  })

  it('counts down to expiry only while the change stands', () => {
    expect(expiryChip(item(), NOW)?.text).toBe('Reverts in 2 h')
    expect(expiryChip(item({ expires_at: '2026-10-12T12:30:00Z' }), NOW)?.text).toBe('Reverts in 30 min')
    expect(expiryChip(item({ expires_at: '2026-10-12T11:00:00Z' }), NOW)?.text).toBe('Expiry due')
    expect(expiryChip(item({ reversed_at: '2026-10-12T11:00:00Z' }), NOW)).toBeNull()
    expect(expiryChip(item({ status: 'pending' }), NOW)).toBeNull()
    expect(expiryChip(item({ expires_at: null }), NOW)).toBeNull()
  })
})

describe('CaseActions', () => {
  it('renders the lifecycle, chips and before/after', () => {
    show([item()])
    const row = screen.getByRole('listitem', { name: 'Block 203.0.113.9 at the edge' })
    expect(within(row).getByText('Executed', { selector: '.case-expl-pill' })).toBeTruthy()
    expect(within(row).getByText('Verified', { selector: '.case-expl-pill' })).toBeTruthy()
    expect(within(row).getByText('Reverts in 2 h')).toBeTruthy()
    expect(within(row).getByText('alice + bob')).toBeTruthy()
    expect(within(row).getByText('severity=high [met]')).toBeTruthy()
    expect(within(row).getByText(/Proposed by responder-agent/)).toBeTruthy()
    expect(within(row).getByText('Before and after')).toBeTruthy()
    const events = within(row).getByRole('list', { name: 'Lifecycle' })
    expect(within(events).getAllByRole('listitem')).toHaveLength(4)
  })

  it('shows loading, error and empty states', () => {
    const onRetry = vi.fn()
    const { rerender } = render(<CaseActions actions={[]} phase="loading" error={null} canRevert onRetry={onRetry} onReverted={vi.fn()} />)
    expect(screen.getByText('Loading the actions…')).toBeTruthy()
    rerender(<CaseActions actions={[]} phase="error" error="backend down" canRevert onRetry={onRetry} onReverted={vi.fn()} />)
    expect(screen.getByText('backend down')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /Retry/ }))
    expect(onRetry).toHaveBeenCalled()
    rerender(<CaseActions actions={[]} phase="ready" error={null} canRevert onRetry={onRetry} onReverted={vi.fn()} />)
    expect(screen.getByText('No actions on this case')).toBeTruthy()
  })

  it('hides Revert without the permission or when the row cannot be reverted', () => {
    show([item()], false)
    expect(screen.queryByRole('button', { name: 'Revert' })).toBeNull()
    cleanup()
    show([
      item({ action_id: 'a', title: 'irreversible', reversibility: 'irreversible', can_revert: false }),
      item({ action_id: 'b', title: 'pending', status: 'pending', can_revert: false }),
      item({ action_id: 'c', title: 'reverted', reversed_at: '2026-10-12T11:00:00Z', can_revert: false }),
    ])
    expect(screen.queryByRole('button', { name: 'Revert' })).toBeNull()
    expect(screen.getByText('Cannot be undone')).toBeTruthy()
  })

  it('reverts with a required reason', async () => {
    vi.mocked(responseActionsApi.revert).mockResolvedValue({ data: {} } as never)
    const onReverted = show([item()])
    fireEvent.click(screen.getByRole('button', { name: 'Revert' }))
    const confirm = screen.getByRole('button', { name: 'Confirm revert' }) as HTMLButtonElement
    expect(confirm.disabled).toBe(true)
    fireEvent.change(screen.getByLabelText('Revert reason'), { target: { value: '  false positive  ' } })
    expect(confirm.disabled).toBe(false)
    fireEvent.click(confirm)
    await waitFor(() => expect(onReverted).toHaveBeenCalled())
    expect(responseActionsApi.revert).toHaveBeenCalledWith('act-1', 'false positive')
    expect(await screen.findByText(/Revert requested/)).toBeTruthy()
    expect(screen.queryByLabelText('Revert reason')).toBeNull()
  })

  it.each([404, 501])('says revert is unavailable on %i, without a refresh', async (status) => {
    vi.mocked(responseActionsApi.revert).mockRejectedValue({ response: { status, data: { detail: 'Not Found' } } })
    const onReverted = show([item()])
    fireEvent.click(screen.getByRole('button', { name: 'Revert' }))
    fireEvent.change(screen.getByLabelText('Revert reason'), { target: { value: 'oops' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm revert' }))
    expect(await screen.findByText(/Revert is not available on this AutoSecOps server yet/)).toBeTruthy()
    expect(onReverted).not.toHaveBeenCalled()
    // The form stays open so the reason is not lost.
    expect(screen.getByLabelText('Revert reason')).toBeTruthy()
  })

  it('shows the message of a 502 object detail and refreshes the timeline', async () => {
    vi.mocked(responseActionsApi.revert).mockRejectedValue({
      message: 'Request failed with status code 502',
      response: {
        status: 502,
        data: { detail: { message: 'The reversal did not take effect', reverse_action_id: 'act-2', verify_status: 'failed' } },
      },
    })
    const onReverted = show([item()])
    fireEvent.click(screen.getByRole('button', { name: 'Revert' }))
    fireEvent.change(screen.getByLabelText('Revert reason'), { target: { value: 'oops' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm revert' }))
    expect(await screen.findByText('The reversal did not take effect (verify: failed)')).toBeTruthy()
    expect(screen.queryByText(/status code 502/)).toBeNull()
    await waitFor(() => expect(onReverted).toHaveBeenCalled())
  })

  it('shows the server detail on any other failure', async () => {
    vi.mocked(responseActionsApi.revert).mockRejectedValue({ response: { status: 409, data: { detail: 'Already reverted' } } })
    show([item()])
    fireEvent.click(screen.getByRole('button', { name: 'Revert' }))
    fireEvent.change(screen.getByLabelText('Revert reason'), { target: { value: 'oops' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm revert' }))
    expect(await screen.findByText('Already reverted')).toBeTruthy()
  })
})

describe('useCaseActions', () => {
  function Probe({ id, k }: { id: string; k: number }) {
    const { actions, phase, error } = useCaseActions(id, k)
    return <span data-testid="probe">{`${phase}:${actions.length}:${error ?? ''}`}</span>
  }

  it('loads, keeps rows on a failed re-read, and reports a first-load error', async () => {
    const get = vi.mocked(casesApi.getActionTimeline)
    get.mockResolvedValueOnce({ data: { case_id: 'c1', count: 1, truncated: false, actions: [item()] } } as never)
    const { rerender } = render(<Probe id="c1" k={0} />)
    await waitFor(() => expect(screen.getByTestId('probe').textContent).toBe('ready:1:'))
    get.mockRejectedValueOnce(new Error('blip'))
    rerender(<Probe id="c1" k={1} />)
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
    expect(screen.getByTestId('probe').textContent).toBe('ready:1:')
    get.mockRejectedValueOnce({ response: { data: { detail: 'Case not found' } } })
    rerender(<Probe id="c2" k={1} />)
    await waitFor(() => expect(screen.getByTestId('probe').textContent).toBe('error:0:Case not found'))
  })
})
