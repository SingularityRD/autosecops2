import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import SegregationSection from './SegregationSection'
import { segregationApi } from '../../services/api'

vi.mock('../../services/api', () => ({
  segregationApi: {
    report: vi.fn(),
    fourEyes: vi.fn(),
    setDistinctRole: vi.fn(),
    exportUrl: (format: string, v: boolean) => `/api/response/segregation/export?format=${format}${v ? '&violations_only=true' : ''}`,
  },
}))

const report = {
  policy: { four_eyes_types: ['disable_user'], distinct_role_types: ['disable_user'] },
  summary: { total: 1, with_violations: 1, by_kind: { same_role: 1 } },
  rows: [
    {
      action_id: 'a-1',
      action_type: 'disable_user',
      status: 'executed',
      proposed_by: 'agent',
      approved_by: 'alice',
      approved_role: 'Senior Analyst',
      second_approver: 'bob',
      second_role: 'Senior Analyst',
      executed_by: 'system:dispatcher',
      four_eyes: true,
      distinct_role: true,
      violations: ['same_role'],
    },
  ],
}

describe('segregation of duties section', () => {
  const notify = vi.fn()
  beforeEach(() => {
    vi.mocked(segregationApi.report).mockReset().mockResolvedValue({ data: report } as never)
    vi.mocked(segregationApi.fourEyes)
      .mockReset()
      .mockResolvedValue({ data: { four_eyes_types: ['disable_user', 'revoke_sessions'], distinct_role_types: ['disable_user'] } } as never)
    vi.mocked(segregationApi.setDistinctRole)
      .mockReset()
      .mockResolvedValue({ data: { four_eyes_types: ['disable_user', 'revoke_sessions'], distinct_role_types: ['disable_user', 'revoke_sessions'] } } as never)
    notify.mockReset()
  })

  it('lists who proposed, approved and executed, with roles and violations', async () => {
    render(<SegregationSection notify={notify} />)
    expect(await screen.findByText('same role')).toBeInTheDocument()
    expect(screen.getByText('alice (Senior Analyst)')).toBeInTheDocument()
    expect(screen.getByText('system:dispatcher')).toBeInTheDocument()
    expect(screen.getByTestId('sod-summary')).toHaveTextContent('1 with violations')
    expect(screen.getByText('Export CSV')).toHaveAttribute('href', '/api/response/segregation/export?format=csv&violations_only=true')
  })

  it('needs a reason before changing the role condition, then saves it', async () => {
    render(<SegregationSection notify={notify} />)
    const toggle = await screen.findByLabelText('Different role for revoke sessions')
    fireEvent.click(toggle)
    expect(notify).toHaveBeenCalledWith('err', expect.stringContaining('reason'))
    expect(segregationApi.setDistinctRole).not.toHaveBeenCalled()

    fireEvent.change(screen.getByPlaceholderText(/Why the rule changes/), { target: { value: 'audit finding' } })
    fireEvent.click(screen.getByLabelText('Different role for revoke sessions'))
    await waitFor(() =>
      expect(segregationApi.setDistinctRole).toHaveBeenCalledWith('revoke_sessions', { distinct_role: true, reason: 'audit finding' })
    )
  })
})
