import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import AutonomyTiersPanel from './AutonomyTiersPanel'
import { autonomyApi } from '../../services/api'

vi.mock('../../services/api', () => ({
  autonomyApi: {
    tiers: vi.fn(),
    audit: vi.fn(),
    setTier: vi.fn(),
    check: vi.fn(),
  },
}))

const entry = (action_type: string, tier = 'approve', eligible = true) => ({
  category: 'phishing',
  action_type,
  tier,
  min_confidence: null,
  max_ttl_seconds: null,
  updated_by: null,
  updated_at: null,
  explicit: false,
  eligible,
})

const matrix = {
  default_tier: 'approve',
  tiers: ['watch', 'suggest', 'approve', 'autonomous'],
  categories: ['*', 'phishing'],
  action_classes: ['waf_block', 'access_revoke'],
  eligible: ['waf_block'],
  max_ttl_seconds: 604800,
  fn_bound_target: 0.01,
  fn_bound_min_reviews: 299,
  bounds_readable: true,
  bounds: {
    phishing: {
      category: 'phishing',
      reviewed: 299,
      misses: 0,
      fn_upper_bound: 0.00997,
      holds: true,
      readable: true,
      reason: 'FN upper bound 0.0100 <= 1.00% at n=299',
    },
  },
  entries: [entry('waf_block'), entry('access_revoke', 'approve', false)],
}

describe('autonomy tiers panel', () => {
  const notify = vi.fn()

  beforeEach(() => {
    vi.mocked(autonomyApi.tiers).mockReset().mockResolvedValue({ data: matrix } as never)
    vi.mocked(autonomyApi.audit).mockReset().mockResolvedValue({ data: { entries: [] } } as never)
    vi.mocked(autonomyApi.setTier).mockReset().mockResolvedValue({ data: {} } as never)
    notify.mockReset()
  })

  it('shows the tier per action and the category bound', async () => {
    render(<AutonomyTiersPanel notify={notify} />)
    expect(await screen.findByLabelText('Tier for waf block')).toHaveValue('approve')
    expect(screen.getByTestId('autonomy-bound')).toHaveTextContent('holds')
  })

  it('never offers autonomous for an ineligible action', async () => {
    render(<AutonomyTiersPanel notify={notify} />)
    const select = await screen.findByLabelText('Tier for access revoke')
    const values = Array.from(select.querySelectorAll('option')).map((o) => o.getAttribute('value'))
    expect(values).not.toContain('autonomous')
  })

  it('asks for evidence before raising to autonomous, then sends ttl and floor', async () => {
    render(<AutonomyTiersPanel notify={notify} />)
    fireEvent.change(await screen.findByLabelText('Tier for waf block'), { target: { value: 'autonomous' } })
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'met for a month' } })
    fireEvent.click(screen.getByText('Save'))
    expect(await screen.findByRole('alert')).toHaveTextContent('evidence link')
    expect(autonomyApi.setTier).not.toHaveBeenCalled()

    fireEvent.change(screen.getByLabelText(/Evidence link/), { target: { value: 'https://console.example/scorecard' } })
    fireEvent.click(screen.getByText('Save'))
    await waitFor(() => expect(autonomyApi.setTier).toHaveBeenCalled())
    expect(vi.mocked(autonomyApi.setTier).mock.calls[0]).toEqual([
      'phishing',
      'waf_block',
      {
        tier: 'autonomous',
        reason: 'met for a month',
        evidence_url: 'https://console.example/scorecard',
        max_ttl_seconds: 86400,
        min_confidence: 0.9,
      },
    ])
  })
})
