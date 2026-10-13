/* The Scorecard reads per-category FN upper bounds against the 1% target and
   gives analysts a queue of sampled benign closures to review. */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import ScorecardScreen from './ScorecardScreen'
import { fmtBound } from './format'
import { ToastProvider } from '../../shell/toast'
import { qaApi } from '../../services/api'

const state = vi.hoisted(() => ({
  perms: new Set<string>(['ai_decisions.approve', 'findings.write']),
  samples: [] as Array<Record<string, unknown>>,
}))

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({ user: { username: 'ana' }, hasPermission: (p: string) => state.perms.has(p) }),
}))

const score = (category: string, over: Record<string, unknown> = {}) => ({
  category,
  reviewed: 0,
  misses: 0,
  disagreements: 0,
  pending: 0,
  fn_upper_bound: 1,
  status: 'no_data',
  reviews_needed: 299,
  risk_weighted: { reviewed: 0, misses: 0, pending: 0 },
  ...over,
})

vi.mock('../../services/api', () => ({
  qaApi: {
    scorecard: vi.fn(() =>
      Promise.resolve({
        data: {
          target: 0.01,
          confidence: 0.95,
          categories: [
            score('phishing', { reviewed: 299, fn_upper_bound: 0.009969, status: 'meets', reviews_needed: 0, risk_weighted: { reviewed: 12, misses: 1, pending: 0 } }),
            score('malware', { reviewed: 298, fn_upper_bound: 0.0100024, status: 'not_met', reviews_needed: 1 }),
            score('identity', { reviewed: 40, misses: 2, fn_upper_bound: 0.1497, status: 'not_met', reviews_needed: 590 }),
            score('network'),
            score('cloud'),
            score('other'),
          ],
        },
      }),
    ),
    samples: vi.fn(() => Promise.resolve({ data: { samples: state.samples, count: state.samples.length } })),
    review: vi.fn(() => Promise.resolve({ data: {} })),
    draw: vi.fn(() =>
      Promise.resolve({
        data: {
          categories: { phishing: { population: 40, drawn: 10, inclusion_probability: 0.25 } },
          risk_weighted: { population: 30, drawn: 2 },
        },
      }),
    ),
  },
}))

const sample = (id: number, over: Record<string, unknown> = {}) => ({
  id,
  sampling_kind: 'simple_random',
  inclusion_probability: 0.25,
  subject_kind: 'ai_decision',
  subject_id: `dec-${id}`,
  category: 'phishing',
  ai_verdict: 'benign',
  ai_confidence: 0.92,
  verdict: {},
  sampled_at: '2026-10-12T09:30:00+00:00',
  reasoning: 'Sender domain is the tenant’s own mail relay',
  ...over,
})

function renderAt(path = '/scorecard') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ToastProvider>
        <ScorecardScreen />
      </ToastProvider>
    </MemoryRouter>,
  )
}

const row = (category: string) => document.querySelector(`tr[data-category="${category}"]`) as HTMLElement

beforeEach(() => {
  state.perms = new Set(['ai_decisions.approve', 'findings.write'])
  state.samples = []
  vi.clearAllMocks()
})

describe('fmtBound', () => {
  it('rounds an upper bound up, so 298 clean reviews never read as 1.000%', () => {
    expect(fmtBound(0.009969146792899508)).toBe('0.997%')
    expect(fmtBound(0.010002432437677733)).toBe('1.001%')
    expect(fmtBound(0.2588)).toBe('25.9%')
  })
})

describe('scorecard tab', () => {
  it('shows each category’s sample count, bound and status against the target', async () => {
    renderAt()
    await screen.findByText('False-negative rate by category')

    const phishing = row('phishing')
    expect(within(phishing).getByText('299')).toBeInTheDocument()
    expect(within(phishing).getByText('0.997%')).toBeInTheDocument()
    expect(within(phishing).getByText('Meets target')).toBeInTheDocument()
    expect(within(phishing).getByText('12 reviewed · 1 miss')).toBeInTheDocument()

    const malware = row('malware')
    expect(within(malware).getByText('1.001%')).toBeInTheDocument()
    expect(within(malware).getByText('Above target')).toBeInTheDocument()
    expect(within(malware).getByText('1 more review, all agreeing')).toBeInTheDocument()

    // Off the 0–3% scale: capped, and says so.
    expect(within(row('identity')).getByText('> 3.000%')).toBeInTheDocument()
    expect(within(row('cloud')).getByText('No reviews yet')).toBeInTheDocument()

    expect(screen.getByText('1 / 6')).toBeInTheDocument()
    expect(screen.getByText(/target 1% · 95% one-sided upper bound/)).toBeInTheDocument()
  })

  it('names the product AutoSecOps, never Vigil', async () => {
    renderAt()
    await screen.findByText('False-negative rate by category')
    expect(document.body.textContent).toMatch(/AutoSecOps/)
    expect(document.body.textContent).not.toMatch(/Vigil/)
  })
})

describe('review queue tab', () => {
  it('records an agreement and a disagreement with the correct verdict', async () => {
    state.samples = [sample(1), sample(2, { sampling_kind: 'risk_weighted', category: 'identity' })]
    renderAt('/scorecard?tab=queue')

    const first = (await screen.findByText('dec-1')).closest('tr') as HTMLElement
    expect(within(first).getByText('Random')).toBeInTheDocument()
    expect(within(first).getByText('92%')).toBeInTheDocument()
    fireEvent.click(within(first).getByRole('button', { name: /Agree/ }))
    await waitFor(() => expect(qaApi.review).toHaveBeenCalledWith(1, { agrees: true, review_verdict: null, notes: null }))

    const second = screen.getByText('dec-2').closest('tr') as HTMLElement
    expect(within(second).getByText('Risk-weighted')).toBeInTheDocument()
    fireEvent.click(within(second).getByRole('button', { name: /Disagree/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Notes'), { target: { value: 'beacon to known C2' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save review' }))
    await waitFor(() =>
      expect(qaApi.review).toHaveBeenCalledWith(2, { agrees: false, review_verdict: 'malicious', notes: 'beacon to known C2' }),
    )
  })

  it('shows the queue without review buttons to a role that cannot review', async () => {
    state.perms = new Set()
    state.samples = [sample(1)]
    renderAt('/scorecard?tab=queue')
    await screen.findByText('dec-1')
    expect(screen.queryByRole('button', { name: /Agree/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Draw samples/ })).not.toBeInTheDocument()
    expect(screen.getByText('Your role can see the queue but not review it.')).toBeInTheDocument()
  })

  it('draws samples from an empty queue', async () => {
    renderAt('/scorecard?tab=queue')
    await screen.findByText('Nothing to review')
    fireEvent.click(screen.getAllByRole('button', { name: /Draw samples/ })[0])
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Risk-weighted extras'), { target: { value: '5' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Draw' }))
    await waitFor(() => expect(qaApi.draw).toHaveBeenCalledWith({ days: 7, per_category: 30, risk_weighted_extra: 5 }))
    expect(await screen.findByText('Drew 10 random samples and 2 risk-weighted extras')).toBeInTheDocument()
  })
})
