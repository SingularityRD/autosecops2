import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import SummaryStep from './SummaryStep'
import { SETUP_DISMISSED_KEY } from './setupDismissed'
import { CONSOLE_TOUR_SEEN_KEY } from '../../shell/consoleTourSeen'
import { aiConfigApi, budgetsApi, configApi, llmProviderApi, workflowApi } from '../../services/api'

vi.mock('../../services/api', () => ({
  configApi: {
    getIntegrations: vi.fn(),
    getAutonomy: vi.fn(),
    getOrchestrator: vi.fn(),
    getSetupSteps: vi.fn(),
    getSetupReadiness: vi.fn(),
    putSetupProgress: vi.fn(),
  },
  budgetsApi: { getQuota: vi.fn() },
  llmProviderApi: { list: vi.fn() },
  aiConfigApi: { getConfig: vi.fn() },
  workflowApi: { listAll: vi.fn() },
}))

const values = {
  max_concurrent_agents: 3,
  max_iterations_per_agent: 50,
  max_runtime_per_investigation: 3600,
  max_cost_per_investigation: 5,
  max_total_hourly_cost: 20,
}

const step = (id: string, done: boolean) => ({ id, title: id, state_line: '', done, href: '/' })

const item = (id: string, label: string, required: boolean, ready: boolean) => ({
  id,
  label,
  required,
  ready,
  detail: `${label} detail`,
  href: `/settings?section=${id}`,
})
const readiness = (items: ReturnType<typeof item>[]) => ({
  data: {
    ready: items.every((i) => !i.required || i.ready),
    missing: items.filter((i) => i.required && !i.ready).map((i) => i.id),
    recommended_missing: items.filter((i) => !i.required && !i.ready).map((i) => i.id),
    items,
  },
})
const EMPTY_INSTALL = [
  item('data', 'Alert source', true, false),
  item('model', 'AI model', true, false),
  item('executor', 'Response actions', false, false),
  item('notify', 'Notifications', false, true),
]

const Where = () => {
  const { pathname, search, state } = useLocation()
  return <div data-testid="where">{`${pathname}${search} ${JSON.stringify(state)}`}</div>
}

const renderDone = (onChange = vi.fn()) =>
  render(
    <MemoryRouter initialEntries={['/setup']}>
      <Routes>
        <Route path="/setup" element={<SummaryStep onChange={onChange} />} />
        <Route path="*" element={<Where />} />
      </Routes>
    </MemoryRouter>,
  )

describe('SummaryStep', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    localStorage.clear()
    vi.mocked(configApi.getIntegrations).mockResolvedValue({
      data: { enabled_integrations: ['splunk', 'crowdstrike', 'not-in-catalog'] },
    } as never)
    vi.mocked(llmProviderApi.list).mockResolvedValue({
      data: [
        { provider_id: 'o', name: 'Other', is_active: true, is_default: false, default_model: 'x' },
        { provider_id: 'a', name: 'Anthropic', is_active: true, is_default: true, default_model: 'claude-sonnet-5-5' },
      ],
    } as never)
    vi.mocked(aiConfigApi.getConfig).mockResolvedValue({ data: { components: [], assignments: {} } } as never)
    vi.mocked(workflowApi.listAll).mockResolvedValue({
      data: { workflows: [{ enabled: true }, { enabled: true }, { enabled: false }] },
    } as never)
    vi.mocked(configApi.getAutonomy).mockResolvedValue({
      data: { auto_response_enabled: true, force_manual_approval: false, autonomous_tiers: 2, mode: 'act' },
    } as never)
    vi.mocked(configApi.getOrchestrator).mockResolvedValue({
      data: { enabled: true, ...values, profiles: { balanced: { label: 'Balanced', values } } },
    } as never)
    vi.mocked(budgetsApi.getQuota).mockResolvedValue({
      data: { configured: true, available: true, quota: { budgets: [{ max_limit: 2000, reset_duration: '1M' }] } },
    } as never)
    vi.mocked(configApi.getSetupSteps).mockResolvedValue({
      data: { steps: [step('connect_tools', true), step('notify', true), step('rules', false), step('per_agent', false)] },
    } as never)
    vi.mocked(configApi.getSetupReadiness).mockResolvedValue(
      readiness([item('data', 'Alert source', true, true), item('model', 'AI model', true, true)]) as never,
    )
    vi.mocked(configApi.putSetupProgress).mockResolvedValue({ data: {} } as never)
  })

  describe('readiness (W0.33)', () => {
    it('does not call an empty install ready, and names what is missing', async () => {
      vi.mocked(configApi.getSetupReadiness).mockResolvedValue(readiness(EMPTY_INSTALL) as never)
      renderDone()
      expect(await screen.findByRole('heading', { name: 'AutoSecOps is not ready yet' })).toBeInTheDocument()
      expect(screen.queryByText('AutoSecOps is ready')).not.toBeInTheDocument()
      expect(screen.queryByText('Setup complete')).not.toBeInTheDocument()
      const missing = within(screen.getByRole('region', { name: 'What is missing' }))
      expect(missing.getByText('Alert source detail')).toBeInTheDocument()
      expect(missing.getByText('AI model detail')).toBeInTheDocument()
      expect(missing.getByText('Response actions detail')).toBeInTheDocument()
      expect(missing.queryByText('Notifications detail')).not.toBeInTheDocument()
      expect(missing.getAllByText('Required')).toHaveLength(2)
      expect(screen.getByText('Not ready · 2 required items missing')).toBeInTheDocument()
    })

    it('opens the setting a missing item points at', async () => {
      vi.mocked(configApi.getSetupReadiness).mockResolvedValue(readiness(EMPTY_INSTALL) as never)
      renderDone()
      fireEvent.click(await screen.findByRole('button', { name: 'Fix Alert source' }))
      expect(screen.getByTestId('where')).toHaveTextContent('/settings?section=data')
    })

    it('says ready only when the server does', async () => {
      renderDone()
      expect(await screen.findByRole('heading', { name: 'AutoSecOps is ready' })).toBeInTheDocument()
      expect(screen.queryByRole('region', { name: 'What is missing' })).not.toBeInTheDocument()
    })

    it('claims nothing when readiness cannot be read', async () => {
      vi.mocked(configApi.getSetupReadiness).mockRejectedValue(new Error('down'))
      renderDone()
      expect(await screen.findByRole('heading', { name: 'Readiness could not be checked' })).toBeInTheDocument()
      expect(screen.queryByText('AutoSecOps is ready')).not.toBeInTheDocument()
    })

    it('records "completed" when ready and "deferred" when not', async () => {
      const first = renderDone()
      await screen.findByRole('heading', { name: 'AutoSecOps is ready' })
      fireEvent.click(screen.getByRole('button', { name: 'Go to Home' }))
      expect(configApi.putSetupProgress).toHaveBeenLastCalledWith(
        expect.objectContaining({ status: 'completed' }),
      )
      first.unmount()

      vi.mocked(configApi.getSetupReadiness).mockResolvedValue(readiness(EMPTY_INSTALL) as never)
      renderDone()
      await screen.findByRole('heading', { name: 'AutoSecOps is not ready yet' })
      fireEvent.click(screen.getByRole('button', { name: 'Go to Home' }))
      expect(configApi.putSetupProgress).toHaveBeenLastCalledWith(
        expect.objectContaining({ status: 'deferred' }),
      )
    })
  })

  it('recaps each step from its own API, with catalog names and the ceiling', async () => {
    renderDone()
    expect(screen.getAllByText('Loading…')).toHaveLength(6)
    expect(await screen.findByText(/^Splunk.*CrowdStrike.*not-in-catalog$/)).toBeInTheDocument()
    expect(screen.queryByText(/splunk, crowdstrike/)).not.toBeInTheDocument()
    expect(screen.getByText('Anthropic · claude-sonnet-5-5')).toBeInTheDocument()
    expect(screen.getByText('2 of 3 on · investigates new alerts automatically')).toBeInTheDocument()
    expect(screen.getByText('Act · reversible changes on its own')).toBeInTheDocument()
    expect(await screen.findByText('Balanced · $2,000 a month')).toBeInTheDocument()
    expect(screen.getByText('Slack')).toBeInTheDocument()
  })

  it('reads the empty and off cases', async () => {
    vi.mocked(configApi.getIntegrations).mockResolvedValue({ data: { enabled_integrations: [] } } as never)
    vi.mocked(llmProviderApi.list).mockResolvedValue({ data: [] } as never)
    vi.mocked(configApi.getAutonomy).mockResolvedValue({
      data: { auto_response_enabled: false, force_manual_approval: true, autonomous_tiers: 0, mode: 'assist' },
    } as never)
    vi.mocked(configApi.getOrchestrator).mockResolvedValue({
      data: { enabled: false, ...values, max_concurrent_agents: 9, profiles: { balanced: { label: 'Balanced', values } } },
    } as never)
    vi.mocked(budgetsApi.getQuota).mockResolvedValue({ data: { configured: false } } as never)
    vi.mocked(configApi.getSetupSteps).mockResolvedValue({ data: { steps: [step('notify', false)] } } as never)
    renderDone()
    expect(await screen.findByText('Nothing connected yet')).toBeInTheDocument()
    expect(screen.getByText('No provider')).toBeInTheDocument()
    expect(screen.getByText('Assist · asks before changes')).toBeInTheDocument()
    expect(await screen.findByText('2 of 3 on · starts only when asked')).toBeInTheDocument()
    expect(screen.getByText('Custom')).toBeInTheDocument()
    expect(await screen.findByText('Not set')).toBeInTheDocument()
  })

  describe('AI row', () => {
    const row = (provider_id: string, name: string, over: object = {}) => ({
      provider_id, name, is_active: true, is_default: true, default_model: `${name}-model`, ...over,
    })

    it('picks the earliest active default when several types are default', async () => {
      vi.mocked(llmProviderApi.list).mockResolvedValue({
        data: [row('a', 'Anthropic'), row('o', 'OpenAI')],
      } as never)
      renderDone()
      expect(await screen.findByText('Anthropic · Anthropic-model')).toBeInTheDocument()
    })

    it('skips an inactive default row', async () => {
      vi.mocked(llmProviderApi.list).mockResolvedValue({
        data: [row('a', 'Anthropic', { is_active: false }), row('o', 'OpenAI')],
      } as never)
      renderDone()
      expect(await screen.findByText('OpenAI · OpenAI-model')).toBeInTheDocument()
    })

    it('falls back to the first active row when none is default', async () => {
      vi.mocked(llmProviderApi.list).mockResolvedValue({
        data: [row('a', 'Anthropic', { is_active: false }), row('o', 'OpenAI', { is_default: false })],
      } as never)
      renderDone()
      expect(await screen.findByText('OpenAI · OpenAI-model')).toBeInTheDocument()
    })

    it('follows a chat_default assignment over the default rows', async () => {
      vi.mocked(llmProviderApi.list).mockResolvedValue({
        data: [row('a', 'Anthropic'), row('o', 'OpenAI', { is_default: false })],
      } as never)
      vi.mocked(aiConfigApi.getConfig).mockResolvedValue({
        data: { components: [], assignments: { chat_default: { provider_id: 'o', model_id: 'gpt-x' } } },
      } as never)
      renderDone()
      expect(await screen.findByText('OpenAI · gpt-x')).toBeInTheDocument()
    })

    it('falls back to the default rows when the config read fails', async () => {
      vi.mocked(aiConfigApi.getConfig).mockRejectedValue(new Error('down'))
      renderDone()
      expect(await screen.findByText('Anthropic · claude-sonnet-5-5')).toBeInTheDocument()
    })
  })

  it('shows a short error in the failing row and keeps the others', async () => {
    vi.mocked(llmProviderApi.list).mockRejectedValue(new Error('down'))
    vi.mocked(budgetsApi.getQuota).mockRejectedValue(new Error('gateway down'))
    renderDone()
    expect(await screen.findByText('Could not read this.')).toBeInTheDocument()
    expect(await screen.findByText(/^Splunk/)).toBeInTheDocument()
    // an unreadable ceiling leaves the profile label alone
    expect(await screen.findByText('Balanced')).toBeInTheDocument()
  })

  it('takes the optional-step count from setup-steps, and hides it on error', async () => {
    const first = renderDone()
    expect(await screen.findByText('Setup complete · 2 optional steps left in Setup')).toBeInTheDocument()
    expect(screen.getByText('Setup in the profile menu keeps track of what is left: 2 optional steps.')).toBeInTheDocument()
    first.unmount()

    vi.mocked(configApi.getSetupSteps).mockRejectedValue(new Error('down'))
    renderDone()
    // Notifications reads as unreadable, not as "Not set"
    expect(await screen.findByText('Could not read this.')).toBeInTheDocument()
    expect(screen.queryByText('Not set')).not.toBeInTheDocument()
    expect(await screen.findByText('Setup complete', { selector: '.su-foot-note' })).toBeInTheDocument()
    expect(screen.queryByText(/optional step/)).not.toBeInTheDocument()
  })

  it('jumps to the step a Change link belongs to', async () => {
    const onChange = vi.fn()
    renderDone(onChange)
    await screen.findByText('Balanced · $2,000 a month')
    for (const [name, target] of [
      ['Change Data', 'data'],
      ['Change AI models', 'ai'],
      ['Change Workflows', 'workflows'],
      ['Change On their own', 'workflows'],
      ['Change Limits', 'limits'],
      ['Change Notifications', 'limits'],
    ]) {
      fireEvent.click(screen.getByRole('button', { name }))
      expect(onChange).toHaveBeenLastCalledWith(target)
    }
  })

  it('Go to Home marks setup done and the tour seen, then opens Home', async () => {
    renderDone()
    fireEvent.click(screen.getByRole('button', { name: 'Go to Home' }))
    expect(localStorage.getItem(SETUP_DISMISSED_KEY)).toBe('1')
    expect(localStorage.getItem(CONSOLE_TOUR_SEEN_KEY)).toBe('1')
    expect(screen.getByTestId('where')).toHaveTextContent('/ null')
  })

  it.each([['footer', 0], ['tile', 1]])('Take the tour from the %s asks for the tour, even if it was seen', (_, at) => {
    localStorage.setItem(CONSOLE_TOUR_SEEN_KEY, '1')
    renderDone()
    fireEvent.click(screen.getAllByRole('button', { name: /Take the 1-minute tour/ })[at])
    expect(localStorage.getItem(SETUP_DISMISSED_KEY)).toBe('1')
    expect(screen.getByTestId('where')).toHaveTextContent('/ {"startTour":true}')
  })

  it('opens the other tiles after marking setup done', () => {
    renderDone()
    fireEvent.click(screen.getByRole('button', { name: /Connect more sources/ }))
    expect(localStorage.getItem(SETUP_DISMISSED_KEY)).toBe('1')
    expect(screen.getByTestId('where')).toHaveTextContent('/settings?section=integrations')
  })
})
