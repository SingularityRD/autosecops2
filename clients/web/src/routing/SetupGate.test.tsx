import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import SetupGate from './SetupGate'
import { SETUP_DISMISSED_KEY } from '../screens/setup/setupDismissed'
import { configApi } from '../services/api'

const auth = vi.hoisted(() => ({ admin: true }))

vi.mock('../contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: () => auth.admin }),
}))

vi.mock('../services/api', () => ({
  configApi: { getSetupProgress: vi.fn(), putSetupProgress: vi.fn() },
}))

const server = (status: string, started = true) =>
  vi.mocked(configApi.getSetupProgress).mockResolvedValue({
    data: { furthest: 1, passed: [], status, started },
  } as never)

describe('SetupGate', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.resetAllMocks()
    auth.admin = true
  })

  function renderAtDashboard() {
    return render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <Routes>
          <Route path="/setup" element={<div>setup-route</div>} />
          <Route
            path="/dashboard"
            element={
              <SetupGate>
                <div>console</div>
              </SetupGate>
            }
          />
        </Routes>
      </MemoryRouter>,
    )
  }

  it('sends an administrator to setup while the install has not finished or put it off', async () => {
    server('in_progress', false)
    renderAtDashboard()
    expect(await screen.findByText('setup-route')).toBeInTheDocument()
    expect(screen.queryByText('console')).not.toBeInTheDocument()
  })

  it.each(['deferred', 'completed'])(
    'opens the console once the install is %s, whatever this browser holds',
    async (status) => {
      server(status)
      renderAtDashboard()
      expect(await screen.findByText('console')).toBeInTheDocument()
      expect(screen.queryByText('setup-route')).not.toBeInTheDocument()
    },
  )

  it('the server outranks a dismissal stored in this browser once it has progress', async () => {
    localStorage.setItem(SETUP_DISMISSED_KEY, '1')
    server('in_progress')
    renderAtDashboard()
    expect(await screen.findByText('setup-route')).toBeInTheDocument()
  })

  it('carries a dismissal from before the server kept progress over, once', async () => {
    localStorage.setItem(SETUP_DISMISSED_KEY, '1')
    server('in_progress', false)
    renderAtDashboard()
    expect(await screen.findByText('console')).toBeInTheDocument()
    expect(configApi.putSetupProgress).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'deferred' }),
    )
  })

  it('falls back to this browser when the server cannot be asked', async () => {
    vi.mocked(configApi.getSetupProgress).mockRejectedValue(new Error('down'))
    localStorage.setItem(SETUP_DISMISSED_KEY, '1')
    const first = renderAtDashboard()
    expect(await screen.findByText('console')).toBeInTheDocument()
    first.unmount()

    localStorage.clear()
    renderAtDashboard()
    expect(await screen.findByText('setup-route')).toBeInTheDocument()
  })

  it('never sends someone without settings.write to setup, and does not ask', () => {
    auth.admin = false
    renderAtDashboard()
    expect(screen.getByText('console')).toBeInTheDocument()
    expect(configApi.getSetupProgress).not.toHaveBeenCalled()
  })
})
