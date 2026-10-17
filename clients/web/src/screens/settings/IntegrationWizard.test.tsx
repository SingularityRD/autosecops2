import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import IntegrationWizard from './IntegrationWizard'
import { configApi } from '../../services/api'
import type { IntegrationMetadata } from '../../config/integrationSchema'

vi.mock('../../services/api', () => ({
  configApi: { testIntegration: vi.fn() },
}))

const okta: IntegrationMetadata = {
  id: 'okta',
  name: 'Okta',
  category: 'Identity',
  description: 'Identity provider',
  fields: [
    { name: 'domain', label: 'Domain', type: 'text', required: true },
    { name: 'api_token', label: 'API token', type: 'password', required: true },
  ],
}
const bare: IntegrationMetadata = { ...okta, id: 'bare', name: 'Bare', fields: [] }

const test = vi.mocked(configApi.testIntegration)

function open(props: Partial<React.ComponentProps<typeof IntegrationWizard>> = {}) {
  const onSave = vi.fn(() => Promise.resolve())
  const onClose = vi.fn()
  render(
    <MemoryRouter>
      <IntegrationWizard
        integration={okta}
        existingConfig={{ domain: 'a.okta.com' }}
        secretsSet={{ api_token: true }}
        onSave={onSave}
        onClose={onClose}
        {...props}
      />
    </MemoryRouter>,
  )
  return { onSave, onClose }
}

describe('IntegrationWizard drawer', () => {
  beforeEach(() => test.mockReset())

  it('labels an experimental connector in the title and says why above the form', () => {
    open({ integration: { ...okta, id: 'crowdstrike', name: 'CrowdStrike Falcon' } })
    expect(screen.getByText('Experimental')).toBeInTheDocument()
    expect(screen.getByRole('note')).toHaveTextContent(/not run this connector against a live instance/)
    expect(screen.getByRole('note')).toHaveTextContent(/AutoSecOps support/)
    // the status is not something the drawer can wave away
    expect(screen.queryByRole('button', { name: /dismiss|supported/i })).toBeNull()
  })

  it('shows no experimental label for a supported connector', () => {
    open()
    expect(screen.queryByText('Experimental')).toBeNull()
    expect(screen.queryByRole('note')).toBeNull()
  })

  it('shows the note in the first-run setup popup too', () => {
    open({ variant: 'setup', integration: { ...okta, id: 'sentinelone', name: 'SentinelOne' } })
    expect(screen.getByRole('note')).toHaveTextContent(/may not work/)
  })

  it('empty: an integration with no fields has nothing to ask for and no secret copy', () => {
    open({ integration: bare, existingConfig: {}, secretsSet: {} })
    expect(screen.queryByLabelText('Domain')).toBeNull()
    expect(screen.queryByText('Security controls')).toBeNull()
  })

  it('does not open Verify until the connection is saved, and never claims an egress allowlist', () => {
    open({ existingConfig: {}, secretsSet: {} })
    expect(screen.getByRole('tab', { name: /Verify a read/ })).toBeDisabled()
    expect(screen.getByText('Security controls')).toBeInTheDocument()
    expect(screen.queryByText(/only calls/i)).toBeNull()
    expect(screen.queryByText(/Grant tools/)).toBeNull()
  })

  it('loading, then populated: save runs the test and lists each server', async () => {
    let resolve!: (v: unknown) => void
    test.mockReturnValue(new Promise((r) => (resolve = r)) as never)
    const { onSave, onClose } = open()
    fireEvent.click(screen.getByRole('button', { name: 'Save and verify' }))
    expect(await screen.findByText('Running the test…')).toBeInTheDocument()
    expect(onSave).toHaveBeenCalledWith('okta', { domain: 'a.okta.com' })
    expect(onClose).not.toHaveBeenCalled()
    resolve({ data: { success: false, servers: [{ name: 'okta', success: false, error: '403', missing_credentials: ['OKTA_TOKEN'] }, { name: 'okta-logs', success: true }] } })
    expect(await screen.findByText('403 · Missing OKTA_TOKEN')).toBeInTheDocument()
    expect(screen.getByText('Connected')).toBeInTheDocument()
    expect(screen.getByText('Poor')).toBeInTheDocument()
    test.mockResolvedValueOnce({ data: { success: true, servers: [{ name: 'okta', success: true }] } } as never)
    fireEvent.click(screen.getByRole('button', { name: /Run the test again/ }))
    await waitFor(() => expect(screen.getByText('Good')).toBeInTheDocument())
    expect(test).toHaveBeenCalledTimes(2)
  })

  it('shows the health the Connected table shows, even where nothing was ever tested', () => {
    open({ health: 'good' })
    expect(screen.getByText('Good')).toBeInTheDocument()
    expect(screen.getByText(/never tested/)).toBeInTheDocument()
  })

  it('takes the table\'s level over the stored test, and its last-verified time', () => {
    const at = new Date(Date.now() - 5 * 60_000).toISOString()
    open({ health: 'poor', lastTest: { at, success: true, error: null } })
    expect(screen.getByText('Poor')).toBeInTheDocument()
    expect(screen.getByText(/last read 5 min ago/)).toBeInTheDocument()
  })

  it('lists the URL and credentials check as its own row, and fails the test on it', async () => {
    test.mockResolvedValue({
      data: {
        success: false,
        message: 'HTTP 401: security_exception',
        servers: [{ name: 'elastic', success: true }],
        credentials: { success: false, message: 'HTTP 401: security_exception' },
      },
    } as never)
    open()
    fireEvent.click(screen.getByRole('button', { name: 'Save and verify' }))
    expect(await screen.findByText('Saved URL and credentials')).toBeInTheDocument()
    expect(screen.getByText('HTTP 401: security_exception')).toBeInTheDocument()
    expect(screen.getByText('Connected')).toBeInTheDocument()
    expect(screen.getByText('Poor')).toBeInTheDocument()
  })

  it('says whether an executor can act now, with no restart (W0.37)', async () => {
    const defender = { ...okta, id: 'microsoft-defender', name: 'Microsoft Defender for Endpoint' }
    test.mockResolvedValueOnce({
      data: {
        success: true,
        servers: [{ name: 'microsoft-defender', success: true }],
        credentials: { success: true, message: 'Token issued; machines readable' },
        executor: { available: true, action_types: ['isolate_host'] },
      },
    } as never)
    open({ integration: defender })
    expect(screen.getByText('Experimental')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save and verify' }))
    expect(await screen.findByText('Response actions')).toBeInTheDocument()
    expect(screen.getByText('Available now, after approval: isolate_host')).toBeInTheDocument()

    test.mockResolvedValueOnce({
      data: {
        success: false,
        message: 'Microsoft Defender token request failed (ConnectError); Entra ID could not be reached',
        servers: [{ name: 'microsoft-defender', success: true }],
        credentials: { success: false, message: 'Microsoft Defender token request failed (ConnectError); Entra ID could not be reached' },
        executor: { available: false, action_types: [] },
      },
    } as never)
    fireEvent.click(screen.getByRole('button', { name: 'Run the test again' }))
    expect(await screen.findByText(/Not available: enable the integration/)).toBeInTheDocument()
    expect(screen.getByText(/Entra ID could not be reached/)).toBeInTheDocument()
  })

  it('a registered executor whose credential check fails is not shown as available (W0.44)', async () => {
    const defender = { ...okta, id: 'microsoft-defender', name: 'Microsoft Defender for Endpoint' }
    test.mockResolvedValueOnce({
      data: {
        success: false,
        servers: [{ name: 'microsoft-defender', success: true }],
        credentials: { success: false, message: 'Microsoft Defender returned HTTP 401' },
        executor: { available: true, action_types: ['isolate_host'] },
      },
    } as never)
    open({ integration: defender })
    fireEvent.click(screen.getByRole('button', { name: 'Save and verify' }))
    expect(await screen.findByText(/Not usable yet: the credential check above failed/)).toBeInTheDocument()
    expect(screen.queryByText(/Available now/)).not.toBeInTheDocument()
  })

  it('error: a 400 says to save first; an unavailable MCP client is its own state', async () => {
    test.mockRejectedValueOnce({ response: { status: 400, data: { detail: 'Integration not configured' } } })
    open()
    fireEvent.click(screen.getByRole('tab', { name: /Verify a read/ }))
    expect(await screen.findByText(/Save the connection in step 1/)).toBeInTheDocument()
    test.mockResolvedValueOnce({ data: { success: false, message: 'MCP client is not available.', servers: [] } } as never)
    fireEvent.click(screen.getByRole('button', { name: /Run the test again/ }))
    expect(await screen.findByText('MCP client is not available.')).toBeInTheDocument()
  })

  it('links the last two steps to their Settings sections', () => {
    open()
    fireEvent.click(screen.getByRole('tab', { name: /Collect alerts/ }))
    expect(screen.getByRole('link', { name: 'Open Alert collection' })).toHaveAttribute('href', '/settings?section=federation')
    fireEvent.click(screen.getByRole('tab', { name: /Automatic investigations/ }))
    expect(screen.getByRole('link', { name: /Limits/ })).toHaveAttribute('href', '/settings?section=autoinvestigate')
  })

  it('setup variant: form only, saves and closes without testing', async () => {
    const { onSave, onClose } = open({ variant: 'setup' })
    expect(screen.queryByRole('tab')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /Save Configuration/ }))
    await waitFor(() => expect(onClose).toHaveBeenCalled())
    expect(onSave).toHaveBeenCalled()
    expect(test).not.toHaveBeenCalled()
  })
})
