import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import ResponsePolicySection from './ResponsePolicySection'
import { parseAssetTags } from './responsePolicyDraft'
import { responsePolicyApi } from '../../services/api'

vi.mock('../../services/api', () => ({
  responsePolicyApi: { get: vi.fn(), update: vi.fn() },
}))

const policy = {
  protected_targets: ['dc01.corp.local'],
  protected_tags: ['crown_jewel'],
  asset_tags: { 'fs01.corp.local': ['tier0'] },
  hourly_limits: { block_ip: 5 },
  default_hourly_limit: 20,
  four_eyes_types: [],
  defaults: {
    protected_tags: ['domain_controller', 'tier0'],
    four_eyes_types: ['disable_user', 'revoke_sessions'],
    hourly_limits: { isolate_host: 10, disable_user: 10, revoke_sessions: 10 },
    default_hourly_limit: 20,
  },
  effective: {
    protected_tags: ['crown_jewel', 'domain_controller', 'tier0'],
    four_eyes_types: ['disable_user', 'revoke_sessions'],
    distinct_role_types: [],
    hourly_limits: { block_ip: 5, isolate_host: 10, disable_user: 10, revoke_sessions: 10 },
    default_hourly_limit: 20,
  },
  action_types: ['block_ip', 'disable_user', 'isolate_host'],
}

describe('response policy section', () => {
  const notify = vi.fn()
  beforeEach(() => {
    vi.mocked(responsePolicyApi.get).mockReset().mockResolvedValue({ data: policy } as never)
    vi.mocked(responsePolicyApi.update).mockReset().mockResolvedValue({ data: policy } as never)
    notify.mockReset()
  })

  it('shows the stored policy with built-in classes locked', async () => {
    render(<ResponsePolicySection notify={notify} />)
    expect(await screen.findByLabelText('Protected targets')).toHaveValue('dc01.corp.local')
    expect(screen.getByLabelText('Asset tags')).toHaveValue('fs01.corp.local: tier0')
    expect(screen.getByLabelText('Hourly limit for block ip')).toHaveValue(5)
    const builtIn = screen.getByLabelText('Two approvers for disable user')
    expect(builtIn).toBeDisabled()
    expect(builtIn).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByLabelText('Two approvers for block ip')).not.toBeDisabled()
  })

  it('needs a reason, then saves the whole policy', async () => {
    render(<ResponsePolicySection notify={notify} />)
    const targets = await screen.findByLabelText('Protected targets')
    fireEvent.change(targets, { target: { value: 'dc01.corp.local\n10.0.0.0/24\n' } })
    fireEvent.click(screen.getByLabelText('Two approvers for block ip'))
    fireEvent.click(screen.getByText('Save policy'))
    expect(notify).toHaveBeenCalledWith('err', expect.stringContaining('reason'))
    expect(responsePolicyApi.update).not.toHaveBeenCalled()

    fireEvent.change(screen.getByPlaceholderText(/Why the policy changes/), { target: { value: 'tier0 list' } })
    fireEvent.click(screen.getByText('Save policy'))
    await waitFor(() =>
      expect(responsePolicyApi.update).toHaveBeenCalledWith({
        protected_targets: ['dc01.corp.local', '10.0.0.0/24'],
        asset_tags: { 'fs01.corp.local': ['tier0'] },
        protected_tags: ['crown_jewel'],
        hourly_limits: { block_ip: 5 },
        default_hourly_limit: 20,
        four_eyes_types: ['block_ip'],
        reason: 'tier0 list',
      })
    )
    expect(notify).toHaveBeenCalledWith('ok', 'Response policy saved')
  })

  it('refuses a limit out of range before calling the API', async () => {
    render(<ResponsePolicySection notify={notify} />)
    fireEvent.change(await screen.findByLabelText('Hourly limit for isolate host'), { target: { value: '5000' } })
    fireEvent.change(screen.getByPlaceholderText(/Why the policy changes/), { target: { value: 'x' } })
    fireEvent.click(screen.getByText('Save policy'))
    expect(notify).toHaveBeenCalledWith('err', expect.stringContaining('0 to 1000'))
    expect(responsePolicyApi.update).not.toHaveBeenCalled()
  })

  it('shows the server refusal (e.g. an Analyst without settings.write)', async () => {
    vi.mocked(responsePolicyApi.update).mockRejectedValue({
      response: { data: { detail: 'Permission denied: settings.write required' } },
    })
    render(<ResponsePolicySection notify={notify} />)
    fireEvent.change(await screen.findByPlaceholderText(/Why the policy changes/), { target: { value: 'x' } })
    fireEvent.click(screen.getByText('Save policy'))
    await waitFor(() => expect(notify).toHaveBeenCalledWith('err', 'Permission denied: settings.write required'))
  })

  it('parses asset tag lines, IPv6 included', () => {
    expect(parseAssetTags('dc01: tier0, domain_controller\nfe80::1: tier0\n')).toEqual({
      dc01: ['tier0', 'domain_controller'],
      'fe80::1': ['tier0'],
    })
  })
})
