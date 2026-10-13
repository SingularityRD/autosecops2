import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import SsoSection from './SsoSection'
import { ssoApi } from '../../services/api'

const perms = vi.hoisted(() => ({ value: new Set(['settings.write', 'users.write']) }))

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => perms.value.has(p) }),
}))

vi.mock('./useSettings', () => ({
  useUsers: () => ({
    users: [
      { user_id: 'u-root', username: 'root', role_id: 'role-admin' },
      { user_id: 'u-ana', username: 'ana', role_id: 'role-analyst' },
    ],
    roles: [
      { role_id: 'role-viewer', name: 'Viewer' },
      { role_id: 'role-analyst', name: 'Analyst' },
      { role_id: 'role-admin', name: 'Admin' },
    ],
  }),
}))

vi.mock('../../services/api', () => ({
  ssoApi: {
    adminConfig: vi.fn(),
    saveProvider: vi.fn(),
    deleteProvider: vi.fn(),
    saveLoginPolicy: vi.fn(),
  },
}))

const provider = {
  id: 'entra',
  display_name: 'Microsoft Entra ID',
  kind: 'entra',
  issuer: 'https://login.microsoftonline.com/tid/v2.0',
  client_id: 'client-1',
  scopes: ['openid', 'email', 'profile'],
  enabled: true,
  jit_provisioning: true,
  link_by_verified_email: false,
  default_role_id: 'role-viewer',
  role_mappings: [],
  allow_admin_mapping: false,
  clock_skew_seconds: 60,
  redirect_uri: '',
  effective_redirect_uri: 'https://soc.example.com/api/auth/sso/entra/callback',
  has_client_secret: true,
}

const config = (over = {}) => ({
  data: {
    providers: [provider],
    login_policy: { local_login_enabled: true, break_glass_user_ids: ['u-root'] },
    ...over,
  },
})

function setup() {
  const notify = vi.fn()
  render(<SsoSection notify={notify} />)
  return notify
}

describe('SsoSection', () => {
  beforeEach(() => {
    perms.value = new Set(['settings.write', 'users.write'])
    vi.mocked(ssoApi.adminConfig).mockResolvedValue(config() as never)
    vi.mocked(ssoApi.saveProvider).mockResolvedValue(config() as never)
    vi.mocked(ssoApi.saveLoginPolicy).mockResolvedValue(config() as never)
  })
  afterEach(() => vi.clearAllMocks())

  it('is closed to anyone who cannot change settings and users', () => {
    perms.value = new Set(['settings.write'])
    setup()
    expect(screen.getByText(/Only administrators can configure single sign-on/)).toBeInTheDocument()
    expect(ssoApi.adminConfig).not.toHaveBeenCalled()
  })

  it('lists providers with the redirect URI to register and never a secret', async () => {
    setup()
    expect(await screen.findByText('Microsoft Entra ID')).toBeInTheDocument()
    expect(
      screen.getByText('https://soc.example.com/api/auth/sso/entra/callback'),
    ).toBeInTheDocument()
    expect(screen.getByText(/secret stored/)).toBeInTheDocument()
  })

  it('adds a provider with Viewer as the default role and a write-only secret', async () => {
    const notify = setup()
    await screen.findByText('Microsoft Entra ID')
    fireEvent.click(screen.getByRole('button', { name: /Add provider/ }))

    fireEvent.change(screen.getByLabelText('ID'), { target: { value: 'kc' } })
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Keycloak' } })
    fireEvent.change(screen.getByLabelText('Issuer'), {
      target: { value: 'https://idp.example.com/realms/soc' },
    })
    fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: 'autosecops' } })
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 's3cret' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save provider' }))

    await waitFor(() => expect(ssoApi.saveProvider).toHaveBeenCalled())
    const [id, payload] = vi.mocked(ssoApi.saveProvider).mock.calls[0]
    expect(id).toBe('kc')
    expect(payload).toMatchObject({
      display_name: 'Keycloak',
      issuer: 'https://idp.example.com/realms/soc',
      client_id: 'autosecops',
      client_secret: 's3cret',
      default_role_id: 'role-viewer',
      allow_admin_mapping: false,
      scopes: ['openid', 'email', 'profile'],
    })
    await waitFor(() => expect(notify).toHaveBeenCalledWith('ok', 'Saved Keycloak.'))
  })

  it('refuses a non-https issuer before calling the server', async () => {
    setup()
    await screen.findByText('Microsoft Entra ID')
    fireEvent.click(screen.getByRole('button', { name: /Add provider/ }))
    fireEvent.change(screen.getByLabelText('ID'), { target: { value: 'kc' } })
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Keycloak' } })
    fireEvent.change(screen.getByLabelText('Issuer'), { target: { value: 'http://idp' } })
    fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: 'autosecops' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save provider' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Issuer must be an https:// URL')
    expect(ssoApi.saveProvider).not.toHaveBeenCalled()
  })

  it('editing keeps the stored secret unless a new one is typed', async () => {
    setup()
    await screen.findByText('Microsoft Entra ID')
    fireEvent.click(screen.getByRole('button', { name: 'Edit Microsoft Entra ID' }))
    expect(screen.getByText('A secret is stored. Leave blank to keep it.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save provider' }))
    await waitFor(() => expect(ssoApi.saveProvider).toHaveBeenCalled())
    const [id, payload] = vi.mocked(ssoApi.saveProvider).mock.calls[0]
    expect(id).toBe('entra')
    expect(payload).not.toHaveProperty('client_secret')
  })

  it('turns password sign-in off while keeping the break-glass accounts', async () => {
    setup()
    await screen.findByText('Microsoft Entra ID')
    fireEvent.click(screen.getByRole('switch', { name: 'Allow password sign-in for everyone' }))
    await waitFor(() =>
      expect(ssoApi.saveLoginPolicy).toHaveBeenCalledWith({
        local_login_enabled: false,
        break_glass_user_ids: ['u-root'],
      }),
    )
  })

  it('adds a break-glass account', async () => {
    setup()
    await screen.findByText('Microsoft Entra ID')
    fireEvent.click(screen.getByRole('checkbox', { name: /ana/ }))
    await waitFor(() =>
      expect(ssoApi.saveLoginPolicy).toHaveBeenCalledWith({
        local_login_enabled: true,
        break_glass_user_ids: ['u-root', 'u-ana'],
      }),
    )
  })
})
