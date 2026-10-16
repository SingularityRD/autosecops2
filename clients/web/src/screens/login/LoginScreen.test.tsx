import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { ColorSchemeProvider } from '../../contexts/ColorSchemeContext'
import LoginScreen from './LoginScreen'
import { RESET_ASK_ADMIN, RESET_SSO_NOTE } from './resetMessages'

const login = vi.fn()
const navigate = vi.fn()
const requestPasswordReset = vi.fn()

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({ login }),
}))

// stubbed so the hydrate effect resolves deterministically in jsdom
vi.mock('../../services/api', () => ({
  configApi: {
    getTheme: () => Promise.resolve({ data: { theme: 'dark' } }),
    setTheme: () => Promise.resolve({ data: {} }),
  },
  // unmocked, this throws inside the mount effect and fails every test here
  bootstrapApi: {
    status: () => bootstrapStatus(),
    create: (payload: unknown, token: string) => bootstrapCreate(payload, token),
  },
  ssoApi: {
    providers: () => ssoProviders(),
    loginUrl: (id: string) => `/api/auth/sso/${id}/login`,
  },
  authApi: { requestPasswordReset: (email: string) => requestPasswordReset(email) },
}))

// Default: no single sign-on configured. Hoisted so the vi.mock factory sees it.
type SsoList = {
  data: { providers: { id: string; display_name: string }[]; local_login_enabled: boolean }
}
const { bootstrapStatus, bootstrapCreate } = vi.hoisted(() => ({
  bootstrapStatus: vi.fn(() => Promise.resolve({ data: { required: false } })),
  bootstrapCreate: vi.fn((...args: [unknown, string]) => Promise.resolve({ data: {}, args })),
}))
const { ssoProviders } = vi.hoisted(() => ({
  ssoProviders: vi.fn(
    (): Promise<SsoList> =>
      Promise.resolve({ data: { providers: [], local_login_enabled: true } }),
  ),
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return { ...actual, useNavigate: () => navigate }
})

function renderLogin(path = '/login') {
  return render(
    <ColorSchemeProvider>
      <MemoryRouter initialEntries={[path]}>
        <LoginScreen />
      </MemoryRouter>
    </ColorSchemeProvider>,
  )
}

beforeEach(() => {
  bootstrapStatus.mockClear()
  bootstrapCreate.mockClear()
  login.mockReset()
  navigate.mockReset()
  ssoProviders.mockClear()
  requestPasswordReset.mockReset()
})

describe('LoginScreen', () => {
  describe('first administrator (W0.33)', () => {
    const fill = (token: string) => {
      fireEvent.change(screen.getByLabelText('Setup token'), { target: { value: token } })
      fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'first' } })
      fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'first@example.com' } })
      fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'harbour-lantern-quartz-91' } })
    }

    beforeEach(() => {
      bootstrapStatus.mockResolvedValueOnce({ data: { required: true } })
    })

    it('asks for the setup token and will not submit without it', async () => {
      renderLogin()
      expect(await screen.findByLabelText('Setup token')).toHaveAttribute('type', 'password')
      fill('   ')
      expect(screen.getByRole('button', { name: /create account/i })).toBeDisabled()
    })

    it('sends the token apart from the account details', async () => {
      login.mockResolvedValueOnce(undefined)
      renderLogin()
      await screen.findByLabelText('Setup token')
      fill('  tok-123  ')
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))
      await waitFor(() =>
        expect(bootstrapCreate).toHaveBeenCalledWith(
          { username: 'first', email: 'first@example.com', password: 'harbour-lantern-quartz-91' },
          'tok-123',
        ),
      )
      await waitFor(() => expect(navigate).toHaveBeenCalledWith('/'))
    })

    it("shows the server's reason when the token is refused", async () => {
      bootstrapCreate.mockRejectedValueOnce({
        response: { status: 401, data: { detail: 'Setup token missing or wrong.' } },
      })
      renderLogin()
      await screen.findByLabelText('Setup token')
      fill('wrong')
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))
      expect(await screen.findByRole('alert')).toHaveTextContent('Setup token missing or wrong.')
      expect(login).not.toHaveBeenCalled()
    })
  })

  it('renders the credential form and brand panel', () => {
    renderLogin()
    expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument()
    expect(screen.getByLabelText('Username or email')).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toBeInTheDocument()
  })

  it('signs in and routes into the console', async () => {
    login.mockResolvedValueOnce(undefined)
    renderLogin()
    fireEvent.change(screen.getByLabelText('Username or email'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'admin123' } })
    fireEvent.click(screen.getByRole('button', { name: /^sign in$/i }))
    await waitFor(() => expect(login).toHaveBeenCalledWith('admin', 'admin123', undefined))
    await waitFor(() => expect(navigate).toHaveBeenCalledWith('/'))
  })

  it('reveals the MFA step when the backend requires it', async () => {
    login.mockRejectedValueOnce(new Error('MFA_REQUIRED'))
    renderLogin()
    fireEvent.change(screen.getByLabelText('Username or email'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'admin123' } })
    fireEvent.click(screen.getByRole('button', { name: /^sign in$/i }))
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /two-factor/i })).toBeInTheDocument(),
    )
    expect(screen.getByLabelText('Authentication code')).toBeInTheDocument()
  })

  describe('sign-in errors', () => {
    async function submit() {
      renderLogin()
      fireEvent.change(screen.getByLabelText('Username or email'), { target: { value: 'admin' } })
      fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'pw' } })
      fireEvent.click(screen.getByRole('button', { name: /^sign in$/i }))
      return screen.findByRole('alert')
    }

    it('blames the backend, not the credentials, on a network error', async () => {
      login.mockRejectedValueOnce(new Error('Network Error'))
      expect(await submit()).toHaveTextContent("Can't reach the AutoSecOps API. Is the backend running?")
    })

    it('treats a 5xx without a detail as unreachable', async () => {
      login.mockRejectedValueOnce({ response: { status: 500, data: '' } })
      expect(await submit()).toHaveTextContent("Can't reach the AutoSecOps API")
    })

    it('shows the server detail on a 5xx that has one', async () => {
      login.mockRejectedValueOnce({ response: { status: 500, data: { detail: 'DB locked' } } })
      expect(await submit()).toHaveTextContent('DB locked')
    })

    it('keeps the credentials message on a 401', async () => {
      login.mockRejectedValueOnce({ response: { status: 401, data: {} } })
      expect(await submit()).toHaveTextContent('Sign in failed. Check your credentials.')
    })
  })

  describe('forgot password', () => {
    const GENERIC = 'If that email matches an active account, a reset link has been sent.'

    it('requests a reset and shows only the server message', async () => {
      requestPasswordReset.mockResolvedValueOnce({ data: { message: GENERIC, delivery: 'email' } })
      renderLogin()
      fireEvent.click(screen.getByRole('button', { name: 'Forgot password?' }))
      expect(screen.getByRole('heading', { name: 'Reset your password' })).toBeInTheDocument()
      fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'a@b.co' } })
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }))
      expect(await screen.findByRole('alert')).toHaveTextContent(GENERIC)
      expect(requestPasswordReset).toHaveBeenCalledWith('a@b.co')
      expect(screen.queryByLabelText('Email')).not.toBeInTheDocument()

      fireEvent.click(screen.getByRole('button', { name: /back to sign in/i }))
      expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument()
    })

    it('without mail says to contact an administrator, not that a link was sent', async () => {
      requestPasswordReset.mockResolvedValueOnce({
        data: { message: 'anything the server says', delivery: 'administrator' },
      })
      renderLogin()
      fireEvent.click(screen.getByRole('button', { name: 'Forgot password?' }))
      fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'a@b.co' } })
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }))
      const alert = await screen.findByRole('alert')
      expect(alert).toHaveTextContent(RESET_ASK_ADMIN)
      expect(alert).toHaveTextContent('Contact your AutoSecOps administrator')
      expect(alert).not.toHaveTextContent('has been sent')
    })

    it('tells single-sign-on users to reset at their identity provider', async () => {
      ssoProviders.mockResolvedValueOnce({
        data: { providers: [{ id: 'kc', display_name: 'Keycloak' }], local_login_enabled: true },
      })
      renderLogin()
      await screen.findByRole('link', { name: 'Sign in with Keycloak' })
      fireEvent.click(screen.getByRole('button', { name: 'Forgot password?' }))
      expect(screen.getByText(RESET_SSO_NOTE)).toBeInTheDocument()
      // the forgot view hides the SSO buttons
      expect(screen.queryByRole('link', { name: /sign in with/i })).not.toBeInTheDocument()
    })

    it('shows no SSO note when single sign-on is not configured', async () => {
      renderLogin()
      await waitFor(() => expect(ssoProviders).toHaveBeenCalled())
      fireEvent.click(screen.getByRole('button', { name: 'Forgot password?' }))
      expect(screen.queryByText(RESET_SSO_NOTE)).not.toBeInTheDocument()
    })

    it('explains a rate-limited request', async () => {
      // slowapi's 429 body carries `error`, not `detail`
      requestPasswordReset.mockRejectedValueOnce({
        response: { status: 429, data: { error: 'Rate limit exceeded: 3 per 1 hour' } },
      })
      renderLogin()
      fireEvent.click(screen.getByRole('button', { name: 'Forgot password?' }))
      fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'a@b.co' } })
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }))
      expect(await screen.findByRole('alert')).toHaveTextContent('Too many attempts')
    })
  })

  it('toggles between light and dark mode', async () => {
    const { container } = renderLogin()
    const root = container.querySelector('.auth-root') as HTMLElement
    await waitFor(() => expect(root.getAttribute('data-theme')).toBe('dark'))
    expect(root).toHaveClass('vg-dark')
    fireEvent.click(screen.getByRole('button', { name: /switch to light mode/i }))
    await waitFor(() => expect(root.getAttribute('data-theme')).toBe('light'))
    expect(root).toHaveClass('vg-light')
  })

  describe('single sign-on', () => {
    it('shows no SSO button when no provider is configured', async () => {
      renderLogin()
      await waitFor(() => expect(ssoProviders).toHaveBeenCalled())
      expect(screen.queryByRole('link', { name: /sign in with/i })).not.toBeInTheDocument()
    })

    it('shows a "Sign in with" button per provider that starts the flow', async () => {
      ssoProviders.mockResolvedValueOnce({
        data: {
          providers: [
            { id: 'entra', display_name: 'Microsoft Entra ID' },
            { id: 'okta', display_name: 'Okta' },
          ],
          local_login_enabled: true,
        },
      })
      renderLogin()
      const entra = await screen.findByRole('link', { name: 'Sign in with Microsoft Entra ID' })
      expect(entra).toHaveAttribute('href', '/api/auth/sso/entra/login')
      expect(screen.getByRole('link', { name: 'Sign in with Okta' })).toHaveAttribute(
        'href',
        '/api/auth/sso/okta/login',
      )
      // the password form stays for break-glass accounts
      expect(screen.getByLabelText('Password')).toBeInTheDocument()
      expect(screen.queryByText(/break-glass/i)).not.toBeInTheDocument()
    })

    it('says password sign-in is limited when local login is off', async () => {
      ssoProviders.mockResolvedValueOnce({
        data: {
          providers: [{ id: 'kc', display_name: 'Keycloak' }],
          local_login_enabled: false,
        },
      })
      renderLogin()
      await screen.findByRole('link', { name: 'Sign in with Keycloak' })
      expect(screen.getByText(/limited to break-glass accounts/i)).toHaveTextContent('AutoSecOps')
    })

    it('explains a failed SSO sign-in from the callback redirect', async () => {
      renderLogin('/login?sso_error=account')
      expect(await screen.findByRole('alert')).toHaveTextContent(
        'No AutoSecOps account is linked to that identity',
      )
    })

    it('falls back to a generic message for an unknown SSO error code', async () => {
      renderLogin('/login?sso_error=whatever')
      expect(await screen.findByRole('alert')).toHaveTextContent(
        'Single sign-on is unavailable right now',
      )
    })

    it('keeps sign-in working when the provider list cannot be loaded', async () => {
      ssoProviders.mockRejectedValueOnce(new Error('Network Error'))
      renderLogin()
      await waitFor(() => expect(ssoProviders).toHaveBeenCalled())
      expect(screen.getByRole('button', { name: /^sign in$/i })).toBeInTheDocument()
      expect(screen.queryByRole('link', { name: /sign in with/i })).not.toBeInTheDocument()
    })
  })
})
