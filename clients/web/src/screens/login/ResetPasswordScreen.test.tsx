import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { ColorSchemeProvider } from '../../contexts/ColorSchemeContext'
import ResetPasswordScreen from './ResetPasswordScreen'

const navigate = vi.fn()
const confirmPasswordReset = vi.fn()

vi.mock('../../services/api', () => ({
  configApi: {
    getTheme: () => Promise.resolve({ data: { theme: 'dark' } }),
    setTheme: () => Promise.resolve({ data: {} }),
  },
  authApi: { confirmPasswordReset: (p: unknown) => confirmPasswordReset(p) },
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return { ...actual, useNavigate: () => navigate }
})

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="location">{location.pathname + location.search}</output>
}

function renderAt(url: string) {
  return render(
    <ColorSchemeProvider>
      <MemoryRouter initialEntries={[url]}>
        <ResetPasswordScreen />
        <LocationProbe />
      </MemoryRouter>
    </ColorSchemeProvider>,
  )
}

function submit(pw: string) {
  fireEvent.change(screen.getByLabelText('New password'), { target: { value: pw } })
  fireEvent.click(screen.getByRole('button', { name: /set new password/i }))
}

beforeEach(() => {
  navigate.mockReset()
  confirmPasswordReset.mockReset()
})

describe('ResetPasswordScreen', () => {
  it('confirms with the URL token and hands off to sign-in', async () => {
    confirmPasswordReset.mockResolvedValueOnce({ data: { message: 'ok' } })
    renderAt('/reset-password?token=tok123')
    submit('a-long-new-passphrase')
    await waitFor(() =>
      expect(confirmPasswordReset).toHaveBeenCalledWith({
        token: 'tok123',
        new_password: 'a-long-new-passphrase',
      }),
    )
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith('/login', {
        replace: true,
        state: { notice: 'Password updated. Sign in with your new password.' },
      }),
    )
  })

  it('shows the server detail and retires the spent link on a 400', async () => {
    // the server consumes the token before the policy check, so no retry
    confirmPasswordReset.mockRejectedValueOnce({
      response: { status: 400, data: { detail: 'Password is too short (Add 4 more characters.)' } },
    })
    renderAt('/reset-password?token=tok123')
    submit('short')
    expect(await screen.findByRole('alert')).toHaveTextContent('Password is too short')
    expect(screen.getByRole('heading', { name: 'Reset link used' })).toBeInTheDocument()
    expect(screen.queryByLabelText('New password')).not.toBeInTheDocument()
    expect(navigate).not.toHaveBeenCalled()
  })

  it('keeps the form for a retry when the API is unreachable', async () => {
    confirmPasswordReset.mockRejectedValueOnce(new Error('Network Error'))
    renderAt('/reset-password?token=tok123')
    submit('a-long-new-passphrase')
    expect(await screen.findByRole('alert')).toHaveTextContent("Can't reach the AutoSecOps API")
    expect(screen.getByLabelText('New password')).toBeInTheDocument()
  })

  it('takes the token out of the URL once read, and still confirms with it', async () => {
    confirmPasswordReset.mockResolvedValueOnce({ data: { message: 'ok' } })
    renderAt('/reset-password?token=tok123&lang=en')
    await waitFor(() =>
      expect(screen.getByTestId('location')).toHaveTextContent(/^\/reset-password\?lang=en$/),
    )
    expect(screen.getByTestId('location').textContent).not.toContain('tok123')
    submit('a-long-new-passphrase')
    await waitFor(() =>
      expect(confirmPasswordReset).toHaveBeenCalledWith({
        token: 'tok123',
        new_password: 'a-long-new-passphrase',
      }),
    )
  })

  it('asks the browser for no referrer while the page is open', () => {
    const { unmount } = renderAt('/reset-password?token=tok123')
    const meta = document.head.querySelector('meta[name="referrer"]')
    expect(meta).toHaveAttribute('content', 'no-referrer')
    unmount()
    expect(document.head.querySelector('meta[name="referrer"]')).toBeNull()
  })

  it('explains that a single-sign-on account has no password to reset', async () => {
    confirmPasswordReset.mockRejectedValueOnce({
      response: {
        status: 400,
        data: {
          detail:
            'This account signs in with single sign-on and has no AutoSecOps password to reset. Reset your password at your identity provider.',
        },
      },
    })
    renderAt('/reset-password?token=tok123')
    submit('a-long-new-passphrase')
    expect(await screen.findByRole('alert')).toHaveTextContent('single sign-on')
    expect(screen.getByRole('alert')).toHaveTextContent('identity provider')
  })

  it('has its own state when the token is missing', () => {
    renderAt('/reset-password')
    expect(screen.getByRole('heading', { name: 'Reset link incomplete' })).toBeInTheDocument()
    expect(screen.queryByLabelText('New password')).not.toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: /request a new link/i })[0])
    expect(navigate).toHaveBeenCalledWith('/login', { state: { forgot: true } })
  })
})
