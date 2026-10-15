import { useEffect, useState } from 'react'
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { authApi } from '../../services/api'
import { Icon } from '../../shared/icons'
import AuthLayout from './AuthLayout'
import { requestErrorMessage } from './requestErrorMessage'

// The token travels in the fragment (/reset-password#token=…): a browser never
// sends a fragment to the server, so it can't reach an access log. Links
// issued before that carried ?token=…; those still work.
function tokenFrom(hash: string, search: string): string {
  const fromHash = new URLSearchParams(hash.replace(/^#/, '')).get('token')
  if (fromHash) return fromHash
  return new URLSearchParams(search).get('token') ?? ''
}

// Landing page for the emailed (or administrator-issued) reset link. Public:
// the signed token is the credential. AuthProvider's /auth/me GET on mount
// seeds the csrf_token cookie the confirm POST needs in a fresh browser.
export default function ResetPasswordScreen() {
  const navigate = useNavigate()
  const location = useLocation()
  const [, setParams] = useSearchParams()
  // Read once, then kept in memory only: the address bar, history entry and
  // any Referer stop carrying it (see the effect below).
  const [token] = useState(() => tokenFrom(location.hash, location.search))

  useEffect(() => {
    // Take the token out of the URL as soon as it is read, from the fragment
    // (the whole fragment goes; the screen uses no other) and the query. A replace (the router's history.replaceState), so
    // Back can't bring it back either.
    const search = new URLSearchParams(location.search)
    const inHash = new URLSearchParams(location.hash.replace(/^#/, '')).has('token')
    if (search.has('token') || inHash) {
      search.delete('token')
      // Navigates to "?<rest>" on this path, which also drops the fragment.
      setParams(search, { replace: true })
    }
    // Belt and braces with the server's Referrer-Policy: no-referrer on this
    // page, for a dev server or proxy that doesn't send it.
    const meta = document.createElement('meta')
    meta.name = 'referrer'
    meta.content = 'no-referrer'
    document.head.appendChild(meta)
    return () => {
      meta.remove()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(
    token ? '' : 'This reset link is missing its token. Request a new link.',
  )
  // The server consumes the token before checking the password, so any 400
  // (bad token or policy failure) leaves this link unusable.
  const [spent, setSpent] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await authApi.confirmPasswordReset({ token, new_password: password })
      navigate('/login', {
        replace: true,
        state: { notice: 'Password updated. Sign in with your new password.' },
      })
    } catch (err: any) {
      setError(requestErrorMessage(err, 'Could not reset your password. Please try again.'))
      setSpent(err?.response?.status === 400)
      setLoading(false)
    }
  }

  const requestNewLink = () => navigate('/login', { state: { forgot: true } })

  return (
    <AuthLayout
      screenLabel="Reset password"
      title={!token ? 'Reset link incomplete' : spent ? 'Reset link used' : 'Choose a new password'}
      subtitle={
        !token
          ? 'Open the full link from your reset email, or request another.'
          : spent
            ? "This link can't be used again. Request a new one to try again."
            : 'This signs out every existing session.'
      }
      message={{ text: error }}
    >
      {token && !spent ? (
        <form onSubmit={handleSubmit} autoComplete="on" noValidate>
          <div className="field">
            <label htmlFor="reset-pass">New password</label>
            <div className="ctrl">
              <Icon name="lock" className="lead" />
              <input
                id="reset-pass"
                name="new-password"
                type={showPassword ? 'text' : 'password'}
                placeholder="At least 12 characters"
                autoComplete="new-password"
                autoFocus
                disabled={loading}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <button
                className="reveal"
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                title={showPassword ? 'Hide password' : 'Show password'}
              >
                <Icon name="eye" size={17} />
              </button>
            </div>
          </div>

          <button className="btn-signin" type="submit" disabled={loading || !password}>
            {loading ? (
              <span className="spin" aria-hidden="true" />
            ) : (
              <>
                Set new password
                <Icon name="arrowR" />
              </>
            )}
          </button>

          <div className="mfa-back">
            <button type="button" className="link" onClick={requestNewLink}>
              Request a new link
            </button>
          </div>
        </form>
      ) : (
        <>
          <button className="btn-signin" type="button" onClick={requestNewLink}>
            Request a new link
            <Icon name="arrowR" />
          </button>
          <div className="mfa-back">
            <button type="button" className="link" onClick={() => navigate('/login')}>
              ← Back to sign in
            </button>
          </div>
        </>
      )}
    </AuthLayout>
  )
}
