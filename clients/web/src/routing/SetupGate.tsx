import { ReactNode, useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import {
  fetchSetupProgress,
  markSetupDismissed,
  readSetupDismissed,
} from '../screens/setup/setupDismissed'

interface Props {
  children: ReactNode
}

type Gate = 'checking' | 'console' | 'setup'

// /setup lives outside this gate, so opening it from the account menu does
// not bounce. The decision is the install's, not the browser's: an
// administrator is sent through the wizard until someone finishes or puts it
// off (server-side progress, W0.33). Without settings.write there is nothing
// to set up, so the console opens. When the server cannot be asked, this
// browser's own dismissal decides. A dismissal made in this browser before
// the server kept progress is carried over once, so an upgrade does not send
// an administrator back through the wizard.
const SetupGate = ({ children }: Props) => {
  const { hasPermission } = useAuth()
  const admin = hasPermission('settings.write')
  const [gate, setGate] = useState<Gate>(admin ? 'checking' : 'console')

  useEffect(() => {
    if (!admin) {
      setGate('console')
      return
    }
    let live = true
    fetchSetupProgress().then((server) => {
      if (!live) return
      if (!server) {
        setGate(readSetupDismissed() ? 'console' : 'setup')
      } else if (!server.started && readSetupDismissed()) {
        markSetupDismissed('deferred')
        setGate('console')
      } else {
        setGate(server.status === 'in_progress' ? 'setup' : 'console')
      }
    })
    return () => {
      live = false
    }
  }, [admin])

  if (gate === 'checking') return null
  if (gate === 'setup') return <Navigate to="/setup" replace />
  return <>{children}</>
}

export default SetupGate
