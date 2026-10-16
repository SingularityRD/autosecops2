import { configApi, type SetupProgressRead } from '../../services/api'

// The wizard's progress lives on the server (GET/PUT /api/config/setup-progress),
// so a second administrator or another browser picks up where the first left
// off. The localStorage copies below are a cache: what the wizard shows before
// the server answers, and what the gate falls back to when it cannot ask.
export const SETUP_DISMISSED_KEY = 'vigil.setupDismissed'

export type SetupOutcome = 'deferred' | 'completed'

function saveToServer(progress: SetupProgress, status: SetupProgressRead['status']): void {
  try {
    void configApi.putSetupProgress({ ...progress, status }).catch(() => {
      /* the local copy stands until the next save */
    })
  } catch {
    /* no API in this context */
  }
}

/** The server's progress, or null when it cannot be read. */
export async function fetchSetupProgress(): Promise<SetupProgressRead | null> {
  try {
    const { data } = await configApi.getSetupProgress()
    return data ?? null
  } catch {
    return null
  }
}

export function readSetupDismissed(): boolean {
  try {
    return localStorage.getItem(SETUP_DISMISSED_KEY) === '1'
  } catch {
    return false
  }
}

/** Leave the wizard. "completed" is recorded only if the server agrees the
    install is ready; otherwise it records "deferred". */
export function markSetupDismissed(outcome: SetupOutcome = 'deferred'): void {
  try {
    localStorage.setItem(SETUP_DISMISSED_KEY, '1')
  } catch {
    /* private mode */
  }
  saveToServer(readSetupProgress(), outcome)
}

// Wizard progress: the furthest step reached (1-5) and the steps the person
// continued past. Any unreadable cached value reads as "not started".
export const SETUP_PROGRESS_KEY = 'vigil.setupProgress'
export const SETUP_STEP_COUNT = 5

export interface SetupProgress {
  furthest: number
  passed: number[]
}

const inRange = (n: unknown): n is number =>
  Number.isInteger(n) && (n as number) >= 1 && (n as number) <= SETUP_STEP_COUNT

export function readSetupProgress(): SetupProgress {
  try {
    const raw = JSON.parse(localStorage.getItem(SETUP_PROGRESS_KEY) ?? 'null')
    if (raw && inRange(raw.furthest) && Array.isArray(raw.passed) && raw.passed.every(inRange)) {
      return { furthest: raw.furthest, passed: [...new Set<number>(raw.passed)] }
    }
  } catch {
    /* unreadable or malformed */
  }
  return { furthest: 1, passed: [] }
}

/** Cache only: writeSetupProgress and markSetupDismissed also save to the server. */
export function cacheSetupProgress(progress: SetupProgress): void {
  try {
    localStorage.setItem(SETUP_PROGRESS_KEY, JSON.stringify(progress))
  } catch {
    /* private mode */
  }
}

export function writeSetupProgress(progress: SetupProgress): void {
  cacheSetupProgress(progress)
  saveToServer(progress, 'in_progress')
}
