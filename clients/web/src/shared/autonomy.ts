// What the console promises about autonomy (W0.32). Containment always waits
// for a person, whatever the tier: core/autonomy/tiers.py ALWAYS_HUMAN is the
// code's list, and tests/unit/_ratchets/test_always_human_promise.py holds the
// ids below to it. Change one and the ratchet asks for the other.

/** Containment a person always approves: action id and how the console says it. */
export const ALWAYS_HUMAN_ACTIONS = [
  { id: 'isolate_host', label: 'isolating a host' },
  { id: 'disable_user', label: 'disabling an account' },
  { id: 'revoke_sessions', label: 'signing an account out everywhere' },
  { id: 'access_revoke', label: 'revoking an account’s access' },
  { id: 'block_ip', label: 'blocking an address on the network firewall' },
  { id: 'waf_block', label: 'blocking an address on the web application firewall' },
  { id: 'quarantine_file', label: 'quarantining a file' },
] as const

/** What always waits for a person, as one phrase. */
export const ALWAYS_HUMAN_SUMMARY =
  'Isolating a host, disabling or locking an account, blocking on a firewall, quarantining a file and anything that cannot be undone'

/** The lock line shown wherever the Assist/Act choice is made. */
export const ALWAYS_HUMAN_SENTENCE = `${ALWAYS_HUMAN_SUMMARY} always need a person. This cannot be changed.`

export const AUTONOMY_ASSIST = 'Assist · asks before changes'
export const AUTONOMY_ACT = 'Act · reversible changes on its own'
/** The flags allow Act but the tiers could not be read; the gate holds every action. */
export const AUTONOMY_UNKNOWN = 'Unknown · approvals held'

export interface AutonomyRead {
  auto_response_enabled?: boolean
  force_manual_approval?: boolean
  autonomous_tiers?: number | null
  mode?: 'assist' | 'act' | 'unknown'
}

/** The effective mode the API reports; Assist when it says nothing else. */
export function autonomyIsAct(data: AutonomyRead | null | undefined): boolean {
  return data?.mode === 'act'
}

/** The chip's words for the effective mode. */
export function autonomyLabel(data: AutonomyRead | null | undefined): string {
  if (data?.mode === 'act') return AUTONOMY_ACT
  if (data?.mode === 'unknown') return AUTONOMY_UNKNOWN
  return AUTONOMY_ASSIST
}
