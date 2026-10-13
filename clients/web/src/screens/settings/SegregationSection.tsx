// W3.2: the two-person rule's distinct-role condition per action class, and
// the segregation-of-duties report (who proposed, approved, executed; in which
// role; what broke the rules) with a CSV / JSON export.
import { useCallback, useEffect, useState } from 'react'
import { segregationApi } from '../../services/api'
import type { Schema } from '../../services/apiTypes'
import { SettingsCard, TextInput, Toggle } from '../../shared/ui'
import type { SectionProps } from './types'

type Report = Schema<'SegregationReport'>
type FourEyes = Schema<'FourEyesConfig'>

const CLASSES = ['disable_user', 'revoke_sessions', 'access_revoke', 'isolate_host', 'block_ip', 'block_domain', 'waf_block', 'gateway_block', 'quarantine_file']
const pretty = (s: string) => s.replace(/_/g, ' ')

function errText(e: unknown, fallback: string): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

export default function SegregationSection({ notify }: SectionProps) {
  const [fourEyes, setFourEyes] = useState<FourEyes | null>(null)
  const [report, setReport] = useState<Report | null>(null)
  const [violationsOnly, setViolationsOnly] = useState(true)
  const [reason, setReason] = useState('')
  const [failed, setFailed] = useState('')

  const load = useCallback(async () => {
    try {
      const [cfg, rep] = await Promise.all([
        segregationApi.fourEyes(),
        segregationApi.report({ violations_only: violationsOnly }),
      ])
      setFourEyes(cfg.data)
      setReport(rep.data)
      setFailed('')
    } catch (e) {
      setFailed(errText(e, 'Could not load the segregation-of-duties report'))
    }
  }, [violationsOnly])

  useEffect(() => {
    void load()
  }, [load])

  const toggle = async (actionType: string, on: boolean) => {
    if (!reason.trim()) {
      notify('err', 'Give a reason before changing the two-person rule')
      return
    }
    try {
      const res = await segregationApi.setDistinctRole(actionType, { distinct_role: on, reason: reason.trim() })
      setFourEyes(res.data)
      notify('ok', `${pretty(actionType)}: ${on ? 'second approver must hold another role' : 'any second approver'}`)
    } catch (e) {
      notify('err', errText(e, 'Could not save'))
    }
  }

  if (failed) {
    return (
      <SettingsCard title="Segregation of duties" wide>
        <p className="text-sm text-tx-2">{failed}</p>
      </SettingsCard>
    )
  }
  if (!fourEyes || !report) {
    return (
      <SettingsCard title="Segregation of duties" wide>
        <p className="text-sm text-tx-3">Loading…</p>
      </SettingsCard>
    )
  }

  const distinct = new Set(fourEyes.distinct_role_types)
  const fourEyesSet = new Set(fourEyes.four_eyes_types)
  const rows = report.rows ?? []

  return (
    <>
      <SettingsCard
        title="Two-person rule"
        desc="Action classes that need two approvers. Turn on “different role” to also require the second approver to hold a role the first does not."
        wide
      >
        <label className="field">
          <span className="field-label">Reason for a change</span>
          <TextInput value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why the rule changes (audited)" />
        </label>
        <table className="tbl mt-2">
          <thead>
            <tr><th>Action</th><th>Two approvers</th><th>Different role</th></tr>
          </thead>
          <tbody>
            {CLASSES.map((c) => (
              <tr key={c}>
                <td>{pretty(c)}</td>
                <td>{fourEyesSet.has(c) ? 'Yes' : 'No'}</td>
                <td>
                  <Toggle
                    label={`Different role for ${pretty(c)}`}
                    checked={distinct.has(c)}
                    onChange={(v) => void toggle(c, v)}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </SettingsCard>

      <SettingsCard
        title="Segregation-of-duties report"
        desc="Who proposed, approved and executed each response action, in which role, and every violation of the rules above."
        actions={
          <span className="flex gap-2">
            <a className="btn ghost" href={segregationApi.exportUrl('csv', violationsOnly)}>Export CSV</a>
            <a className="btn ghost" href={segregationApi.exportUrl('json', violationsOnly)}>Export JSON</a>
          </span>
        }
        wide
      >
        <div className="flex items-center gap-2 mb-2">
          <Toggle label="Only violations" checked={violationsOnly} onChange={setViolationsOnly} />
          <span className="text-sm">Only violations</span>
          <span className="text-xs text-tx-3 ml-auto" data-testid="sod-summary">
            {report.summary.total} action(s), {report.summary.with_violations} with violations
          </span>
        </div>
        {rows.length === 0 ? (
          <p className="text-sm text-tx-3">Nothing to show.</p>
        ) : (
          <table className="tbl">
            <thead>
              <tr>
                <th>Action</th><th>Proposed by</th><th>Approved by</th><th>Second approver</th><th>Executed by</th><th>Violations</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.action_id}>
                  <td>{pretty(r.action_type)} <span className="text-xs text-tx-3">{r.action_id}</span></td>
                  <td>{r.proposed_by ?? '—'}{r.proposed_role ? ` (${r.proposed_role})` : ''}</td>
                  <td>{r.approved_by ?? '—'}{r.approved_role ? ` (${r.approved_role})` : ''}</td>
                  <td>{r.second_approver ?? '—'}{r.second_role ? ` (${r.second_role})` : ''}</td>
                  <td>{r.executed_by ?? '—'}</td>
                  <td>{(r.violations ?? []).map(pretty).join(', ') || 'none'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </SettingsCard>
    </>
  )
}
