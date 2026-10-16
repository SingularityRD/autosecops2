// W0.36: the response policy every action passes before an executor runs it:
// protected assets (never acted on), hourly action limits (blast radius) and the
// action classes under the two-person rule. Built-in protected tags and
// four-eyes classes are shown locked: the policy only adds to them. Every save
// takes a reason and is written to the configuration audit log.
import { useCallback, useEffect, useState } from 'react'
import { responsePolicyApi } from '../../services/api'
import type { Schema } from '../../services/apiTypes'
import { Field, NumberInput, SettingsCard, TextInput, Toggle } from '../../shared/ui'
import type { SectionProps } from './types'
import { type Draft, pretty, toDraft, toUpdate } from './responsePolicyDraft'

type Policy = Schema<'ResponsePolicyView'>

export const CONFLICT_TEXT =
  'Someone else changed the response policy after you opened it. It has been reloaded with their change; your edits were not saved. Review and save again.'

function errText(e: unknown, fallback: string): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0] as { loc?: unknown[]; msg?: string }
    return `${(first.loc ?? []).slice(1).join('.')}: ${first.msg ?? 'invalid'}`
  }
  return fallback
}

export default function ResponsePolicySection({ notify }: SectionProps) {
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [draft, setDraft] = useState<Draft | null>(null)
  const [reason, setReason] = useState('')
  const [failed, setFailed] = useState('')
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    try {
      const res = await responsePolicyApi.get()
      setPolicy(res.data)
      setDraft(toDraft(res.data))
      setFailed('')
    } catch (e) {
      setFailed(errText(e, 'Could not load the response policy'))
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  if (failed) {
    return (
      <SettingsCard title="Response policy" wide>
        <p className="text-sm text-tx-2">{failed}</p>
      </SettingsCard>
    )
  }
  if (!policy || !draft) {
    return (
      <SettingsCard title="Response policy" wide>
        <p className="text-sm text-tx-3">Loading…</p>
      </SettingsCard>
    )
  }

  const set = (patch: Partial<Draft>) => setDraft({ ...draft, ...patch })
  const builtInFourEyes = new Set(policy.defaults.four_eyes_types)
  const distinct = new Set(policy.effective.distinct_role_types)

  const save = async () => {
    if (!reason.trim()) {
      notify('err', 'Give a reason before changing the response policy')
      return
    }
    const body = toUpdate(draft, reason.trim(), policy.version)
    if (typeof body === 'string') {
      notify('err', body)
      return
    }
    setSaving(true)
    try {
      const res = await responsePolicyApi.update(body)
      setPolicy(res.data)
      setDraft(toDraft(res.data))
      setReason('')
      notify('ok', 'Response policy saved')
    } catch (e) {
      if ((e as { response?: { status?: number } })?.response?.status === 409) {
        // Someone saved in between (here or under Segregation of duties).
        // Show theirs rather than let a stale copy overwrite it.
        notify('err', CONFLICT_TEXT)
        await load()
      } else {
        notify('err', errText(e, 'Could not save the response policy'))
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <SettingsCard
        title="Protected assets"
        desc="No response action runs against these, whatever approves it: hosts (full or short name), addresses and ranges, and accounts. An asset carrying a protected tag is protected too."
        wide
      >
        <Field label="Protected targets" hint="One per line: dc01.corp.local, 10.0.0.0/24, svc-backup@corp.com">
          <textarea
            className="field-input font-mono text-xs"
            rows={6}
            aria-label="Protected targets"
            value={draft.targets}
            onChange={(e) => set({ targets: e.target.value })}
            spellCheck={false}
          />
        </Field>
        <Field label="Asset tags" hint="One asset per line, then its tags: fs01.corp.local: tier0, critical_infrastructure">
          <textarea
            className="field-input font-mono text-xs"
            rows={4}
            aria-label="Asset tags"
            value={draft.assetTags}
            onChange={(e) => set({ assetTags: e.target.value })}
            spellCheck={false}
          />
        </Field>
        <Field
          label="Extra protected tags"
          hint={`Always protected: ${policy.defaults.protected_tags.join(', ')}`}
        >
          <TextInput aria-label="Extra protected tags" value={draft.tags} onChange={(e) => set({ tags: e.target.value })} />
        </Field>
      </SettingsCard>

      <SettingsCard
        title="Hourly action limits"
        desc="At most this many actions of a type execute per rolling hour (blast radius). Blank uses the default."
        wide
      >
        <Field label="Default limit (types not listed)">
          <NumberInput
            aria-label="Default hourly limit"
            min={0}
            max={1000}
            value={draft.defaultLimit}
            onChange={(e) => set({ defaultLimit: e.target.value })}
          />
        </Field>
        <table className="tbl mt-2">
          <thead>
            <tr><th>Action</th><th>Limit per hour</th><th>In effect</th></tr>
          </thead>
          <tbody>
            {policy.action_types.map((t) => (
              <tr key={t}>
                <td>{pretty(t)}</td>
                <td>
                  <NumberInput
                    aria-label={`Hourly limit for ${pretty(t)}`}
                    min={0}
                    max={1000}
                    placeholder={String(policy.defaults.hourly_limits[t] ?? policy.default_hourly_limit)}
                    value={draft.limits[t] ?? ''}
                    onChange={(e) => set({ limits: { ...draft.limits, [t]: e.target.value } })}
                  />
                </td>
                <td>{policy.effective.hourly_limits[t] ?? policy.effective.default_hourly_limit}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </SettingsCard>

      <SettingsCard
        title="Two-person rule"
        desc="Action classes that need a second, different approver. Built-in classes cannot be turned off. The different-role condition is under Segregation of duties."
        wide
      >
        <table className="tbl">
          <thead>
            <tr><th>Action</th><th>Two approvers</th></tr>
          </thead>
          <tbody>
            {policy.action_types.map((t) => {
              const locked = builtInFourEyes.has(t) || distinct.has(t)
              const on = locked || draft.fourEyes.has(t)
              return (
                <tr key={t}>
                  <td>
                    {pretty(t)}
                    {locked && <span className="text-xs text-tx-3"> ({builtInFourEyes.has(t) ? 'built in' : 'different role'})</span>}
                  </td>
                  <td>
                    <Toggle
                      label={`Two approvers for ${pretty(t)}`}
                      checked={on}
                      disabled={locked}
                      onChange={(v) => {
                        const next = new Set(draft.fourEyes)
                        if (v) next.add(t)
                        else next.delete(t)
                        set({ fourEyes: next })
                      }}
                    />
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </SettingsCard>

      <SettingsCard title="Save the policy" desc="Needs settings.write. Recorded in the configuration audit log with your name, the reason and the old and new policy." wide>
        <Field label="Reason for the change">
          <TextInput value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why the policy changes (audited)" />
        </Field>
        <div className="flex gap-2 mt-2">
          <button type="button" className="btn primary" disabled={saving} onClick={() => void save()}>
            Save policy
          </button>
          <button type="button" className="btn ghost" disabled={saving} onClick={() => setDraft(toDraft(policy))}>
            Discard changes
          </button>
        </div>
      </SettingsCard>
    </>
  )
}
