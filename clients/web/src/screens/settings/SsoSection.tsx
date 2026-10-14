import { useCallback, useEffect, useState } from 'react'
import { Icon } from '../../shared/icons'
import {
  ConfirmDialog,
  Field,
  PasswordInput,
  Popup,
  Select,
  SettingsCard,
  TextInput,
  ToggleRow,
} from '../../shared/ui'
import { useAuth } from '../../contexts/AuthContext'
import {
  ssoApi,
  type SsoAdminConfig,
  type SsoProvider,
  type SsoProviderPayload,
} from '../../services/api'
import { useUsers } from './useSettings'
import type { SectionProps } from './types'

type Kind = SsoProviderPayload['kind']
type Mapping = { claim: string; value: string; role_id: string }

const KIND_OPTIONS: { value: NonNullable<Kind>; label: string }[] = [
  { value: 'entra', label: 'Microsoft Entra ID' },
  { value: 'okta', label: 'Okta' },
  { value: 'keycloak', label: 'Keycloak' },
  { value: 'generic', label: 'Other OpenID Connect provider' },
]

const ISSUER_HINT: Record<NonNullable<Kind>, string> = {
  entra: 'https://login.microsoftonline.com/<tenant-id>/v2.0 — one tenant, not "common".',
  okta: 'https://<your-org>.okta.com/oauth2/default (or your custom authorization server).',
  keycloak: 'https://<host>/realms/<realm>',
  generic: 'The exact issuer from the provider’s /.well-known/openid-configuration.',
}

// Entra puts security groups in "groups" (object IDs) and app roles in "roles".
const GROUP_CLAIM_HINT: Record<NonNullable<Kind>, string> = {
  entra: 'groups (object IDs) or roles (app roles)',
  okta: 'groups (add a groups claim to the ID token)',
  keycloak: 'groups (add the group membership mapper)',
  generic: 'groups',
}

interface FormState {
  id: string
  display_name: string
  kind: NonNullable<Kind>
  issuer: string
  client_id: string
  client_secret: string
  scopes: string
  enabled: boolean
  jit_provisioning: boolean
  link_by_verified_email: boolean
  default_role_id: string
  allow_admin_mapping: boolean
  role_mappings: Mapping[]
  redirect_uri: string
  clock_skew_seconds: number
}

const EMPTY_FORM: FormState = {
  id: '',
  display_name: '',
  kind: 'entra',
  issuer: '',
  client_id: '',
  client_secret: '',
  scopes: 'openid email profile',
  enabled: true,
  jit_provisioning: true,
  link_by_verified_email: false,
  default_role_id: 'role-viewer',
  allow_admin_mapping: false,
  role_mappings: [],
  redirect_uri: '',
  clock_skew_seconds: 60,
}

function fromProvider(p: SsoProvider): FormState {
  return {
    id: p.id,
    display_name: p.display_name,
    kind: p.kind,
    issuer: p.issuer,
    client_id: p.client_id,
    client_secret: '',
    scopes: p.scopes.join(' '),
    enabled: p.enabled,
    jit_provisioning: p.jit_provisioning,
    link_by_verified_email: p.link_by_verified_email,
    default_role_id: p.default_role_id,
    allow_admin_mapping: p.allow_admin_mapping,
    role_mappings: p.role_mappings.map((m) => ({
      claim: m.claim ?? 'groups',
      value: m.value,
      role_id: m.role_id,
    })),
    redirect_uri: p.redirect_uri,
    clock_skew_seconds: p.clock_skew_seconds,
  }
}

function errText(e: unknown, fallback: string): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return detail.map((d) => (d as { msg?: string })?.msg || JSON.stringify(d)).join(', ')
  }
  return (e as { message?: string })?.message || fallback
}

const ID_RE = /^[a-z0-9][a-z0-9-]{0,31}$/

export default function SsoSection({ notify }: SectionProps) {
  const { hasPermission } = useAuth()
  const allowed = hasPermission('settings.write') && hasPermission('users.write')

  if (!allowed) {
    return (
      <div className="settings-banner err">
        <Icon name="alert" size={14} /> Only administrators can configure single sign-on.
      </div>
    )
  }
  return <SsoSettings notify={notify} />
}

function SsoSettings({ notify }: SectionProps) {
  const { users, roles } = useUsers()
  const [config, setConfig] = useState<SsoAdminConfig | null>(null)
  const [loadError, setLoadError] = useState('')
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<SsoProvider | null>(null)
  const [form, setForm] = useState<FormState>(EMPTY_FORM)
  const [dialogError, setDialogError] = useState('')
  const [saving, setSaving] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState<SsoProvider | null>(null)
  const [policySaving, setPolicySaving] = useState(false)

  const load = useCallback(() => {
    setLoadError('')
    ssoApi
      .adminConfig()
      .then((res) => setConfig(res.data))
      .catch((e) => setLoadError(errText(e, 'Failed to load single sign-on settings')))
  }, [])

  useEffect(() => {
    load()
  }, [load])

  if (loadError) {
    return (
      <div className="py-16 text-center flex flex-col items-center gap-2.5">
        <span className="text-sm text-tx-3">Couldn’t load single sign-on settings: {loadError}</span>
        <button className="btn ghost" onClick={load}>Retry</button>
      </div>
    )
  }
  if (!config) {
    return <div className="text-sm text-tx-3 py-16 text-center">Loading single sign-on…</div>
  }

  const roleOptions = (allowAdmin: boolean) =>
    (roles.length
      ? roles.map((r) => ({ value: r.role_id, label: r.name }))
      : [{ value: 'role-viewer', label: 'Viewer' }]
    ).filter((o) => allowAdmin || o.value !== 'role-admin')

  const openCreate = () => {
    setEditing(null)
    setForm(EMPTY_FORM)
    setDialogError('')
    setDialogOpen(true)
  }

  const openEdit = (p: SsoProvider) => {
    setEditing(p)
    setForm(fromProvider(p))
    setDialogError('')
    setDialogOpen(true)
  }

  const validate = (): string | null => {
    if (!editing && !ID_RE.test(form.id)) {
      return 'ID must be lowercase letters, digits or "-" (up to 32 characters)'
    }
    if (!form.display_name.trim()) return 'Display name is required'
    if (!form.issuer.trim().startsWith('https://')) return 'Issuer must be an https:// URL'
    if (!form.client_id.trim()) return 'Client ID is required'
    if (form.role_mappings.some((m) => !m.claim.trim() || !m.value.trim() || !m.role_id)) {
      return 'Every role mapping needs a claim, a value and a role'
    }
    return null
  }

  const handleSave = async () => {
    const v = validate()
    if (v) {
      setDialogError(v)
      return
    }
    setSaving(true)
    setDialogError('')
    const payload: SsoProviderPayload = {
      display_name: form.display_name.trim(),
      kind: form.kind,
      issuer: form.issuer.trim(),
      client_id: form.client_id.trim(),
      scopes: form.scopes.split(/\s+/).filter(Boolean),
      enabled: form.enabled,
      jit_provisioning: form.jit_provisioning,
      link_by_verified_email: form.link_by_verified_email,
      default_role_id: form.default_role_id,
      allow_admin_mapping: form.allow_admin_mapping,
      role_mappings: form.role_mappings.map((m) => ({
        claim: m.claim.trim(),
        value: m.value.trim(),
        role_id: m.role_id,
      })),
      redirect_uri: form.redirect_uri.trim(),
      clock_skew_seconds: form.clock_skew_seconds,
      clear_client_secret: false,
      ...(form.client_secret ? { client_secret: form.client_secret } : {}),
    }
    try {
      const res = await ssoApi.saveProvider(editing ? editing.id : form.id, payload)
      setConfig(res.data)
      notify('ok', `Saved ${payload.display_name}.`)
      setDialogOpen(false)
    } catch (e) {
      setDialogError(errText(e, 'Failed to save the provider'))
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!confirmDelete) return
    try {
      const res = await ssoApi.deleteProvider(confirmDelete.id)
      setConfig(res.data)
      notify('ok', `Removed ${confirmDelete.display_name}.`)
    } catch (e) {
      notify('err', errText(e, 'Failed to remove the provider'))
    } finally {
      setConfirmDelete(null)
    }
  }

  const savePolicy = async (local_login_enabled: boolean, break_glass_user_ids: string[]) => {
    setPolicySaving(true)
    try {
      const res = await ssoApi.saveLoginPolicy({ local_login_enabled, break_glass_user_ids })
      setConfig(res.data)
      notify('ok', local_login_enabled ? 'Password sign-in is on for everyone.' : 'Password sign-in is limited to break-glass accounts.')
    } catch (e) {
      notify('err', errText(e, 'Failed to save the sign-in policy'))
    } finally {
      setPolicySaving(false)
    }
  }

  const policy = config.login_policy
  const breakGlass = policy.break_glass_user_ids ?? []

  const setMapping = (i: number, patch: Partial<Mapping>) =>
    setForm({
      ...form,
      role_mappings: form.role_mappings.map((m, j) => (j === i ? { ...m, ...patch } : m)),
    })

  return (
    <>
      <SettingsCard
        title="Single sign-on"
        desc="Let people sign in to AutoSecOps with your identity provider (OpenID Connect). New users get the Viewer role unless a group mapping says otherwise."
        actions={
          <button className="btn primary" onClick={openCreate}>
            <Icon name="plus" /> Add provider
          </button>
        }
      >
        {config.providers.length === 0 ? (
          <div className="muted" style={{ padding: '18px 0' }}>
            No identity provider yet. Add one to show a “Sign in with …” button on the sign-in screen.
          </div>
        ) : (
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Provider</th>
                  <th>Issuer</th>
                  <th>Redirect URI to register</th>
                  <th>Status</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {config.providers.map((p) => (
                  <tr key={p.id}>
                    <td>
                      {p.display_name}
                      <div className="text-xs text-tx-3">
                        {KIND_OPTIONS.find((k) => k.value === p.kind)?.label ?? p.kind}
                        {p.has_client_secret ? ' · secret stored' : ' · no client secret'}
                      </div>
                    </td>
                    <td className="muted mono">{p.issuer}</td>
                    <td className="muted mono">{p.effective_redirect_uri}</td>
                    <td>
                      <span className={`status ${p.enabled ? 'closed' : 'open'}`}>
                        {p.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <div className="inline-flex gap-1.5">
                        <button className="btn ghost icon" title={`Edit ${p.display_name}`} onClick={() => openEdit(p)}>
                          <Icon name="edit" size={15} />
                        </button>
                        <button className="btn ghost icon" title={`Remove ${p.display_name}`} onClick={() => setConfirmDelete(p)}>
                          <Icon name="trash" size={15} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SettingsCard>

      <SettingsCard
        title="Password sign-in"
        desc="Keep a few break-glass accounts that can always sign in with a password, in case the identity provider is down. Service accounts always use their password."
      >
        <div className="flex flex-col gap-3.5">
          <ToggleRow
            label="Allow password sign-in for everyone"
            hint="Turn off to require single sign-on for everyone except the break-glass accounts below."
            checked={policy.local_login_enabled ?? true}
            disabled={policySaving}
            onChange={(v) => savePolicy(v, breakGlass)}
          />
          <div>
            <div className="field-label" style={{ marginBottom: 6 }}>Break-glass accounts</div>
            {users.length === 0 ? (
              <div className="text-xs text-tx-3">No users loaded.</div>
            ) : (
              <div className="flex flex-col gap-1.5">
                {users.map((u) => (
                  <label key={u.user_id} className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={breakGlass.includes(u.user_id)}
                      disabled={policySaving}
                      onChange={(e) =>
                        savePolicy(
                          policy.local_login_enabled ?? true,
                          e.target.checked
                            ? [...breakGlass, u.user_id]
                            : breakGlass.filter((id) => id !== u.user_id),
                        )
                      }
                    />
                    {u.username}
                    <span className="text-xs text-tx-3">{roles.find((r) => r.role_id === u.role_id)?.name ?? u.role_id}</span>
                  </label>
                ))}
              </div>
            )}
          </div>
        </div>
      </SettingsCard>

      <Popup
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        title={editing ? `Edit ${editing.display_name}` : 'Add identity provider'}
        width={560}
      >
        <div className="flex flex-col gap-3.5">
          {dialogError && (
            <div className="settings-banner err" role="alert">
              <Icon name="alert" size={14} /> {dialogError}
            </div>
          )}
          <Field label="Provider type">
            <Select
              value={form.kind}
              options={KIND_OPTIONS}
              onSelect={(v) => setForm({ ...form, kind: v as NonNullable<Kind> })}
            />
          </Field>
          {!editing && (
            <Field label="ID" hint="Short, lowercase; part of the redirect URI.">
              <TextInput
                aria-label="ID"
                value={form.id}
                placeholder="entra"
                onChange={(e) => setForm({ ...form, id: e.target.value.trim().toLowerCase() })}
              />
            </Field>
          )}
          <Field label="Display name" hint="Shown on the sign-in button.">
            <TextInput
              aria-label="Display name"
              value={form.display_name}
              placeholder="Microsoft Entra ID"
              onChange={(e) => setForm({ ...form, display_name: e.target.value })}
            />
          </Field>
          <Field label="Issuer" hint={ISSUER_HINT[form.kind]}>
            <TextInput
              aria-label="Issuer"
              value={form.issuer}
              onChange={(e) => setForm({ ...form, issuer: e.target.value })}
            />
          </Field>
          <Field label="Client ID">
            <TextInput
              aria-label="Client ID"
              value={form.client_id}
              onChange={(e) => setForm({ ...form, client_id: e.target.value })}
            />
          </Field>
          <Field
            label="Client secret"
            hint={
              editing?.has_client_secret
                ? 'A secret is stored. Leave blank to keep it.'
                : 'Stored encrypted on the server and never shown again.'
            }
          >
            <PasswordInput
              aria-label="Client secret"
              value={form.client_secret}
              autoComplete="new-password"
              onChange={(e) => setForm({ ...form, client_secret: e.target.value })}
            />
          </Field>
          <Field label="Scopes" hint="Space-separated; must include openid.">
            <TextInput
              aria-label="Scopes"
              value={form.scopes}
              onChange={(e) => setForm({ ...form, scopes: e.target.value })}
            />
          </Field>
          <ToggleRow
            label="Enabled"
            checked={form.enabled}
            onChange={(v) => setForm({ ...form, enabled: v })}
          />
          <ToggleRow
            label="Create accounts on first sign-in"
            hint="Off: only identities already linked to an account can sign in."
            checked={form.jit_provisioning}
            onChange={(v) => setForm({ ...form, jit_provisioning: v })}
          />
          <ToggleRow
            label="Link to an existing account by verified email"
            hint="Only when the provider marks the email as verified."
            checked={form.link_by_verified_email}
            onChange={(v) => setForm({ ...form, link_by_verified_email: v })}
          />
          <Field label="Default role" hint="When no mapping below matches.">
            <Select
              value={form.default_role_id}
              options={roleOptions(false)}
              onSelect={(v) => setForm({ ...form, default_role_id: v })}
            />
          </Field>
          <div>
            <div className="field-label" style={{ marginBottom: 6 }}>
              Role mappings <span className="text-xs text-tx-3">(first match wins; claim: {GROUP_CLAIM_HINT[form.kind]})</span>
            </div>
            <div className="flex flex-col gap-2">
              {form.role_mappings.map((m, i) => (
                <div key={i} className="flex items-center gap-2">
                  <TextInput
                    aria-label={`Mapping ${i + 1} claim`}
                    value={m.claim}
                    style={{ width: 110 }}
                    onChange={(e) => setMapping(i, { claim: e.target.value })}
                  />
                  <TextInput
                    aria-label={`Mapping ${i + 1} value`}
                    value={m.value}
                    placeholder="group name or ID"
                    onChange={(e) => setMapping(i, { value: e.target.value })}
                  />
                  <div style={{ minWidth: 150 }}>
                    <Select
                      value={m.role_id}
                      options={roleOptions(form.allow_admin_mapping)}
                      onSelect={(v) => setMapping(i, { role_id: v })}
                    />
                  </div>
                  <button
                    className="btn ghost icon"
                    title="Remove mapping"
                    onClick={() =>
                      setForm({ ...form, role_mappings: form.role_mappings.filter((_, j) => j !== i) })
                    }
                  >
                    <Icon name="trash" size={15} />
                  </button>
                </div>
              ))}
              <button
                className="btn ghost"
                style={{ alignSelf: 'flex-start' }}
                onClick={() =>
                  setForm({
                    ...form,
                    role_mappings: [...form.role_mappings, { claim: 'groups', value: '', role_id: 'role-analyst' }],
                  })
                }
              >
                <Icon name="plus" /> Add mapping
              </button>
            </div>
          </div>
          <ToggleRow
            label="Allow mapping to Admin"
            hint="Off by default. Even when on, only an explicit mapping grants Admin."
            checked={form.allow_admin_mapping}
            onChange={(v) =>
              setForm({
                ...form,
                allow_admin_mapping: v,
                role_mappings: v
                  ? form.role_mappings
                  : form.role_mappings.map((m) =>
                      m.role_id === 'role-admin' ? { ...m, role_id: 'role-viewer' } : m,
                    ),
              })
            }
          />
          <Field label="Redirect URI override" hint="Leave blank to use the address shown in the provider list.">
            <TextInput
              aria-label="Redirect URI override"
              value={form.redirect_uri}
              onChange={(e) => setForm({ ...form, redirect_uri: e.target.value })}
            />
          </Field>
          <div className="flex justify-end gap-2.5 mt-1">
            <button className="btn ghost" onClick={() => setDialogOpen(false)} disabled={saving}>
              Cancel
            </button>
            <button className="btn primary" onClick={handleSave} disabled={saving}>
              {saving ? 'Saving…' : 'Save provider'}
            </button>
          </div>
        </div>
      </Popup>

      <ConfirmDialog
        open={!!confirmDelete}
        title="Remove provider?"
        body={`People who sign in with ${confirmDelete?.display_name ?? 'this provider'} will no longer be able to. Their accounts stay.`}
        confirmLabel="Remove"
        onConfirm={handleDelete}
        onClose={() => setConfirmDelete(null)}
      />
    </>
  )
}
