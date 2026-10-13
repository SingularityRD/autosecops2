/* Lessons tab: list, replay-gated promote and one-click rollback (W3.11). */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import LessonsTab from './LessonsTab'
import { ToastProvider } from '../../shell/toast'
import { lessonsApi } from '../../services/lessonsApi'

const state = vi.hoisted(() => ({
  perms: new Set<string>(['ai_decisions.approve', 'findings.write']),
  lessons: [] as Array<Record<string, unknown>>,
}))

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({ user: { username: 'ana' }, hasPermission: (p: string) => state.perms.has(p) }),
}))

vi.mock('../../services/lessonsApi', () => ({
  lessonsApi: {
    list: vi.fn(() => Promise.resolve({ data: { lessons: state.lessons } })),
    replay: vi.fn(),
    promote: vi.fn(() => Promise.resolve({ data: {} })),
    rollback: vi.fn(() => Promise.resolve({ data: {} })),
  },
}))

const lesson = (id: string, over: Record<string, unknown> = {}) => ({
  id,
  lesson: `Lesson ${id}`,
  effect: 'benign_hint',
  applies_to: { data_source: 'entra', src_ips: ['198.51.100.157'], max_severity: 'high' },
  category: null,
  status: 'proposed',
  provenance: 'analyst',
  provenance_detail: {},
  source_kind: 'manual',
  created_by: 'ayse',
  created_at: '2026-10-13T09:00:00+00:00',
  expires_at: '2026-11-12T09:00:00+00:00',
  expired: false,
  replay: null,
  replay_passed: false,
  ...over,
})

function renderTab() {
  return render(
    <ToastProvider>
      <LessonsTab />
    </ToastProvider>,
  )
}

const row = async (id: string) => {
  await screen.findByText(`Lesson ${id}`)
  return document.querySelector(`[data-lesson="${id}"]`) as HTMLElement
}

beforeEach(() => {
  vi.clearAllMocks()
  state.perms = new Set(['ai_decisions.approve', 'findings.write'])
  state.lessons = [
    lesson('a'),
    lesson('b', {
      status: 'active',
      approved_by: 'mehmet',
      replay_passed: true,
      replay: { passed: true, regressions: 0, baseline: { fp: 53, tp: 687 }, with_lesson: { fp: 52, tp: 687 } },
    }),
    lesson('c', { provenance: 'adversary_text' }),
    lesson('d', { status: 'retired', retired_by: 'ayse', retire_reason: 'moved' }),
  ]
})

describe('LessonsTab', () => {
  it('lists lessons with scope, status, provenance and replay result', async () => {
    renderTab()
    const b = await row('b')
    expect(within(b).getByText(/FP 53 → 52/)).toBeTruthy()
    expect(within(b).getByText(/0 regressions/)).toBeTruthy()
    expect(within(await row('a')).getByText(/src_ips=198.51.100.157/)).toBeTruthy()
    expect(within(await row('c')).getByText('Alert text — blocked')).toBeTruthy()
  })

  it('offers promote only on proposed, trusted lessons and calls the endpoint', async () => {
    renderTab()
    expect(within(await row('b')).queryByRole('button', { name: /Promote/ })).toBeNull()
    expect(within(await row('c')).queryByRole('button', { name: /Promote/ })).toBeNull()
    expect(within(await row('d')).queryByRole('button', { name: /Roll back/ })).toBeNull()
    fireEvent.click(within(await row('a')).getByRole('button', { name: /Promote/ }))
    await waitFor(() => expect(lessonsApi.promote).toHaveBeenCalledWith('a'))
    await waitFor(() => expect(lessonsApi.list).toHaveBeenCalledTimes(2))
  })

  it('shows the refusal when replay fails', async () => {
    vi.mocked(lessonsApi.promote).mockRejectedValueOnce({
      response: { status: 409, data: { detail: '3 historical alert(s) got a worse verdict' } },
    })
    renderTab()
    fireEvent.click(within(await row('a')).getByRole('button', { name: /Promote/ }))
    expect(await screen.findByText(/worse verdict/)).toBeTruthy()
  })

  it('rolls back with a reason in one step', async () => {
    renderTab()
    fireEvent.click(within(await row('b')).getByRole('button', { name: /Roll back/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByRole('textbox'), { target: { value: 'scanner moved' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Roll back' }))
    await waitFor(() => expect(lessonsApi.rollback).toHaveBeenCalledWith('b', 'scanner moved'))
  })

  it('hides promote without approval rights and every action for a viewer', async () => {
    state.perms = new Set(['findings.write'])
    const { unmount } = renderTab()
    expect(within(await row('a')).queryByRole('button', { name: /Promote/ })).toBeNull()
    expect(within(await row('a')).getByRole('button', { name: /Roll back/ })).toBeTruthy()
    unmount()
    state.perms = new Set()
    renderTab()
    expect(within(await row('b')).queryAllByRole('button')).toHaveLength(0)
  })
})
