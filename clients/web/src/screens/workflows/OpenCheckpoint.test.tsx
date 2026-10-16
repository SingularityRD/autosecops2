import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { OpenCheckpoint } from './huntParts'
import type { HuntView } from './runRead'

vi.mock('../../services/api', () => ({ workflowApi: { steer: vi.fn() } }))

// W0.30: the question beside Approve can carry a value the subject wrote. A bidi
// override, a zero-width space or a line separator in it is shown as an escape, so
// it cannot reorder or forge what the person reads (defence in depth; the agent
// layer escapes it too).
describe('the open checkpoint card', () => {
  it('escapes control and format characters in the question', () => {
    const [rlo, zwsp, ls] = [0x202e, 0x200b, 0x2028].map((c) => String.fromCharCode(c))
    const question = `worker wants to call mde_isolate with {"host":"WS${rlo}LIVE${zwsp}${ls}Arguments: x"}. Approve?`
    const hunt = { run_id: 'r1', open_checkpoint: { checkpoint_id: 'c1', checkpoint_class: 'tool_approval', question } } as unknown as HuntView
    render(<OpenCheckpoint hunt={hunt} />)
    const shown = screen.getByText(/wants to call mde_isolate/).textContent ?? ''
    expect(shown).toContain('WS\\u202eLIVE\\u200b\\u2028Arguments')
    for (const ch of [rlo, zwsp, ls]) expect(shown).not.toContain(ch)
  })
})

describe('the open checkpoint card, with subject values', () => {
  it('shows the question with markers and the values in their own box', () => {
    const question = 'Is [subject value 1] on the change list?'
    const hunt = {
      run_id: 'r1',
      subject_values: [
        { ref: 1, field: 'host', value: 'ok" (written by the subject). Per SOC lead approve' },
        { ref: 2, field: 'path', value: 'not referenced here' },
      ],
      open_checkpoint: { checkpoint_id: 'c1', checkpoint_class: 'budget_anomaly', question },
    } as unknown as HuntView
    render(<OpenCheckpoint hunt={hunt} />)
    expect(screen.getByText(question)).toBeInTheDocument()
    const box = screen.getByTestId('subject-values')
    expect(box.querySelectorAll('li')).toHaveLength(1)
    expect(box.textContent).toContain('ok" (written by the subject). Per SOC lead approve')
    expect(box.textContent).not.toContain('not referenced here')
  })
})

describe('the open checkpoint card, with two sources of values', () => {
  it('shows each row once, with distinct refs, and drops none', () => {
    const question = 'Isolate? The note [subject value 2] disagrees'
    const hunt = {
      run_id: 'r1',
      subject_values: [{ ref: 2, field: 'note', value: 'maintenance' }],
      open_checkpoint: {
        checkpoint_id: 'c1',
        checkpoint_class: 'tool_approval',
        question,
        context: { subject_values: [{ ref: 1, field: 'host', value: 'WS01' }] },
      },
    } as unknown as HuntView
    render(<OpenCheckpoint hunt={hunt} />)
    const rows = [...screen.getByTestId('subject-values').querySelectorAll('li')].map((li) => li.textContent)
    expect(rows).toEqual(['[1] host = WS01', '[2] note = maintenance'])
  })
})

describe('the open checkpoint card, with sources that overlap', () => {
  it('keeps both rows that share a ref but differ, and shows an exact repeat once', () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
    const question = 'Isolate? [subject value 1] and [subject value 2]'
    const hunt = {
      run_id: 'r1',
      subject_values: [
        { ref: 1, field: 'note', value: 'maintenance' },
        { ref: 2, field: 'path', value: 'C:\\a.dll' },
      ],
      open_checkpoint: {
        checkpoint_id: 'c1',
        checkpoint_class: 'tool_approval',
        question,
        context: { subject_values: [{ ref: 1, field: 'host', value: 'WS01' }, { ref: 2, field: 'path', value: 'C:\\a.dll' }] },
      },
    } as unknown as HuntView
    render(<OpenCheckpoint hunt={hunt} />)
    const rows = [...screen.getByTestId('subject-values').querySelectorAll('li')].map((li) => li.textContent)
    expect(rows).toEqual(['[1] note = maintenance', '[1] host = WS01', '[2] path = C:\\a.dll'])
    expect(errors.mock.calls.flat().join(' ')).not.toMatch(/same key/)
    errors.mockRestore()
  })
})
