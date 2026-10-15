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
