/* An approval shows the whole call it binds (W0.14): padding in one argument
   used to push the target host out of a 600-character summary. */
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ToolCallDetail, displaySafe, questionOf, toolCallOf } from './ToolCallDetail'

const padded = JSON.stringify({ comment: 'x'.repeat(5000), machine_id: 'host-b' })

describe('the tool call an approval binds', () => {
  it('reads the full canonical arguments and the target off the row', () => {
    const call = toolCallOf({ tool: 'mde_isolate', args_canonical: padded, args_targets: [['machine_id', 'host-b']] })
    expect(call).not.toBeNull()
    render(<ToolCallDetail call={call!} />)
    expect(screen.getByLabelText('Arguments').textContent).toBe(padded)
    expect(screen.getByText('machine_id=host-b')).toBeInTheDocument()
  })

  it('binds nothing for a row without the canonical arguments', () => {
    expect(toolCallOf({ checkpoint_class: 'verdict_review' })).toBeNull()
    expect(toolCallOf({ tool: 'mde_isolate', args_summary: 'cut' })).toBeNull()
  })

  it('drops the argument block from the question it already shows', () => {
    const call = toolCallOf({ tool: 'mde_isolate', args_canonical: '{}' })
    expect(questionOf('parked on approval for mde_isolate\n\nTool: mde_isolate\nArguments: {}', call)).toBe(
      'parked on approval for mde_isolate',
    )
    expect(questionOf('plain question', null)).toBe('plain question')
  })

  it('shows bidi and control characters as escapes (W0.16)', () => {
    const args = JSON.stringify({ machine_id: 'evil\u202emoc.knab\u2066' })
    const call = toolCallOf({ tool: 'mde\u200fisolate', args_canonical: args, args_targets: [['machine_id', 'evil\u202emoc.knab']] })
    render(<ToolCallDetail call={call!} />)
    const text = screen.getByTestId('tool-call').textContent || ''
    for (const ch of ['\u202e', '\u2066', '\u200f']) expect(text).not.toContain(ch)
    expect(screen.getByLabelText('Arguments').textContent).toBe('{"machine_id":"evil\\u202emoc.knab\\u2066"}')
    expect(screen.getByText('machine_id=evil\\u202emoc.knab')).toBeInTheDocument()
    expect(displaySafe('a\nb\u0000c')).toBe('a\\u000ab\\u0000c')
    expect(displaySafe('plain host-a')).toBe('plain host-a')
  })
})
