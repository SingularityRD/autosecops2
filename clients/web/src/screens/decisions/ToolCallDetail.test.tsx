/* An approval shows the whole call it binds (W0.14): padding in one argument
   used to push the target host out of a 600-character summary. */
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ToolCallDetail, questionOf, toolCallOf } from './ToolCallDetail'

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
})
