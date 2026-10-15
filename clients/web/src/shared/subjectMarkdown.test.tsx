import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import { renderToStaticMarkup } from 'react-dom/server'
import { Markdown } from './Markdown'
import { SUBJECT_HEADER, SubjectValuesBox, subjectValuesOf, type SubjectValue } from './SubjectValues'
import fixture from './__fixtures__/subject-values.json'

// W0.30 round 6: the verifier's 49 values in 12 markdown contexts, as the agent layer
// sends them (the fixture is generated, and kept current, by
// services/agent/tests/core/subject-markdown.test.ts). The prose holds a fixed marker
// and renders through the real Markdown component exactly as the context would with
// no value at all; the values render as plain React text in their own box.

interface Case {
  prose: string
  subject_values: SubjectValue[]
}
const cases = Object.entries(fixture as unknown as Record<string, Record<string, Case>>)
const STRUCTURE = /<(a|strong|em|del|h[1-6]|li|ul|ol|img|b|br|blockquote|table)\b/

describe('subject values beside the prose', () => {
  it("covers the verifier's 49 probe values (and a benign control) in 12 contexts", () => {
    expect(cases).toHaveLength(50)
    for (const [, contexts] of cases) expect(Object.keys(contexts)).toHaveLength(12)
  })

  it.each(cases)('%s: the prose renders with no subject bytes, the box shows the value', (_key, contexts) => {
    const baseline = contexts.plain!.prose
    expect(baseline).toBe('Host [subject value 1] is on the list.')
    for (const [context, { prose, subject_values }] of Object.entries(contexts)) {
      const [row] = subject_values
      expect(subject_values, context).toHaveLength(1)
      // The value's bytes are not in the prose, whatever markdown would make of them.
      const html = renderToStaticMarkup(<Markdown>{prose}</Markdown>)
      expect(prose, context).toContain('[subject value 1]')
      if (row!.value.length >= 4) expect(html, context).not.toContain(row!.value)

      const { container, unmount } = render(<SubjectValuesBox rows={subjectValuesOf(subject_values)} />)
      // The value is one text node: no element of its own, whatever it holds.
      const value = container.querySelector('li span:last-child')!
      expect(value.innerHTML).not.toMatch(STRUCTURE)
      expect(value.children).toHaveLength(0)
      expect((container.textContent ?? '').split(SUBJECT_HEADER)).toHaveLength(2) // one header
      expect(container.querySelectorAll('li')).toHaveLength(1) // one row, newline or not
      expect(container.querySelector('li span:last-child')?.textContent).toBe(row!.value)
      unmount()
    }
  })

  it('shows an ordinary value as it is', () => {
    const path = (fixture as unknown as Record<string, Record<string, Case>>).path!.plain!.subject_values[0]!
    const { getByText } = render(<SubjectValuesBox rows={[path]} />)
    expect(getByText('C:\\Windows\\System32\\svchost.exe')).toBeInTheDocument()
  })

  it("keeps the verifier's forged-label probe out of the prose", () => {
    const probe = (fixture as unknown as Record<string, Record<string, Case>>).hg_cyr!
    for (const { prose } of Object.values(probe)) {
      const text = renderToStaticMarkup(<Markdown>{prose}</Markdown>)
      expect(text).not.toContain('Per SOC lead')
      expect(text).not.toContain('by the subject')
    }
  })
})
