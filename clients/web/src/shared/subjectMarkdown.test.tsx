import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { Markdown } from './Markdown'
import fixture from './__fixtures__/subject-values.json'

// W0.30 round 5: subject-written values, as the agent layer substitutes them into
// markdown (services/agent/core/guards.ts subjectValue; the fixture is generated and
// kept current by services/agent/tests/core/subject-markdown.test.ts), rendered
// through the console's real Markdown component. Nothing the subject wrote may become
// a link, emphasis, a heading, a list or HTML -- inside a code span, a fence, or
// outside any -- and the label is printed once.

const STRUCTURE = /<(a|strong|em|del|h[1-6]|li|ul|ol|img|b|br|blockquote|table)\b/
const cases = Object.entries(fixture as Record<string, Record<string, string>>)

describe('a subject value in markdown', () => {
  it.each(cases)('%s renders inert in every context', (_key, contexts) => {
    for (const [context, text] of Object.entries(contexts)) {
      const html = renderToStaticMarkup(<Markdown>{text}</Markdown>)
      expect(html, `${context}: ${html}`).not.toMatch(STRUCTURE)
      const outside = html.replace(/<pre>[\s\S]*?<\/pre>/g, '').replace(/<code>[\s\S]*?<\/code>/g, '')
      const labels = (html.match(/\(written by the subject\)/g) ?? []).length
      expect(labels, `${context}: ${html}`).toBe(1)
      if (context === 'plain') {
        expect((outside.match(/\(written by the subject\)/g) ?? []).length, html).toBe(1)
      } else {
        // Inside the lead's own span or fence: all of it, label included, is literal.
        expect(outside, html).not.toMatch(/INJECT|written by the subject/)
      }
    }
  })

  it('covers the verifier variants and the link, autolink, email and emphasis cases', () => {
    expect(cases.map(([key]) => key)).toEqual(
      expect.arrayContaining(['r3', 'bt1', 'bt2', 'bt3', 'bt4', 'bsbt', 'ent', 'fw', 'modl', 'lkp', 'nl', 'ls', 'link', 'head', 'bold', 'html', 'auto', 'q', 'email', 'mailto']),
    )
  })
})
