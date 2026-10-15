/* W0.30: values a monitored party could have written, kept out of the agent's prose.
   The prose names each as "[subject value N]"; the values arrive beside it as
   {ref, field, value} rows and are shown here as plain React text -- never through
   Markdown -- under one fixed header. The agent layer already neutralised controls,
   bidi characters and newlines in each value, and rows are built from the array, so
   a value cannot add a row or a header of its own. */

export interface SubjectValue {
  ref: number
  field: string
  value: string
}

export const SUBJECT_HEADER = 'Written by the subject — untrusted'
// The plain-text block the backend appends after a description (core/workflows/subject_values.py).
const PLAIN_BLOCK = '\n\nWritten by the subject (untrusted):'

/** The well-formed rows of an unknown value; anything else is dropped. */
export function subjectValuesOf(raw: unknown): SubjectValue[] {
  if (!Array.isArray(raw)) return []
  return raw.flatMap((one) => {
    const row = one as Record<string, unknown>
    if (typeof row?.ref !== 'number' || typeof row.value !== 'string') return []
    return [{ ref: row.ref, field: typeof row.field === 'string' ? row.field : 'value', value: row.value }]
  })
}

/** Only the rows a text refers to, by marker, in ref order and each once. */
export function referencedIn(texts: readonly (string | null | undefined)[], rows: readonly SubjectValue[]): SubjectValue[] {
  const joined = texts.filter(Boolean).join('\n')
  const seen = new Set<number>()
  return rows
    .filter((row) => joined.includes(`[subject value ${row.ref}]`) && !seen.has(row.ref) && seen.add(row.ref))
    .sort((a, b) => a.ref - b.ref)
}

/** A description without the backend's plain-text block, when the box shows it instead. */
export function withoutSubjectBlock(text: string): string {
  const at = text.indexOf(PLAIN_BLOCK)
  return at >= 0 ? text.slice(0, at) : text
}

export function SubjectValuesBox({ rows }: { rows: readonly SubjectValue[] }) {
  if (rows.length === 0) return null
  return (
    <div
      role="group"
      aria-label={SUBJECT_HEADER}
      data-testid="subject-values"
      className="rounded-[10px] border p-2.5 text-[12px]"
      style={{ borderColor: 'var(--poor-ln)', background: 'var(--bg-2, transparent)' }}
    >
      <div className="font-semibold text-[11.5px]" style={{ color: 'var(--poor)' }}>{SUBJECT_HEADER}</div>
      <ul className="mt-1 flex flex-col gap-0.5" style={{ listStyle: 'none', padding: 0, margin: 0 }}>
        {rows.map((row) => (
          <li key={row.ref} className="mono" style={{ overflowWrap: 'anywhere' }}>
            <span className="muted">[{row.ref}] {row.field} = </span>
            <span>{row.value}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
