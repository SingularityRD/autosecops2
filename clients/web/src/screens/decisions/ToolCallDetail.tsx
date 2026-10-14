/* The one gated tool call an approval binds (W1.7b), shown whole (W0.14).
   The row's parameters carry the canonical arguments the digest covers; a cut
   of them once let padding push the target host out of what the approver read. */

export interface ToolCall {
  tool: string
  args: string
  targets: [string, string][]
}

// Control, line/paragraph-separator and format characters (bidi embeddings,
// overrides and isolates, LRM/RLM, ALM, zero-width, BOM ...). Shown as escapes
// so a value cannot reorder what is around it (W0.16); the server escapes the
// targets already, this also covers the canonical arguments and older rows.
// eslint-disable-next-line no-control-regex
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u206f\ufeff\ufff9-\ufffb]/g

/** `text` with every unsafe character written as `\uXXXX`. Display only. */
export function displaySafe(text: string): string {
  return text.replace(UNSAFE, (ch) => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0'))
}

/** The bound call on an approval row, or null when it binds none. */
export function toolCallOf(parameters: Record<string, unknown> | undefined | null): ToolCall | null {
  const p = parameters || {}
  if (typeof p.tool !== 'string' || typeof p.args_canonical !== 'string') return null
  const targets = Array.isArray(p.args_targets)
    ? (p.args_targets as unknown[]).filter(
        (t): t is [string, string] => Array.isArray(t) && t.length === 2 && typeof t[0] === 'string' && typeof t[1] === 'string',
      )
    : []
  return { tool: p.tool, args: p.args_canonical, targets }
}

/** The question above the bound call: the description without the
 *  "Tool: / Target: / Arguments:" block the row already shows in full. */
export function questionOf(description: string | undefined, call: ToolCall | null): string {
  if (!description) return ''
  if (!call) return description
  const at = description.indexOf('\n\nTool: ')
  return at >= 0 ? description.slice(0, at) : description
}

export function ToolCallDetail({ call }: { call: ToolCall }) {
  return (
    <div className="mt-1" style={{ fontSize: 12 }} data-testid="tool-call">
      <div>
        Tool: <span className="mono">{displaySafe(call.tool)}</span>
      </div>
      {call.targets.length > 0 && (
        <div style={{ fontWeight: 600 }}>
          Target:{' '}
          <span className="mono">{call.targets.map(([k, v]) => `${displaySafe(k)}=${displaySafe(v)}`).join(', ')}</span>
        </div>
      )}
      <pre
        className="mono"
        aria-label="Arguments"
        style={{ margin: '4px 0 0', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 240, overflowY: 'auto', fontSize: 11 }}
      >
        {displaySafe(call.args)}
      </pre>
    </div>
  )
}
