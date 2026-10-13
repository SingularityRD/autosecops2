/* Number and word formatting for the Scorecard. */

export const titleCase = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

/** An upper bound, rounded up so it never reads better than it is: 0.997%, 1.001%, 25.9%. */
export function fmtBound(p: number): string {
  const pct = p * 100
  return pct < 10 ? `${(Math.ceil(pct * 1000) / 1000).toFixed(3)}%` : `${(Math.ceil(pct * 10) / 10).toFixed(1)}%`
}

export const fmtTarget = (t: number) => `${+(t * 100).toFixed(2)}%`

export const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`
