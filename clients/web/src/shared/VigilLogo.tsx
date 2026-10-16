/* Inline SVG so it recolors with the theme via `fill: currentColor`. The
   component names are internal identifiers, kept so no caller changes. */
import type { CSSProperties } from 'react'

/** Neutral placeholder mark: a hexagon outline (outer minus inner, even-odd),
   the same shape as the desktop app's placeholder icons. AutoSecOps has no
   approved logo yet (K6-04): the upstream Vigil circuit-shield is gone, and a
   designer's mark replaces this path when it exists (W0.38). The bounding box
   keeps the old mark's, so the wordmark layout below is unchanged. */
const MARK =
  'M1097.7 1374.3L763.8 1181.5L763.8 795.9L1097.7 603.1L1431.7 795.9L1431.7 1181.5Z' +
  'M1097.7 1308.7L820.5 1148.7L820.5 828.6L1097.7 668.6L1374.9 828.6L1374.9 1148.7Z'

/** the "AutoSecOps" wordmark, to the right of the mark. Set as text in the UI
   font at weight 600; baseline, cap height (WORD_SIZE × 0.745) and left edge
   match the glyph wordmark it replaced. WORD_LENGTH is the run's shaped width
   in Plus Jakarta Sans 600 (6.242 em); textLength pins it there so a fallback
   font is fitted to the viewBox instead of clipped by it. */
const WORD = 'AutoSecOps'
const WORD_X = 1640
const WORD_BASELINE = 1240
const WORD_SIZE = 640
const WORD_LENGTH = 3995

interface LogoProps {
  className?: string
  style?: CSSProperties
}

export function VigilMark({ className, style }: LogoProps) {
  return (
    <svg
      className={className}
      style={style}
      viewBox="712 603 771.426 771.341"
      fill="currentColor"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <path d={MARK} fillRule="evenodd" />
    </svg>
  )
}

export function VigilLogo({ className, style }: LogoProps) {
  return (
    <svg
      className={className}
      style={style}
      viewBox={`712 603 ${WORD_X + WORD_LENGTH - 712} 778.91`}
      fill="currentColor"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label="AutoSecOps"
    >
      <path d={MARK} fillRule="evenodd" />
      <text
        x={WORD_X}
        y={WORD_BASELINE}
        fill="currentColor"
        fontFamily="'Plus Jakarta Sans', system-ui, sans-serif"
        fontSize={WORD_SIZE}
        fontWeight={600}
        textLength={WORD_LENGTH}
        lengthAdjust="spacingAndGlyphs"
      >
        {WORD}
      </text>
    </svg>
  )
}
