/* Inlined from the vector source so it recolors with the theme via
   `fill: currentColor` — the old black PNGs were CSS-inverted to white, which
   broke under light mode. */
import type { CSSProperties } from 'react'

/** the circuit-shield mark; bounding box matches the source clip rect */
const MARK =
  'M1201.14 1149.76C1239.24 1106.61 1260.15 1051.68 1266.45 1002.2H1326.76C1333.18 1039.34 1365.55 1067.6 1404.53 1067.6C1448.13 1067.6 1483.45 1032.25 1483.45 988.67C1483.45 945.093 1448.1 909.743 1404.53 909.743C1366 909.743 1333.94 937.348 1327.02 973.833H1268.49C1268.49 972.783 1268.55 971.705 1268.55 970.655V843.923L1201.17 810.162V696.141H1326.91C1333.6 732.966 1365.8 760.883 1404.56 760.883C1448.16 760.883 1483.48 725.533 1483.48 681.955C1483.48 638.378 1448.08 603 1404.5 603C1365.74 603 1333.54 630.917 1326.85 667.742H1198.27C1184.2 667.742 1172.74 679.204 1172.74 693.275V795.92L1097.05 757.989L1021.01 796.062V693.275C1021.01 679.204 1009.55 667.742 995.479 667.742H868.521C861.882 630.917 829.681 603 790.927 603C747.35 603 712 638.35 712 681.927C712 725.504 747.35 760.854 790.927 760.854C829.681 760.854 861.882 732.938 868.578 696.112H992.699V810.304L925.631 843.895V970.627C925.631 1026.86 946.483 1096.82 992.699 1149.36V1281.2H868.578C861.882 1244.38 829.681 1216.46 790.927 1216.46C747.321 1216.46 712 1251.81 712 1295.39C712 1338.96 747.35 1374.31 790.927 1374.31C829.681 1374.31 861.882 1346.4 868.578 1309.57H995.536C1009.61 1309.57 1021.07 1298.11 1021.07 1284.04V1176.63C1042.46 1193.9 1067.71 1207.78 1097.1 1216.43C1126.32 1207.81 1151.46 1194.02 1172.8 1176.88V1284.01C1172.8 1298.08 1184.26 1309.54 1198.33 1309.54H1326.91C1333.6 1346.37 1365.8 1374.28 1404.56 1374.28C1448.16 1374.28 1483.48 1338.93 1483.48 1295.36C1483.48 1251.78 1448.13 1216.43 1404.56 1216.43C1365.8 1216.43 1333.6 1244.35 1326.91 1281.17H1201.17V1149.7L1201.14 1149.76ZM1404.5 938.114C1432.39 938.114 1455.06 960.782 1455.06 988.67C1455.06 1016.56 1432.39 1039.23 1404.5 1039.23C1376.61 1039.23 1353.94 1016.56 1353.94 988.67C1353.94 960.782 1376.61 938.114 1404.5 938.114ZM1404.5 631.371C1432.39 631.371 1455.06 654.039 1455.06 681.927C1455.06 709.815 1432.39 732.484 1404.5 732.484C1376.61 732.484 1353.94 709.815 1353.94 681.927C1353.94 654.039 1376.61 631.371 1404.5 631.371ZM1404.5 1244.86C1432.39 1244.86 1455.06 1267.53 1455.06 1295.41C1455.06 1323.3 1432.39 1345.97 1404.5 1345.97C1376.61 1345.97 1353.94 1323.3 1353.94 1295.41C1353.94 1267.53 1376.61 1244.86 1404.5 1244.86Z'

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
      <path d={MARK} />
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
      <path d={MARK} />
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
