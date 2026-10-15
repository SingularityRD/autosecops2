#!/usr/bin/env python3
"""Draw the neutral placeholder icon set in clients/desktop/build/icons.

AutoSecOps has no approved logo yet (gap K6-04, plan decision #1), and the
desktop app must not ship the upstream Vigil mark. Until a designer delivers
the AutoSecOps mark, the app uses this deliberately plain placeholder: a dark
rounded square with a light hexagon outline, and the same outline as a
monochrome macOS template image for the tray.

To replace it, drop the designer's files in with the same names and sizes
(256x256.png, 512x512.png, icon.icns, tray.png 44x44, tray@2x.png 88x88) and
delete this script. Needs Pillow; run from anywhere:

    python3 clients/desktop/scripts/placeholder-icons.py
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "build" / "icons"
BG = (12, 15, 20, 255)  # --bg of clients/web/src/styles.css
FG = (201, 206, 214, 255)  # neutral light grey, no brand colour
TRAY = (150, 156, 166, 255)
SS = 4  # supersampling factor for smooth edges


def _hexagon(cx: float, cy: float, r: float) -> list[tuple[float, float]]:
    return [
        (
            cx + r * math.cos(math.radians(90 + 60 * i)),
            cy + r * math.sin(math.radians(90 + 60 * i)),
        )
        for i in range(6)
    ]


def _ring(s: int, radius: float, width: float) -> Image.Image:
    """Mask of a hexagon outline: outer hexagon minus inner hexagon."""
    mask = Image.new("L", (s, s), 0)
    d = ImageDraw.Draw(mask)
    d.polygon(_hexagon(s / 2, s / 2, s * radius), fill=255)
    d.polygon(_hexagon(s / 2, s / 2, s * (radius - width)), fill=0)
    return mask


def app_icon(size: int) -> Image.Image:
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, s - 1, s - 1), radius=int(s * 0.22), fill=BG)
    img.paste(FG, (0, 0), _ring(s, 0.32, 0.055))
    return img.resize((size, size), Image.LANCZOS)


def tray_icon(size: int) -> Image.Image:
    # Mid grey reads on light and dark Linux/Windows panels; on macOS main.ts
    # marks it a template image, so only the alpha channel is used there.
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    img.paste(TRAY, (0, 0), _ring(s, 0.44, 0.10))
    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    app_icon(256).save(OUT / "256x256.png")
    big = app_icon(1024)
    big.resize((512, 512), Image.LANCZOS).save(OUT / "512x512.png")
    big.save(
        OUT / "icon.icns",
        sizes=[
            (16, 16),
            (32, 32),
            (64, 64),
            (128, 128),
            (256, 256),
            (512, 512),
            (1024, 1024),
        ],
    )
    tray_icon(44).save(OUT / "tray.png")
    tray_icon(88).save(OUT / "tray@2x.png")
    print(f"placeholder icons written to {OUT}")


if __name__ == "__main__":
    main()
