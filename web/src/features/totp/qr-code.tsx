import * as React from "react"
// uqr: zero-dependency QR encoder from the unjs project (MIT, ~10 kB). We only
// take the module matrix and draw it ourselves, so the secret never leaves the
// page and the CSP needs no external image source.
import { encode } from "uqr"

import { cn } from "@/lib/utils"

/** Path of the dark modules, one horizontal run per segment. */
function modulesPath(data: boolean[][]) {
  let d = ""
  data.forEach((row, y) => {
    let x = 0
    while (x < row.length) {
      if (!row[x]) {
        x++
        continue
      }
      const start = x
      while (x < row.length && row[x]) x++
      d += `M${start} ${y}h${x - start}v1h${start - x}z`
    }
  })
  return d
}

/**
 * A QR code as inline SVG. Always dark on white, whatever the theme: phone
 * cameras read inverted codes poorly.
 */
export function QrCode({
  value,
  label,
  className,
}: {
  value: string
  label: string
  className?: string
}) {
  const qr = React.useMemo(
    () => encode(value, { ecc: "M", border: 2 }),
    [value]
  )
  return (
    <svg
      role="img"
      aria-label={label}
      viewBox={`0 0 ${qr.size} ${qr.size}`}
      shapeRendering="crispEdges"
      className={cn("rounded-md bg-white", className)}
    >
      <rect width={qr.size} height={qr.size} fill="#fff" />
      <path d={modulesPath(qr.data)} fill="#000" />
    </svg>
  )
}
