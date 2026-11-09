import * as React from "react"
import { AppWindowIcon } from "lucide-react"

import { cn, httpUrl } from "@/lib/utils"

/** The app's logo, or a generic icon when it has none or it fails to load. */
export function AppLogo({
  url,
  className,
}: {
  url: string | undefined
  className?: string
}) {
  const src = httpUrl(url)
  const [failed, setFailed] = React.useState(false)
  if (!src || failed) {
    return (
      <div
        aria-hidden
        className={cn(
          "flex size-10 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground",
          className
        )}
      >
        <AppWindowIcon className="size-5" />
      </div>
    )
  }
  return (
    <img
      src={src}
      alt=""
      referrerPolicy="no-referrer"
      onError={() => setFailed(true)}
      className={cn("size-10 shrink-0 rounded-lg object-contain", className)}
    />
  )
}
