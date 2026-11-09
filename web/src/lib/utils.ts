import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * The URL when it is an absolute http(s) address, otherwise undefined. App
 * homepages and logos are typed in by app managers, so a link or image never
 * uses another scheme (javascript:, data:).
 */
export function httpUrl(raw: string | undefined) {
  if (!raw) return undefined
  try {
    const url = new URL(raw)
    return url.protocol === "https:" || url.protocol === "http:"
      ? url.href
      : undefined
  } catch {
    return undefined
  }
}
