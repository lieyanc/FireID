import type { User } from "@/lib/types"

/** The name to show for a person: their display name, else the username. */
export function displayName(user: User) {
  return user.displayName || user.username
}

/** One or two letters for an avatar. */
export function initials(user: User) {
  const name = displayName(user).trim()
  const parts = name.split(/\s+/)
  const letters =
    parts.length > 1
      ? parts[0][0] + parts[parts.length - 1][0]
      : Array.from(name).slice(0, 2).join("")
  return letters.toUpperCase()
}
