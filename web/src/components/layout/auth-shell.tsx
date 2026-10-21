import { Brand } from "@/components/layout/brand"
import { Preferences } from "@/components/layout/preferences"

/** Centered frame for the sign-in, setup and email-link screens. */
export function AuthShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="relative flex min-h-svh flex-col items-center justify-center gap-6 bg-muted/40 p-4">
      <div className="absolute top-3 right-3">
        <Preferences />
      </div>
      <Brand />
      <div className="w-full max-w-sm">{children}</div>
    </div>
  )
}
