import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { QueryClientProvider } from "@tanstack/react-query"
import { RouterProvider } from "react-router"

import "./index.css"
import { ThemeProvider } from "@/components/theme-provider"
import { AppToaster } from "@/components/layout/app-toaster"
import { TooltipProvider } from "@/components/ui/tooltip"
import { I18nProvider } from "@/i18n"
import { queryClient } from "@/lib/queries"
import { router } from "@/router"

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <I18nProvider>
        <QueryClientProvider client={queryClient}>
          <TooltipProvider delayDuration={300}>
            <RouterProvider router={router} />
            <AppToaster />
          </TooltipProvider>
        </QueryClientProvider>
      </I18nProvider>
    </ThemeProvider>
  </StrictMode>
)
