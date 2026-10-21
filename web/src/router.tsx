import { lazy } from "react"
import { createBrowserRouter } from "react-router"

import { SessionGate, SetupGate } from "@/components/layout/gates"
import { RouteError } from "@/components/layout/route-error"

const SetupPage = lazy(() => import("@/pages/setup"))
const SignInPage = lazy(() => import("@/pages/sign-in"))
const EmailLoginPage = lazy(() => import("@/pages/email-login"))
const HomePage = lazy(() => import("@/pages/home"))
const NotFoundPage = lazy(() => import("@/pages/not-found"))

export const router = createBrowserRouter([
  {
    element: <SetupGate />,
    errorElement: <RouteError />,
    children: [
      { path: "setup", element: <SetupPage /> },
      { path: "sign-in", element: <SignInPage /> },
      { path: "email-login", element: <EmailLoginPage /> },
      {
        element: <SessionGate />,
        children: [{ index: true, element: <HomePage /> }],
      },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
])
