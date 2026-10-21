import { lazy } from "react"
import { createBrowserRouter } from "react-router"

import { SessionGate, SetupGate } from "@/components/layout/gates"
import { RouteError } from "@/components/layout/route-error"

const SetupPage = lazy(() => import("@/pages/setup"))
const SignInPage = lazy(() => import("@/pages/sign-in"))
const EmailLoginPage = lazy(() => import("@/pages/email-login"))
const HomePage = lazy(() => import("@/pages/home"))
const AppsListPage = lazy(() => import("@/pages/admin/apps-list"))
const AppsNewPage = lazy(() => import("@/pages/admin/apps-new"))
const AppDetailPage = lazy(() => import("@/pages/admin/apps-detail"))
const GroupsPage = lazy(() => import("@/pages/admin/groups"))
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
        // Admin pages check permissions themselves and redirect home when
        // the person may not be there.
        children: [
          { index: true, element: <HomePage /> },
          { path: "apps", element: <AppsListPage /> },
          { path: "apps/new", element: <AppsNewPage /> },
          { path: "apps/:slug", element: <AppDetailPage /> },
          { path: "groups", element: <GroupsPage /> },
        ],
      },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
])
