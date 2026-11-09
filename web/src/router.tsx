import { lazy } from "react"
import { createBrowserRouter } from "react-router"

import { SessionGate, SetupGate } from "@/components/layout/gates"
import { RouteError } from "@/components/layout/route-error"

const SetupPage = lazy(() => import("@/pages/setup"))
const SignInPage = lazy(() => import("@/pages/sign-in"))
const EmailLoginPage = lazy(() => import("@/pages/email-login"))
const DeniedPage = lazy(() => import("@/pages/denied"))
const HomePage = lazy(() => import("@/pages/home"))
const CatalogPage = lazy(() => import("@/pages/apps"))
const InvitePage = lazy(() => import("@/pages/invite"))
const RegisterPage = lazy(() => import("@/pages/register"))
const AppsListPage = lazy(() => import("@/pages/admin/apps-list"))
const AppsNewPage = lazy(() => import("@/pages/admin/apps-new"))
const AppDetailPage = lazy(() => import("@/pages/admin/apps-detail"))
const GroupsPage = lazy(() => import("@/pages/admin/groups"))
const AuditPage = lazy(() => import("@/pages/admin/audit"))
const SigningKeysPage = lazy(() => import("@/pages/admin/keys"))
const NotFoundPage = lazy(() => import("@/pages/not-found"))

export const router = createBrowserRouter([
  {
    element: <SetupGate />,
    errorElement: <RouteError />,
    children: [
      { path: "setup", element: <SetupPage /> },
      { path: "sign-in", element: <SignInPage /> },
      { path: "email-login", element: <EmailLoginPage /> },
      // Forward auth's refusal page: no session needed to read it.
      { path: "denied", element: <DeniedPage /> },
      // Previews the invitation without a session; accepting needs one.
      { path: "invite/:token", element: <InvitePage /> },
      { path: "register", element: <RegisterPage /> },
      {
        element: <SessionGate />,
        // Admin pages check permissions themselves and redirect home when
        // the person may not be there.
        children: [
          { index: true, element: <HomePage /> },
          { path: "apps", element: <CatalogPage /> },
          { path: "admin/apps", element: <AppsListPage /> },
          { path: "admin/apps/new", element: <AppsNewPage /> },
          { path: "admin/apps/:slug", element: <AppDetailPage /> },
          { path: "groups", element: <GroupsPage /> },
          { path: "audit", element: <AuditPage /> },
          // Not "keys": that is the OIDC JWKS endpoint (oidc.Handles).
          { path: "signing-keys", element: <SigningKeysPage /> },
        ],
      },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
])
