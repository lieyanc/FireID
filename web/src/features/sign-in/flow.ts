import * as React from "react"
import { useNavigate } from "react-router"

import { ApiError } from "@/lib/api"
import { refreshSession } from "@/lib/session"
import {
  isChallenge,
  type SignedIn,
  type SignInResult,
  type TotpEnrolment,
} from "@/lib/types"

/** Username and password, kept in component state only, never in storage. */
export type Credentials = { username: string; password: string }

/**
 * Every screen of a sign-in. "start" is the page's own first screen (the
 * password form, or the email-link button); the rest are shared.
 */
export type Step =
  | { kind: "start" }
  | { kind: "email" }
  | { kind: "email-code"; email: string }
  | { kind: "enrol-intro"; creds: Credentials }
  | { kind: "enrol"; creds: Credentials; enrolment: TotpEnrolment }
  | { kind: "totp"; verify: (code: string) => Promise<SignInResult> }
  | { kind: "recovery"; result: SignedIn }
  | { kind: "request-error"; error: string }
  | { kind: "redirecting" }
  | { kind: "finishing" }

export function useSignInFlow() {
  const navigate = useNavigate()
  const [step, setStep] = React.useState<Step>({ kind: "start" })

  /** Leaves the sign-in screens once the person is signed in. */
  const complete = React.useCallback(
    async (result: SignedIn) => {
      // With an authorization request the app gets the answer, including a
      // refusal (`denied`): the provider sends it access_denied.
      if (result.redirectTo) {
        setStep({ kind: "redirecting" })
        window.location.assign(result.redirectTo)
        return
      }
      if (result.authRequestError) {
        setStep({ kind: "request-error", error: result.authRequestError })
        void refreshSession().catch(() => {})
        return
      }
      setStep({ kind: "finishing" })
      await refreshSession().catch(() => {})
      navigate("/", { replace: true })
    },
    [navigate]
  )

  /** Shows new recovery codes first, when the sign-in just enrolled TOTP. */
  const finish = React.useCallback(
    async (result: SignedIn) => {
      if (result.recoveryCodes?.length) {
        setStep({ kind: "recovery", result })
        return
      }
      await complete(result)
    },
    [complete]
  )

  /**
   * Routes a sign-in response: a TOTP challenge moves to the code screen,
   * whose answers go through verify. A totp_enrol challenge is returned for
   * the caller, the only one able to enrol.
   */
  const handle = React.useCallback(
    async (
      result: SignInResult,
      verify: (code: string) => Promise<SignInResult>
    ) => {
      if (!isChallenge(result)) {
        await finish(result)
        return null
      }
      if (result.challenge === "totp") {
        setStep({ kind: "totp", verify })
        return null
      }
      return result.challenge
    },
    [finish]
  )

  return { step, setStep, complete, finish, handle }
}

export type SignInFlow = ReturnType<typeof useSignInFlow>

/** A second challenge after the code was accepted is treated as a bad code. */
export function expectSignedIn(result: SignInResult): SignedIn {
  if (isChallenge(result)) {
    throw new ApiError(401, "invalid_code", "unexpected challenge")
  }
  return result
}
