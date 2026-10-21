// Passkey ceremonies in the browser. The server (go-webauthn) sends options
// with every binary field as base64url and expects the browser's answer in the
// same encoding; navigator.credentials works on ArrayBuffers both ways.

import { useSyncExternalStore } from "react"

import type { Translate } from "@/i18n"

/** JSON options as go-webauthn sends them: binary fields are base64url. */
export type CreationOptionsJSON = Record<string, unknown>
export type RequestOptionsJSON = Record<string, unknown>

export type RegistrationResponseJSON = {
  id: string
  rawId: string
  type: string
  authenticatorAttachment?: string
  clientExtensionResults: AuthenticationExtensionsClientOutputs
  response: {
    attestationObject: string
    clientDataJSON: string
    transports?: string[]
  }
}

export type AssertionResponseJSON = {
  id: string
  rawId: string
  type: string
  authenticatorAttachment?: string
  clientExtensionResults: AuthenticationExtensionsClientOutputs
  response: {
    authenticatorData: string
    clientDataJSON: string
    signature: string
    userHandle: string | null
  }
}

export function bufferToBase64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export function base64urlToBuffer(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/")
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

/** go-webauthn wraps the options as {publicKey: {...}}; accept either form. */
function unwrap(options: Record<string, unknown>): Record<string, unknown> {
  const inner = options.publicKey
  return inner && typeof inner === "object"
    ? (inner as Record<string, unknown>)
    : options
}

type DescriptorJSON = { id: string; type: string; transports?: string[] }

function decodeDescriptors(list: unknown) {
  if (!Array.isArray(list)) return undefined
  return (list as DescriptorJSON[]).map((d) => ({
    ...d,
    id: base64urlToBuffer(d.id),
    transports: d.transports as AuthenticatorTransport[] | undefined,
  })) as PublicKeyCredentialDescriptor[]
}

export function decodeCreationOptions(
  options: CreationOptionsJSON
): PublicKeyCredentialCreationOptions {
  const o = unwrap(options)
  const user = o.user as { id: string; name: string; displayName: string }
  return {
    ...(o as unknown as PublicKeyCredentialCreationOptions),
    challenge: base64urlToBuffer(o.challenge as string),
    user: { ...user, id: base64urlToBuffer(user.id) },
    excludeCredentials: decodeDescriptors(o.excludeCredentials),
  }
}

export function decodeRequestOptions(
  options: RequestOptionsJSON
): PublicKeyCredentialRequestOptions {
  const o = unwrap(options)
  return {
    ...(o as unknown as PublicKeyCredentialRequestOptions),
    challenge: base64urlToBuffer(o.challenge as string),
    allowCredentials: decodeDescriptors(o.allowCredentials),
  }
}

export function serializeCredentialCreation(
  cred: PublicKeyCredential
): RegistrationResponseJSON {
  const response = cred.response as AuthenticatorAttestationResponse
  return {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      attestationObject: bufferToBase64url(response.attestationObject),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      transports: response.getTransports?.(),
    },
  }
}

export function serializeCredentialAssertion(
  cred: PublicKeyCredential
): AssertionResponseJSON {
  const response = cred.response as AuthenticatorAssertionResponse
  return {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      authenticatorData: bufferToBase64url(response.authenticatorData),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle
        ? bufferToBase64url(response.userHandle)
        : null,
    },
  }
}

/** True when this browser has the WebAuthn API at all. */
export function passkeysAvailable() {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential === "function" &&
    !!navigator.credentials
  )
}

// The server answers 404 passkeys_unavailable from either begin endpoint when
// its issuer cannot be a WebAuthn RP ID (an IP address, say). Once seen, the
// passkey UI stays hidden for the rest of the page's life.
let serverUnavailable = false
const listeners = new Set<() => void>()

export function markPasskeysUnavailable() {
  if (serverUnavailable) return
  serverUnavailable = true
  for (const listener of listeners) listener()
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

/** False once the server said it has no passkeys. */
export function usePasskeysOffered() {
  return !useSyncExternalStore(subscribe, () => serverUnavailable)
}

/** Thrown when the browser hands back no credential. */
class NoCredentialError extends DOMException {
  constructor() {
    super("No credential returned", "NotAllowedError")
  }
}

/** Runs a registration prompt and returns the answer for the server. */
export async function createPasskey(options: CreationOptionsJSON) {
  const cred = await navigator.credentials.create({
    publicKey: decodeCreationOptions(options),
  })
  if (!cred) throw new NoCredentialError()
  return serializeCredentialCreation(cred as PublicKeyCredential)
}

/** Runs a sign-in prompt and returns the answer for the server. */
export async function getPasskey(options: RequestOptionsJSON) {
  const cred = await navigator.credentials.get({
    publicKey: decodeRequestOptions(options),
  })
  if (!cred) throw new NoCredentialError()
  return serializeCredentialAssertion(cred as PublicKeyCredential)
}

/** True when the person closed or cancelled the browser's passkey prompt. */
export function isPasskeyCancelled(error: unknown) {
  return (
    error instanceof DOMException &&
    (error.name === "NotAllowedError" || error.name === "AbortError")
  )
}

/**
 * Wording for a failed browser prompt, or undefined when the error did not
 * come from WebAuthn (an API error, say) and the caller should handle it.
 */
export function webauthnErrorMessage(error: unknown, t: Translate) {
  if (!(error instanceof DOMException)) return undefined
  switch (error.name) {
    case "NotAllowedError":
    case "AbortError":
      return t("common.errors.webauthn_cancelled")
    case "NotSupportedError":
      return t("common.errors.webauthn_not_supported")
    case "InvalidStateError":
      return t("common.errors.webauthn_already_registered")
    case "SecurityError":
      return t("common.errors.webauthn_security")
    default:
      return t("common.errors.webauthn_failed")
  }
}
