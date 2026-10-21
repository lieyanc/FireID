import * as React from "react"
import { useForm, useWatch } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { CircleAlertIcon } from "lucide-react"
import { z } from "zod"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Textarea } from "@/components/ui/textarea"
import {
  AUTH_METHODS_FOR,
  AUTH_METHOD_LABELS,
  CLIENT_TYPE_LABELS,
  DEFAULT_ACCESS_LABELS,
  REGISTRATION_MODE_LABELS,
  optionsOf,
} from "@/features/admin/labels"
import { NativeSelect } from "@/features/admin/native-select"
import { useI18n, type MessageKey } from "@/i18n"
import { errorMessage, hasCode } from "@/lib/errors"
import type {
  App,
  AppClientType,
  DefaultAccess,
  RegistrationMode,
  TokenEndpointAuthMethod,
} from "@/lib/types"

// Mirrors store.validateSlug, validateApp and validateHomepage; the server
// has the final say.
const SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
export const SLUG_MAX = 63
const NAME_MAX = 100
const DESCRIPTION_MAX = 500

export type AppFormValues = {
  slug: string
  name: string
  description: string
  homepageUrl: string
  clientType: AppClientType
  tokenEndpointAuthMethod: TokenEndpointAuthMethod
  redirectUris: string[]
  postLogoutRedirectUris: string[]
  registrationMode: RegistrationMode
  defaultAccess: DefaultAccess
}

export function FormAlert({ message }: { message: string | null }) {
  if (!message) return null
  return (
    <Alert variant="destructive">
      <CircleAlertIcon />
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  )
}

/** One URI per line; blank lines are ignored. */
function parseLines(value: string) {
  return value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
}

function isLoopback(hostname: string) {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase()
  return host === "localhost" || host === "::1" || /^127\./.test(host)
}

/** Why a redirect URI would be refused (store.ValidateRedirectURI), or null. */
function redirectUriProblem(raw: string): MessageKey | null {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return "admin.apps.uris.notAbsolute"
  }
  if (!url.host) return "admin.apps.uris.notAbsolute"
  if (raw.includes("#")) return "admin.apps.uris.fragment"
  if (url.username || url.password) return "admin.apps.uris.userinfo"
  if (url.protocol === "https:") return null
  if (url.protocol === "http:") {
    return isLoopback(url.hostname) ? null : "admin.apps.uris.httpNotLoopback"
  }
  return "admin.apps.uris.scheme"
}

function isHttpUrl(raw: string) {
  try {
    const url = new URL(raw)
    return (url.protocol === "http:" || url.protocol === "https:") && !!url.host
  } catch {
    return false
  }
}

/** Form state: URI lists are edited as one textarea line per URI. */
type Draft = Omit<AppFormValues, "redirectUris" | "postLogoutRedirectUris"> & {
  redirectUris: string
  postLogoutRedirectUris: string
}

function draftOf(app?: App): Draft {
  return {
    slug: app?.slug ?? "",
    name: app?.name ?? "",
    description: app?.description ?? "",
    homepageUrl: app?.homepageUrl ?? "",
    clientType: app?.clientType ?? "confidential",
    tokenEndpointAuthMethod:
      app?.tokenEndpointAuthMethod ?? "client_secret_basic",
    redirectUris: (app?.redirectUris ?? []).join("\n"),
    postLogoutRedirectUris: (app?.postLogoutRedirectUris ?? []).join("\n"),
    registrationMode: app?.registrationMode ?? "closed",
    defaultAccess: app?.defaultAccess ?? "members_only",
  }
}

/**
 * Create and edit form for an app. Without `app` it creates: the slug and
 * client type are asked for, and fixed afterwards. `onSubmit` throws an API
 * error to have it shown.
 */
export function AppForm({
  app,
  onSubmit,
  submitLabel,
  submittingLabel,
}: {
  app?: App
  onSubmit: (values: AppFormValues) => Promise<void>
  submitLabel: string
  submittingLabel: string
}) {
  const { t } = useI18n()
  const creating = !app
  const [formError, setFormError] = React.useState<string | null>(null)

  const schema = React.useMemo(() => {
    const uriList = (required: boolean) =>
      z.string().superRefine((value, ctx) => {
        const lines = parseLines(value)
        if (required && lines.length === 0) {
          ctx.addIssue({
            code: "custom",
            message: t("admin.apps.redirectUris.required"),
          })
          return
        }
        for (const uri of lines) {
          const problem = redirectUriProblem(uri)
          if (problem) {
            ctx.addIssue({ code: "custom", message: t(problem, { uri }) })
            return
          }
        }
      })
    return z.object({
      slug: creating
        ? z
            .string()
            .trim()
            .min(1, t("admin.apps.slug.required"))
            .max(SLUG_MAX, t("admin.apps.slug.tooLong", { max: SLUG_MAX }))
            .regex(SLUG_PATTERN, t("admin.apps.slug.invalid"))
        : z.string(),
      name: z
        .string()
        .trim()
        .min(1, t("admin.apps.name.required"))
        .max(NAME_MAX, t("admin.apps.name.tooLong", { max: NAME_MAX })),
      description: z
        .string()
        .max(
          DESCRIPTION_MAX,
          t("admin.apps.descriptionField.tooLong", { max: DESCRIPTION_MAX })
        ),
      homepageUrl: z
        .string()
        .trim()
        .refine((v) => !v || isHttpUrl(v), t("admin.apps.homepage.invalid")),
      clientType: z.enum(["confidential", "public"]),
      tokenEndpointAuthMethod: z.enum([
        "client_secret_basic",
        "client_secret_post",
        "none",
      ]),
      redirectUris: uriList(true),
      postLogoutRedirectUris: uriList(false),
      registrationMode: z.enum(["closed", "invite", "open", "admin_approval"]),
      defaultAccess: z.enum(["all_users", "groups", "members_only"]),
    })
  }, [t, creating])

  const form = useForm<Draft>({
    resolver: zodResolver(schema),
    defaultValues: draftOf(app),
  })
  const { errors, isSubmitting, isDirty } = form.formState
  // useWatch (rather than watch()) keeps the component memoizable.
  const clientType = useWatch({ control: form.control, name: "clientType" })
  const authMethods = AUTH_METHODS_FOR[clientType]

  // A client type allows only some token endpoint methods; keep the choice
  // valid when the type changes.
  React.useEffect(() => {
    const current = form.getValues("tokenEndpointAuthMethod")
    if (!authMethods.includes(current)) {
      form.setValue("tokenEndpointAuthMethod", authMethods[0])
    }
  }, [authMethods, form])

  const submit = async (draft: Draft) => {
    setFormError(null)
    try {
      await onSubmit({
        ...draft,
        slug: draft.slug.trim(),
        name: draft.name.trim(),
        homepageUrl: draft.homepageUrl.trim(),
        redirectUris: parseLines(draft.redirectUris),
        postLogoutRedirectUris: parseLines(draft.postLogoutRedirectUris),
      })
    } catch (error) {
      if (creating && hasCode(error, "conflict")) {
        form.setError(
          "slug",
          { message: t("admin.apps.slug.taken") },
          { shouldFocus: true }
        )
      } else {
        setFormError(errorMessage(error, t))
      }
      return
    }
    // The saved values become the new baseline for "unchanged".
    form.reset(draft)
  }

  const id = (name: string) => `app-${name}`

  return (
    <form onSubmit={form.handleSubmit(submit)} noValidate>
      <FieldGroup>
        <FormAlert message={formError} />
        {creating && (
          <Field data-invalid={!!errors.slug || undefined}>
            <FieldLabel htmlFor={id("slug")}>
              {t("admin.apps.slug.label")}
            </FieldLabel>
            <Input
              id={id("slug")}
              autoFocus
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              maxLength={SLUG_MAX}
              placeholder={t("admin.apps.slug.placeholder")}
              aria-invalid={!!errors.slug}
              {...form.register("slug")}
            />
            <FieldDescription>{t("admin.apps.slug.hint")}</FieldDescription>
            <FieldError errors={[errors.slug]} />
          </Field>
        )}
        <Field data-invalid={!!errors.name || undefined}>
          <FieldLabel htmlFor={id("name")}>
            {t("admin.apps.name.label")}
          </FieldLabel>
          <Input
            id={id("name")}
            autoFocus={!creating}
            maxLength={NAME_MAX}
            aria-invalid={!!errors.name}
            {...form.register("name")}
          />
          <FieldDescription>{t("admin.apps.name.hint")}</FieldDescription>
          <FieldError errors={[errors.name]} />
        </Field>
        <Field data-invalid={!!errors.description || undefined}>
          <FieldLabel htmlFor={id("description")}>
            {t("admin.apps.descriptionField.label")}
          </FieldLabel>
          <Textarea
            id={id("description")}
            maxLength={DESCRIPTION_MAX}
            aria-invalid={!!errors.description}
            {...form.register("description")}
          />
          <FieldDescription>
            {t("admin.apps.descriptionField.hint")}
          </FieldDescription>
          <FieldError errors={[errors.description]} />
        </Field>
        <Field data-invalid={!!errors.homepageUrl || undefined}>
          <FieldLabel htmlFor={id("homepageUrl")}>
            {t("admin.apps.homepage.label")}
          </FieldLabel>
          <Input
            id={id("homepageUrl")}
            type="url"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            placeholder="https://example.com"
            aria-invalid={!!errors.homepageUrl}
            {...form.register("homepageUrl")}
          />
          <FieldDescription>{t("admin.apps.homepage.hint")}</FieldDescription>
          <FieldError errors={[errors.homepageUrl]} />
        </Field>
        {creating && (
          <Field>
            <FieldLabel htmlFor={id("clientType")}>
              {t("admin.apps.clientType.label")}
            </FieldLabel>
            <NativeSelect
              id={id("clientType")}
              {...form.register("clientType")}
            >
              {optionsOf(CLIENT_TYPE_LABELS).map((key) => (
                <option key={key} value={key}>
                  {t(CLIENT_TYPE_LABELS[key])}
                </option>
              ))}
            </NativeSelect>
            <FieldDescription>
              {t("admin.apps.clientType.hint")}
            </FieldDescription>
          </Field>
        )}
        <Field>
          <FieldLabel htmlFor={id("tokenEndpointAuthMethod")}>
            {t("admin.apps.authMethod.label")}
          </FieldLabel>
          <NativeSelect
            id={id("tokenEndpointAuthMethod")}
            {...form.register("tokenEndpointAuthMethod")}
          >
            {authMethods.map((method) => (
              <option key={method} value={method}>
                {t(AUTH_METHOD_LABELS[method])}
              </option>
            ))}
          </NativeSelect>
          <FieldDescription>{t("admin.apps.authMethod.hint")}</FieldDescription>
        </Field>
        <Field data-invalid={!!errors.redirectUris || undefined}>
          <FieldLabel htmlFor={id("redirectUris")}>
            {t("admin.apps.redirectUris.label")}
          </FieldLabel>
          <Textarea
            id={id("redirectUris")}
            spellCheck={false}
            placeholder={t("admin.apps.redirectUris.placeholder")}
            aria-invalid={!!errors.redirectUris}
            {...form.register("redirectUris")}
          />
          <FieldDescription>
            {t("admin.apps.redirectUris.hint")}
          </FieldDescription>
          <FieldError errors={[errors.redirectUris]} />
        </Field>
        <Field data-invalid={!!errors.postLogoutRedirectUris || undefined}>
          <FieldLabel htmlFor={id("postLogoutRedirectUris")}>
            {t("admin.apps.postLogoutUris.label")}
          </FieldLabel>
          <Textarea
            id={id("postLogoutRedirectUris")}
            spellCheck={false}
            placeholder={t("admin.apps.postLogoutUris.placeholder")}
            aria-invalid={!!errors.postLogoutRedirectUris}
            {...form.register("postLogoutRedirectUris")}
          />
          <FieldDescription>
            {t("admin.apps.postLogoutUris.hint")}
          </FieldDescription>
          <FieldError errors={[errors.postLogoutRedirectUris]} />
        </Field>
        <Field>
          <FieldLabel htmlFor={id("registrationMode")}>
            {t("admin.apps.registrationMode.label")}
          </FieldLabel>
          <NativeSelect
            id={id("registrationMode")}
            {...form.register("registrationMode")}
          >
            {optionsOf(REGISTRATION_MODE_LABELS).map((mode) => (
              <option key={mode} value={mode}>
                {t(REGISTRATION_MODE_LABELS[mode])}
              </option>
            ))}
          </NativeSelect>
          <FieldDescription>
            {t("admin.apps.registrationMode.hint")}
          </FieldDescription>
        </Field>
        <Field>
          <FieldLabel htmlFor={id("defaultAccess")}>
            {t("admin.apps.defaultAccess.label")}
          </FieldLabel>
          <NativeSelect
            id={id("defaultAccess")}
            {...form.register("defaultAccess")}
          >
            {optionsOf(DEFAULT_ACCESS_LABELS).map((access) => (
              <option key={access} value={access}>
                {t(DEFAULT_ACCESS_LABELS[access])}
              </option>
            ))}
          </NativeSelect>
          <FieldDescription>
            {t("admin.apps.defaultAccess.hint")}
          </FieldDescription>
        </Field>
        <Button
          type="submit"
          disabled={isSubmitting || (!creating && !isDirty)}
        >
          {isSubmitting && <Spinner data-icon="inline-start" />}
          {isSubmitting ? submittingLabel : submitLabel}
        </Button>
      </FieldGroup>
    </form>
  )
}
