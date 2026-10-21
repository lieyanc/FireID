# OpenID conformance

The OpenID Foundation publishes a conformance suite
([gitlab.com/openid/conformance-suite](https://gitlab.com/openid/conformance-suite)) that
certifies OpenID Providers. It is a Java web application, with MongoDB behind it and nginx
in front, run with Docker Compose. It plays the relying party, drives the provider through
the test plans, and records each check as passed, warning or failed.

**State (2026-10-21):** the official suite has not been run against Fire ID. The tests in
`internal/api/conformance_test.go` walk the items of the plans that apply and check the same
wire behaviour against the real HTTP server. The [known gaps](#known-gaps) are written as
skipped subtests. Set `FIREID_CONFORMANCE_STRICT=1` to make them fail, which is how to
confirm a fix:

```sh
go test ./internal/api -run TestConformance -v
FIREID_CONFORMANCE_STRICT=1 go test ./internal/api -run TestConformance
```

## Why the suite was not run here

The development machine has no Docker and no password-less sudo to install it, and the
suite does not run without its containers. It also needs an `https` issuer that both the
suite's server and the tester's browser can reach. A loopback Fire ID on
`http://127.0.0.1:8099` is neither. See [Running the official suite](#running-the-official-suite).

## Plans

| Plan | Applies | Why |
|---|---|---|
| `oidcc-basic-certification-test-plan` | yes | Authorization code flow |
| `oidcc-config-certification-test-plan` | yes | Discovery and JWKS |
| `oidcc-rp-initiated-logout-certification-test-plan` | yes | `/end_session` |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | yes | Back-channel logout |
| `oidcc-dynamic-certification-test-plan` | no | No registration endpoint |
| implicit, hybrid, form_post plans | no | Code flow and query response mode only |
| front-channel logout, session management | no | Not implemented; `check_session_iframe` is removed from discovery |
| FAPI, mTLS (RFC 8705), DPoP, PAR, JARM | no | Not implemented |

## Coverage

The test names below are the top-level tests in `internal/api/conformance_test.go`. Each
row's subtests are named after the case. Rows marked *existing* point to older tests that
already cover the item.

| Item | Suite test or spec | Fire ID test |
|---|---|---|
| Issuer equals the base URL; the client module's discovery accepts it | `oidcc-discovery-endpoint-verification`, Discovery 4.3 | `TestConformanceDiscovery/issuer_equals_the_base_URL` |
| Required metadata present, of the right JSON type | Discovery 3 | `…/metadata_members_have_the_right_type` |
| Only implemented features advertised (code, query, S256, auth methods, algs, scopes, claims) | Discovery 3 | `…/advertises_only_what_is_implemented` |
| Endpoint URLs sit under the issuer and resolve (no 404, no 5xx) | config plan | `…/endpoints_are_under_the_issuer_and_resolve` |
| JWKS: unique `kid`, advertised `alg`, `use=sig`, no private members | `oidcc-server`, RFC 7517 | `…/JWKS_serves_the_advertised_public_keys` |
| An ID token verifies against the JWKS | `oidcc-server` | `…/an_ID_token_verifies_against_the_JWKS` |
| Key rotation keeps old tokens verifiable | config plan | *existing* `TestSigningKeyRotation`, `TestClientKeyRotation` |
| Untrusted `redirect_uri` (unknown client, unregistered, added query, fragment, case, trailing slash, missing, another client's) shown in the browser, not redirected | `oidcc-ensure-registered-redirect-uri`, Core 3.1.2.1 | `TestConformanceErrorResponses/errors_with_an_untrusted_redirect_uri_are_shown,_not_redirected` |
| Missing or bad `response_type`, implicit and hybrid without nonce, missing `openid`, missing scope, request object | `oidcc-response-type-missing`, `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`, Core 3.1.2.2 | `TestConformanceAuthorizationRequest/error_to_the_client:_*` |
| Unsupported `response_mode` ignored, response in the query | Multiple Response Types 2.1 | `…/unsupported_response_mode_falls_back_to_query` |
| `state` echoed unchanged; absent stays absent | Core 3.1.2.5 | `…/state_is_echoed_unchanged` |
| No nonce, other scope order, unknown parameter, `display`, `ui_locales`, `claims_locales`, `login_hint`, `acr_values`, `claims`, `max_age=10000` | `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`, `oidcc-ensure-other-scope-order-succeeds`, `oidcc-ensure-request-with-unknown-parameter-succeeds`, `oidcc-display-*`, `oidcc-ui-locales`, `oidcc-claims-locales`, `oidcc-login-hint`, `oidcc-ensure-request-with-acr-values-succeeds`, `oidcc-claims-essential`, `oidcc-max-age-10000` | `…/accepted:_*` |
| Authorization request by POST | `oidcc-ensure-post-request-succeeds` | `…/authorization_request_by_POST` |
| `prompt=none` without a session: `login_required` at the redirect URI, with `state`, no page shown | `oidcc-prompt-none-not-logged-in` | `…/prompt=none_without_a_session` |
| `prompt=none` with a session, with `id_token_hint` | `oidcc-prompt-none-logged-in`, `oidcc-id-token-hint` | `…/accepted:_prompt=none_with_a_session`, `…/prompt=none_with_the_id_token_hint_of_the_signed-in_user` |
| `max_age=1` forces a new sign-in; `auth_time` moves | `oidcc-max-age-1` | `…/max_age=1_after_the_session_aged` |
| `prompt=login` forces a new sign-in | `oidcc-prompt-login` | *existing* `TestOIDCCodeFlowConfidential/prompt=login_forces_a_new_sign-in` |
| PKCE: missing challenge (public client), `plain`, unknown method, no method | RFC 7636 4.4 | `TestConformancePKCE/*` |
| PKCE: wrong, missing, or challenge-as-verifier; replay after success revokes | RFC 7636 4.6, `oidcc-codereuse` | `TestConformancePKCE/*` |
| PKCE on a confidential client | `oidcc-ensure-request-with-valid-pkce-succeeds` | `TestConformancePKCE/confidential_client_with_PKCE` |
| `client_secret_basic`, `client_secret_post`, `none` | `oidcc-server`, `oidcc-server-client-secret-post` | `TestConformanceTokenEndpoint/client_authentication_methods` |
| Token response: `token_type`, `expires_in`, JSON, `Cache-Control: no-store` | RFC 6749 5.1, Core 3.1.3.3 | `…/client_authentication_methods`, `…/token_response_carries_Cache-Control:_no-store` |
| Credentials in the token endpoint's URL refused | RFC 6749 3.2 | `TestConformanceTokenEndpoint/credentials_in_the_URL_are_refused` |
| Wrong secret, no authentication, wrong or missing `redirect_uri`, another client's code, unknown code, expired code, missing or unsupported `grant_type` | RFC 6749 5.2 | `TestConformanceTokenEndpoint/*` |
| Refresh: rotation; another client refused; same `iss`/`sub`/`aud`/`auth_time`/`azp`, no nonce; reuse revokes the family and its access tokens | `oidcc-refresh-token`, Core 12.2, RFC 9700 4.14 | `…/refresh_token_rotation_and_reuse_detection` |
| Code replay | `oidcc-codereuse`, `oidcc-codereuse-30seconds` | `TestConformancePKCE/code_replayed_after_success`, *existing* `TestOIDCCodeFlowConfidential/code_replay…` |
| ID token header: `alg` advertised (ES256 or RS256), `kid` in JWKS, `typ` JWT | Core 3.1.3.7 | `TestConformanceIDToken/header` |
| ID token claims: `iss`, `aud`, `azp`, `sub` (= userinfo), `nonce`, `sid`, `iat`, `exp`, `auth_time`, `at_hash`, `c_hash` | Core 2, 3.1.3.6 | `TestConformanceIDToken/claims` |
| Verifies with `client.VerifyIDTokenWithAccessToken`; wrong nonce, wrong access token, bad signature, other audience refused | Core 3.1.3.7 | `TestConformanceIDToken/verifies_with_the_client_module` |
| Userinfo: GET header, POST header, POST body; `sub` matches | `oidcc-userinfo-get`, `oidcc-userinfo-post-header`, `oidcc-userinfo-post-body` | `TestConformanceUserinfo/*_with_*` |
| Token in the query string refused | RFC 6750 2.3 | `…/token_in_the_query_string_is_refused` |
| Claims follow the scopes | `oidcc-scope-profile`, `oidcc-scope-email` | `…/claims_for_scope_*` |
| No, malformed, revoked, expired token: 401 with `WWW-Authenticate: Bearer` | RFC 6750 3, Core 5.3.3 | `…/rejected:_*` |
| Revocation: access token stops working; wrong hint; unknown token 200; another client's token untouched; client authentication; `token` required | RFC 7009 | `TestConformanceRevocation/*` |
| Logout with hint, registered redirect and `state`: redirect, session gone, next authorize shows sign-in, client's tokens revoked | `oidcc-rp-initiated-logout` | `TestConformanceRPInitiatedLogout/logout_with_hint,_redirect_and_state` |
| Hint only: signed out, stays at the provider | `oidcc-rp-initiated-logout-no-post-logout-redirect-uri` | `…/hint_without_a_redirect_stays_at_the_provider` |
| Garbage hint, modified signature, unregistered redirect, query added to redirect, client_id ≠ hint: no redirect, session kept | `oidcc-rp-initiated-logout-bad-id-token-hint`, `-modified-id-token-hint`, `-bad-post-logout-redirect-uri`, `-query-added-to-post-logout-redirect-uri` | `…/refused:_*` |
| No params, only state, no hint: nobody signed out | `oidcc-rp-initiated-logout-no-params`, `-only-state`, `-no-id-token-hint` | `…/without_a_hint:_*` |
| Back-channel: form POST with only `logout_token`; `typ` logout+jwt; `iss`, `aud`, `iat`, `exp`, `jti`, `sid` (= ID token), `sub`, no nonce, empty-object event member; verifies with `client.VerifyLogoutToken`, replay refused, not an ID token | `oidcc-backchannel-rp-initiated-logout`, Back-Channel Logout 2.4 | `TestConformanceBackchannelLogout/*` |
| Errors decided after sign-in (`access_denied`) carry `error_description`, `state`, `iss` | RFC 6749 4.1.2.1, RFC 9207 | `TestConformanceErrorResponses/errors_decided_after_sign-in_are_redirected_too` |
| No stack traces, SQL or Go error chains in any error; no markup reflected | — | `wantAuthzError`, `leaksInternals`, used throughout |

## Known gaps

Each is a skipped subtest. The suite's verdict is an estimate: only a real run settles it.

| Gap | Spec | Where | Suite would report |
|---|---|---|---|
| Discovery lists only `ES256` with the default `oidc.signingAlgorithm` | Core 15.1 (RS256 is mandatory to implement) | configuration | Failure or warning in discovery verification. Use RS256 for the certification run (see below) |
| Unknown and revoked/expired bearer tokens: no `WWW-Authenticate`; revoked/expired answer 403, not 401 | RFC 6750 3, 3.1 | zitadel/oidc `op.Userinfo` (`pkg/op/userinfo.go:33-44`) | Not tested by the basic plan |
| Failed Basic authentication at the token endpoint: no `WWW-Authenticate: Basic` | RFC 6749 5.2 | zitadel/oidc token error writer | Not tested by the basic plan |
| `/revoke` without `token` answers 200 | RFC 7009 2.1 | zitadel/oidc `op.ParseTokenRevocationRequest` | Not tested |
| `request_uri` is ignored instead of refused | Core 6.2 | zitadel/oidc authorize parsing | Skipped, since discovery says `request_uri_parameter_supported: false` |
| `request_not_supported` has no `error_description` | optional in RFC 6749 4.1.2.1 | zitadel/oidc | Passes; the description is optional |
| With `response_type=id_token`, the error is in the fragment but `iss` is added to the query | RFC 9207 2 | `internal/oidc/provider.go` `addIssuer` | Not tested (implicit is not offered) |

Two related deviations are not tests, since no spec requires otherwise. An unsupported
`response_type` returns `unauthorized_client`, where `unsupported_response_type` would be
more exact. The token endpoint accepts either secret method from a confidential client,
whichever method was registered. Neither is a suite check.

Three gaps found by this pass were fixed in the Stage 9 hardening work: token responses
had no `Cache-Control: no-store`, access tokens outlived a refresh-token reuse, and
`/userinfo` accepted `?access_token=`. Their subtests are now hard assertions.

## What only the suite can verify

- **Browser-driven checks.** The suite asks the tester to upload screenshots of the
  sign-in page (`oidcc-prompt-login`, `oidcc-max-age-1`, `oidcc-display-*`) and of the
  logout pages (`oidcc-rp-initiated-logout-no-params`, `-only-state`, `-no-id-token-hint`,
  `-no-post-logout-redirect-uri`), and judges them by hand. The tests here only check
  where the browser is sent. Without an `id_token_hint`, Fire ID signs nobody out and shows
  no confirmation page. A reviewer may expect one for `-no-id-token-hint`.
- **The suite's own JOSE and protocol checks**, run by an independent implementation: JWKS
  caching across rotation in real time, `c_hash` and `at_hash` under its parser, header
  strictness.
- **Real HTTPS and network delivery**: TLS on the issuer, back-channel POSTs crossing a
  network to the suite's endpoint, and retry behaviour.
- **Timing**: `oidcc-codereuse-30seconds` really waits 30 s (the code TTL is at most 60 s).
- **Client registration** (`oidcc-dynamic-certification-test-plan`): not applicable.
- **Certificate-bound tokens** (RFC 8705), DPoP, PAR, JARM, FAPI: not implemented.

## Running the official suite

Requirements: Docker with Compose, about 4 GB of RAM, and an `https` issuer. The suite's
UI and callbacks live at `https://localhost.emobix.co.uk:8443`. That name resolves to
127.0.0.1, and the suite ships with a certificate for it.

**1. Give Fire ID an https issuer.** Either deploy it behind a real certificate, which also
allows the hosted suite at `https://www.certification.openid.net/`, or put a local TLS proxy
in front of a loopback instance:

```sh
# config.json: "server": {"host": "127.0.0.1", "port": 8099,
#   "publicUrl": "https://fireid.localtest.me:9443", "trustProxyHeaders": true},
#   "oidc": {"signingAlgorithm": "RS256", ...}
fireid -c config.json &
caddy reverse-proxy --from https://fireid.localtest.me:9443 --to 127.0.0.1:8099 --internal-certs
```

`fireid.localtest.me` resolves to 127.0.0.1 for the browser. The suite's containers must
reach the same name on the host and trust Caddy's root
(`~/.local/share/caddy/pki/authorities/local/root.crt`). With a real certificate neither
step is needed. If the first key was created as ES256, rotate it once after switching to
RS256 (`POST /api/admin/signing-keys/rotate`). For the back-channel plan, Fire ID must trust
the suite's certificate when it posts logout tokens: start it with `SSL_CERT_FILE` pointing
to a bundle that includes the suite's nginx certificate.

**2. Build and start the suite.**

```sh
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite
MAVEN_CACHE=./m2 docker compose -f builder-compose.yml run --rm builder
cat > docker-compose.override.yml <<'EOF'
services:
  server:
    extra_hosts: ["fireid.localtest.me:host-gateway"]
EOF
docker compose up -d
# then open https://localhost.emobix.co.uk:8443/
```

To trust Caddy's root inside the suite's server container:

```sh
docker compose cp ~/.local/share/caddy/pki/authorities/local/root.crt server:/tmp/caddy.crt
docker compose exec server keytool -importcert -cacerts -noprompt -storepass changeit \
  -alias caddy -file /tmp/caddy.crt
docker compose restart server
```

**3. Register the suite as apps in Fire ID** (admin UI, Apps → New). Create two
confidential apps (the suite's `client` and `client2`) with `client_secret_basic` and
scopes `openid profile email offline_access`. Register a third with `client_secret_post`
if the plan asks for one. Each gets these URIs under
`https://localhost.emobix.co.uk:8443/test/a/fireid/`: `callback` as redirect URI,
`post_logout_redirect` as post-logout URI, and `backchannel_logout` as back-channel URI.
Copy the exact values from the plan page, which shows them once the alias is set.

**4. Write the plan configuration** (`fireid.json`):

```json
{
  "alias": "fireid",
  "description": "Fire ID",
  "server": { "discoveryUrl": "https://fireid.localtest.me:9443/.well-known/openid-configuration" },
  "client": { "client_id": "…", "client_secret": "…", "scope": "openid profile email" },
  "client2": { "client_id": "…", "client_secret": "…", "scope": "openid profile email" }
}
```

**5. Run the plans**, from the UI (Create a new test plan → paste the JSON) or with the
suite's script:

```sh
export CONFORMANCE_SERVER=https://localhost.emobix.co.uk:8443/ CONFORMANCE_DEV_MODE=1
python3 scripts/run-test-plan.py \
  "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" fireid.json \
  "oidcc-config-certification-test-plan" fireid.json \
  "oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]" fireid.json \
  "oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]" fireid.json
```

Variant names differ between suite versions. The UI lists the ones the running version
takes. Without a `browser` automation block in the configuration, each test waits for the
tester to sign in as a Fire ID user in the browser and to upload the screenshots it asks
for. Attach the exported results to the release that claims conformance.
