# Fire ID client

`github.com/lieyanc/FireID/client` is an OpenID Connect relying party for Go
applications. It was written for [Fire ID](../README.md) and works against any
provider that follows the specifications for the parts it uses. It has **no
dependencies outside the standard library**, so importing it adds nothing to
an application's module graph.

```sh
go get github.com/lieyanc/FireID/client
```

It offers three things:

| | |
|---|---|
| **OIDC login** | authorization code flow with PKCE, ID token verification against the provider's JWKS, userinfo, refresh, RP-initiated logout; two `net/http` handlers wrap the whole browser flow |
| **Back-channel logout** | verifies logout tokens (Back-Channel Logout 1.0 §2.6, with replay protection) and serves the logout URI |
| **Trusted headers** | reads the `X-FireID-*` identity headers behind Fire ID's [forward auth](../docs/forward-auth.md), from the reverse proxy only |

## OIDC login

Register the application in Fire ID (Apps → New) with the redirect URI the
callback handler will serve, and copy the client ID and secret.

```go
c, err := client.New(ctx, client.Config{
    Issuer:       "https://id.example.com",
    ClientID:     "my-app",
    ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
    RedirectURL:  "https://app.example.com/auth/callback",
    // Scopes default to openid profile email; add offline_access for a refresh token.
})
if err != nil {
    log.Fatal(err)
}

flow := client.FlowConfig{
    OnLogin: func(w http.ResponseWriter, r *http.Request, res *client.LoginResult) error {
        // Create the application's own session here. Key it on
        // res.Claims.Subject, the stable account ID, and keep res.Claims.SID
        // so back-channel logout can find the session later.
        sessions.Create(w, res.Claims.Subject, res.Claims.SID)
        http.Redirect(w, r, res.ReturnTo, http.StatusFound)
        return nil
    },
}

mux := http.NewServeMux()
mux.Handle("GET /auth/login", c.LoginHandler(flow))       // GET /auth/login?return=/where/it/started
mux.Handle("GET /auth/callback", c.CallbackHandler(flow)) // the RedirectURL's path
```

`LoginHandler` generates `state`, `nonce` and a PKCE verifier, keeps them in a
ten-minute `HttpOnly` cookie and redirects to the provider. `CallbackHandler`
checks `state` in constant time, checks the `iss` parameter (RFC 9207),
exchanges the code, verifies the ID token with the nonce and calls `OnLogin`.
Failures go to `FlowConfig.ErrorHandler`; the default writes a short text page
with the status `client.ErrorStatus` gives (400 for a request that does not
match a login this browser started, 403 for `access_denied`, 502 when the
provider failed). Supply your own to log or to render a page.

`return` is accepted only as a local absolute path; anything else becomes `/`.
Starting a second login in another tab replaces the first: the newest wins.

### The login cookie

The cookie is named `__Host-fireid_rp_<8 hex digits>` when the `RedirectURL`
is https: the prefix means no other host or subdomain can set it, which
together with the `state` check is what protects the flow. The digits come
from a hash of the issuer and client ID, and the cookie records both, so an
application with several `Client`s — two providers, or two registrations —
cannot have a login started at one finished at another's callback. A
`FlowConfig.CookieName` of your own must likewise differ per `Client`. The
cookie is not signed on purpose — a signature would not stop an attacker who
can start a login of their own and obtain a validly signed cookie. On a
plain-http `RedirectURL` (development on loopback) the prefix is not available
and the cookie is `fireid_rp_<8 hex digits>`; do not deploy that.

`Config.HTTPClient` replaces the default client, which has a ten-second
timeout and refuses redirects. One of your own should refuse them too: a
redirect from the token or userinfo endpoint would carry the client secret or
an access token to wherever it points.

### Lower level

Everything the handlers use is public, for an application with its own
session store or a non-browser flow:

```go
state, nonce, verifier := client.RandomString(), client.RandomString(), client.NewPKCEVerifier()
url := c.AuthCodeURL(state, nonce, verifier, client.WithACRValues("urn:fireid:loa:2"))
// ... the browser returns to the redirect URL with code and state; compare state ...
tokens, err := c.Exchange(ctx, code, verifier, client.WithNonce(nonce))
info, err := c.UserInfoFor(ctx, tokens.AccessToken, tokens.Claims.Subject) // sub must match
fresh, err := c.Refresh(ctx, tokens.RefreshToken, client.WithExpectedSubject(tokens.Claims.Subject))
logoutURL, err := c.EndSessionURL(tokens.IDToken, "https://app.example.com/", state)
claims, err := c.VerifyIDToken(ctx, rawIDToken, nonce) // a token from anywhere else
```

A public client (no secret, e.g. a CLI tool) leaves `ClientSecret` empty and
authenticates with PKCE alone.

### What verification checks

Signature by a key from the provider's JWKS, chosen by `kid` — never from a
`jku`/`jwk`/`x5u` header; `alg` in {RS256, PS256, ES256, EdDSA}, equal to the
JWK's `alg` when stated and fitting the key's type; RSA keys of 2048 to 16384
bits; no `crit` header; header and claim names read exactly, with a repeated
name refused. Then `iss`, `aud` (with `azp` when there are several
audiences), `exp` and `iat` within `ClockSkew` (default one minute), `nonce`
when one is expected, `at_hash` against the access token when present. The
JWKS is cached and refreshed at most once per 30 seconds — for an unknown
`kid`, after an hour so a retired key stops verifying, or after a failed
attempt. The cached set keeps serving while the provider is slow or down, and
a refresh never blocks verifications with keys already cached.

## Back-channel logout

Register the URI as the app's back-channel logout URI in Fire ID. Fire ID
POSTs a logout token there whenever a session that signed in to the app ends.

```go
mux.Handle("POST /auth/backchannel-logout", c.BackchannelLogoutHandler(
    func(ctx context.Context, lt *client.LogoutToken) error {
        if lt.SID != "" {
            return sessions.EndBySID(lt.SID) // the SID the ID token carried
        }
        return sessions.EndBySubject(lt.Subject)
    }))
```

The handler answers 200 on success, 400 for a token that does not verify, and
500 when the callback fails — Fire ID retries non-2xx answers, so return an
error only for a transient failure. `VerifyLogoutToken` is available on its
own; it remembers each `jti` for as long as the token would still verify
(`exp` plus `ClockSkew`) so a captured token cannot be replayed.

## Trusted headers

For an application without a login of its own, protected by Fire ID's forward
auth. nginx sets `X-FireID-Sub`, `X-FireID-User`, `X-FireID-Email`,
`X-FireID-Name` and `X-FireID-Groups`; the middleware reads them and makes the
identity available through `client.IdentityFrom`.

```go
th := client.TrustedHeaders{Required: true}
handler := th.Middleware(mux)
// in a handler:
id, ok := client.IdentityFrom(r.Context())
```

The headers are trusted only on requests from `TrustedProxies` — loopback by
default, which is where nginx is when the application is bound as the
[forward-auth guide](../docs/forward-auth.md#rules) asks. From any other
address every `X-FireID-*` header is removed before the request reaches the
application, and the request is anonymous (401 with `Required`). The proxy
must set each header, replacing what the client sent, as `proxy_set_header`
does; a request on which any `X-FireID-*` header appears twice is treated as
anonymous too. An application listening on a Unix socket sets
`TrustUnixSocket`, since such a connection has no peer address to check — the
socket's permissions are then the whole access control, so nothing but the
proxy may reach it. Key local data on `Subject`, the account ID; usernames can
change.

## Development

```sh
cd client
gofmt -l . && go vet ./... && go test -race ./...
```

The tests run against a fake provider in `provider_test.go` that signs with
the standard library. The main module tests the package against the real
Fire ID server.
