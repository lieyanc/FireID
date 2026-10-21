# Fire ID — project notes for Claude

Read [docs/DESIGN.md](docs/DESIGN.md) first; it is the source of truth for the
data model and the security rules.

## Working agreements

- **Repo artifacts are English**: code, comments, identifiers, commit messages,
  README and docs. Conversation with the user is Chinese.
- **Do not commit unless the user asks.** Do not push unless the user asks.
- **Never log or return a secret**: session tokens, authorization codes, refresh
  tokens, client secrets, TOTP secrets, setup tokens, master key material. When a
  secret must reach a person, it goes into the response body exactly once.
- **Stdlib first.** A new dependency needs a reason. The current external set is
  deliberate: `modernc.org/sqlite` (pure Go, so `CGO_ENABLED=0` works),
  `golang.org/x/crypto` (argon2id), and the OIDC/JOSE/WebAuthn libraries chosen
  in DESIGN.md.
- **Security decisions live in one place.** Whether a user may use an app is
  answered only by `store.CanUseApp`. Whether a request is same-site is answered
  only by `api.Server.crossSite`. Do not re-derive either at a call site.
- Style follows the Fire* house convention: `cmd/<name>/main.go` plus flat
  `internal/` packages, `net/http` ServeMux with method patterns, `log/slog`,
  JSON config mutated through `config.Store.Update`, and an embedded
  `migrate.sql` replayed on start.

## Layout

```
cmd/fireid/         entry point: flags, wiring, shutdown
internal/config/    JSON config, atomic Store, master key
internal/secretbox/ AES-256-GCM for values that must be readable at runtime
internal/store/     SQLite schema, queries, and the access decision
internal/auth/      passwords, TOTP, sessions, throttling, setup token
internal/api/       HTTP surface: JSON API, middleware, embedded UI
internal/oidc/      OIDC provider on zitadel/oidc pkg/op
internal/mail/      SMTP delivery
web/                React UI, embedded into the binary
client/             separate module: OIDC client + trusted-header middleware
docs/               design and operational notes
```

## Testing

`go test -race ./...`. Table-driven `t.Run` subtests, `httptest` for handlers.
The store takes a replaceable clock (`SetClock`) so time-based invariants —
session expiry, lockout windows, TOTP steps — are tested without sleeping.

## Notes

Project memory lives in `memory/INDEX.md` beside this file: one fact per file.
