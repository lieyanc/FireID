# Fire ID

A self-hosted OpenID Connect identity provider for a small fleet of personal and
friend-owned services. One Go binary, SQLite storage, an embedded web UI, and an
`auth_request` endpoint for applications that have no login of their own.

- **One user pool, many applications.** People sign in once; each application
  decides who may use it, through membership, groups, or an open policy.
- **Delegated administration.** The operator is the super admin. Each
  application has an owner who manages only their own application.
- **Standards-based.** Generic OIDC clients work unmodified: authorization code
  with PKCE, discovery, JWKS, userinfo, token revocation and introspection,
  RP-initiated and back-channel logout.
- **Small.** No external database, no Redis, no Node runtime. The UI is compiled
  into the binary.

Licence: MIT.

## Status

Early development. The configuration, storage, session and credential layers and
the OIDC provider core (authorization code with PKCE, refresh-token rotation,
userinfo, introspection, revocation, RP-initiated logout) are in place; the sign-in
UI and app administration are next. See [docs/DESIGN.md](docs/DESIGN.md)
for the design and the build order.

## Quick start

```sh
make build            # builds the UI and the binary into bin/fireid
./bin/fireid -c config.json
```

On first start the binary writes a configuration file from the built-in
template, then logs a one-time setup token:

```
level=WARN msg="no administrator account yet: open the web UI and enter this setup token" url=https://id.example.com setupToken=...
```

Open the URL, enter the token, and create the super administrator. The token is
held in memory only and is cleared once used.

`server.publicUrl` must be the URL clients reach this instance on: it is the OIDC
issuer, so changing it later invalidates issued tokens.

### Flags

| Flag | Meaning |
|---|---|
| `-c config.json` | configuration file, created or completed from defaults |
| `-v` | print the version and exit |
| `-reset-auth` | enable account recovery and exit; the next start prints a fresh setup token |

### Behind a reverse proxy

The listener is meant to sit on loopback behind nginx, Caddy or Traefik. Bind it
to `127.0.0.1` and let the proxy terminate TLS. See
[docs/DESIGN.md §7](docs/DESIGN.md) for the forward-auth configuration and the
header rules that must be followed.

## Configuration

`config.json` is written with mode `0600` and rewritten atomically. A minimal
file is enough; missing fields are filled from the template on start.

```json
{
  "server": { "host": "127.0.0.1", "port": 8099, "publicUrl": "https://id.example.com" },
  "auth": { "registration": "closed", "passwordMinLength": 10 },
  "oidc": { "signingAlgorithm": "ES256" },
  "email": { "host": "", "fromEmail": "" },
  "dataDir": "./data"
}
```

`auth.registration` is `closed` (invitation only) or `open` (self-registration).
Each application can override this with its own registration mode.

Leaving `email.host` empty disables email entirely: addresses cannot be verified
and magic-link sign-in is unavailable, but passwords and passkeys still work.

Secrets are kept out of the configuration file. A 32-byte master key is
generated on first start into `data/master.key` (mode `0600`) and encrypts TOTP
secrets and signing keys at rest; passwords and OAuth client secrets are hashed,
never encrypted.

## Storage

Everything lives in one SQLite database in `dataDir`, in WAL mode. Back up the
directory: the database file plus `master.key`. Losing the master key makes
stored TOTP secrets and signing keys unreadable (people re-enrol); losing the
database loses everything, so back it up.

## systemd

```ini
[Unit]
Description=Fire ID
After=network-online.target

[Service]
ExecStart=/opt/fireid/fireid -c /opt/fireid/config.json
WorkingDirectory=/opt/fireid
User=fireid
Group=fireid
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Development

```sh
make dev        # Go backend with the existing web/dist
make dev-web    # Vite dev server with hot reload, proxying /api
make test       # go vet + go test -race
make lint       # eslint + tsc
```

Repo artifacts — code, comments, commit messages, docs — are written in English.

## Licence

MIT. See [LICENSE](LICENSE).
