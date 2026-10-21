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

Licence: MIT. Changes: [CHANGELOG.md](CHANGELOG.md). Reporting a vulnerability:
[SECURITY.md](SECURITY.md).

## Status

Early development. The configuration, storage, session and credential layers and
the OIDC provider core (authorization code with PKCE, refresh-token rotation,
userinfo, introspection, revocation, RP-initiated logout) and the sign-in product
(setup, password, TOTP with recovery codes, email code / magic link, an English and
Chinese web UI) are in place, as are passkeys and self-service account management
(profile, password change, active sessions), app administration (apps with
delegated owners, members, groups, access requests), forward auth for sites
without a login of their own, the audit log, signing-key rotation and
back-channel logout, and the [`client/`](client/README.md) module for Go applications.
Stage 9 added a security hardening pass, a test-by-test walk of the OpenID
conformance plans ([docs/conformance.md](docs/conformance.md)) and the release
pipeline behind [the releases](https://github.com/lieyanc/FireID/releases). The
official conformance suite has not been run yet; that needs Docker and an https
issuer, and the steps are in that document. See [docs/DESIGN.md](docs/DESIGN.md)
for the design and the build order.

## Install

Releases are on the [releases page](https://github.com/lieyanc/FireID/releases).
How they are built and how to check them is in [RELEASING.md](RELEASING.md).

### From a release archive

Static binaries for Linux and macOS on amd64 and arm64, with a `SHA256SUMS` file:

```sh
VERSION=0.1.0 OS=linux ARCH=amd64     # or darwin / arm64
base=https://github.com/lieyanc/FireID/releases/download/v$VERSION
curl -fLO "$base/fireid_${VERSION}_${OS}_${ARCH}.tar.gz"
curl -fLO "$base/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS   # macOS: shasum -a 256 --check --ignore-missing
tar -xzf "fireid_${VERSION}_${OS}_${ARCH}.tar.gz"
sudo mkdir -p /opt/fireid
sudo install -m 0755 "fireid_${VERSION}_${OS}_${ARCH}/fireid" /opt/fireid/fireid
```

Then write a configuration (see [Configuration](#configuration)) and run it
directly or under [systemd](#systemd).

### From the container image

`ghcr.io/lieyanc/fireid` is built for `linux/amd64` and `linux/arm64`, tagged
with the version (`0.1.0`) and `latest`. It runs as UID `65532` on a distroless
base and reads `/data/config.json`. `/data` holds the configuration, the
database and `master.key`, and is the only path it writes, so the root
filesystem can be read-only.

Inside a container the listener must bind `0.0.0.0`, and `dataDir` should be
`/data`. Create the configuration before the first start; `server.publicUrl` is
required:

```sh
sudo install -d -m 0700 -o 65532 -g 65532 /srv/fireid
sudo tee /srv/fireid/config.json >/dev/null <<'EOF'
{
  "server": { "host": "0.0.0.0", "port": 8099, "publicUrl": "https://id.example.com",
              "trustProxyHeaders": true },
  "dataDir": "/data"
}
EOF
sudo chown 65532:65532 /srv/fireid/config.json

docker run -d --name fireid --restart unless-stopped \
  --read-only --tmpfs /tmp \
  -v /srv/fireid:/data \
  -p 127.0.0.1:8099:8099 \
  ghcr.io/lieyanc/fireid:0.1.0
docker logs fireid      # the one-time setup token is logged here
```

Publishing on `127.0.0.1` keeps the reverse proxy the only way in, which is what
`trustProxyHeaders: true` requires. `-reset-auth` runs as
`docker run --rm -v /srv/fireid:/data ghcr.io/lieyanc/fireid:0.1.0 -c /data/config.json -reset-auth`
while the service is stopped. Back up `/srv/fireid` as described under
[Storage](#storage).

### From source

Go 1.26 and Node 22 with npm:

```sh
git clone https://github.com/lieyanc/FireID && cd FireID
make build            # UI into web/dist, static binary into bin/fireid
make release-local    # or: the four release archives and SHA256SUMS into dist/
make docker           # or: a local container image (needs Docker)
```

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
to `127.0.0.1` and let the proxy terminate TLS, and set
`server.trustProxyHeaders` to `true`.

To put a site that has no login behind Fire ID, register
`https://<site>/__fireid/callback` as a redirect URI of its app and paste the two
nginx snippets from the app's *Forward auth* card. See
[docs/forward-auth.md](docs/forward-auth.md) for a complete example and the header
rules that must be followed.

### Go applications

[`github.com/lieyanc/FireID/client`](client/README.md) is a separate,
standard-library-only module: OIDC login handlers with real ID-token
verification, a back-channel logout receiver, and middleware that reads the
forward-auth identity headers from the proxy only.

## Configuration

`config.json` is written with mode `0600` and rewritten atomically. A minimal
file is enough; missing fields are filled from the template on start.

```json
{
  "server": { "host": "127.0.0.1", "port": 8099, "publicUrl": "https://id.example.com",
              "trustProxyHeaders": true },
  "auth": { "registration": "closed", "passwordMinLength": 10 },
  "oidc": { "signingAlgorithm": "ES256" },
  "email": { "host": "", "fromEmail": "" },
  "dataDir": "./data"
}
```

`auth.registration` is `closed` (invitation only) or `open` (self-registration).
Each application can override this with its own registration mode.

`server.trustProxyHeaders` makes Fire ID take the client address from the last
`X-Forwarded-For` entry and the scheme from `X-Forwarded-Proto`. Turn it on only
when the reverse proxy is the sole way to reach the listener; otherwise a client
could choose the address its sign-in attempts are throttled under.

Leaving `email.host` empty disables email entirely: addresses cannot be verified
and magic-link sign-in is unavailable, but passwords and passkeys still work.
Port 465 uses implicit TLS; other ports use STARTTLS when `email.startTls` is set,
and credentials are never sent to a remote relay over plaintext.

### Upgrading from a build before Stage 3

- `server.trustProxyHeaders` used to be always on and now defaults to `false`.
  Behind a reverse proxy, set it to `true`, or every client shares the proxy's
  address and one person's failed sign-ins lock everyone out. Fire ID logs a
  warning when it sees forwarded headers it does not trust.
- On HTTPS without `auth.cookieDomain` the session cookie is now
  `__Host-fireid_session`; everyone signs in once more after the upgrade.

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
make start      # build bin/fireid with the existing web/dist, then run it
make dev        # Go backend with the existing web/dist
make dev-web    # Vite dev server with hot reload, proxying /api
                # (FIREID_BACKEND, default http://127.0.0.1:8099, must equal server.publicUrl)
make test       # go vet + go test -race
make lint       # eslint + tsc
make check      # what CI runs: gofmt, go vet and race tests for both modules, eslint + tsc
```

Repo artifacts — code, comments, commit messages, docs — are written in English.

## Licence

MIT. See [LICENSE](LICENSE).
