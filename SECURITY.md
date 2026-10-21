# Security policy

## Supported versions

Security fixes are made on the latest minor release only. Before 1.0 that means
the newest `0.x` line; upgrade to its latest patch release to receive fixes.

| Version | Supported |
|---|---|
| latest `0.x` minor | yes |
| anything older | no |

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue or pull request.

Use GitHub's private vulnerability reporting: open the repository's **Security**
tab and choose **Report a vulnerability**
(<https://github.com/lieyanc/FireID/security/advisories/new>). Include the
version (`fireid -v`), the configuration that matters (with secrets removed), and
steps to reproduce.

What to expect:

- an acknowledgement within 7 days;
- an assessment, and a fix or mitigation plan, within 30 days for confirmed
  issues, sooner for ones that are actively exploitable;
- a published advisory and a patch release once the fix is out, crediting you
  unless you ask not to be named.

Fire ID is maintained in spare time, so these are targets rather than guarantees.
If you have not heard back within 7 days, comment on your advisory draft.

## Security model

Fire ID is a self-hosted identity provider: the operator runs it, owns its data,
and is trusted with everything in it.

- **Deployment.** It is meant to listen on loopback behind a TLS-terminating
  reverse proxy. `server.trustProxyHeaders` must be on only when that proxy is the
  sole way to reach the listener.
- **Secrets at rest.** A 32-byte master key in `data/master.key` (mode `0600`)
  encrypts TOTP secrets and signing keys in the database. Passwords (argon2id),
  OAuth client secrets, session tokens and recovery codes are stored hashed, never
  encrypted. Anyone who can read both the database and the master key can
  impersonate the provider, so protect and back up the data directory accordingly.
- **Secrets in transit to people.** A secret that must reach a person (setup token,
  TOTP secret, recovery codes, client secret) is shown once and never logged.
- **No telemetry.** Fire ID makes no outbound connections of its own beyond the
  SMTP relay you configure and the back-channel logout URIs your applications
  register.

Out of scope: attacks that need the operator's host, the master key, or the
reverse proxy's configuration; denial of service by volume; and issues in
applications that integrate with Fire ID.
