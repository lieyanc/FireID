-- Fire ID schema. Statements are idempotent so this file can be replayed on
-- every start; incremental column adds live in migrate.go.
--
-- Timestamps are RFC 3339 UTC strings (TEXT), matching the rest of the
-- workspace. Secrets are never stored in the clear: columns ending in _hash
-- hold a SHA-256 of an opaque value, and columns ending in _enc hold an
-- AES-256-GCM ciphertext produced with the master key in data/master.key.

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

-- ---------------------------------------------------------------------------
-- Identity
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT    NOT NULL UNIQUE,
    email            TEXT    NOT NULL UNIQUE,
    display_name     TEXT    NOT NULL DEFAULT '',
    -- pending: registered, address not verified. active: may sign in.
    -- disabled: may not sign in; existing sessions are revoked on transition.
    status           TEXT    NOT NULL DEFAULT 'pending',
    is_super_admin   INTEGER NOT NULL DEFAULT 0,
    password_hash    TEXT    NOT NULL DEFAULT '',
    -- Bumped to revoke every session and refresh token of this user.
    session_gen      INTEGER NOT NULL DEFAULT 0,
    -- Encrypted TOTP shared secret; empty until TOTP enrolment starts.
    totp_secret_enc  TEXT    NOT NULL DEFAULT '',
    totp_confirmed_at TEXT   NOT NULL DEFAULT '',
    locale           TEXT    NOT NULL DEFAULT '',
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL,
    last_login_at    TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BLOB    NOT NULL UNIQUE,
    public_key    BLOB    NOT NULL,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    transports    TEXT    NOT NULL DEFAULT '',
    aaguid        TEXT    NOT NULL DEFAULT '',
    name          TEXT    NOT NULL DEFAULT '',
    -- 1 when the credential may be synced (iCloud/Google/1Password passkeys).
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    backup_state    INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL,
    last_used_at  TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);

-- Single-use tokens delivered by email or printed once. The plaintext value
-- only ever exists in the message and the URL that carries it.
CREATE TABLE IF NOT EXISTS credential_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- email_verify | magic_link | password_reset | invite
    purpose    TEXT    NOT NULL,
    token_hash TEXT    NOT NULL UNIQUE,
    email      TEXT    NOT NULL DEFAULT '',
    expires_at TEXT    NOT NULL,
    used_at    TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL,
    ip         TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_credential_tokens_user ON credential_tokens(user_id, purpose);

-- Group membership drives per-application access.
CREATE TABLE IF NOT EXISTS groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at TEXT    NOT NULL,
    PRIMARY KEY (group_id, user_id)
);

-- ---------------------------------------------------------------------------
-- Applications (OAuth clients)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS apps (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    slug          TEXT    NOT NULL UNIQUE,
    name          TEXT    NOT NULL,
    description   TEXT    NOT NULL DEFAULT '',
    homepage_url  TEXT    NOT NULL DEFAULT '',
    logo_url      TEXT    NOT NULL DEFAULT '',
    client_id     TEXT    NOT NULL UNIQUE,
    -- Empty for public clients.
    client_secret_hash TEXT NOT NULL DEFAULT '',
    secret_rotated_at  TEXT NOT NULL DEFAULT '',
    -- confidential | public
    client_type   TEXT    NOT NULL DEFAULT 'confidential',
    -- client_secret_basic | client_secret_post | none
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic',
    require_pkce  INTEGER NOT NULL DEFAULT 1,
    owner_user_id INTEGER NOT NULL REFERENCES users(id),
    -- active | suspended
    status        TEXT    NOT NULL DEFAULT 'active',
    -- closed | invite | open | admin_approval
    registration_mode TEXT NOT NULL DEFAULT 'closed',
    -- all_users | groups | members_only
    default_access    TEXT NOT NULL DEFAULT 'members_only',
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_apps_owner ON apps(owner_user_id);

CREATE TABLE IF NOT EXISTS app_redirect_uris (
    app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    uri    TEXT    NOT NULL,
    PRIMARY KEY (app_id, uri)
);

CREATE TABLE IF NOT EXISTS app_post_logout_redirect_uris (
    app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    uri    TEXT    NOT NULL,
    PRIMARY KEY (app_id, uri)
);

CREATE TABLE IF NOT EXISTS app_scopes (
    app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    scope  TEXT    NOT NULL,
    PRIMARY KEY (app_id, scope)
);

CREATE TABLE IF NOT EXISTS app_grant_types (
    app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    grant_type TEXT    NOT NULL,
    PRIMARY KEY (app_id, grant_type)
);

CREATE TABLE IF NOT EXISTS app_group_access (
    app_id   INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (app_id, group_id)
);

CREATE TABLE IF NOT EXISTS app_memberships (
    app_id      INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- owner | admin | member
    role        TEXT    NOT NULL DEFAULT 'member',
    -- active | pending | blocked
    status      TEXT    NOT NULL DEFAULT 'active',
    created_at  TEXT    NOT NULL,
    approved_by INTEGER REFERENCES users(id),
    PRIMARY KEY (app_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_app_memberships_user ON app_memberships(user_id, status);

CREATE TABLE IF NOT EXISTS access_requests (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message    TEXT    NOT NULL DEFAULT '',
    -- pending | approved | denied
    status     TEXT    NOT NULL DEFAULT 'pending',
    created_at TEXT    NOT NULL,
    decided_at TEXT    NOT NULL DEFAULT '',
    decided_by INTEGER REFERENCES users(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_access_requests_pending
    ON access_requests(app_id, user_id) WHERE status = 'pending';

-- ---------------------------------------------------------------------------
-- Sessions and OAuth state
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   TEXT    NOT NULL UNIQUE,
    created_at   TEXT    NOT NULL,
    expires_at   TEXT    NOT NULL,
    last_seen_at TEXT    NOT NULL,
    ip           TEXT    NOT NULL DEFAULT '',
    user_agent   TEXT    NOT NULL DEFAULT '',
    -- space-separated authentication methods: pwd otp webauthn email
    amr          TEXT    NOT NULL DEFAULT '',
    acr          TEXT    NOT NULL DEFAULT '',
    revoked_at   TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Authorization requests are held server-side so the code can be bound to the
-- exact parameters they were authorised with.
CREATE TABLE IF NOT EXISTS auth_requests (
    id                    TEXT PRIMARY KEY,
    app_id                INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id               INTEGER REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri          TEXT    NOT NULL,
    scope                 TEXT    NOT NULL,
    nonce                 TEXT    NOT NULL DEFAULT '',
    state                 TEXT    NOT NULL DEFAULT '',
    code_challenge        TEXT    NOT NULL DEFAULT '',
    code_challenge_method TEXT    NOT NULL DEFAULT '',
    -- Space-separated resource indicators (RFC 8707).
    resource              TEXT    NOT NULL DEFAULT '',
    auth_time             TEXT    NOT NULL,
    amr                   TEXT    NOT NULL DEFAULT '',
    acr                   TEXT    NOT NULL DEFAULT '',
    sid                   TEXT    NOT NULL DEFAULT '',
    -- What the client asked for about re-authentication: the prompt values,
    -- max_age in seconds (-1 when absent) and the requested ACR values.
    prompt                TEXT    NOT NULL DEFAULT '',
    max_age               INTEGER NOT NULL DEFAULT -1,
    acr_values            TEXT    NOT NULL DEFAULT '',
    expires_at            TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash             TEXT PRIMARY KEY,
    -- The request the code was issued from. It outlives the request row, which
    -- is deleted on exchange, so a replay can still revoke the tokens minted
    -- from this code.
    auth_request_id       TEXT    NOT NULL DEFAULT '',
    app_id                INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id               INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri          TEXT    NOT NULL,
    scope                 TEXT    NOT NULL,
    nonce                 TEXT    NOT NULL DEFAULT '',
    code_challenge        TEXT    NOT NULL DEFAULT '',
    code_challenge_method TEXT    NOT NULL DEFAULT '',
    resource              TEXT    NOT NULL DEFAULT '',
    auth_time             TEXT    NOT NULL,
    amr                   TEXT    NOT NULL DEFAULT '',
    acr                   TEXT    NOT NULL DEFAULT '',
    sid                   TEXT    NOT NULL DEFAULT '',
    expires_at            TEXT    NOT NULL,
    consumed_at           TEXT    NOT NULL DEFAULT ''
);

-- Refresh tokens rotate on every use. family_id groups the chain so that
-- replaying a consumed token can revoke every descendant at once.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash     TEXT    NOT NULL UNIQUE,
    app_id         INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id      TEXT    NOT NULL,
    scope          TEXT    NOT NULL,
    resource       TEXT    NOT NULL DEFAULT '',
    -- Carried over from the original authorization so refreshed ID tokens keep
    -- saying when and how the user authenticated.
    auth_request_id TEXT   NOT NULL DEFAULT '',
    auth_time      TEXT    NOT NULL DEFAULT '',
    amr            TEXT    NOT NULL DEFAULT '',
    acr            TEXT    NOT NULL DEFAULT '',
    created_at     TEXT    NOT NULL,
    expires_at     TEXT    NOT NULL,
    rotated_at     TEXT    NOT NULL DEFAULT '',
    revoked_at     TEXT    NOT NULL DEFAULT '',
    revoked_reason TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);

-- Access tokens are opaque and encrypted, but the provider still needs to know
-- their scope, lifetime and revocation state. The row is keyed by the random
-- token ID embedded in the ciphertext, never by the token itself.
CREATE TABLE IF NOT EXISTS access_tokens (
    token_id        TEXT    PRIMARY KEY,
    app_id          INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope           TEXT    NOT NULL DEFAULT '',
    auth_request_id TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL,
    expires_at      TEXT    NOT NULL,
    revoked_at      TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_access_tokens_user ON access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_auth_request ON access_tokens(auth_request_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires ON access_tokens(expires_at);

CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_requests_expires ON auth_requests(expires_at);

-- OpenID Connect session tracking, so logout can notify the right clients.
CREATE TABLE IF NOT EXISTS oidc_sessions (
    sid        TEXT    PRIMARY KEY,
    app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT    NOT NULL,
    expires_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oidc_sessions_user ON oidc_sessions(user_id);

CREATE TABLE IF NOT EXISTS device_codes (
    device_code_hash TEXT    PRIMARY KEY,
    user_code        TEXT    NOT NULL UNIQUE,
    app_id           INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    scope            TEXT    NOT NULL DEFAULT '',
    -- pending | approved | denied
    status           TEXT    NOT NULL DEFAULT 'pending',
    user_id          INTEGER REFERENCES users(id),
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    last_polled_at   TEXT    NOT NULL DEFAULT '',
    expires_at       TEXT    NOT NULL,
    created_at       TEXT    NOT NULL
);

-- ---------------------------------------------------------------------------
-- Keys, settings, audit
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS signing_keys (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    kid              TEXT    NOT NULL UNIQUE,
    alg              TEXT    NOT NULL,
    private_key_enc  TEXT    NOT NULL,
    public_jwk       TEXT    NOT NULL,
    created_at       TEXT    NOT NULL,
    activated_at     TEXT    NOT NULL DEFAULT '',
    retired_at       TEXT    NOT NULL DEFAULT '',
    is_current       INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_signing_keys_current
    ON signing_keys(is_current) WHERE is_current = 1;

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    at            TEXT    NOT NULL,
    -- info | warning | critical
    severity      TEXT    NOT NULL DEFAULT 'info',
    event         TEXT    NOT NULL,
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    -- user | admin | system | client
    actor_type    TEXT    NOT NULL DEFAULT 'system',
    app_id        INTEGER REFERENCES apps(id) ON DELETE SET NULL,
    user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
    ip            TEXT    NOT NULL DEFAULT '',
    user_agent    TEXT    NOT NULL DEFAULT '',
    detail_json   TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_app ON audit_log(app_id);

-- Rate-limit counters that must survive a restart (login, registration, email).
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket     TEXT    PRIMARY KEY,
    count      INTEGER NOT NULL DEFAULT 0,
    window_end TEXT    NOT NULL
);
