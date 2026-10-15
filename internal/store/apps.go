package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// App is an OAuth client: one connected application. Ownership is what makes
// delegated administration possible — an owner manages only the apps they own.
type App struct {
	ID            int64
	Slug          string
	Name          string
	Description   string
	HomepageURL   string
	LogoURL       string
	ClientID      string
	SecretHash    string
	SecretRotated time.Time
	ClientType    string
	TEAuthMethod  string
	RequirePKCE   bool
	OwnerUserID   int64
	Status        string
	// RegistrationMode is how new users join this app: closed | invite | open |
	// admin_approval.
	RegistrationMode string
	// DefaultAccess is all_users | groups | members_only.
	DefaultAccess string
	CreatedAt     time.Time
	UpdatedAt     time.Time

	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	Scopes                 []string
	GrantTypes             []string
}

// App and client type values.
const (
	AppActive    = "active"
	AppSuspended = "suspended"

	ClientConfidential = "confidential"
	ClientPublic       = "public"

	AuthBasic = "client_secret_basic"
	AuthPost  = "client_secret_post"
	AuthNone  = "none"

	RegClosed        = "closed"
	RegInvite        = "invite"
	RegOpen          = "open"
	RegAdminApproval = "admin_approval"

	AccessAllUsers    = "all_users"
	AccessGroups      = "groups"
	AccessMembersOnly = "members_only"

	MemberActive  = "active"
	MemberPending = "pending"
	MemberBlocked = "blocked"

	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

const appColumns = `id, slug, name, description, homepage_url, logo_url, client_id,
	client_secret_hash, secret_rotated_at, client_type, token_endpoint_auth_method,
	require_pkce, owner_user_id, status, registration_mode, default_access,
	created_at, updated_at`

func scanApp(row interface{ Scan(...any) error }) (*App, error) {
	var a App
	var secretRotated, createdAt, updatedAt string
	var requirePKCE int
	err := row.Scan(&a.ID, &a.Slug, &a.Name, &a.Description, &a.HomepageURL, &a.LogoURL,
		&a.ClientID, &a.SecretHash, &secretRotated, &a.ClientType, &a.TEAuthMethod,
		&requirePKCE, &a.OwnerUserID, &a.Status, &a.RegistrationMode, &a.DefaultAccess,
		&createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan app: %w", err)
	}
	a.RequirePKCE = requirePKCE != 0
	a.SecretRotated = parseTime(secretRotated)
	a.CreatedAt = parseTime(createdAt)
	a.UpdatedAt = parseTime(updatedAt)
	return &a, nil
}

// AppsOwnedBy returns the apps a user owns, which decides whether they may
// administer anything at all.
func (s *Store) AppsOwnedBy(userID int64) ([]*App, error) {
	return s.queryApps(`SELECT `+appColumns+` FROM apps WHERE owner_user_id = ? ORDER BY name`, userID)
}

// ListApps returns every app, for the super admin's view.
func (s *Store) ListApps() ([]*App, error) {
	return s.queryApps(`SELECT ` + appColumns + ` FROM apps ORDER BY name`)
}

// AppByID looks an app up by primary key and loads its lists.
func (s *Store) AppByID(id int64) (*App, error) {
	row := s.db.QueryRow(`SELECT `+appColumns+` FROM apps WHERE id = ?`, id)
	a, err := scanApp(row)
	if err != nil {
		return nil, err
	}
	if err := s.loadAppLists(a); err != nil {
		return nil, err
	}
	return a, nil
}

// AppByClientID is the lookup the OIDC token and authorize endpoints use.
func (s *Store) AppByClientID(clientID string) (*App, error) {
	row := s.db.QueryRow(`SELECT `+appColumns+` FROM apps WHERE client_id = ?`, clientID)
	a, err := scanApp(row)
	if err != nil {
		return nil, err
	}
	if err := s.loadAppLists(a); err != nil {
		return nil, err
	}
	return a, nil
}

// AppBySlug looks an app up by its short name.
func (s *Store) AppBySlug(slug string) (*App, error) {
	row := s.db.QueryRow(`SELECT `+appColumns+` FROM apps WHERE slug = ?`, slug)
	a, err := scanApp(row)
	if err != nil {
		return nil, err
	}
	if err := s.loadAppLists(a); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Store) queryApps(q string, args ...any) ([]*App, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}
	defer rows.Close()

	var out []*App
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// loadAppLists fills the URI, scope and grant-type lists of an app.
func (s *Store) loadAppLists(a *App) error {
	var err error
	if a.RedirectURIs, err = s.strings(`SELECT uri FROM app_redirect_uris WHERE app_id = ? ORDER BY uri`, a.ID); err != nil {
		return err
	}
	if a.PostLogoutRedirectURIs, err = s.strings(`SELECT uri FROM app_post_logout_redirect_uris WHERE app_id = ? ORDER BY uri`, a.ID); err != nil {
		return err
	}
	if a.Scopes, err = s.strings(`SELECT scope FROM app_scopes WHERE app_id = ? ORDER BY scope`, a.ID); err != nil {
		return err
	}
	if a.GrantTypes, err = s.strings(`SELECT grant_type FROM app_grant_types WHERE app_id = ? ORDER BY grant_type`, a.ID); err != nil {
		return err
	}
	return nil
}

func (s *Store) strings(q string, args ...any) ([]string, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query strings: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("scan string: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// NewApp is the input to CreateApp. The plaintext secret is returned once and
// never stored.
type NewApp struct {
	Slug                   string
	Name                   string
	Description            string
	HomepageURL            string
	ClientType             string
	TEAuthMethod           string
	OwnerUserID            int64
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	Scopes                 []string
	GrantTypes             []string
	RegistrationMode       string
	DefaultAccess          string
}

// CreateApp inserts an app and returns it together with the plaintext client
// secret, which is shown to the owner exactly once.
func (s *Store) CreateApp(in NewApp) (*App, string, error) {
	if in.Slug == "" || in.Name == "" {
		return nil, "", fmt.Errorf("%w: slug and name are required", ErrInvalid)
	}
	if in.ClientType == "" {
		in.ClientType = ClientConfidential
	}
	switch in.ClientType {
	case ClientConfidential, ClientPublic:
	default:
		return nil, "", fmt.Errorf("%w: unknown client type %q", ErrInvalid, in.ClientType)
	}
	if in.TEAuthMethod == "" {
		if in.ClientType == ClientPublic {
			in.TEAuthMethod = AuthNone
		} else {
			in.TEAuthMethod = AuthBasic
		}
	}
	if in.RegistrationMode == "" {
		in.RegistrationMode = RegClosed
	}
	if in.DefaultAccess == "" {
		in.DefaultAccess = AccessMembersOnly
	}
	if len(in.RedirectURIs) == 0 {
		return nil, "", fmt.Errorf("%w: at least one redirect URI is required", ErrInvalid)
	}
	for _, uri := range in.RedirectURIs {
		if err := ValidateRedirectURI(uri, in.ClientType); err != nil {
			return nil, "", err
		}
	}
	if len(in.Scopes) == 0 {
		in.Scopes = []string{"openid", "profile", "email"}
	}
	if len(in.GrantTypes) == 0 {
		in.GrantTypes = []string{"authorization_code", "refresh_token"}
	}

	clientID, err := randomHex(16)
	if err != nil {
		return nil, "", err
	}
	secret := ""
	secretHash := ""
	if in.ClientType == ClientConfidential {
		secret, err = randomTokenString(32)
		if err != nil {
			return nil, "", err
		}
		secretHash = HashToken(secret)
	}

	now := s.nowText()
	err = s.inTx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`INSERT INTO apps
			(slug, name, description, homepage_url, client_id, client_secret_hash,
			 client_type, token_endpoint_auth_method, require_pkce, owner_user_id,
			 status, registration_mode, default_access, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			in.Slug, in.Name, in.Description, in.HomepageURL, clientID, secretHash,
			in.ClientType, in.TEAuthMethod, boolToInt(in.ClientType == ClientPublic),
			in.OwnerUserID, AppActive, in.RegistrationMode, in.DefaultAccess, now, now)
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: an app with that slug or client id already exists", ErrConflict)
			}
			return fmt.Errorf("insert app: %w", err)
		}
		appID, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("insert app: %w", err)
		}
		for _, uri := range in.RedirectURIs {
			if _, err := tx.Exec(`INSERT INTO app_redirect_uris(app_id, uri) VALUES (?, ?)`, appID, uri); err != nil {
				return fmt.Errorf("insert redirect uri: %w", err)
			}
		}
		for _, uri := range in.PostLogoutRedirectURIs {
			if err := ValidateRedirectURI(uri, in.ClientType); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO app_post_logout_redirect_uris(app_id, uri) VALUES (?, ?)`, appID, uri); err != nil {
				return fmt.Errorf("insert post-logout redirect uri: %w", err)
			}
		}
		for _, scope := range in.Scopes {
			if _, err := tx.Exec(`INSERT INTO app_scopes(app_id, scope) VALUES (?, ?)`, appID, scope); err != nil {
				return fmt.Errorf("insert scope: %w", err)
			}
		}
		for _, gt := range in.GrantTypes {
			if _, err := tx.Exec(`INSERT INTO app_grant_types(app_id, grant_type) VALUES (?, ?)`, appID, gt); err != nil {
				return fmt.Errorf("insert grant type: %w", err)
			}
		}
		// The creator becomes the owner member.
		_, err = tx.Exec(`INSERT INTO app_memberships(app_id, user_id, role, status, created_at)
			VALUES (?, ?, ?, ?, ?)`, appID, in.OwnerUserID, RoleOwner, MemberActive, now)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	app, err := s.AppByClientID(clientID)
	if err != nil {
		return nil, "", err
	}
	return app, secret, nil
}

// RotateAppSecret replaces the client secret and returns the new plaintext.
// Existing tokens keep working until they expire, which is why the UI tells the
// owner to update the client first.
func (s *Store) RotateAppSecret(appID int64) (string, error) {
	app, err := s.AppByID(appID)
	if err != nil {
		return "", err
	}
	if app.ClientType != ClientConfidential {
		return "", fmt.Errorf("%w: public clients have no secret", ErrInvalid)
	}
	secret, err := randomTokenString(32)
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(`UPDATE apps SET client_secret_hash = ?, secret_rotated_at = ?, updated_at = ?
		WHERE id = ?`, HashToken(secret), s.nowText(), s.nowText(), appID)
	if err != nil {
		return "", fmt.Errorf("rotate secret: %w", err)
	}
	return secret, nil
}

// SetAppStatus activates or suspends an app.
func (s *Store) SetAppStatus(appID int64, status string) error {
	switch status {
	case AppActive, AppSuspended:
	default:
		return fmt.Errorf("%w: unknown app status %q", ErrInvalid, status)
	}
	_, err := s.db.Exec(`UPDATE apps SET status = ?, updated_at = ? WHERE id = ?`,
		status, s.nowText(), appID)
	if err != nil {
		return fmt.Errorf("set app status: %w", err)
	}
	return nil
}

// AppMembership is a user's relationship with an app.
type AppMembership struct {
	AppID     int64
	UserID    int64
	Role      string
	Status    string
	CreatedAt time.Time
}

// Membership returns a user's membership in an app, or ErrNotFound.
func (s *Store) Membership(appID, userID int64) (*AppMembership, error) {
	var m AppMembership
	var createdAt string
	row := s.db.QueryRow(`SELECT app_id, user_id, role, status, created_at
		FROM app_memberships WHERE app_id = ? AND user_id = ?`, appID, userID)
	err := row.Scan(&m.AppID, &m.UserID, &m.Role, &m.Status, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan membership: %w", err)
	}
	m.CreatedAt = parseTime(createdAt)
	return &m, nil
}

// randomHex returns n random bytes, base64url encoded.
func randomHex(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// randomTokenString returns n random bytes, base64url encoded.
func randomTokenString(n int) (string, error) { return randomHex(n) }

// NewAppMembership columns are written with the owner as the first member; see
// CreateApp.

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
