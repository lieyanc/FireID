package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Self-service access: the catalog of apps a user may see, joining an open app,
// asking for an admin_approval one, and invitations. Whether someone may use
// an app is still decided only by CanUseApp; these functions act on its Join
// answer.

// Catalog states.
const (
	CatalogAllowed   = "allowed"
	CatalogPending   = "pending"
	CatalogAvailable = "available"
)

// CatalogEntry is one app in a user's catalog.
type CatalogEntry struct {
	App *App
	// State is CatalogAllowed, CatalogPending or CatalogAvailable.
	State string
	// Join is the Access.Join value: JoinSelf, JoinRequest or "".
	Join string
}

// CatalogEntry answers whether an app belongs in a user's catalog: every
// active app they may use, every app they may join or ask for, and apps where
// their request is pending. It returns ErrNotFound for anything else, so a
// caller cannot tell a hidden app from a missing one.
func (s *Store) CatalogEntry(app *App, user *User) (*CatalogEntry, error) {
	if app.Status != AppActive {
		return nil, ErrNotFound
	}
	acc, err := s.CanUseApp(app, user)
	if err != nil {
		return nil, err
	}
	switch {
	case acc.Allowed:
		return &CatalogEntry{App: app, State: CatalogAllowed}, nil
	case acc.Reason == ReasonPending:
		return &CatalogEntry{App: app, State: CatalogPending}, nil
	case acc.Join != "":
		return &CatalogEntry{App: app, State: CatalogAvailable, Join: acc.Join}, nil
	}
	return nil, ErrNotFound
}

// Catalog lists a user's catalog, sorted by name.
func (s *Store) Catalog(user *User) ([]*CatalogEntry, error) {
	apps, err := s.queryApps(`SELECT `+appColumns+` FROM apps WHERE status = ? ORDER BY name, id`, AppActive)
	if err != nil {
		return nil, err
	}
	out := []*CatalogEntry{}
	for _, a := range apps {
		e, err := s.CatalogEntry(a, user)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// JoinApp makes the user an active member of the app. The caller has checked
// that CanUseApp offers JoinSelf; an existing membership of any kind is a
// conflict and is left alone.
func (s *Store) JoinApp(appID, userID int64) error {
	res, err := s.db.Exec(`INSERT INTO app_memberships(app_id, user_id, role, status, created_at)
		VALUES (?, ?, ?, ?, ?) ON CONFLICT(app_id, user_id) DO NOTHING`,
		appID, userID, RoleMember, MemberActive, s.nowText())
	if err != nil {
		if isForeignKeyViolation(err) {
			return ErrNotFound
		}
		return fmt.Errorf("join app: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: already a member", ErrConflict)
	}
	return nil
}

// RequestAppAccess records a pending membership and an access request in one
// transaction. The caller has checked that CanUseApp offers JoinRequest. A
// second request while one is pending is a conflict.
func (s *Store) RequestAppAccess(appID, userID int64, message string) (*AccessRequest, error) {
	var req *AccessRequest
	err := s.inTx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`INSERT INTO app_memberships(app_id, user_id, role, status, created_at)
			VALUES (?, ?, ?, ?, ?) ON CONFLICT(app_id, user_id) DO NOTHING`,
			appID, userID, RoleMember, MemberPending, s.nowText())
		if err != nil {
			if isForeignKeyViolation(err) {
				return ErrNotFound
			}
			return fmt.Errorf("pending membership: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%w: a membership already exists", ErrConflict)
		}
		req, err = s.createAccessRequest(tx, appID, userID, message)
		return err
	})
	if err != nil {
		return nil, err
	}
	return req, nil
}

// AppManagers returns the people who manage an app and should hear about a
// request: the owning account and every active owner or admin member.
func (s *Store) AppManagers(app *App) ([]*User, error) {
	rows, err := s.db.Query(`SELECT `+prefixed("u.", userColumns)+` FROM users u
		WHERE u.status = ? AND (u.id = ? OR u.id IN (SELECT user_id FROM app_memberships
			WHERE app_id = ? AND status = ? AND role IN (?, ?)))
		ORDER BY u.id`, UserActive, app.OwnerUserID, app.ID, MemberActive, RoleOwner, RoleAdmin)
	if err != nil {
		return nil, fmt.Errorf("app managers: %w", err)
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Invites
// ---------------------------------------------------------------------------

// Invite limits.
const (
	InviteMaxDays = 30
	InviteMaxUses = 100
)

// ErrInviteEmailMismatch is returned when an invite bound to an address is
// accepted by an account with another one.
var ErrInviteEmailMismatch = errors.New("this invitation is for a different email address")

// ErrMembershipBlocked is returned when an invite is accepted by someone the
// app has blocked; an invite never lifts a block.
var ErrMembershipBlocked = errors.New("the account is blocked from this application")

// Invite is an invitation to one app. The token itself is never stored.
type Invite struct {
	ID        int64
	AppID     int64
	Email     string
	Role      string
	CreatedBy int64
	CreatedAt time.Time
	ExpiresAt time.Time
	MaxUses   int
	Uses      int
	RevokedAt time.Time
	// Creator is filled by ListInvites; nil when the account is gone.
	Creator *User
}

const inviteColumns = `id, app_id, email, role, COALESCE(created_by, 0), created_at, expires_at,
	max_uses, uses, revoked_at`

func scanInvite(row interface{ Scan(...any) error }) (*Invite, error) {
	var inv Invite
	var created, expires, revoked string
	err := row.Scan(&inv.ID, &inv.AppID, &inv.Email, &inv.Role, &inv.CreatedBy, &created, &expires,
		&inv.MaxUses, &inv.Uses, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan invite: %w", err)
	}
	inv.CreatedAt, inv.ExpiresAt, inv.RevokedAt = parseTime(created), parseTime(expires), parseTime(revoked)
	return &inv, nil
}

// NewInvite is the input to CreateInvite.
type NewInvite struct {
	AppID     int64
	CreatedBy int64
	// Email binds the invite to one address; "" for anyone with the link.
	Email   string
	Role    string
	TTL     time.Duration
	MaxUses int
}

// CreateInvite stores an invite and returns it with the plaintext token, which
// is shown to the manager once.
func (s *Store) CreateInvite(in NewInvite) (*Invite, string, error) {
	if in.Email != "" {
		in.Email = NormaliseEmail(in.Email)
		if err := ValidateEmail(in.Email); err != nil {
			return nil, "", err
		}
	}
	switch in.Role {
	case RoleMember, RoleAdmin:
	default:
		return nil, "", fmt.Errorf("%w: role must be member or admin", ErrInvalid)
	}
	if in.TTL <= 0 || in.TTL > InviteMaxDays*24*time.Hour {
		return nil, "", fmt.Errorf("%w: an invite lasts 1 to %d days", ErrInvalid, InviteMaxDays)
	}
	if in.MaxUses < 1 || in.MaxUses > InviteMaxUses {
		return nil, "", fmt.Errorf("%w: an invite may be used 1 to %d times", ErrInvalid, InviteMaxUses)
	}
	token, err := randomTokenString(32)
	if err != nil {
		return nil, "", err
	}
	now := s.now()
	res, err := s.db.Exec(`INSERT INTO app_invites(app_id, token_hash, email, role, created_by,
			created_at, expires_at, max_uses)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, in.AppID, HashToken(token), in.Email, in.Role,
		nullInt(in.CreatedBy), formatTime(now), formatTime(now.Add(in.TTL)), in.MaxUses)
	if err != nil {
		if isForeignKeyViolation(err) {
			return nil, "", ErrNotFound
		}
		return nil, "", fmt.Errorf("insert invite: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, "", fmt.Errorf("insert invite: %w", err)
	}
	inv, err := s.inviteByID(in.AppID, id)
	if err != nil {
		return nil, "", err
	}
	return inv, token, nil
}

func (s *Store) inviteByID(appID, id int64) (*Invite, error) {
	return scanInvite(s.db.QueryRow(`SELECT `+inviteColumns+` FROM app_invites
		WHERE id = ? AND app_id = ?`, id, appID))
}

// ListInvites returns an app's invites, newest first: every one still usable
// and those that ended in the last 30 days.
func (s *Store) ListInvites(appID int64) ([]*Invite, error) {
	cutoff := formatTime(s.now().Add(-30 * 24 * time.Hour))
	rows, err := s.db.Query(`SELECT `+inviteColumns+` FROM app_invites
		WHERE app_id = ? AND (created_at >= ? OR expires_at >= ?)
		ORDER BY created_at DESC, id DESC LIMIT 200`, appID, cutoff, cutoff)
	if err != nil {
		return nil, fmt.Errorf("list invites: %w", err)
	}
	var out []*Invite
	for rows.Next() {
		inv, err := scanInvite(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, inv)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, inv := range out {
		if inv.CreatedBy == 0 {
			continue
		}
		u, err := s.UserByID(inv.CreatedBy)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		inv.Creator = u
	}
	return out, nil
}

// RevokeInvite ends an invite. Revoking one twice keeps the first time.
func (s *Store) RevokeInvite(appID, id int64) (*Invite, error) {
	if _, err := s.db.Exec(`UPDATE app_invites SET revoked_at = ?
		WHERE id = ? AND app_id = ? AND revoked_at = ''`, s.nowText(), id, appID); err != nil {
		return nil, fmt.Errorf("revoke invite: %w", err)
	}
	return s.inviteByID(appID, id)
}

// InviteByToken returns a usable invite: known, not revoked, not expired and
// not used up. Every other case is ErrNotFound, so the answer says nothing
// about which.
func (s *Store) InviteByToken(token string) (*Invite, error) {
	if token == "" || len(token) > 128 {
		return nil, ErrNotFound
	}
	return scanInvite(s.db.QueryRow(`SELECT `+inviteColumns+` FROM app_invites
		WHERE token_hash = ? AND revoked_at = '' AND expires_at > ? AND uses < max_uses`,
		HashToken(token), s.nowText()))
}

// roleRank orders membership roles so an invite never downgrades one.
func roleRank(role string) int {
	switch role {
	case RoleOwner:
		return 3
	case RoleAdmin:
		return 2
	case RoleMember:
		return 1
	}
	return 0
}

// AcceptInvite spends one use of an invite and makes the user an active
// member with the invite's role, or keeps a higher role they already have. The
// use is counted in the same UPDATE that checks the limit, so two people
// racing for the last use cannot both get it. A blocked membership stays
// blocked (ErrMembershipBlocked) and an address-bound invite needs that
// address (ErrInviteEmailMismatch); neither spends a use.
func (s *Store) AcceptInvite(token string, user *User) (*Invite, error) {
	var inv *Invite
	err := s.inTx(func(tx *sql.Tx) error {
		now := s.nowText()
		var err error
		inv, err = scanInvite(tx.QueryRow(`SELECT `+inviteColumns+` FROM app_invites
			WHERE token_hash = ? AND revoked_at = '' AND expires_at > ? AND uses < max_uses`,
			HashToken(token), now))
		if err != nil {
			return err
		}
		if inv.Email != "" && !strings.EqualFold(inv.Email, user.Email) {
			return ErrInviteEmailMismatch
		}
		var role, status string
		err = tx.QueryRow(`SELECT role, status FROM app_memberships WHERE app_id = ? AND user_id = ?`,
			inv.AppID, user.ID).Scan(&role, &status)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			role = ""
		case err != nil:
			return fmt.Errorf("lookup membership: %w", err)
		case status == MemberBlocked:
			return ErrMembershipBlocked
		}
		res, err := tx.Exec(`UPDATE app_invites SET uses = uses + 1
			WHERE id = ? AND revoked_at = '' AND expires_at > ? AND uses < max_uses`, inv.ID, now)
		if err != nil {
			return fmt.Errorf("spend invite: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		inv.Uses++
		if roleRank(inv.Role) > roleRank(role) {
			role = inv.Role
		}
		_, err = tx.Exec(`INSERT INTO app_memberships(app_id, user_id, role, status, created_at, approved_by)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(app_id, user_id) DO UPDATE SET role = excluded.role, status = excluded.status`,
			inv.AppID, user.ID, role, MemberActive, now, nullInt(inv.CreatedBy))
		if err != nil {
			return fmt.Errorf("invite membership: %w", err)
		}
		// A request still pending is settled by the invite; the inviter is
		// recorded as the one who decided it (NULL if their account is gone).
		return closePendingRequest(tx, inv.AppID, user.ID, inv.CreatedBy, now)
	})
	if err != nil {
		return nil, err
	}
	return inv, nil
}
