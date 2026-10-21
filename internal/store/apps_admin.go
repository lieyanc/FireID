package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// SlugMaxLen bounds an app slug, which appears in URLs and nginx config.
const SlugMaxLen = 63

// ValidateSlug accepts lowercase ASCII letters, digits and inner hyphens.
func ValidateSlug(slug string) error {
	if slug == "" || len(slug) > SlugMaxLen {
		return fmt.Errorf("%w: slug must be 1 to %d characters", ErrInvalid, SlugMaxLen)
	}
	for _, r := range slug {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return fmt.Errorf("%w: slug may contain only lowercase letters, digits and hyphens", ErrInvalid)
		}
	}
	if slug[0] == '-' || slug[len(slug)-1] == '-' {
		return fmt.Errorf("%w: slug must not start or end with a hyphen", ErrInvalid)
	}
	return nil
}

// validateAppPolicy checks an app's enum fields against each other.
func validateAppPolicy(clientType, authMethod, mode, access string) error {
	switch mode {
	case RegClosed, RegInvite, RegOpen, RegAdminApproval:
	default:
		return fmt.Errorf("%w: unknown registration mode %q", ErrInvalid, mode)
	}
	switch access {
	case AccessAllUsers, AccessGroups, AccessMembersOnly:
	default:
		return fmt.Errorf("%w: unknown default access %q", ErrInvalid, access)
	}
	ok := false
	switch authMethod {
	case AuthBasic, AuthPost:
		ok = clientType == ClientConfidential
	case AuthNone:
		ok = clientType == ClientPublic
	}
	if !ok {
		return fmt.Errorf("%w: token auth method %q does not fit a %s client", ErrInvalid, authMethod, clientType)
	}
	return nil
}

// validateHomepage accepts an empty value or an absolute http(s) URL.
func validateHomepage(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%w: homepage must be an http or https URL", ErrInvalid)
	}
	return nil
}

// validateGroup checks a group's name and description.
func validateGroup(name, description string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 100 {
		return "", fmt.Errorf("%w: name must be 1 to 100 characters", ErrInvalid)
	}
	if !groupNameOK(name) {
		return "", fmt.Errorf("%w: a group name may not contain commas or control characters", ErrInvalid)
	}
	if len([]rune(description)) > 500 {
		return "", fmt.Errorf("%w: description is longer than 500 characters", ErrInvalid)
	}
	return name, nil
}

// AppUpdate is a partial change to an app. A nil field is left alone; a nil
// list is left alone, an empty one clears it (redirect URIs may not be empty).
type AppUpdate struct {
	Name             *string
	Description      *string
	HomepageURL      *string
	RegistrationMode *string
	DefaultAccess    *string
	TEAuthMethod     *string
	RedirectURIs     []string
	PostLogoutURIs   []string
}

// UpdateApp applies a partial change. Every value is validated against the
// app's client type before anything is written.
func (s *Store) UpdateApp(appID int64, in AppUpdate) error {
	app, err := s.AppByID(appID)
	if err != nil {
		return err
	}
	var sets []string
	var args []any
	set := func(col string, v any) {
		sets = append(sets, col+" = ?")
		args = append(args, v)
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" || len([]rune(name)) > 100 {
			return fmt.Errorf("%w: name must be 1 to 100 characters", ErrInvalid)
		}
		set("name", name)
	}
	if in.Description != nil {
		if len([]rune(*in.Description)) > 500 {
			return fmt.Errorf("%w: description is longer than 500 characters", ErrInvalid)
		}
		set("description", *in.Description)
	}
	if in.HomepageURL != nil {
		if err := validateHomepage(*in.HomepageURL); err != nil {
			return err
		}
		set("homepage_url", *in.HomepageURL)
	}
	mode, access, method := app.RegistrationMode, app.DefaultAccess, app.TEAuthMethod
	if in.RegistrationMode != nil {
		mode = *in.RegistrationMode
		set("registration_mode", mode)
	}
	if in.DefaultAccess != nil {
		access = *in.DefaultAccess
		set("default_access", access)
	}
	if in.TEAuthMethod != nil {
		method = *in.TEAuthMethod
		set("token_endpoint_auth_method", method)
	}
	if err := validateAppPolicy(app.ClientType, method, mode, access); err != nil {
		return err
	}
	if in.RedirectURIs != nil && len(in.RedirectURIs) == 0 {
		return fmt.Errorf("%w: at least one redirect URI is required", ErrInvalid)
	}
	for _, uri := range append(append([]string{}, in.RedirectURIs...), in.PostLogoutURIs...) {
		if err := ValidateRedirectURI(uri, app.ClientType); err != nil {
			return err
		}
	}

	return s.inTx(func(tx *sql.Tx) error {
		set("updated_at", s.nowText())
		if _, err := tx.Exec(`UPDATE apps SET `+strings.Join(sets, ", ")+` WHERE id = ?`,
			append(args, appID)...); err != nil {
			return fmt.Errorf("update app: %w", err)
		}
		if err := replaceList(tx, "app_redirect_uris", "uri", appID, in.RedirectURIs); err != nil {
			return err
		}
		return replaceList(tx, "app_post_logout_redirect_uris", "uri", appID, in.PostLogoutURIs)
	})
}

// replaceList swaps the rows of one of the app's list tables. A nil list
// leaves the table alone. Table and column names are constants of this file.
func replaceList(tx *sql.Tx, table, col string, appID int64, values []string) error {
	if values == nil {
		return nil
	}
	if _, err := tx.Exec(`DELETE FROM `+table+` WHERE app_id = ?`, appID); err != nil {
		return fmt.Errorf("clear %s: %w", table, err)
	}
	seen := map[string]bool{}
	for _, v := range values {
		if seen[v] {
			continue
		}
		seen[v] = true
		if _, err := tx.Exec(`INSERT INTO `+table+`(app_id, `+col+`) VALUES (?, ?)`, appID, v); err != nil {
			return fmt.Errorf("insert %s: %w", table, err)
		}
	}
	return nil
}

// DeleteApp removes an app. Its URIs, memberships, requests and every token
// issued to it go with it (ON DELETE CASCADE); audit rows keep a NULL app.
func (s *Store) DeleteApp(appID int64) error {
	res, err := s.db.Exec(`DELETE FROM apps WHERE id = ?`, appID)
	if err != nil {
		return fmt.Errorf("delete app: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CanManageApp reports whether user may administer app: a super admin, the
// owner, or an active member with the owner or admin role. This is the only
// place that question is answered.
func (s *Store) CanManageApp(user *User, app *App) (bool, error) {
	if user == nil || app == nil || user.Status != UserActive {
		return false, nil
	}
	if user.IsSuperAdmin || app.OwnerUserID == user.ID {
		return true, nil
	}
	m, err := s.Membership(app.ID, user.ID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return m.Status == MemberActive && (m.Role == RoleOwner || m.Role == RoleAdmin), nil
}

// ManagedApps lists the apps user may administer: every app for a super
// admin, otherwise owned apps plus those where user is an active owner/admin.
func (s *Store) ManagedApps(user *User) ([]*App, error) {
	if user.IsSuperAdmin {
		return s.ListApps()
	}
	return s.queryApps(`SELECT `+appColumns+` FROM apps WHERE owner_user_id = ?
		OR id IN (SELECT app_id FROM app_memberships
			WHERE user_id = ? AND status = ? AND role IN (?, ?))
		ORDER BY slug`, user.ID, user.ID, MemberActive, RoleOwner, RoleAdmin)
}

// AppMember is a membership with the user it belongs to.
type AppMember struct {
	AppMembership
	User *User
}

// ListAppMembers returns an app's memberships, oldest first.
func (s *Store) ListAppMembers(appID int64) ([]*AppMember, error) {
	rows, err := s.db.Query(`SELECT m.role, m.status, m.created_at, `+prefixed("u.", userColumns)+`
		FROM app_memberships m JOIN users u ON u.id = m.user_id
		WHERE m.app_id = ? ORDER BY m.created_at, u.id`, appID)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	defer rows.Close()
	var out []*AppMember
	for rows.Next() {
		m := &AppMember{AppMembership: AppMembership{AppID: appID}}
		var createdAt string
		u, err := scanUser(prependScan(rows, &m.Role, &m.Status, &createdAt))
		if err != nil {
			return nil, err
		}
		m.UserID, m.User, m.CreatedAt = u.ID, u, parseTime(createdAt)
		out = append(out, m)
	}
	return out, rows.Err()
}

// RemoveMembership deletes a user's membership. The owner's cannot be removed.
func (s *Store) RemoveMembership(appID, userID int64) error {
	res, err := s.db.Exec(`DELETE FROM app_memberships WHERE app_id = ? AND user_id = ?
		AND user_id <> (SELECT owner_user_id FROM apps WHERE id = ?)`, appID, userID, appID)
	if err != nil {
		return fmt.Errorf("remove membership: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var owner int64
		if err := s.db.QueryRow(`SELECT owner_user_id FROM apps WHERE id = ?`, appID).Scan(&owner); err == nil && owner == userID {
			return fmt.Errorf("%w: the owner's membership cannot be removed", ErrInvalid)
		}
		return ErrNotFound
	}
	return nil
}

// AppGroupIDs returns the IDs of the groups granted access to the app.
func (s *Store) AppGroupIDs(appID int64) ([]int64, error) {
	return s.int64s(`SELECT group_id FROM app_group_access WHERE app_id = ? ORDER BY group_id`, appID)
}

// GroupByID returns a group with its member count, or ErrNotFound.
func (s *Store) GroupByID(id int64) (*Group, error) {
	var g Group
	var createdAt string
	err := s.db.QueryRow(`SELECT g.id, g.name, g.description, g.created_at,
			(SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id)
		FROM groups g WHERE g.id = ?`, id).Scan(&g.ID, &g.Name, &g.Description, &createdAt, &g.MemberCount)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("group: %w", err)
	}
	g.CreatedAt = parseTime(createdAt)
	return &g, nil
}

// GroupMembers returns the users in a group, oldest first.
func (s *Store) GroupMembers(groupID int64) ([]*User, error) {
	rows, err := s.db.Query(`SELECT `+prefixed("u.", userColumns)+`
		FROM group_members gm JOIN users u ON u.id = gm.user_id
		WHERE gm.group_id = ? ORDER BY gm.added_at, u.id`, groupID)
	if err != nil {
		return nil, fmt.Errorf("group members: %w", err)
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

// SetGroupMembers replaces a group's membership.
func (s *Store) SetGroupMembers(groupID int64, userIDs []int64) error {
	return s.inTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM group_members WHERE group_id = ?`, groupID); err != nil {
			return fmt.Errorf("clear members: %w", err)
		}
		now := s.nowText()
		for _, uid := range userIDs {
			if _, err := tx.Exec(`INSERT INTO group_members(group_id, user_id, added_at) VALUES (?, ?, ?)`,
				groupID, uid, now); err != nil {
				if isForeignKeyViolation(err) {
					return fmt.Errorf("%w: user %d not found", ErrInvalid, uid)
				}
				return fmt.Errorf("insert member: %w", err)
			}
		}
		return nil
	})
}

// UpdateGroup changes a group's name and description.
func (s *Store) UpdateGroup(groupID int64, name, description string) error {
	name, err := validateGroup(name, description)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE groups SET name = ?, description = ? WHERE id = ?`, name, description, groupID)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: a group with that name already exists", ErrConflict)
		}
		return fmt.Errorf("update group: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteGroup removes a group; its memberships and app grants cascade.
func (s *Store) DeleteGroup(groupID int64) error {
	res, err := s.db.Exec(`DELETE FROM groups WHERE id = ?`, groupID)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AccessRequest is a user's request to use an app, tracked until decided.
type AccessRequest struct {
	ID        int64
	AppID     int64
	UserID    int64
	Message   string
	Status    string
	CreatedAt time.Time
	DecidedAt time.Time
	DecidedBy int64
}

// AccessRequestDetail is a request with the user's details.
type AccessRequestDetail struct {
	AccessRequest
	User *User
}

// CreateAccessRequest inserts a pending request; a user may have one per app.
func (s *Store) CreateAccessRequest(appID, userID int64, message string) (*AccessRequest, error) {
	if len([]rune(message)) > 500 {
		return nil, fmt.Errorf("%w: message is longer than 500 characters", ErrInvalid)
	}
	now := s.now()
	res, err := s.db.Exec(`INSERT INTO access_requests(app_id, user_id, message, status, created_at)
		VALUES (?, ?, ?, ?, ?)`, appID, userID, message, "pending", formatTime(now))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: a pending request already exists", ErrConflict)
		}
		if isForeignKeyViolation(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("insert request: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("last insert: %w", err)
	}
	return &AccessRequest{
		ID: id, AppID: appID, UserID: userID, Message: message, Status: "pending", CreatedAt: now,
	}, nil
}

// PendingAccessRequests lists the pending requests for an app, oldest first.
func (s *Store) PendingAccessRequests(appID int64) ([]*AccessRequestDetail, error) {
	rows, err := s.db.Query(`SELECT r.id, r.user_id, r.message, r.created_at, `+prefixed("u.", userColumns)+`
		FROM access_requests r JOIN users u ON u.id = r.user_id
		WHERE r.app_id = ? AND r.status = ? ORDER BY r.created_at, r.id`, appID, "pending")
	if err != nil {
		return nil, fmt.Errorf("pending requests: %w", err)
	}
	defer rows.Close()
	var out []*AccessRequestDetail
	for rows.Next() {
		var d AccessRequestDetail
		d.AppID, d.Status = appID, "pending"
		var createdAt string
		u, err := scanUser(prependScan(rows, &d.ID, &d.UserID, &d.Message, &createdAt))
		if err != nil {
			return nil, err
		}
		d.User, d.CreatedAt = u, parseTime(createdAt)
		out = append(out, &d)
	}
	return out, rows.Err()
}

// DecideAccessRequest approves or denies a request. An owner may only decide
// requests for their own apps. If approved, the user becomes an active member.
func (s *Store) DecideAccessRequest(appID, requestID, decidedBy int64, approve bool) (*AccessRequest, error) {
	var r AccessRequest
	err := s.inTx(func(tx *sql.Tx) error {
		var status, createdAt string
		err := tx.QueryRow(`SELECT app_id, user_id, message, status, created_at
			FROM access_requests WHERE id = ?`, requestID).Scan(&r.AppID, &r.UserID, &r.Message, &status,
			&createdAt)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && r.AppID != appID) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("lookup request: %w", err)
		}
		if status != "pending" {
			return fmt.Errorf("%w: request already decided", ErrConflict)
		}
		r.ID, r.CreatedAt = requestID, parseTime(createdAt)

		newStatus := "denied"
		if approve {
			newStatus = "approved"
		}
		now := s.nowText()
		if _, err := tx.Exec(`UPDATE access_requests SET status = ?, decided_at = ?, decided_by = ?
			WHERE id = ?`, newStatus, now, decidedBy, requestID); err != nil {
			return fmt.Errorf("update request: %w", err)
		}
		r.Status, r.DecidedAt, r.DecidedBy = newStatus, parseTime(now), decidedBy

		if approve {
			_, err := tx.Exec(`INSERT INTO app_memberships(app_id, user_id, role, status, created_at, approved_by)
				VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT(app_id, user_id) DO UPDATE SET status = ?, approved_by = ?`,
				r.AppID, r.UserID, RoleMember, MemberActive, now, decidedBy, MemberActive, decidedBy)
			if err != nil {
				return fmt.Errorf("create membership: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// UserByLogin returns the user for an exact username or email match.
func (s *Store) UserByLogin(q string) (*User, error) {
	u, err := s.UserByUsername(q)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return s.UserByEmail(q)
}

// SearchUsers finds users whose username, email or display name starts with q,
// up to limit (default 20).
func (s *Store) SearchUsers(q string, limit int) ([]*User, error) {
	if limit <= 0 {
		limit = 20
	}
	// Escape SQL LIKE wildcards so a search for "test_user" doesn't match "test%user".
	escaped := strings.NewReplacer("%", `\%`, "_", `\_`).Replace(q)
	pattern := escaped + "%"
	rows, err := s.db.Query(`SELECT `+userColumns+` FROM users
		WHERE username LIKE ? ESCAPE '\' OR email LIKE ? ESCAPE '\' OR display_name LIKE ? ESCAPE '\'
		ORDER BY username LIMIT ?`, pattern, pattern, pattern, limit)
	if err != nil {
		return nil, fmt.Errorf("search users: %w", err)
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

// int64s is a helper that returns a single-column result as a slice of int64.
func (s *Store) int64s(q string, args ...any) ([]int64, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// prefixed adds a prefix to every column in a comma-separated list.
func prefixed(pfx, list string) string {
	cols := strings.Split(list, ",")
	for i, c := range cols {
		cols[i] = pfx + strings.TrimSpace(c)
	}
	return strings.Join(cols, ", ")
}

// prependScan wraps a row so its Scan(...) method takes extra pointers before
// the ones scanUser expects. Use: scanUser(prependScan(row, &a, &b)).
func prependScan(row interface{ Scan(...any) error }, head ...any) prependedRow {
	return prependedRow{row: row, head: head}
}

type prependedRow struct {
	row  interface{ Scan(...any) error }
	head []any
}

func (p prependedRow) Scan(tail ...any) error {
	return p.row.Scan(append(p.head, tail...)...)
}
