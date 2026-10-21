package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Access describes whether a user may sign in to an app, and why. The reason is
// returned so the UI can explain a refusal without the caller re-deriving it.
type Access struct {
	Allowed bool
	// Reason is one of the AccessReason values.
	Reason string
	// Role is the user's role in the app when they are a member.
	Role string
}

// Reasons an access decision can carry.
const (
	ReasonSuperAdmin   = "super_admin"
	ReasonMember       = "member"
	ReasonGroup        = "group"
	ReasonAllUsers     = "all_users"
	ReasonPending      = "pending_approval"
	ReasonBlocked      = "blocked"
	ReasonSuspended    = "app_suspended"
	ReasonUserStatus   = "user_not_active"
	ReasonNotPermitted = "not_permitted"
)

// CanUseApp decides whether a user may sign in to an app. It is the single
// place that answers this question, so every caller agrees: the authorize
// endpoint, the forward-auth endpoint, and the admin UI all call it.
//
// The rules, in order:
//  1. A suspended app, or an account that is not active, refuses everyone.
//  2. The super admin may use every active app.
//  3. A blocked membership refuses.
//  4. A pending membership refuses with a reason the UI can act on.
//  5. An active membership allows, with its role.
//  6. A granted group allows.
//  7. Otherwise, an app whose default access is all_users allows any active user.
func (s *Store) CanUseApp(app *App, user *User) (*Access, error) {
	if app.Status != AppActive {
		return &Access{Allowed: false, Reason: ReasonSuspended}, nil
	}
	if user == nil || user.Status != UserActive {
		return &Access{Allowed: false, Reason: ReasonUserStatus}, nil
	}
	if user.IsSuperAdmin {
		return &Access{Allowed: true, Reason: ReasonSuperAdmin}, nil
	}

	m, err := s.Membership(app.ID, user.ID)
	switch {
	case err == nil:
		switch m.Status {
		case MemberBlocked:
			return &Access{Allowed: false, Reason: ReasonBlocked, Role: m.Role}, nil
		case MemberPending:
			return &Access{Allowed: false, Reason: ReasonPending}, nil
		case MemberActive:
			return &Access{Allowed: true, Reason: ReasonMember, Role: m.Role}, nil
		}
		return &Access{Allowed: false, Reason: ReasonNotPermitted}, nil
	case errors.Is(err, ErrNotFound):
		// Fall through to the group and default checks.
	default:
		return nil, err
	}

	inGroup, err := s.UserInAppGroups(app.ID, user.ID)
	if err != nil {
		return nil, err
	}
	if inGroup {
		return &Access{Allowed: true, Reason: ReasonGroup}, nil
	}

	if app.DefaultAccess == AccessAllUsers {
		return &Access{Allowed: true, Reason: ReasonAllUsers}, nil
	}
	return &Access{Allowed: false, Reason: ReasonNotPermitted}, nil
}

// UserInAppGroups reports whether any group granted to the app contains the user.
func (s *Store) UserInAppGroups(appID, userID int64) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*)
		FROM app_group_access aga
		JOIN group_members gm ON gm.group_id = aga.group_id
		WHERE aga.app_id = ? AND gm.user_id = ?`, appID, userID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("check group access: %w", err)
	}
	return n > 0, nil
}

// SetMembership creates or updates a user's relationship with an app.
func (s *Store) SetMembership(appID, userID int64, role, status string, approvedBy int64) error {
	now := s.nowText()
	_, err := s.db.Exec(`INSERT INTO app_memberships(app_id, user_id, role, status, created_at, approved_by)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(app_id, user_id) DO UPDATE SET role = excluded.role, status = excluded.status,
			approved_by = excluded.approved_by`,
		appID, userID, role, status, now, nullInt(approvedBy))
	if err != nil {
		return fmt.Errorf("set membership: %w", err)
	}
	return nil
}

// SetUserGroups replaces the groups a user belongs to. It is used by the admin
// UI, which sends the complete desired set.
func (s *Store) SetUserGroups(userID int64, groupIDs []int64) error {
	return s.inTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM group_members WHERE user_id = ?`, userID); err != nil {
			return fmt.Errorf("clear group memberships: %w", err)
		}
		now := s.nowText()
		for _, gid := range groupIDs {
			if _, err := tx.Exec(`INSERT INTO group_members(group_id, user_id, added_at) VALUES (?, ?, ?)`,
				gid, userID, now); err != nil {
				return fmt.Errorf("add group member: %w", err)
			}
		}
		return nil
	})
}

// Group is a named set of users.
type Group struct {
	ID          int64
	Name        string
	Description string
	CreatedAt   time.Time
	MemberCount int
}

// ListGroups returns every group with its member count.
func (s *Store) ListGroups() ([]*Group, error) {
	rows, err := s.db.Query(`SELECT g.id, g.name, g.description, g.created_at,
			(SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id)
		FROM groups g ORDER BY g.name`)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()

	var out []*Group
	for rows.Next() {
		var g Group
		var createdAt string
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &createdAt, &g.MemberCount); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		g.CreatedAt = parseTime(createdAt)
		out = append(out, &g)
	}
	return out, rows.Err()
}

// CreateGroup inserts a group.
func (s *Store) CreateGroup(name, description string) (*Group, error) {
	name, err := validateGroup(name, description)
	if err != nil {
		return nil, err
	}
	res, err := s.db.Exec(`INSERT INTO groups(name, description, created_at) VALUES (?, ?, ?)`,
		name, description, s.nowText())
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: a group with that name already exists", ErrConflict)
		}
		return nil, fmt.Errorf("insert group: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("insert group: %w", err)
	}
	return &Group{ID: id, Name: name, Description: description, CreatedAt: s.now()}, nil
}

// SetAppGroups replaces the groups granted access to an app.
func (s *Store) SetAppGroups(appID int64, groupIDs []int64) error {
	return s.inTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM app_group_access WHERE app_id = ?`, appID); err != nil {
			return fmt.Errorf("clear app groups: %w", err)
		}
		for _, gid := range groupIDs {
			if _, err := tx.Exec(`INSERT INTO app_group_access(app_id, group_id) VALUES (?, ?)`,
				appID, gid); err != nil {
				return fmt.Errorf("grant group: %w", err)
			}
		}
		return nil
	})
}

// nullInt renders 0 as SQL NULL, for optional foreign keys.
func nullInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
