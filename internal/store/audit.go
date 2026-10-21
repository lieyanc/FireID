package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Audit severities.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Audit actor types.
const (
	ActorUser   = "user"
	ActorAdmin  = "admin"
	ActorSystem = "system"
	ActorClient = "client"
)

// AuditRetention is how long audit rows are kept.
const AuditRetention = 180 * 24 * time.Hour

// AuditEvent is one entry to record. Zero IDs are stored as NULL. Detail must
// never hold a secret: it is shown to administrators as is.
type AuditEvent struct {
	Event       string
	Severity    string
	ActorUserID int64
	ActorType   string
	AppID       int64
	UserID      int64
	IP          string
	UserAgent   string
	Detail      map[string]any
}

// AuditEntry is a stored audit row.
type AuditEntry struct {
	ID          int64
	At          time.Time
	Severity    string
	Event       string
	ActorUserID int64
	ActorType   string
	AppID       int64
	UserID      int64
	IP          string
	UserAgent   string
	Detail      map[string]any
}

// Audit records an event. Callers treat a failure as something to log, not a
// reason to fail the request the event describes.
func (s *Store) Audit(e AuditEvent) error {
	if e.Event == "" {
		return fmt.Errorf("%w: audit event without a name", ErrInvalid)
	}
	if e.Severity == "" {
		e.Severity = SeverityInfo
	}
	if e.ActorType == "" {
		e.ActorType = ActorSystem
	}
	detail := ""
	if len(e.Detail) > 0 {
		raw, err := json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("encode audit detail: %w", err)
		}
		detail = string(raw)
	}
	_, err := s.db.Exec(`INSERT INTO audit_log
		(at, severity, event, actor_user_id, actor_type, app_id, user_id, ip, user_agent, detail_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.nowText(), e.Severity, e.Event, nullID(e.ActorUserID), e.ActorType, nullID(e.AppID),
		nullID(e.UserID), normaliseIP(e.IP), truncate(e.UserAgent, 400), detail)
	if err != nil && isForeignKeyViolation(err) {
		// A user or app deleted in the meantime; keep the event without it.
		_, err = s.db.Exec(`INSERT INTO audit_log
			(at, severity, event, actor_type, ip, user_agent, detail_json)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			s.nowText(), e.Severity, e.Event, e.ActorType, normaliseIP(e.IP), truncate(e.UserAgent, 400), detail)
	}
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

// AuditQuery filters ListAudit. Zero values match everything. BeforeID pages
// backwards: pass the smallest ID of the previous page.
type AuditQuery struct {
	AppID    int64
	UserID   int64
	Event    string
	BeforeID int64
	Limit    int
}

// AuditMaxLimit caps one page of audit rows.
const AuditMaxLimit = 200

// ListAudit returns audit rows newest first. UserID matches the row's subject
// or its actor. Event matches exactly, or as a prefix when it ends in ".".
func (s *Store) ListAudit(q AuditQuery) ([]*AuditEntry, error) {
	if q.Limit <= 0 || q.Limit > AuditMaxLimit {
		q.Limit = 50
	}
	var where []string
	var args []any
	if q.AppID != 0 {
		where = append(where, "app_id = ?")
		args = append(args, q.AppID)
	}
	if q.UserID != 0 {
		where = append(where, "(user_id = ? OR actor_user_id = ?)")
		args = append(args, q.UserID, q.UserID)
	}
	if q.Event != "" {
		if strings.HasSuffix(q.Event, ".") {
			where = append(where, `event LIKE ? ESCAPE '\'`)
			args = append(args, strings.NewReplacer("%", `\%`, "_", `\_`).Replace(q.Event)+"%")
		} else {
			where = append(where, "event = ?")
			args = append(args, q.Event)
		}
	}
	if q.BeforeID != 0 {
		where = append(where, "id < ?")
		args = append(args, q.BeforeID)
	}
	query := `SELECT id, at, severity, event, COALESCE(actor_user_id, 0), actor_type,
		COALESCE(app_id, 0), COALESCE(user_id, 0), ip, user_agent, detail_json FROM audit_log`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, q.Limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []*AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at, detail string
		if err := rows.Scan(&e.ID, &at, &e.Severity, &e.Event, &e.ActorUserID, &e.ActorType,
			&e.AppID, &e.UserID, &e.IP, &e.UserAgent, &detail); err != nil {
			return nil, fmt.Errorf("scan audit: %w", err)
		}
		e.At = parseTime(at)
		if detail != "" {
			// A row that does not parse still shows; only its detail is lost.
			_ = json.Unmarshal([]byte(detail), &e.Detail)
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// DeleteOldAudit removes rows older than AuditRetention.
func (s *Store) DeleteOldAudit() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM audit_log WHERE at < ?`, formatTime(s.now().Add(-AuditRetention)))
	if err != nil {
		return 0, fmt.Errorf("delete old audit rows: %w", err)
	}
	return res.RowsAffected()
}

// nullID stores a zero ID as NULL.
func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}
