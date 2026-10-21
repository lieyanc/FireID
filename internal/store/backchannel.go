package store

import (
	"fmt"
	"time"
)

// RecordSessionApp notes that a browser session signed in to an app, so the
// app is told when the session ends. Recording the same pair twice is a no-op.
func (s *Store) RecordSessionApp(sessionID, appID int64) error {
	_, err := s.db.Exec(`INSERT INTO session_apps(session_id, app_id, created_at) VALUES (?, ?, ?)
		ON CONFLICT(session_id, app_id) DO NOTHING`, sessionID, appID, s.nowText())
	if err != nil {
		if isForeignKeyViolation(err) {
			return ErrNotFound
		}
		return fmt.Errorf("record session app: %w", err)
	}
	return nil
}

// BackchannelJob is a pending logout notification with what is needed to send
// it. The app's URI is read at delivery time, so a corrected URI takes effect
// on the next attempt.
type BackchannelJob struct {
	ID       int64
	AppID    int64
	ClientID string
	URI      string
	UserID   int64
	SID      string
	Attempts int
}

// DueBackchannel returns up to limit notifications whose next attempt is due,
// oldest first. A row whose app no longer has a URI is dropped, as there is
// nowhere to send it.
func (s *Store) DueBackchannel(limit int) ([]*BackchannelJob, error) {
	if limit <= 0 {
		limit = 50
	}
	if _, err := s.db.Exec(`DELETE FROM backchannel_outbox WHERE app_id IN
		(SELECT id FROM apps WHERE backchannel_logout_uri = '')`); err != nil {
		return nil, fmt.Errorf("drop orphaned notifications: %w", err)
	}
	rows, err := s.db.Query(`SELECT o.id, o.app_id, a.client_id, a.backchannel_logout_uri,
			o.user_id, o.sid, o.attempts
		FROM backchannel_outbox o JOIN apps a ON a.id = o.app_id
		WHERE o.next_attempt_at <= ?
		ORDER BY o.next_attempt_at, o.id LIMIT ?`, s.nowText(), limit)
	if err != nil {
		return nil, fmt.Errorf("due notifications: %w", err)
	}
	defer rows.Close()
	var out []*BackchannelJob
	for rows.Next() {
		var j BackchannelJob
		if err := rows.Scan(&j.ID, &j.AppID, &j.ClientID, &j.URI, &j.UserID, &j.SID, &j.Attempts); err != nil {
			return nil, fmt.Errorf("scan notification: %w", err)
		}
		out = append(out, &j)
	}
	return out, rows.Err()
}

// BackchannelDone removes a notification that was delivered or given up on.
func (s *Store) BackchannelDone(id int64) error {
	if _, err := s.db.Exec(`DELETE FROM backchannel_outbox WHERE id = ?`, id); err != nil {
		return fmt.Errorf("finish notification: %w", err)
	}
	return nil
}

// BackchannelRetry records a failed attempt and when to try again. The error
// text is the worker's own description, never the response body.
func (s *Store) BackchannelRetry(id int64, lastError string, next time.Time) error {
	_, err := s.db.Exec(`UPDATE backchannel_outbox
		SET attempts = attempts + 1, last_error = ?, next_attempt_at = ? WHERE id = ?`,
		truncate(lastError, 300), formatTime(next), id)
	if err != nil {
		return fmt.Errorf("reschedule notification: %w", err)
	}
	return nil
}

// PendingBackchannel counts undelivered notifications for an app, for the
// app's admin page.
func (s *Store) PendingBackchannel(appID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM backchannel_outbox WHERE app_id = ?`, appID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count notifications: %w", err)
	}
	return n, nil
}
