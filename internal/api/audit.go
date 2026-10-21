package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/lieyanc/FireID/internal/auth"
	"github.com/lieyanc/FireID/internal/store"
)

// Audit log: recording events from handlers, and the two admin views of it
// (DESIGN §4, Keys and audit). Recording is best effort — a failed write is logged and never
// fails the request it describes. Detail never holds a secret.

// auditPageSize is the default number of rows per page.
const auditPageSize = 50

// audit records an event with the request's source address and user agent.
func (s *Server) audit(r *http.Request, e store.AuditEvent) {
	e.IP, e.UserAgent = s.clientIP(r), r.UserAgent()
	if err := s.deps.Store.Audit(e); err != nil {
		s.deps.Log.Warn("could not record audit event", "event", e.Event, "err", err)
	}
}

// auditAccount records an account holder's change to their own account.
func (s *Server) auditAccount(r *http.Request, user *store.User, event string, detail map[string]any) {
	s.audit(r, store.AuditEvent{Event: event, ActorType: store.ActorUser,
		ActorUserID: user.ID, UserID: user.ID, Detail: detail})
}

// auditAdmin records an administrative action. appID and userID name what it
// touched and may be zero.
func (s *Server) auditAdmin(r *http.Request, actor *store.User, event, severity string, appID, userID int64, detail map[string]any) {
	s.audit(r, store.AuditEvent{Event: event, Severity: severity, ActorType: store.ActorAdmin,
		ActorUserID: actor.ID, AppID: appID, UserID: userID, Detail: detail})
}

// auditSignIn records a successful sign-in.
func (s *Server) auditSignIn(r *http.Request, res *auth.LoginResult) {
	amr := strings.Fields(res.AMR)
	s.audit(r, store.AuditEvent{Event: "auth.sign_in", ActorType: store.ActorUser,
		ActorUserID: res.User.ID, UserID: res.User.ID,
		Detail: map[string]any{"method": signInMethod(amr), "amr": amr}})
}

// signInMethod names the first factor of a sign-in for the audit log.
func signInMethod(amr []string) string {
	if len(amr) > 0 {
		switch amr[0] {
		case "webauthn":
			return "passkey"
		case "email":
			return "email"
		}
	}
	return "password"
}

// auditSignInFailure records a sign-in refused for its credentials; method is
// the first factor. Rate-limited attempts are not recorded one by one: the
// auth.locked event that started the lock-out covers them. The attempted
// username, password and codes never appear — only the account, when the
// attempt identified one.
func (s *Server) auditSignInFailure(r *http.Request, method string, err error) {
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		return
	}
	reason := "invalid_credentials"
	var userID int64
	var f *auth.SignInFailure
	if errors.As(err, &f) {
		reason = f.Reason
		if f.User != nil {
			userID = f.User.ID
		}
	}
	s.audit(r, store.AuditEvent{Event: "auth.sign_in_failed", Severity: store.SeverityWarning,
		ActorType: store.ActorSystem, UserID: userID,
		Detail: map[string]any{"method": method, "reason": reason}})
}

// adminAudit is the deployment-wide log (super admin).
func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request, user *store.User) {
	q, ok := auditQuery(w, r)
	if !ok {
		return
	}
	if slug := r.URL.Query().Get("app"); slug != "" {
		app, err := s.deps.Store.AppBySlug(slug)
		if err != nil {
			s.failFromStore(w, err, "could not load the application")
			return
		}
		q.AppID = app.ID
	}
	s.writeAuditPage(w, q)
}

// adminAppAudit is one app's log, for anyone who manages the app.
func (s *Server) adminAppAudit(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	q, ok := auditQuery(w, r)
	if !ok {
		return
	}
	q.AppID = app.ID
	s.writeAuditPage(w, q)
}

// auditQuery reads the filters both views share. On false the response has
// been written.
func auditQuery(w http.ResponseWriter, r *http.Request) (store.AuditQuery, bool) {
	v := r.URL.Query()
	q := store.AuditQuery{Event: strings.TrimSpace(v.Get("event")), Limit: auditPageSize}
	var limit int64
	for _, f := range []struct {
		name string
		dst  *int64
	}{{"user", &q.UserID}, {"before", &q.BeforeID}, {"limit", &limit}} {
		raw := v.Get(f.name)
		if raw == "" {
			continue
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n <= 0 {
			fail(w, http.StatusBadRequest, "invalid", f.name+" must be a positive integer")
			return q, false
		}
		*f.dst = n
	}
	if limit > 0 {
		q.Limit = int(min(limit, store.AuditMaxLimit))
	}
	return q, true
}

// writeAuditPage answers with one page of entries. The people and apps they
// name are looked up once per page; one deleted since shows as null.
func (s *Server) writeAuditPage(w http.ResponseWriter, q store.AuditQuery) {
	entries, err := s.deps.Store.ListAudit(q)
	if err != nil {
		s.failFromStore(w, err, "could not read the audit log")
		return
	}
	people := map[int64]any{0: nil}
	apps := map[int64]any{0: nil}
	for _, e := range entries {
		for _, id := range []int64{e.ActorUserID, e.UserID} {
			if _, seen := people[id]; seen {
				continue
			}
			u, err := s.deps.Store.UserByID(id)
			switch {
			case err == nil:
				people[id] = map[string]any{"id": u.ID, "username": u.Username, "displayName": u.DisplayName}
			case errors.Is(err, store.ErrNotFound):
				people[id] = nil
			default:
				s.failFromStore(w, err, "could not read the audit log")
				return
			}
		}
		if _, seen := apps[e.AppID]; !seen {
			a, err := s.deps.Store.AppByID(e.AppID)
			switch {
			case err == nil:
				apps[e.AppID] = map[string]any{"slug": a.Slug, "name": a.Name}
			case errors.Is(err, store.ErrNotFound):
				apps[e.AppID] = nil
			default:
				s.failFromStore(w, err, "could not read the audit log")
				return
			}
		}
	}

	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		var detail any
		if len(e.Detail) > 0 {
			detail = e.Detail
		}
		out = append(out, map[string]any{
			"id":        e.ID,
			"at":        timeText(e.At),
			"severity":  e.Severity,
			"event":     e.Event,
			"actorType": e.ActorType,
			"actor":     people[e.ActorUserID],
			"app":       apps[e.AppID],
			"user":      people[e.UserID],
			"ip":        e.IP,
			"userAgent": e.UserAgent,
			"detail":    detail,
		})
	}
	var next any
	if len(entries) == q.Limit {
		next = entries[len(entries)-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out, "nextBefore": next})
}
