package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lieyanc/FireID/internal/auth"
	"github.com/lieyanc/FireID/internal/store"
)

// Self-service access (DESIGN §8): the app catalog, joining and asking for
// access, invitations, and self-registration. Whether a person may use an app
// is decided by store.CanUseApp; these handlers act on its Join answer and
// never re-derive it.

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

func publicCatalogApp(e *store.CatalogEntry) map[string]any {
	return map[string]any{
		"slug":        e.App.Slug,
		"name":        e.App.Name,
		"description": e.App.Description,
		"homepageUrl": e.App.HomepageURL,
		"logoUrl":     e.App.LogoURL,
		"state":       e.State,
		"join":        e.Join,
	}
}

// catalogApps lists the apps the signed-in person may use, join or ask for.
func (s *Server) catalogApps(w http.ResponseWriter, r *http.Request, user *store.User) {
	entries, err := s.deps.Store.Catalog(user)
	if err != nil {
		s.failFromStore(w, err, "could not list applications")
		return
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, publicCatalogApp(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": out})
}

// catalogEntry loads the {slug} app as the caller's catalog sees it. An app
// outside the catalog answers 404, exactly like an unknown slug.
func (s *Server) catalogEntry(w http.ResponseWriter, r *http.Request, user *store.User) (*store.CatalogEntry, bool) {
	app, err := s.deps.Store.AppBySlug(r.PathValue("slug"))
	if err == nil {
		var e *store.CatalogEntry
		if e, err = s.deps.Store.CatalogEntry(app, user); err == nil {
			return e, true
		}
	}
	s.failFromStore(w, err, "could not load the application")
	return nil, false
}

// catalogApp is one catalog entry, for the denied page.
func (s *Server) catalogApp(w http.ResponseWriter, r *http.Request, user *store.User) {
	e, ok := s.catalogEntry(w, r, user)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"app": publicCatalogApp(e)})
}

// appJoin makes the caller a member of an app open to anyone.
func (s *Server) appJoin(w http.ResponseWriter, r *http.Request, user *store.User) {
	var req struct{}
	if !decodeJSON(w, r, &req) {
		return
	}
	e, ok := s.catalogEntry(w, r, user)
	if !ok {
		return
	}
	if e.State != store.CatalogAvailable || e.Join != store.JoinSelf {
		fail(w, http.StatusConflict, "conflict", "this application cannot be joined from here")
		return
	}
	if err := s.deps.Store.JoinApp(e.App.ID, user.ID); err != nil {
		s.failFromStore(w, err, "could not join the application")
		return
	}
	s.deps.Log.Info("joined app", "appId", e.App.ID, "userId", user.ID)
	s.audit(r, store.AuditEvent{Event: "app.self_join", ActorType: store.ActorUser,
		ActorUserID: user.ID, AppID: e.App.ID, UserID: user.ID})
	w.WriteHeader(http.StatusNoContent)
}

// appRequest asks an admin_approval app's managers for access.
func (s *Server) appRequest(w http.ResponseWriter, r *http.Request, user *store.User) {
	var req struct {
		Message string `json:"message"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	e, ok := s.catalogEntry(w, r, user)
	if !ok {
		return
	}
	if e.State != store.CatalogAvailable || e.Join != store.JoinRequest {
		fail(w, http.StatusConflict, "conflict", "access to this application cannot be requested from here")
		return
	}
	created, err := s.deps.Store.RequestAppAccess(e.App.ID, user.ID, strings.TrimSpace(req.Message))
	if err != nil {
		s.failFromStore(w, err, "could not record the request")
		return
	}
	s.deps.Log.Info("access requested", "appId", e.App.ID, "userId", user.ID, "requestId", created.ID)
	s.audit(r, store.AuditEvent{Event: "app.access_request", ActorType: store.ActorUser,
		ActorUserID: user.ID, AppID: e.App.ID, UserID: user.ID,
		Detail: map[string]any{"requestId": created.ID}})
	if managers, err := s.deps.Store.AppManagers(e.App); err == nil {
		s.deps.Auth.NotifyAccessRequest(managers, e.App.Name, e.App.Slug, user)
	} else {
		s.deps.Log.Error("could not load the app's managers for a request notice", "appId", e.App.ID, "err", err)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": created.ID})
}

// ---------------------------------------------------------------------------
// Invites
// ---------------------------------------------------------------------------

// Invite defaults.
const (
	inviteDefaultDays = 7
	inviteDefaultUses = 1
)

func publicInvite(inv *store.Invite) map[string]any {
	var creator any
	if inv.Creator != nil {
		creator = map[string]any{"id": inv.Creator.ID, "username": inv.Creator.Username,
			"displayName": inv.Creator.DisplayName}
	}
	var revoked any
	if !inv.RevokedAt.IsZero() {
		revoked = timeText(inv.RevokedAt)
	}
	return map[string]any{
		"id":        inv.ID,
		"email":     inv.Email,
		"role":      inv.Role,
		"createdBy": creator,
		"createdAt": timeText(inv.CreatedAt),
		"expiresAt": timeText(inv.ExpiresAt),
		"maxUses":   inv.MaxUses,
		"uses":      inv.Uses,
		"revokedAt": revoked,
	}
}

// ownsApp reports whether the user may hand out admin invites: the super
// admin, the owning account, or an active owner member.
func (s *Server) ownsApp(user *store.User, app *store.App) (bool, error) {
	if user.IsSuperAdmin || user.ID == app.OwnerUserID {
		return true, nil
	}
	m, err := s.deps.Store.Membership(app.ID, user.ID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return m.Status == store.MemberActive && m.Role == store.RoleOwner, nil
}

// adminInviteCreate makes an invite link. The token is in this response only.
func (s *Server) adminInviteCreate(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	var req struct {
		Email         string `json:"email"`
		Role          string `json:"role"`
		ExpiresInDays *int   `json:"expiresInDays"`
		MaxUses       *int   `json:"maxUses"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Role == "" {
		req.Role = store.RoleMember
	}
	days, uses := inviteDefaultDays, inviteDefaultUses
	if req.ExpiresInDays != nil {
		days = *req.ExpiresInDays
	}
	if req.MaxUses != nil {
		uses = *req.MaxUses
	}
	if days < 1 || days > store.InviteMaxDays {
		fail(w, http.StatusBadRequest, "invalid", "expiresInDays must be 1 to 30")
		return
	}
	if req.Role == store.RoleAdmin {
		owns, err := s.ownsApp(user, app)
		if err != nil {
			s.failFromStore(w, err, "could not check permissions")
			return
		}
		if !owns {
			fail(w, http.StatusForbidden, "forbidden", "only the app's owner or an administrator may invite admins")
			return
		}
	}
	inv, token, err := s.deps.Store.CreateInvite(store.NewInvite{
		AppID: app.ID, CreatedBy: user.ID, Email: strings.TrimSpace(req.Email), Role: req.Role,
		TTL: time.Duration(days) * 24 * time.Hour, MaxUses: uses,
	})
	if err != nil {
		s.failFromStore(w, err, "could not create the invite")
		return
	}
	inv.Creator = user
	link := s.deps.PublicBase + "/invite/" + token
	s.deps.Log.Info("invite created", "appId", app.ID, "inviteId", inv.ID, "role", inv.Role, "by", user.ID)
	s.auditAdmin(r, user, "app.invite_create", store.SeverityInfo, app.ID, 0,
		map[string]any{"inviteId": inv.ID, "role": inv.Role, "maxUses": inv.MaxUses})
	if inv.Email != "" {
		s.deps.Auth.SendInvite(inv.Email, app.Name, link)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"invite": publicInvite(inv), "url": link})
}

// adminInvites lists an app's recent invites.
func (s *Server) adminInvites(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	invs, err := s.deps.Store.ListInvites(app.ID)
	if err != nil {
		s.failFromStore(w, err, "could not list invites")
		return
	}
	out := make([]map[string]any, 0, len(invs))
	for _, inv := range invs {
		out = append(out, publicInvite(inv))
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

// adminInviteRevoke ends an invite.
func (s *Server) adminInviteRevoke(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.deps.Store.RevokeInvite(app.ID, id); err != nil {
		s.failFromStore(w, err, "could not revoke the invite")
		return
	}
	s.deps.Log.Info("invite revoked", "appId", app.ID, "inviteId", id, "by", user.ID)
	s.auditAdmin(r, user, "app.invite_revoke", store.SeverityInfo, app.ID, 0, map[string]any{"inviteId": id})
	w.WriteHeader(http.StatusNoContent)
}

// liveInvite resolves an invite token to a usable invite on an active app.
// Every failure is the same 404 and counts against the source address, so
// tokens cannot be guessed at speed.
func (s *Server) liveInvite(w http.ResponseWriter, r *http.Request, token string) (*store.Invite, *store.App, bool) {
	ip := s.clientIP(r)
	if wait := s.inviteThrottle.RetryAfter("invite:" + ip); wait > 0 {
		s.failFromAuth(w, &auth.RateLimitError{RetryAfter: wait})
		return nil, nil, false
	}
	inv, err := s.deps.Store.InviteByToken(token)
	var app *store.App
	if err == nil {
		app, err = s.deps.Store.AppByID(inv.AppID)
		if err == nil && app.Status != store.AppActive {
			err = store.ErrNotFound
		}
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			if lock := s.inviteThrottle.Fail("invite:" + ip); lock > 0 {
				s.deps.Log.Warn("invite lookups throttled", "ip", ip, "lockout", lock.String())
			}
		}
		s.failFromStore(w, err, "could not load the invite")
		return nil, nil, false
	}
	return inv, app, true
}

// invitePreview shows who is inviting to what, without a session.
func (s *Server) invitePreview(w http.ResponseWriter, r *http.Request) {
	inv, app, ok := s.liveInvite(w, r, r.PathValue("token"))
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"app":       map[string]any{"name": app.Name, "description": app.Description, "logoUrl": app.LogoURL},
		"email":     inv.Email,
		"expiresAt": timeText(inv.ExpiresAt),
	})
}

// inviteAccept spends one use of an invite on the signed-in account.
func (s *Server) inviteAccept(w http.ResponseWriter, r *http.Request, user *store.User) {
	var req struct{}
	if !decodeJSON(w, r, &req) {
		return
	}
	token := r.PathValue("token")
	_, app, ok := s.liveInvite(w, r, token)
	if !ok {
		return
	}
	if user.Status != store.UserActive {
		// An unverified address cannot satisfy an address-bound invite, and
		// a pending account cannot use the app anyway.
		fail(w, http.StatusForbidden, "forbidden", "verify your email address first")
		return
	}
	inv, err := s.deps.Store.AcceptInvite(token, user)
	switch {
	case errors.Is(err, store.ErrInviteEmailMismatch):
		fail(w, http.StatusForbidden, "invite_email_mismatch", err.Error())
		return
	case errors.Is(err, store.ErrMembershipBlocked):
		fail(w, http.StatusForbidden, "blocked", err.Error())
		return
	case err != nil:
		s.failFromStore(w, err, "could not accept the invite")
		return
	}
	s.deps.Log.Info("invite accepted", "appId", app.ID, "inviteId", inv.ID, "userId", user.ID)
	s.audit(r, store.AuditEvent{Event: "app.invite_accept", ActorType: store.ActorUser,
		ActorUserID: user.ID, AppID: app.ID, UserID: user.ID,
		Detail: map[string]any{"inviteId": inv.ID, "role": inv.Role}})
	writeJSON(w, http.StatusOK, map[string]any{
		"app": map[string]any{"slug": app.Slug, "name": app.Name, "homepageUrl": app.HomepageURL},
	})
}

// ---------------------------------------------------------------------------
// Self-registration
// ---------------------------------------------------------------------------

type registerRequest struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Password    string `json:"password"`
	// Invite is an app invite token; a live one allows registration while
	// auth.registration is closed. It is checked here and spent by accept.
	Invite string `json:"invite"`
	Lang   string `json:"lang"`
}

// register creates a pending account. When email is configured the address
// is sent a sign-in code at once, and redeeming it activates the account.
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	invited := false
	if req.Invite != "" {
		if _, _, ok := s.liveInvite(w, r, req.Invite); !ok {
			return
		}
		invited = true
	}
	ip := s.clientIP(r)
	res, err := s.deps.Auth.Register(strings.TrimSpace(req.Username), req.Email,
		strings.TrimSpace(req.DisplayName), req.Password, ip, invited)
	if err != nil {
		if errors.Is(err, store.ErrInvalid) || errors.Is(err, store.ErrConflict) {
			s.failFromStore(w, err, "could not create the account")
		} else {
			s.failFromAuth(w, err)
		}
		return
	}
	s.deps.Log.Info("account registered", "userId", res.User.ID, "invited", invited, "ip", ip)
	s.audit(r, store.AuditEvent{Event: "account.register", ActorType: store.ActorUser,
		ActorUserID: res.User.ID, UserID: res.User.ID, Detail: map[string]any{"invited": invited}})
	verification := false
	if s.deps.Auth.EmailEnabled() {
		lang := req.Lang
		if lang == "" {
			lang = r.Header.Get("Accept-Language")
		}
		if err := s.deps.Auth.StartEmailLogin(res.User.Email, "", ip, lang); err != nil {
			s.deps.Log.Warn("could not send the verification email", "userId", res.User.ID, "err", err)
		} else {
			verification = true
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": publicUser(res.User),
		"emailVerification": verification})
}

// redactPath hides the invite token in request paths before they are logged.
func redactPath(p string) string {
	for _, prefix := range []string{"/api/invites/", "/invite/"} {
		if rest, ok := strings.CutPrefix(p, prefix); ok && rest != "" {
			tail := ""
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				tail = rest[i:]
			}
			return prefix + "[redacted]" + tail
		}
	}
	return p
}
