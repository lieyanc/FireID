package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/lieyanc/FireID/internal/auth"
	"github.com/lieyanc/FireID/internal/store"
)

type emailStartRequest struct {
	Email     string `json:"email"`
	AuthReqID string `json:"authReqId"`
	// Lang is the UI language, for the message; Accept-Language otherwise.
	Lang string `json:"lang"`
}

// emailStart sends a sign-in code and link. The answer is the same whether or
// not the address has an account.
func (s *Server) emailStart(w http.ResponseWriter, r *http.Request) {
	var req emailStartRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	lang := req.Lang
	if lang == "" {
		lang = r.Header.Get("Accept-Language")
	}
	err := s.deps.Auth.StartEmailLogin(req.Email, req.AuthReqID, s.clientIP(r), lang)
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, struct{}{})
	case errors.Is(err, auth.ErrEmailUnavailable):
		fail(w, http.StatusNotFound, "email_unavailable", err.Error())
	default:
		s.failFromAuth(w, err)
	}
}

type emailVerifyRequest struct {
	Token     string `json:"token"`
	Email     string `json:"email"`
	Code      string `json:"code"`
	TOTP      string `json:"totp"`
	AuthReqID string `json:"authReqId"`
}

// emailVerify redeems the link or the typed code.
func (s *Server) emailVerify(w http.ResponseWriter, r *http.Request) {
	var req emailVerifyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.deps.Auth.EmailEnabled() {
		fail(w, http.StatusNotFound, "email_unavailable", auth.ErrEmailUnavailable.Error())
		return
	}
	ip := s.clientIP(r)
	res, err := s.deps.Auth.FinishEmailLogin(auth.EmailLoginProof{
		Token: req.Token, Email: req.Email, Code: req.Code, TOTP: req.TOTP,
	}, ip)
	var sf *auth.SecondFactorError
	switch {
	case err == nil:
		s.finishLogin(w, r, res, req.AuthReqID)
	case errors.As(err, &sf) && sf.Enrol:
		fail(w, http.StatusForbidden, "totp_enrol_required",
			"two-step verification must be set up first; sign in with your password")
	case errors.As(err, &sf):
		writeChallenge(w, sf)
	case errors.Is(err, auth.ErrInvalidCredentials):
		s.deps.Log.Info("failed email sign-in", "ip", ip)
		s.auditSignInFailure(r, "email", err)
		fail(w, http.StatusUnauthorized, "invalid_code", "that code or link is not valid")
	default:
		s.failSecondFactor(w, err)
	}
}

type passwordRequest struct {
	Password string `json:"password"`
}

type codeRequest struct {
	Code string `json:"code"`
}

// accountTOTPEnrol starts turning on two-step verification. The password is
// asked for again, so a borrowed session cannot tie the account to someone
// else's authenticator.
func (s *Server) accountTOTPEnrol(w http.ResponseWriter, r *http.Request, user *store.User) {
	var req passwordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if user.PasswordHash != "" {
		if err := s.deps.Auth.VerifyCurrentPassword(user, req.Password, s.clientIP(r)); err != nil {
			if errors.Is(err, auth.ErrInvalidCredentials) {
				fail(w, http.StatusUnauthorized, "invalid_credentials", "that password is not correct")
				return
			}
			s.failFromAuth(w, err)
			return
		}
	}
	secret, uri, err := s.deps.Auth.BeginEnrolment(user)
	if err != nil {
		s.failSecondFactor(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "uri": uri})
}

// accountTOTPConfirm checks the first code and returns the recovery codes.
func (s *Server) accountTOTPConfirm(w http.ResponseWriter, r *http.Request, user *store.User) {
	var req codeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	codes, err := s.deps.Auth.ConfirmEnrolment(user, strings.TrimSpace(req.Code), s.clientIP(r))
	if err != nil {
		s.failSecondFactor(w, err)
		return
	}
	s.auditAccount(r, user, "account.totp_enable", nil)
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}

// accountTOTPDisable turns two-step verification off.
func (s *Server) accountTOTPDisable(w http.ResponseWriter, r *http.Request, user *store.User) {
	var req codeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.deps.Auth.DisableTOTP(user, req.Code, s.clientIP(r)); err != nil {
		s.failSecondFactor(w, err)
		return
	}
	s.auditAccount(r, user, "account.totp_disable", nil)
	w.WriteHeader(http.StatusNoContent)
}

// accountRecoveryCodes replaces the recovery codes.
func (s *Server) accountRecoveryCodes(w http.ResponseWriter, r *http.Request, user *store.User) {
	var req codeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	codes, err := s.deps.Auth.RegenerateRecoveryCodes(user, req.Code, s.clientIP(r))
	if err != nil {
		s.failSecondFactor(w, err)
		return
	}
	s.auditAccount(r, user, "account.recovery_codes", nil)
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}

// accountSessions lists the account's live sessions, marking this one.
func (s *Server) accountSessions(w http.ResponseWriter, r *http.Request, sess *store.Session, user *store.User) {
	sessions, err := s.deps.Store.ListSessions(user.ID, sess.ID)
	if err != nil {
		s.failFromStore(w, err, "could not list sessions")
		return
	}
	out := make([]map[string]any, 0, len(sessions))
	for _, si := range sessions {
		amr := strings.Fields(si.AMR)
		if amr == nil {
			amr = []string{}
		}
		out = append(out, map[string]any{
			"id":         si.ID,
			"createdAt":  timeText(si.CreatedAt),
			"lastSeenAt": timeText(si.LastSeenAt),
			"expiresAt":  timeText(si.ExpiresAt),
			"ip":         si.IP,
			"userAgent":  si.UserAgent,
			"amr":        amr,
			"current":    si.Current,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// accountSessionRevoke signs one of the account's other browsers out. The
// current session goes through /api/auth/logout, which also clears the cookie.
func (s *Server) accountSessionRevoke(w http.ResponseWriter, r *http.Request, sess *store.Session, user *store.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if id == sess.ID {
		fail(w, http.StatusConflict, "cannot_revoke_current", "use sign out to end this session")
		return
	}
	if err := s.deps.Store.RevokeUserSession(user.ID, id); err != nil {
		s.failFromStore(w, err, "could not revoke the session")
		return
	}
	s.deps.Log.Info("session revoked by account holder", "userId", user.ID, "sessionId", id)
	s.auditAccount(r, user, "account.session_revoke", map[string]any{"sessionId": id})
	w.WriteHeader(http.StatusNoContent)
}

// accountSessionsRevokeOthers signs every other browser out and revokes the
// tokens issued to applications, keeping this session.
func (s *Server) accountSessionsRevokeOthers(w http.ResponseWriter, r *http.Request, sess *store.Session, user *store.User) {
	var req struct{}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.deps.Store.RevokeOtherSessions(user.ID, sess.ID); err != nil {
		s.failFromStore(w, err, "could not revoke the other sessions")
		return
	}
	s.deps.Log.Info("other sessions revoked by account holder", "userId", user.ID, "keep", sess.ID)
	s.auditAccount(r, user, "account.sessions_revoke_others", nil)
	w.WriteHeader(http.StatusNoContent)
}

type profileRequest struct {
	DisplayName string `json:"displayName"`
}

// accountProfile changes the display name. The username and email address are
// not editable here.
func (s *Server) accountProfile(w http.ResponseWriter, r *http.Request, user *store.User) {
	var req profileRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.deps.Store.SetDisplayName(user.ID, req.DisplayName); err != nil {
		s.failFromStore(w, err, "could not change the display name")
		return
	}
	if strings.TrimSpace(req.DisplayName) != user.DisplayName {
		s.auditAccount(r, user, "account.update", map[string]any{"fields": []string{"displayName"}})
	}
	w.WriteHeader(http.StatusNoContent)
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// accountPassword changes the password. The current one is checked when the
// account has one, so a borrowed session cannot lock the owner out. This
// session stays signed in; every other session and every application token is
// revoked, and the account holder is emailed.
func (s *Server) accountPassword(w http.ResponseWriter, r *http.Request, sess *store.Session, user *store.User) {
	var req changePasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	err := s.deps.Auth.ChangePassword(user, sess.ID, req.CurrentPassword, req.NewPassword, s.clientIP(r))
	switch {
	case err == nil:
		s.auditAccount(r, user, "account.password_change", nil)
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, auth.ErrInvalidCredentials):
		fail(w, http.StatusUnauthorized, "invalid_credentials", "that password is not correct")
	default:
		// Rate limits, weak_password and store errors.
		s.failFromAuth(w, err)
	}
}
