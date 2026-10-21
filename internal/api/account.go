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
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}
