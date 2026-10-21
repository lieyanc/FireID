package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/lieyanc/FireID/internal/auth"
	"github.com/lieyanc/FireID/internal/store"
)

type passkeyLoginRequest struct {
	CeremonyID string `json:"ceremonyId"`
	// Response is the PublicKeyCredential as JSON, passed to the library as
	// it arrived.
	Response json.RawMessage `json:"response"`
	// AuthReqID is set when the sign-in belongs to an authorization request.
	AuthReqID string `json:"authReqId"`
}

type passkeyRegisterRequest struct {
	CeremonyID string          `json:"ceremonyId"`
	Name       string          `json:"name"`
	Response   json.RawMessage `json:"response"`
}

// passkeyLoginBegin starts a username-less passkey sign-in. The options go to
// navigator.credentials.get; the ceremony id comes back with the answer.
func (s *Server) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	options, ceremonyID, err := s.deps.Auth.BeginPasskeyLogin(s.clientIP(r))
	if err != nil {
		s.failPasskey(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": options.Response, "ceremonyId": ceremonyID})
}

// passkeyLoginFinish checks the assertion and signs in. A user-verified
// passkey is loa:2 on its own, so no second step follows.
func (s *Server) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req passkeyLoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	res, err := s.deps.Auth.FinishPasskeyLogin(req.CeremonyID, req.Response, s.clientIP(r))
	if err != nil {
		s.failPasskey(w, err)
		return
	}
	s.finishLogin(w, r, res, req.AuthReqID)
}

// accountPasskeysBegin starts adding a passkey. The password is asked for
// again when the account has one; the ceremony is bound to this session.
func (s *Server) accountPasskeysBegin(w http.ResponseWriter, r *http.Request, sess *store.Session, user *store.User) {
	var req passwordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	options, ceremonyID, err := s.deps.Auth.BeginPasskeyRegistration(user, sess.ID, req.Password, s.clientIP(r))
	if err != nil {
		s.failPasskey(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": options.Response, "ceremonyId": ceremonyID})
}

// accountPasskeysFinish stores the new passkey under the given name.
func (s *Server) accountPasskeysFinish(w http.ResponseWriter, r *http.Request, sess *store.Session, user *store.User) {
	var req passkeyRegisterRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	pk, err := s.deps.Auth.FinishPasskeyRegistration(user, sess.ID, req.CeremonyID, req.Name, req.Response)
	if err != nil {
		s.failPasskey(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"passkey": publicPasskey(pk)})
}

// accountPasskeys lists the account's passkeys.
func (s *Server) accountPasskeys(w http.ResponseWriter, r *http.Request, user *store.User) {
	passkeys, err := s.deps.Store.ListPasskeys(user.ID)
	if err != nil {
		s.failFromStore(w, err, "could not list passkeys")
		return
	}
	out := make([]map[string]any, 0, len(passkeys))
	for _, p := range passkeys {
		out = append(out, publicPasskey(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": out})
}

type nameRequest struct {
	Name string `json:"name"`
}

// accountPasskeyRename changes a passkey's label.
func (s *Server) accountPasskeyRename(w http.ResponseWriter, r *http.Request, user *store.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req nameRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.deps.Auth.RenamePasskey(user, id, req.Name); err != nil {
		s.failPasskey(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// accountPasskeyDelete removes a passkey. The account's last way to sign in
// is refused unless an emailed link can still reach it.
func (s *Server) accountPasskeyDelete(w http.ResponseWriter, r *http.Request, user *store.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.deps.Auth.DeletePasskey(user, id); err != nil {
		s.failPasskey(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// failPasskey maps passkey errors onto responses. An unknown or foreign
// passkey is deliberately just invalid_credentials. Store errors (conflict for
// an already registered passkey, invalid for a too-long name, not found) and
// rate limits go through failFromAuth.
func (s *Server) failPasskey(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrCeremony):
		fail(w, http.StatusUnauthorized, "invalid_ceremony", err.Error())
	case errors.Is(err, auth.ErrPasskeysUnavailable):
		fail(w, http.StatusNotFound, "passkeys_unavailable", err.Error())
	case errors.Is(err, store.ErrLastCredential):
		fail(w, http.StatusConflict, "last_credential",
			"this is the account's last way to sign in; add another passkey or a password first")
	case errors.Is(err, auth.ErrInvalidCredentials):
		fail(w, http.StatusUnauthorized, "invalid_credentials", "that passkey or password was not accepted")
	default:
		s.failFromAuth(w, err)
	}
}

// publicPasskey is a passkey as the UI sees it. Key material and the
// credential id never appear here.
func publicPasskey(p *store.Passkey) map[string]any {
	transports := strings.Fields(p.Transports)
	if transports == nil {
		transports = []string{}
	}
	return map[string]any{
		"id":             p.ID,
		"name":           p.Name,
		"createdAt":      timeText(p.CreatedAt),
		"lastUsedAt":     timeText(p.LastUsedAt),
		"backupEligible": p.BackupEligible,
		"backupState":    p.BackupState,
		"transports":     transports,
	}
}

// pathID reads the {id} path segment. A malformed id is answered as not
// found, the same as an id that belongs to someone else.
func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		fail(w, http.StatusNotFound, "not_found", "no such record")
		return 0, false
	}
	return id, true
}
