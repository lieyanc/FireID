package api

import (
	"net/http"
	"time"

	"github.com/lieyanc/FireID/internal/store"
)

// Signing keys (super admin). Rotation makes a new key current and leaves the
// old one published, so tokens it signed keep verifying until it is retired.
// The private halves never leave the oidc package.

// adminSigningKeys lists every key, retired ones included, newest first.
func (s *Server) adminSigningKeys(w http.ResponseWriter, r *http.Request, user *store.User) {
	keys, err := s.deps.Store.ListSigningKeys()
	if err != nil {
		s.failFromStore(w, err, "could not list signing keys")
		return
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{
			"kid":         k.KID,
			"alg":         k.Alg,
			"createdAt":   timeText(k.CreatedAt),
			"activatedAt": timeText(k.ActivatedAt),
			"retiredAt":   timeOrNull(k.RetiredAt),
			"current":     k.IsCurrent,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

// adminSigningKeyRotate makes a fresh key current.
func (s *Server) adminSigningKeyRotate(w http.ResponseWriter, r *http.Request, user *store.User) {
	var req struct{}
	if !decodeJSON(w, r, &req) {
		return
	}
	kid, err := s.oidcProvider.RotateSigningKey()
	if err != nil {
		s.failFromStore(w, err, "could not rotate the signing key")
		return
	}
	s.deps.Log.Warn("signing key rotated", "kid", kid, "by", user.ID)
	s.auditAdmin(r, user, "key.rotate", store.SeverityWarning, 0, 0, map[string]any{"kid": kid})
	writeJSON(w, http.StatusCreated, map[string]any{"kid": kid})
}

// adminSigningKeyRetire stops publishing a key; tokens it signed stop
// verifying. The current key cannot be retired.
func (s *Server) adminSigningKeyRetire(w http.ResponseWriter, r *http.Request, user *store.User) {
	kid := r.PathValue("kid")
	if err := s.deps.Store.RetireSigningKey(kid); err != nil {
		s.failFromStore(w, err, "could not retire the signing key")
		return
	}
	s.deps.Log.Warn("signing key retired", "kid", kid, "by", user.ID)
	s.auditAdmin(r, user, "key.retire", store.SeverityWarning, 0, 0, map[string]any{"kid": kid})
	w.WriteHeader(http.StatusNoContent)
}

// timeOrNull is timeText for fields documented as null when unset.
func timeOrNull(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return timeText(t)
}
