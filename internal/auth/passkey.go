package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/lieyanc/FireID/internal/store"
)

// ErrPasskeysUnavailable is returned when the public URL cannot be a WebAuthn
// relying party: the specification forbids an IP address as the RP ID, so a
// deployment reached by IP has no passkeys.
var ErrPasskeysUnavailable = errors.New("passkeys need the public URL to use a host name, not an IP address")

// ErrCeremony is returned when a passkey answer arrives without a matching
// pending challenge: it expired, was already answered, or belongs to another
// browser session.
var ErrCeremony = errors.New("this passkey prompt has expired; start again")

// relyingParty builds the WebAuthn relying party from the public URL: the RP
// ID is its host name and the only accepted origin is the URL's own origin.
func (s *Service) relyingParty() (*webauthn.WebAuthn, error) {
	u, err := url.Parse(s.issuer)
	if err != nil || u.Hostname() == "" || protocol.ValidateRPID(u.Hostname()) != nil {
		return nil, ErrPasskeysUnavailable
	}
	rp, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Fire ID",
		RPID:          u.Hostname(),
		RPOrigins:     []string{u.Scheme + "://" + u.Host},
		// Only a user-verified passkey is accepted, so it counts as loa:2.
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPasskeysUnavailable, err)
	}
	return rp, nil
}

// PasskeysAvailable reports whether this deployment can offer passkeys.
func (s *Service) PasskeysAvailable() bool {
	_, err := s.relyingParty()
	return err == nil
}

// BeginPasskeyRegistration starts adding a passkey to a signed-in account. The
// password is asked for again when the account has one, so a borrowed session
// cannot attach someone else's authenticator. The options go to
// navigator.credentials.create; ceremonyID comes back with the answer.
func (s *Service) BeginPasskeyRegistration(user *store.User, sessionID int64, password, ip string) (options *protocol.CredentialCreation, ceremonyID string, err error) {
	if user.PasswordHash != "" {
		if err := s.VerifyCurrentPassword(user, password, ip); err != nil {
			return nil, "", err
		}
	}
	rp, err := s.relyingParty()
	if err != nil {
		return nil, "", err
	}
	handle, err := s.store.EnsureWebAuthnID(user.ID)
	if err != nil {
		return nil, "", err
	}
	wu, err := s.webAuthnUser(user, handle)
	if err != nil {
		return nil, "", err
	}
	options, data, err := rp.BeginRegistration(wu,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(webauthn.Credentials(wu.WebAuthnCredentials()).CredentialDescriptors()),
	)
	if err != nil {
		return nil, "", fmt.Errorf("begin passkey registration: %w", err)
	}
	ceremonyID, err = s.ceremonies.put(ceremony{data: *data, userID: user.ID, sessionID: sessionID})
	if err != nil {
		return nil, "", err
	}
	return options, ceremonyID, nil
}

// FinishPasskeyRegistration checks the browser's answer and stores the new
// passkey under name. response is the PublicKeyCredential as JSON.
func (s *Service) FinishPasskeyRegistration(user *store.User, sessionID int64, ceremonyID, name string, response []byte) (*store.Passkey, error) {
	if err := store.ValidatePasskeyName(strings.TrimSpace(name)); err != nil {
		return nil, err
	}
	c, ok := s.ceremonies.take(ceremonyID)
	if !ok || c.userID != user.ID || c.sessionID != sessionID {
		return nil, ErrCeremony
	}
	rp, err := s.relyingParty()
	if err != nil {
		return nil, err
	}
	wu, err := s.webAuthnUser(user, user.WebAuthnID)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCredentials, err)
	}
	cred, err := rp.CreateCredential(wu, c.data, parsed)
	if err != nil {
		s.log.Info("passkey registration refused", "userId", user.ID, "err", err)
		return nil, ErrInvalidCredentials
	}
	pk, err := s.store.CreatePasskey(&store.Passkey{
		UserID:            user.ID,
		CredentialID:      cred.ID,
		PublicKey:         cred.PublicKey,
		SignCount:         cred.Authenticator.SignCount,
		Transports:        joinTransports(cred.Transport),
		AAGUID:            cred.Authenticator.AAGUID,
		Name:              name,
		BackupEligible:    cred.Flags.BackupEligible,
		BackupState:       cred.Flags.BackupState,
		UserVerified:      cred.Flags.UserVerified,
		AttestationType:   cred.AttestationType,
		AttestationFormat: cred.AttestationFormat,
	})
	if err != nil {
		return nil, err
	}
	s.log.Info("passkey added", "userId", user.ID, "passkeyId", pk.ID)
	s.notifySecurityChange(user, changePasskeyAdded)
	return pk, nil
}

// BeginPasskeyLogin starts a username-less sign-in. The options go to
// navigator.credentials.get; ceremonyID comes back with the answer.
func (s *Service) BeginPasskeyLogin(ip string) (options *protocol.CredentialAssertion, ceremonyID string, err error) {
	if wait := s.login.RetryAfter("login:" + ip); wait > 0 {
		return nil, "", &RateLimitError{RetryAfter: wait}
	}
	rp, err := s.relyingParty()
	if err != nil {
		return nil, "", err
	}
	options, data, err := rp.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", fmt.Errorf("begin passkey sign-in: %w", err)
	}
	ceremonyID, err = s.ceremonies.put(ceremony{data: *data})
	if err != nil {
		return nil, "", err
	}
	return options, ceremonyID, nil
}

// FinishPasskeyLogin checks a passkey assertion. Every failure is reported as
// ErrInvalidCredentials and counted against the source address, so unknown,
// foreign and forged credentials look the same. A user-verified passkey is
// two factors in one (something held, something known or biometric), so the
// result is loa:2 and no TOTP is asked for.
func (s *Service) FinishPasskeyLogin(ceremonyID string, response []byte, ip string) (*LoginResult, error) {
	if wait := s.login.RetryAfter("login:" + ip); wait > 0 {
		return nil, &RateLimitError{RetryAfter: wait}
	}
	c, ok := s.ceremonies.take(ceremonyID)
	if !ok || c.userID != 0 {
		return nil, ErrCeremony
	}
	rp, err := s.relyingParty()
	if err != nil {
		return nil, err
	}
	fail := func(reason string, args ...any) (*LoginResult, error) {
		s.log.Info("failed passkey sign-in", append([]any{"ip", ip, "reason", reason}, args...)...)
		if lock := s.login.Fail("login:" + ip); lock > 0 {
			s.log.Warn("login throttled by source", "ip", ip, "lockout", lock.String())
		}
		return nil, ErrInvalidCredentials
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return fail("unparsable assertion")
	}

	var (
		account *store.User
		stored  *store.Passkey
	)
	lookup := func(rawID, userHandle []byte) (webauthn.User, error) {
		u, err := s.store.UserByWebAuthnID(base64.RawURLEncoding.EncodeToString(userHandle))
		if err != nil {
			return nil, err
		}
		if u.Status != store.UserActive {
			return nil, ErrInvalidCredentials
		}
		wu, err := s.webAuthnUser(u, u.WebAuthnID)
		if err != nil {
			return nil, err
		}
		for _, p := range wu.passkeys {
			if bytes.Equal(p.CredentialID, rawID) {
				stored = p
			}
		}
		account = u
		return wu, nil
	}
	_, cred, err := rp.ValidatePasskeyLogin(lookup, c.data, parsed)
	if err != nil {
		return fail(err.Error())
	}
	if account == nil || stored == nil {
		return fail("credential not on record")
	}
	if cred.Authenticator.CloneWarning {
		// The counter went backwards: two copies of the key may exist.
		s.log.Warn("passkey signature counter did not increase", "userId", account.ID, "passkeyId", stored.ID)
		return fail("signature counter did not increase")
	}
	flags := parsed.Response.AuthenticatorData.Flags
	if err := s.store.RecordPasskeyUse(stored.ID, stored.SignCount, cred.Authenticator.SignCount,
		flags.HasBackupState(), flags.HasUserVerified()); err != nil {
		if errors.Is(err, store.ErrConsumed) {
			return fail("concurrent use of the same counter", "userId", account.ID)
		}
		return nil, err
	}
	s.login.Reset("login:" + ip)
	return &LoginResult{User: account, AMR: "webauthn", ACR: store.ACRLoA2}, nil
}

// RenamePasskey changes the label of one of the account's passkeys.
func (s *Service) RenamePasskey(user *store.User, id int64, name string) error {
	return s.store.RenamePasskey(user.ID, id, name)
}

// DeletePasskey removes one of the account's passkeys. The last way to sign
// in may go only when an emailed link can still reach the account; otherwise
// the account would need an administrator reset, which DESIGN.md allows only
// as a deliberate admin action.
func (s *Service) DeletePasskey(user *store.User, id int64) error {
	allowLast := s.EmailEnabled() && user.Status == store.UserActive
	if err := s.store.DeletePasskey(user.ID, id, allowLast); err != nil {
		return err
	}
	s.log.Info("passkey removed", "userId", user.ID, "passkeyId", id)
	s.notifySecurityChange(user, changePasskeyRemoved)
	return nil
}

// webAuthnUser adapts an account and its passkeys to the library's User.
func (s *Service) webAuthnUser(u *store.User, handle string) (*webAuthnUser, error) {
	id, err := base64.RawURLEncoding.DecodeString(handle)
	if err != nil || len(id) == 0 {
		return nil, fmt.Errorf("account %d has no valid passkey user handle", u.ID)
	}
	passkeys, err := s.store.ListPasskeys(u.ID)
	if err != nil {
		return nil, err
	}
	return &webAuthnUser{user: u, id: id, passkeys: passkeys}, nil
}

type webAuthnUser struct {
	user     *store.User
	id       []byte
	passkeys []*store.Passkey
}

func (w *webAuthnUser) WebAuthnID() []byte   { return w.id }
func (w *webAuthnUser) WebAuthnName() string { return w.user.Username }

func (w *webAuthnUser) WebAuthnDisplayName() string {
	if w.user.DisplayName != "" {
		return w.user.DisplayName
	}
	return w.user.Username
}

func (w *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(w.passkeys))
	for _, p := range w.passkeys {
		var flags protocol.AuthenticatorFlags = protocol.FlagUserPresent
		if p.UserVerified {
			flags |= protocol.FlagUserVerified
		}
		if p.BackupEligible {
			flags |= protocol.FlagBackupEligible
		}
		if p.BackupState {
			flags |= protocol.FlagBackupState
		}
		out = append(out, webauthn.Credential{
			ID:                p.CredentialID,
			PublicKey:         p.PublicKey,
			AttestationType:   p.AttestationType,
			AttestationFormat: p.AttestationFormat,
			Transport:         splitTransports(p.Transports),
			Flags:             webauthn.NewCredentialFlags(flags),
			Authenticator:     webauthn.Authenticator{AAGUID: p.AAGUID, SignCount: p.SignCount},
		})
	}
	return out
}

func joinTransports(ts []protocol.AuthenticatorTransport) string {
	parts := make([]string, 0, len(ts))
	for _, t := range ts {
		parts = append(parts, string(t))
	}
	return strings.Join(parts, " ")
}

func splitTransports(s string) []protocol.AuthenticatorTransport {
	var out []protocol.AuthenticatorTransport
	for _, f := range strings.Fields(s) {
		out = append(out, protocol.AuthenticatorTransport(f))
	}
	return out
}
