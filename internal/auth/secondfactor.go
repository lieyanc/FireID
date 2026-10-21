package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/lieyanc/FireID/internal/store"
)

// RecoveryCodeCount is how many recovery codes an enrolment issues.
const RecoveryCodeCount = 10

// recoveryAlphabet is lower-case base32. Its 32 symbols take five bits of a
// random byte each, so every symbol is equally likely.
const recoveryAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// PolicyRequiresTOTP reports whether the deployment's policy demands a second
// factor from this account, whether or not it has one.
func (s *Service) PolicyRequiresTOTP(user *store.User) bool {
	return s.cfg.RequireSecondFactorForAdmins && user.IsSuperAdmin
}

// needsSecondFactor reports whether a first factor alone is not enough. An
// unconfirmed secret does not count as enrolled: that would let a policy be
// skipped by starting an enrolment and never finishing it.
func (s *Service) needsSecondFactor(user *store.User) bool {
	if user.Status != store.UserActive {
		return false
	}
	return user.TOTPConfirmed || s.PolicyRequiresTOTP(user)
}

// AuthenticateTOTP completes a sign-in whose first factor (firstAMR) the
// caller has already verified. code is a TOTP code or a recovery code. For an
// account that must enrol, it is the first code from the new authenticator,
// and the result carries the account's recovery codes.
func (s *Service) AuthenticateTOTP(user *store.User, code, ip, firstAMR string) (*LoginResult, error) {
	if user.Status != store.UserActive {
		return nil, ErrInvalidCredentials
	}
	res := &LoginResult{User: user, AMR: firstAMR + " otp", ACR: store.ACRLoA2}
	if !user.TOTPConfirmed {
		if !s.PolicyRequiresTOTP(user) || user.TOTPSecretEnc == "" {
			return nil, ErrInvalidCredentials
		}
		codes, err := s.ConfirmEnrolment(user, code, ip)
		if err != nil {
			return nil, err
		}
		res.RecoveryCodes = codes
		return res, nil
	}
	if err := s.checkSecondFactor(user, code, ip); err != nil {
		return nil, err
	}
	return res, nil
}

// checkSecondFactor verifies a TOTP code, refusing one already used, or spends
// a recovery code. Failures are throttled per source and per account, so a
// six-digit code cannot be guessed from many addresses at once.
func (s *Service) checkSecondFactor(user *store.User, code, ip string) error {
	keys := []string{"totp:" + ip, "totp-acct:" + strconv.FormatInt(user.ID, 10)}
	for _, k := range keys {
		if wait := s.login.RetryAfter(k); wait > 0 {
			return &RateLimitError{RetryAfter: wait}
		}
	}
	ok, err := s.matchSecondFactor(user, code)
	if err != nil {
		return err
	}
	if !ok {
		for _, k := range keys {
			if lock := s.login.Fail(k); lock > 0 {
				s.log.Warn("second factor throttled", "key", k, "lockout", lock.String())
			}
		}
		return ErrInvalidCredentials
	}
	for _, k := range keys {
		s.login.Reset(k)
	}
	return nil
}

func (s *Service) matchSecondFactor(user *store.User, code string) (bool, error) {
	code = strings.TrimSpace(code)
	if isTOTPCode(code) {
		secret, err := s.box.OpenString(user.TOTPSecretEnc)
		if err != nil || secret == "" {
			return false, nil
		}
		step, ok := VerifyTOTPStep(secret, code, s.now(), user.TOTPLastStep)
		if !ok {
			return false, nil
		}
		// The stored step is the authority: user may be a stale copy, and a
		// concurrent request may have used the same code a moment ago.
		if err := s.store.AcceptTOTPStep(user.ID, step); err != nil {
			if errors.Is(err, store.ErrConsumed) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}
	norm, ok := normaliseRecoveryCode(code)
	if !ok {
		return false, nil
	}
	if err := s.store.UseRecoveryCode(user.ID, store.HashToken(norm)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	s.log.Info("recovery code used", "userId", user.ID)
	return true, nil
}

// BeginEnrolment creates a new TOTP secret for the account and returns it with
// the otpauth URI for a QR code. The secret is shown once; it is stored only
// encrypted.
func (s *Service) BeginEnrolment(user *store.User) (secret, uri string, err error) {
	if user.TOTPConfirmed {
		return "", "", ErrTOTPEnabled
	}
	secret, err = NewTOTPSecret()
	if err != nil {
		return "", "", err
	}
	enc, err := s.box.SealString(secret)
	if err != nil {
		return "", "", fmt.Errorf("encrypt totp secret: %w", err)
	}
	if err := s.store.BeginTOTPEnrolment(user.ID, enc); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return "", "", ErrTOTPEnabled
		}
		return "", "", err
	}
	return secret, TOTPURI(s.totpIssuer(), user.Username, secret), nil
}

// totpIssuer is the name an authenticator app shows: the host name of the
// public URL, which tells two deployments apart. The port is left out, since
// the label separates issuer and account with a colon.
func (s *Service) totpIssuer() string {
	if u, err := url.Parse(s.issuer); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return "Fire ID"
}

// ConfirmEnrolment checks the first code from a new authenticator, turns TOTP
// on and returns fresh recovery codes.
func (s *Service) ConfirmEnrolment(user *store.User, code, ip string) ([]string, error) {
	if user.TOTPConfirmed {
		return nil, ErrTOTPEnabled
	}
	if user.TOTPSecretEnc == "" {
		return nil, ErrTOTPNotPending
	}
	key := "totp-acct:" + strconv.FormatInt(user.ID, 10)
	if wait := s.login.RetryAfter(key); wait > 0 {
		return nil, &RateLimitError{RetryAfter: wait}
	}
	secret, err := s.box.OpenString(user.TOTPSecretEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt totp secret: %w", err)
	}
	step, ok := VerifyTOTPStep(secret, code, s.now(), user.TOTPLastStep)
	if !ok {
		s.login.Fail(key)
		return nil, ErrInvalidCredentials
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	if err := s.store.ConfirmTOTP(user.ID, user.TOTPSecretEnc, step, hashes); err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			return nil, ErrTOTPNotPending
		case errors.Is(err, store.ErrConsumed):
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	s.login.Reset(key)
	s.log.Info("two-step verification turned on", "userId", user.ID)
	s.notifySecurityChange(user, changeTOTPOn)
	return codes, nil
}

// DisableTOTP turns two-step verification off after a current code proves the
// person still holds the authenticator or a recovery code.
func (s *Service) DisableTOTP(user *store.User, code, ip string) error {
	if !user.TOTPConfirmed {
		return ErrTOTPNotEnabled
	}
	if s.PolicyRequiresTOTP(user) {
		return fmt.Errorf("%w: policy requires two-step verification for this account", ErrForbidden)
	}
	if err := s.checkSecondFactor(user, code, ip); err != nil {
		return err
	}
	if err := s.store.DisableTOTP(user.ID); err != nil {
		return err
	}
	s.log.Info("two-step verification turned off", "userId", user.ID)
	s.notifySecurityChange(user, changeTOTPOff)
	return nil
}

// RegenerateRecoveryCodes replaces the recovery codes after a current code.
func (s *Service) RegenerateRecoveryCodes(user *store.User, code, ip string) ([]string, error) {
	if !user.TOTPConfirmed {
		return nil, ErrTOTPNotEnabled
	}
	if err := s.checkSecondFactor(user, code, ip); err != nil {
		return nil, err
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	if err := s.store.ReplaceRecoveryCodes(user.ID, hashes); err != nil {
		return nil, err
	}
	s.log.Info("recovery codes replaced", "userId", user.ID)
	s.notifySecurityChange(user, changeRecoveryCodes)
	return codes, nil
}

// VerifyCurrentPassword re-checks the password of a signed-in account before a
// sensitive change, with the same throttling as sign-in.
func (s *Service) VerifyCurrentPassword(user *store.User, password, ip string) error {
	for _, k := range []string{"login:" + ip, "acct:" + user.Username} {
		if wait := s.login.RetryAfter(k); wait > 0 {
			return &RateLimitError{RetryAfter: wait}
		}
	}
	if user.PasswordHash == "" || VerifyPassword(password, user.PasswordHash) != nil {
		s.recordFailure(user.Username, ip)
		return ErrInvalidCredentials
	}
	return nil
}

// isTOTPCode reports whether code has the shape of a TOTP code rather than a
// recovery code.
func isTOTPCode(code string) bool {
	if len(code) != totpDigits {
		return false
	}
	for i := range code {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// newRecoveryCodes returns codes for the person and their hashes for storage.
// Each code is ten base32 characters (50 bits), shown as xxxxx-xxxxx.
func newRecoveryCodes() (codes, hashes []string, err error) {
	for range RecoveryCodeCount {
		raw := make([]byte, 10)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, fmt.Errorf("generate recovery code: %w", err)
		}
		var b strings.Builder
		for i, v := range raw {
			if i == 5 {
				b.WriteByte('-')
			}
			b.WriteByte(recoveryAlphabet[v&31])
		}
		code := b.String()
		norm, _ := normaliseRecoveryCode(code)
		codes = append(codes, code)
		hashes = append(hashes, store.HashToken(norm))
	}
	return codes, hashes, nil
}

// normaliseRecoveryCode accepts the code as shown, in any case, with or
// without the dash and spaces.
func normaliseRecoveryCode(code string) (string, bool) {
	code = strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(code))
	if len(code) != 10 {
		return "", false
	}
	for i := range code {
		if !strings.ContainsRune(recoveryAlphabet, rune(code[i])) {
			return "", false
		}
	}
	return code, true
}
