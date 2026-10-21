package client

import (
	"errors"
	"fmt"
)

// Errors a caller can test for with errors.Is. Each one wraps the specific
// reason, so the message says what failed while the identity stays stable.
var (
	// ErrInvalidToken is returned for a token that does not verify: bad
	// signature, unknown key, wrong issuer or audience, expired, and so on.
	ErrInvalidToken = errors.New("client: invalid token")
	// ErrStateMismatch is returned by the callback handler when the request
	// does not belong to a login this browser started: no login cookie, a
	// different state, or a login older than ten minutes.
	ErrStateMismatch = errors.New("client: state mismatch")
	// ErrIssuerMismatch is returned when a discovery document or an
	// authorization response names an issuer other than the configured one.
	ErrIssuerMismatch = errors.New("client: issuer mismatch")
	// ErrProvider is returned when the provider cannot be reached or answers
	// in a way the protocol does not allow: a transport failure, an
	// unexpected status, a body that is not the JSON expected.
	ErrProvider = errors.New("client: provider request failed")
	// ErrBadCallback is returned for an authorization response that is
	// neither a code nor an error, which no provider sends.
	ErrBadCallback = errors.New("client: malformed callback")
)

// TokenError is an OAuth 2.0 error response from the token endpoint (RFC
// 6749 section 5.2), such as invalid_grant for a code that was already used.
type TokenError struct {
	Code        string
	Description string
}

func (e *TokenError) Error() string {
	if e.Description == "" {
		return "client: token endpoint: " + e.Code
	}
	return "client: token endpoint: " + e.Code + ": " + e.Description
}

// AuthError is an error the provider returned to the redirect URI (RFC 6749
// section 4.1.2.1), such as access_denied when the person refused or the
// provider's rules do not allow them to use the application.
type AuthError struct {
	Code        string
	Description string
}

func (e *AuthError) Error() string {
	if e.Description == "" {
		return "client: authorization: " + e.Code
	}
	return "client: authorization: " + e.Code + ": " + e.Description
}

// invalid wraps a reason into ErrInvalidToken.
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidToken, fmt.Sprintf(format, args...))
}
