package store

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"unicode"
)

// Validation limits. They are deliberately generous but bounded: every column
// that a person controls has a maximum here.
const (
	UsernameMinLen = 3
	UsernameMaxLen = 32
	EmailMaxLen    = 254
	DisplayMaxLen  = 64
)

// ErrInvalid is the base for validation failures; callers wrap it with detail
// and the API layer turns it into a 400.
var ErrInvalid = errors.New("invalid")

// ValidateUsername enforces the username grammar: lower-case letters, digits,
// dot, dash and underscore, with a letter or digit at each end. The grammar is
// narrow on purpose — usernames end up in URLs and in `preferred_username`.
func ValidateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("%w: username is required", ErrInvalid)
	}
	if len(username) < UsernameMinLen || len(username) > UsernameMaxLen {
		return fmt.Errorf("%w: username must be %d to %d characters", ErrInvalid, UsernameMinLen, UsernameMaxLen)
	}
	for i, r := range username {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
		case unicode.IsUpper(r):
			// Normalisation should have handled this, but a caller that bypasses
			// it must not silently create a second account.
			return fmt.Errorf("%w: username must be lower-case", ErrInvalid)
		default:
			return fmt.Errorf("%w: username may only contain letters, digits, dot, dash and underscore (found %q)", ErrInvalid, string(r))
		}
		if i == 0 && (r == '.' || r == '-' || r == '_') {
			return fmt.Errorf("%w: username must start with a letter or digit", ErrInvalid)
		}
	}
	last := rune(username[len(username)-1])
	if last == '.' || last == '-' || last == '_' {
		return fmt.Errorf("%w: username must end with a letter or digit", ErrInvalid)
	}
	return nil
}

// ValidateEmail checks the address parses and is not absurdly long. It does not
// attempt to verify deliverability; email verification does that.
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("%w: email is required", ErrInvalid)
	}
	if len(email) > EmailMaxLen {
		return fmt.Errorf("%w: email must be at most %d characters", ErrInvalid, EmailMaxLen)
	}
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("%w: email is not a valid address", ErrInvalid)
	}
	if addr.Address != email {
		return fmt.Errorf("%w: email must be a bare address with no display name", ErrInvalid)
	}
	if !strings.Contains(strings.SplitN(email, "@", 2)[1], ".") {
		return fmt.Errorf("%w: email domain must contain a dot", ErrInvalid)
	}
	return nil
}

// ValidateDisplayName bounds the free-text display name.
func ValidateDisplayName(name string) error {
	if len([]rune(name)) > DisplayMaxLen {
		return fmt.Errorf("%w: display name must be at most %d characters", ErrInvalid, DisplayMaxLen)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: display name must not contain control characters", ErrInvalid)
		}
	}
	return nil
}
