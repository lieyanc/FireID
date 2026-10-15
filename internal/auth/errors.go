package auth

import "errors"

// ErrForbidden is returned when a policy — not a credential — refuses the
// operation, such as self-registration while the deployment is closed.
var ErrForbidden = errors.New("forbidden")

// ErrInvalidPassword is returned when a new password violates the policy. It is
// distinct from ErrInvalidCredentials so the UI can explain the rule.
var ErrInvalidPassword = errors.New("password does not meet the policy")

// ErrNoCredentials is returned when an account has no usable credential at all.
var ErrNoCredentials = errors.New("account has no usable credential")
