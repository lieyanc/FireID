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

// ErrTOTPEnabled is returned when enrolment starts on an account that already
// has two-step verification.
var ErrTOTPEnabled = errors.New("two-step verification is already on")

// ErrTOTPNotPending is returned when a confirmation arrives without an
// enrolment in progress.
var ErrTOTPNotPending = errors.New("no two-step verification enrolment is pending")

// ErrTOTPNotEnabled is returned when an operation needs two-step verification
// and the account does not have it.
var ErrTOTPNotEnabled = errors.New("two-step verification is not on")
