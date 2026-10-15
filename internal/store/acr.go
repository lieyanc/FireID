package store

// Authentication context class references. A client can demand a minimum level
// with the `acr_values` parameter; the provider compares it against the level of
// the session that authorised the request.
const (
	// ACRLoA1 is a single factor: a password, a passkey without user
	// verification, or an emailed link.
	ACRLoA1 = "urn:fireid:loa:1"
	// ACRLoA2 is two factors, or one user-verified passkey: a password plus
	// TOTP, or a passkey that asserted user verification.
	ACRLoA2 = "urn:fireid:loa:2"
)

// Satisfies reports whether have meets the demanded level. An empty demand is
// always satisfied.
func Satisfies(demand, have string) bool {
	if demand == "" {
		return true
	}
	switch demand {
	case ACRLoA1:
		return have == ACRLoA1 || have == ACRLoA2
	case ACRLoA2:
		return have == ACRLoA2
	default:
		return false
	}
}
