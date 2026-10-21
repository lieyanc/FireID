package client

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// IDTokenClaims are the verified claims of an ID token. Raw holds every
// claim as decoded JSON for anything not surfaced here.
type IDTokenClaims struct {
	Issuer   string
	Subject  string
	Audience []string
	Expiry   time.Time
	IssuedAt time.Time
	// AuthTime is when the person authenticated; zero when absent. It is
	// what to check after WithMaxAge.
	AuthTime time.Time
	Nonce    string
	// AZP is the authorized party, present when the token has more than one
	// audience; it then equals the client ID.
	AZP string
	// ACR is the authentication context class, e.g. urn:fireid:loa:2.
	ACR string
	// AMR lists the authentication methods, e.g. pwd, otp, webauthn.
	AMR []string
	// SID is the provider's session identifier, which back-channel logout
	// tokens name. Store it with the local session.
	SID               string
	Email             string
	EmailVerified     bool
	Name              string
	PreferredUsername string
	Raw               map[string]any
}

// claims are the typed claims both token kinds share. Presence checks
// (nonce, events, jti) go through the raw map, since a decoded zero value
// cannot tell absent from empty.
type claims struct {
	Iss      string
	Sub      string
	Aud      audience
	Exp      *numericDate
	Iat      *numericDate
	Nbf      *numericDate
	AuthTime *numericDate
	Nonce    string
	AZP      string
	ACR      string
	AMR      []string
	SID      string
	JTI      string
	AtHash   string
	Email    string
	Verified bool
	Name     string
	Username string
}

// parseClaims fills claims from the payload's members by exact name, so a
// claim spelled in another case is just an unknown claim, as it is for the
// raw map; encoding/json's struct decoding would have matched it. A member
// of the wrong type is an error.
func parseClaims(members map[string]json.RawMessage) (*claims, error) {
	var cl claims
	for name, raw := range members {
		var dst any
		switch name {
		case "iss":
			dst = &cl.Iss
		case "sub":
			dst = &cl.Sub
		case "aud":
			dst = &cl.Aud
		case "exp":
			dst = &cl.Exp
		case "iat":
			dst = &cl.Iat
		case "nbf":
			dst = &cl.Nbf
		case "auth_time":
			dst = &cl.AuthTime
		case "nonce":
			dst = &cl.Nonce
		case "azp":
			dst = &cl.AZP
		case "acr":
			dst = &cl.ACR
		case "amr":
			dst = &cl.AMR
		case "sid":
			dst = &cl.SID
		case "jti":
			dst = &cl.JTI
		case "at_hash":
			dst = &cl.AtHash
		case "email":
			dst = &cl.Email
		case "email_verified":
			dst = &cl.Verified
		case "name":
			dst = &cl.Name
		case "preferred_username":
			dst = &cl.Username
		default:
			continue
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			return nil, fmt.Errorf("%s: %v", name, err)
		}
	}
	return &cl, nil
}

// audience is aud, which may be a string or an array of strings (RFC 7519
// section 4.1.3).
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return errors.New("aud is neither a string nor an array of strings")
	}
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("aud is neither a string nor an array of strings")
	}
	*a = audience(many)
	return nil
}

// numericDate is a JWT date: seconds since the epoch as a JSON number. Values
// outside [0, 2^40) — before 1970 or after the year 36000 — are refused
// rather than converted, since float-to-integer conversion of an
// out-of-range value is not defined.
type numericDate time.Time

func (d *numericDate) UnmarshalJSON(data []byte) error {
	var secs float64
	if err := json.Unmarshal(data, &secs); err != nil {
		return errors.New("date is not a number")
	}
	if secs < 0 || secs >= 1<<40 {
		return errors.New("date out of range")
	}
	whole, frac := int64(secs), secs-float64(int64(secs))
	*d = numericDate(time.Unix(whole, int64(frac*1e9)))
	return nil
}

func (d *numericDate) time() time.Time {
	if d == nil {
		return time.Time{}
	}
	return time.Time(*d)
}

// verified is a token whose signature checked out, with its payload decoded
// both into typed claims and as a map.
type verified struct {
	jws    *jws
	claims claims
	raw    map[string]any
}

// verifySignature parses raw, looks up the key the header names in the
// provider's key set and checks the signature. Nothing about the claims is
// examined yet, except that the payload is a JSON object.
func (c *Client) verifySignature(ctx context.Context, raw string) (*verified, error) {
	tok, err := parseJWS(raw)
	if err != nil {
		return nil, invalid("%v", err)
	}
	key, err := c.keys.key(ctx, tok.header.Kid)
	if err != nil {
		if errors.Is(err, ErrProvider) {
			return nil, err
		}
		return nil, invalid("%v", err)
	}
	if err := key.verify(tok.header.Alg, tok.signInput, tok.signature); err != nil {
		return nil, invalid("%v", err)
	}
	cl, err := parseClaims(tok.claims)
	if err != nil {
		return nil, invalid("claims: %v", err)
	}
	v := &verified{jws: tok, claims: *cl}
	// The raw map sees the same members as the typed claims: names are
	// exact in both and parseJWS refused duplicates.
	if err := json.Unmarshal(tok.payload, &v.raw); err != nil {
		return nil, invalid("claims: %v", err)
	}
	return v, nil
}

// checkIssuerAudience applies the rules both token kinds share (OpenID
// Connect Core 1.0 section 3.1.3.7, items 2 to 5): iss equals the configured
// issuer; aud contains the client ID; with more than one audience azp must
// be present; and azp, whenever present, must equal the client ID.
func (c *Client) checkIssuerAudience(cl *claims) error {
	if cl.Iss != c.cfg.Issuer {
		return invalid("iss %q is not %q", cl.Iss, c.cfg.Issuer)
	}
	found := false
	for _, a := range cl.Aud {
		if a == c.cfg.ClientID {
			found = true
		}
	}
	if !found {
		return invalid("aud does not contain the client id")
	}
	if len(cl.Aud) > 1 && cl.AZP == "" {
		return invalid("aud has several values but no azp")
	}
	if cl.AZP != "" && cl.AZP != c.cfg.ClientID {
		return invalid("azp %q is not the client id", cl.AZP)
	}
	return nil
}

// checkTimes applies exp, iat and nbf with the configured skew: exp must be
// in the future, iat and nbf must not be in the future. Both exp and iat
// are required for an ID token and for a logout token.
func (c *Client) checkTimes(cl *claims) error {
	now := c.now()
	skew := c.cfg.ClockSkew
	if cl.Exp == nil {
		return invalid("no exp")
	}
	if !now.Before(cl.Exp.time().Add(skew)) {
		return invalid("expired at %s", cl.Exp.time().UTC().Format(time.RFC3339))
	}
	if cl.Iat == nil {
		return invalid("no iat")
	}
	if cl.Iat.time().After(now.Add(skew)) {
		return invalid("iat %s is in the future", cl.Iat.time().UTC().Format(time.RFC3339))
	}
	if cl.Nbf != nil && cl.Nbf.time().After(now.Add(skew)) {
		return invalid("not valid before %s", cl.Nbf.time().UTC().Format(time.RFC3339))
	}
	return nil
}

// VerifyIDToken verifies a raw ID token against the provider's keys and the
// configuration (OpenID Connect Core 1.0 section 3.1.3.7): signature by a
// published key under an accepted algorithm, iss, aud and azp, exp and iat
// within the clock skew. When nonce is not empty the token's nonce must
// equal it; when it is empty, the claim is not checked. For a token that
// came with an access token use VerifyIDTokenWithAccessToken, which also
// checks at_hash.
func (c *Client) VerifyIDToken(ctx context.Context, raw, nonce string) (*IDTokenClaims, error) {
	return c.VerifyIDTokenWithAccessToken(ctx, raw, nonce, "")
}

// VerifyIDTokenWithAccessToken is VerifyIDToken plus the at_hash check: when
// accessToken is not empty and the token carries at_hash, the two must
// agree. at_hash is optional in the code flow, so its absence is not an
// error.
func (c *Client) VerifyIDTokenWithAccessToken(ctx context.Context, raw, nonce, accessToken string) (*IDTokenClaims, error) {
	v, err := c.verifySignature(ctx, raw)
	if err != nil {
		return nil, err
	}
	// A logout token or a JWT access token has iss, sub, aud, iat and exp
	// too. Refuse them by the marks they carry, so neither can stand in for
	// an ID token when no nonce is expected.
	if typ := normalizeTyp(v.jws.header.Typ); typ == "logout+jwt" || typ == "at+jwt" {
		return nil, invalid("typ %q is not an ID token", v.jws.header.Typ)
	}
	if _, ok := v.raw["events"]; ok {
		return nil, invalid("an ID token has no events claim")
	}
	cl := &v.claims
	if err := c.checkIssuerAudience(cl); err != nil {
		return nil, err
	}
	if cl.Sub == "" {
		return nil, invalid("no sub")
	}
	if err := c.checkTimes(cl); err != nil {
		return nil, err
	}
	if nonce != "" && !constantTimeEqual(cl.Nonce, nonce) {
		return nil, invalid("nonce mismatch")
	}
	if accessToken != "" && cl.AtHash != "" &&
		!constantTimeEqual(cl.AtHash, leftHalfHash(v.jws.header.Alg, accessToken)) {
		return nil, invalid("at_hash does not match the access token")
	}
	return &IDTokenClaims{
		Issuer:            cl.Iss,
		Subject:           cl.Sub,
		Audience:          []string(cl.Aud),
		Expiry:            cl.Exp.time(),
		IssuedAt:          cl.Iat.time(),
		AuthTime:          cl.AuthTime.time(),
		Nonce:             cl.Nonce,
		AZP:               cl.AZP,
		ACR:               cl.ACR,
		AMR:               cl.AMR,
		SID:               cl.SID,
		Email:             cl.Email,
		EmailVerified:     cl.Verified,
		Name:              cl.Name,
		PreferredUsername: cl.Username,
		Raw:               v.raw,
	}, nil
}

// normalizeTyp lower-cases a typ header and drops the application/ prefix
// RFC 7515 section 4.1.9 allows, so logout+jwt and application/LOGOUT+JWT
// compare equal.
func normalizeTyp(typ string) string {
	return strings.TrimPrefix(strings.ToLower(typ), "application/")
}

// constantTimeEqual compares two strings without an early exit on the first
// differing byte. Unequal lengths still return at once, which reveals only
// the length.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// String is a short description for logs: subject and issuer, never a claim
// that could be personal.
func (cl *IDTokenClaims) String() string {
	return fmt.Sprintf("sub %s at %s", cl.Subject, cl.Issuer)
}
