package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters. RFC 6238 with the values every authenticator app expects:
// HMAC-SHA1, 6 digits, 30-second steps.
const (
	totpDigits = 6
	totpPeriod = 30 * time.Second
	// totpSkew is how many steps either side of now are accepted, covering
	// clock drift between the server and the phone.
	totpSkew = 1
	// totpSecretLen is the number of random bytes in a shared secret; 20 is the
	// SHA-1 block size.
	totpSecretLen = 20
)

// NewTOTPSecret returns a fresh shared secret in base32 (no padding), the form
// authenticator apps accept.
func NewTOTPSecret() (string, error) {
	raw := make([]byte, totpSecretLen)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// TOTPURI builds the otpauth:// URI an authenticator app scans.
func TOTPURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(int(totpPeriod.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// VerifyTOTP checks a submitted code against the secret, accepting the current
// step and one either side. It reports the matched step so the caller can
// reject a replay; see VerifyTOTPStep.
func VerifyTOTP(secret, code string, now time.Time) bool {
	_, ok := VerifyTOTPStep(secret, code, now, 0)
	return ok
}

// VerifyTOTPStep is VerifyTOTP with replay protection. lastStep is the highest
// step already accepted for this account; a code whose step is not greater than
// lastStep is refused, so a code cannot be used twice even inside its validity
// window. Pass 0 when no code has been used yet.
func VerifyTOTPStep(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	for i := range code {
		if code[i] < '0' || code[i] > '9' {
			return 0, false
		}
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) == 0 {
		return 0, false
	}

	current := now.Unix() / int64(totpPeriod.Seconds())
	for delta := -totpSkew; delta <= totpSkew; delta++ {
		step := current + int64(delta)
		if step <= 0 || step <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(totpCode(key, step)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// totpCode computes the HOTP value for a counter, per RFC 4226.
func totpCode(key []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%mod)
}
