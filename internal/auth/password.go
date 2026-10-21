// Package auth owns the credentials that identify a person: passwords, TOTP,
// email codes and passkeys, plus the sessions they produce. It deliberately
// knows nothing about OAuth or HTTP beyond the request metadata it records.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrInvalidCredentials is returned for a wrong password, an unknown user, or a
// malformed stored hash. Callers must not distinguish between these cases in
// their response.
var ErrInvalidCredentials = errors.New("invalid credentials")

// Argon2id parameters: memory 64 MiB, 3 iterations, 2 lanes, 16-byte salt,
// 32-byte tag. That is above the OWASP minimum (19 MiB, 2 iterations, 1 lane).
const (
	argonMemory  = 64 * 1024
	argonTime    = 3
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// argonSlots bounds how many hashes are computed at once. Each one holds
// argonMemory for its duration, so a burst of sign-in attempts — which all get
// past the throttle before the first failure is counted — would otherwise
// exhaust memory. Callers beyond the limit wait their turn.
var argonSlots = make(chan struct{}, max(2, runtime.GOMAXPROCS(0)))

// argonKey is argon2.IDKey under argonSlots.
func argonKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	argonSlots <- struct{}{}
	defer func() { <-argonSlots }()
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}

// HashPassword returns an encoded argon2id hash in the standard
// $argon2id$v=19$m=...,t=...,p=...$salt$hash form, so parameters travel with
// the hash and can be raised later without invalidating old passwords.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password is empty")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}
	tag := argonKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return encodeHash(salt, tag), nil
}

// VerifyPassword checks a password against an encoded hash. A malformed hash is
// reported as invalid credentials so a corrupt row cannot become a bypass.
func VerifyPassword(password, encoded string) error {
	salt, want, m, t, p, err := decodeHash(encoded)
	if err != nil {
		return ErrInvalidCredentials
	}
	got := argonKey([]byte(password), salt, t, m, p, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrInvalidCredentials
	}
	return nil
}

// NeedsRehash reports whether an encoded hash uses parameters weaker than the
// current defaults, so a successful sign-in can transparently upgrade it.
func NeedsRehash(encoded string) bool {
	_, _, m, t, p, err := decodeHash(encoded)
	if err != nil {
		return true
	}
	return m < argonMemory || t < argonTime || p < argonThreads
}

// dummyHash is verified against when the username does not exist, so that a
// failed sign-in costs the same time whether or not the account is real.
var dummyHash = func() string {
	h, err := HashPassword("fireid-dummy-password-for-timing")
	if err != nil {
		panic("auth: cannot build dummy hash: " + err.Error())
	}
	return h
}()

// VerifyDummy spends the same work as a real verification. Call it on the
// unknown-user path.
func VerifyDummy(password string) {
	_ = VerifyPassword(password, dummyHash)
}

func encodeHash(salt, tag []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(tag))
}

func decodeHash(encoded string) (salt, tag []byte, memory, time uint32, threads uint8, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, 0, 0, 0, errors.New("unrecognised hash format")
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return nil, nil, 0, 0, 0, errors.New("unsupported argon2 version")
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("parse parameters: %w", err)
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("decode salt: %w", err)
	}
	tag, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("decode tag: %w", err)
	}
	if len(salt) == 0 || len(tag) == 0 {
		return nil, nil, 0, 0, 0, errors.New("empty salt or tag")
	}
	return salt, tag, m, t, p, nil
}
