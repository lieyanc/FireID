package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"strings"
)

// joinSpaceList joins a slice of strings with spaces.
func joinSpaceList(ss []string) string {
	return strings.Join(ss, " ")
}

// parseSpaceList splits a space-separated string into a slice.
func parseSpaceList(s string) []string {
	return strings.Fields(s)
}

// hasScope reports whether scope is in the space-separated list.
func hasScope(list, scope string) bool {
	return slices.Contains(parseSpaceList(list), scope)
}

// subjectOf is the OIDC subject for a user: the numeric account ID. It never
// changes, unlike the username, so a rename does not turn a person into a new
// account at every connected app.
func subjectOf(userID int64) string {
	return strconv.FormatInt(userID, 10)
}

// errBadSubject is returned for a subject that is not one of ours.
var errBadSubject = errors.New("malformed subject")

// userIDFromSubject reverses subjectOf.
func userIDFromSubject(sub string) (int64, error) {
	id, err := strconv.ParseInt(sub, 10, 64)
	if err != nil || id <= 0 {
		return 0, errBadSubject
	}
	return id, nil
}

// randomTokenID generates a URL-safe random ID of the given byte length.
func randomTokenID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
