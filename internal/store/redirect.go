package store

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateRedirectURI checks a registered redirect URI.
//
// The rules follow RFC 9700 §2.1 and RFC 8252 §7.3, and they are strict on
// purpose: a redirect URI that matches too loosely is a token-exfiltration
// vector, which is exactly the bug class that produced CVE-2020-15233 in
// Fosite. There is no wildcard support anywhere.
//
//   - The URI must be absolute, with a scheme and a host, and must carry no
//     fragment.
//   - https is required, except for loopback (http://127.0.0.1, http://[::1],
//     http://localhost), which RFC 8252 permits for native apps.
//   - http on a non-loopback host is refused: an authorization code sent over
//     plaintext is an authorization code anyone on the path can take.
//   - A loopback URI may omit the port or use any port in the registered form
//     "http://127.0.0.1" / "http://localhost", which matches any port at
//     request time. A URI with an explicit port matches only that port.
func ValidateRedirectURI(raw, clientType string) error {
	if raw == "" {
		return fmt.Errorf("%w: a redirect URI is empty", ErrInvalid)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %q is not a valid URI", ErrInvalid, raw)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%w: %q must be absolute, with a scheme and a host", ErrInvalid, raw)
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("%w: %q must not contain a fragment", ErrInvalid, raw)
	}
	if u.User != nil {
		return fmt.Errorf("%w: %q must not contain user information", ErrInvalid, raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return fmt.Errorf("%w: %q uses http on a non-loopback host; use https", ErrInvalid, raw)
		}
		return nil
	default:
		return fmt.Errorf("%w: %q uses the unsupported scheme %q", ErrInvalid, raw, u.Scheme)
	}
}

// MatchesRedirectURI reports whether a request's redirect_uri is one the client
// registered. Registration and comparison both normalise the same way, so a
// trailing slash or a default port cannot be used to slip past.
//
// A registered loopback URI without an explicit port matches any port, per
// RFC 8252 §7.3; every other URI must match exactly.
func MatchesRedirectURI(registered []string, requested string) bool {
	req, err := url.Parse(requested)
	if err != nil || req.Fragment != "" || req.User != nil {
		return false
	}
	for _, reg := range registered {
		if reg == requested {
			return true
		}
		r, err := url.Parse(reg)
		if err != nil {
			continue
		}
		if !strings.EqualFold(r.Scheme, req.Scheme) || !strings.EqualFold(r.Hostname(), req.Hostname()) {
			continue
		}
		if !isLoopbackHost(r.Hostname()) {
			continue
		}
		// Loopback: a registered URI with no port accepts any port.
		if r.Port() == "" && req.Port() != "" {
			if normalisePath(r.Path) == normalisePath(req.Path) {
				return true
			}
		}
	}
	return false
}

// NormaliseRedirectURI puts a URI into the canonical form used for storage and
// comparison. It only removes differences that cannot change the destination.
func NormaliseRedirectURI(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %q is not a valid URI", ErrInvalid, raw)
	}
	if u.Scheme != "" {
		u.Scheme = strings.ToLower(u.Scheme)
	}
	if u.Host != "" {
		host := strings.ToLower(u.Hostname())
		if port := u.Port(); port != "" {
			if !isDefaultPort(u.Scheme, port) {
				host = net.JoinHostPort(host, port)
			}
		}
		u.Host = host
	}
	if u.Path == "" {
		u.Path = "/"
	}
	// A redirect URI's query is part of the destination for some clients, so it
	// is preserved verbatim; only the ordering within it is left alone.
	return u.String(), nil
}

func normalisePath(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isDefaultPort(scheme, port string) bool {
	return (scheme == "https" && port == "443") || (scheme == "http" && port == "80")
}
