package client

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
)

// HeaderIdentity is the person Fire ID's forward auth identified, as the
// reverse proxy passed it on in X-FireID-* headers.
type HeaderIdentity struct {
	// Subject is the stable account ID, the same sub OIDC applications see.
	// Key local data on it, not on Username.
	Subject  string
	Username string
	Email    string
	Name     string
	Groups   []string
}

// TrustedHeaders reads the identity headers nginx sets after Fire ID's
// forward auth (docs/forward-auth.md) and makes them available through
// IdentityFrom. The headers are trusted only on a request that arrived from
// one of TrustedProxies; from anywhere else they are stripped before the
// next handler sees the request, so nothing downstream can be fooled by a
// client that sent its own.
//
// The proxy must set each header, replacing whatever the client sent, as
// nginx's proxy_set_header does. A request on which any X-FireID-* header
// appears more than once is treated as anonymous and loses the headers,
// since nothing says which value is the proxy's.
type TrustedHeaders struct {
	// TrustedProxies are the networks the proxy connects from. Empty means
	// loopback only (127.0.0.0/8 and ::1), which is where the proxy is when
	// the application is bound as forward-auth.md asks.
	TrustedProxies []netip.Prefix
	// TrustUnixSocket trusts a request whose RemoteAddr is not an IP
	// address and port — what a Unix socket listener reports — in addition
	// to TrustedProxies. Set it only when the application listens on a
	// socket that nothing but the proxy can reach: the socket's file
	// permissions are then the whole access control.
	TrustUnixSocket bool
	// Required answers 401 when a trusted request carries no identity, and
	// for every untrusted request. Off, such requests pass through
	// anonymous and IdentityFrom reports no identity.
	Required bool
}

// headerPrefix is what every forward-auth identity header starts with.
// Go canonicalises header names, so the comparison is case-insensitive.
const headerPrefix = "X-Fireid-"

var loopback = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

type identityKey struct{}

// Middleware wraps next. On a request from a trusted proxy with a non-empty
// X-FireID-Sub, the identity is put in the context; the other headers are
// read as they are, with control characters removed, and X-FireID-Groups
// split on commas. A request from anywhere else, or one on which an
// X-FireID-* header is repeated, loses every X-FireID-* header. Nothing is
// logged.
func (t TrustedHeaders) Middleware(next http.Handler) http.Handler {
	proxies := t.TrustedProxies
	if len(proxies) == 0 {
		proxies = loopback
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !t.trusts(r.RemoteAddr, proxies) || repeatedIdentityHeader(r.Header) {
			stripIdentityHeaders(r.Header)
		}
		id := identityFromHeaders(r.Header)
		if id == nil {
			if t.Required {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)))
	})
}

// IdentityFrom returns the identity Middleware found on the request, if any.
func IdentityFrom(ctx context.Context) (*HeaderIdentity, bool) {
	id, ok := ctx.Value(identityKey{}).(*HeaderIdentity)
	return id, ok
}

// trusts reports whether a request from remote came through the proxy: from
// one of the proxy networks, or over a Unix socket when that is trusted.
func (t TrustedHeaders) trusts(remote string, proxies []netip.Prefix) bool {
	if t.TrustUnixSocket {
		if _, ok := remoteAddr(remote); !ok {
			return true
		}
	}
	return fromTrusted(remote, proxies)
}

func fromTrusted(remote string, proxies []netip.Prefix) bool {
	addr, ok := remoteAddr(remote)
	if !ok {
		return false
	}
	for _, p := range proxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// isIdentityHeader reports whether name is an X-FireID-* header, under any
// spelling.
func isIdentityHeader(name string) bool {
	return len(name) >= len(headerPrefix) && strings.EqualFold(name[:len(headerPrefix)], headerPrefix)
}

// stripIdentityHeaders removes every X-FireID-* header.
func stripIdentityHeaders(h http.Header) {
	for name := range h {
		if isIdentityHeader(name) {
			delete(h, name)
		}
	}
}

// repeatedIdentityHeader reports whether any X-FireID-* header has more than
// one value, counting every spelling of a name together.
func repeatedIdentityHeader(h http.Header) bool {
	seen := map[string]int{}
	for name, values := range h {
		if !isIdentityHeader(name) {
			continue
		}
		key := http.CanonicalHeaderKey(name)
		seen[key] += len(values)
		if seen[key] > 1 {
			return true
		}
	}
	return false
}

// identityFromHeaders reads the identity, or nil when X-FireID-Sub is empty.
func identityFromHeaders(h http.Header) *HeaderIdentity {
	sub := cleanHeader(h.Get("X-FireID-Sub"))
	if sub == "" {
		return nil
	}
	id := &HeaderIdentity{
		Subject:  sub,
		Username: cleanHeader(h.Get("X-FireID-User")),
		Email:    cleanHeader(h.Get("X-FireID-Email")),
		Name:     cleanHeader(h.Get("X-FireID-Name")),
	}
	for _, g := range strings.Split(cleanHeader(h.Get("X-FireID-Groups")), ",") {
		if g = strings.TrimSpace(g); g != "" {
			id.Groups = append(id.Groups, g)
		}
	}
	return id
}

// cleanHeader drops control characters and keeps everything else as it
// came, byte for byte: nginx passes the values through as raw UTF-8.
func cleanHeader(v string) string {
	clean := true
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return strings.TrimSpace(v)
	}
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v); i++ {
		if v[i] >= 0x20 && v[i] != 0x7f {
			b.WriteByte(v[i])
		}
	}
	return strings.TrimSpace(b.String())
}
