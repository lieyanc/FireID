package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	// defaultTimeout bounds every request to the provider when the caller
	// supplies no http.Client of their own.
	defaultTimeout = 10 * time.Second
	// maxResponseBytes bounds every response body read from the provider.
	// Discovery documents, key sets and token responses are a few kilobytes.
	maxResponseBytes = 1 << 20
	// wellKnown is the discovery path (OpenID Connect Discovery 1.0 section 4).
	wellKnown = ".well-known/openid-configuration"
)

// Provider is what Discover learns from an issuer's configuration document:
// the endpoints this package uses and the two capabilities it adapts to.
type Provider struct {
	// Issuer is the identifier the provider puts in iss, exactly as configured.
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	// UserInfoEndpoint is empty when the provider offers none.
	UserInfoEndpoint string
	JWKSURI          string
	// EndSessionEndpoint is empty when RP-initiated logout is not offered.
	EndSessionEndpoint string
	// IssuerParameterSupported reports that authorization responses carry an
	// iss parameter (RFC 9207), which the callback handler then requires.
	IssuerParameterSupported bool
	// BackchannelLogoutSupported reports that the provider sends logout tokens.
	BackchannelLogoutSupported bool
}

// DiscoverOption adjusts Discover.
type DiscoverOption func(*discoverOptions)

type discoverOptions struct {
	http *http.Client
}

// WithHTTPClient makes Discover use hc instead of the default client, for a
// proxy, custom TLS roots or a different timeout. The default client has a
// ten-second timeout and does not follow redirects.
func WithHTTPClient(hc *http.Client) DiscoverOption {
	return func(o *discoverOptions) { o.http = hc }
}

// Discover fetches <issuer>/.well-known/openid-configuration and returns the
// endpoints it names. The document's issuer must equal the given one exactly
// (OpenID Connect Discovery 1.0 section 4.3): configure the issuer as the
// provider states it, trailing slash included or not. The issuer must be an
// https URL; http is accepted for loopback hosts only, for development.
func Discover(ctx context.Context, issuer string, opts ...DiscoverOption) (*Provider, error) {
	var o discoverOptions
	for _, opt := range opts {
		opt(&o)
	}
	if o.http == nil {
		o.http = defaultHTTPClient()
	}
	if err := checkIssuerURL(issuer); err != nil {
		return nil, fmt.Errorf("client: issuer %q: %w", issuer, err)
	}
	discoveryURL := issuer + "/" + wellKnown
	if strings.HasSuffix(issuer, "/") {
		discoveryURL = issuer + wellKnown
	}
	body, err := getJSON(ctx, o.http, discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	var doc struct {
		Issuer                     string `json:"issuer"`
		AuthorizationEndpoint      string `json:"authorization_endpoint"`
		TokenEndpoint              string `json:"token_endpoint"`
		UserInfoEndpoint           string `json:"userinfo_endpoint"`
		JWKSURI                    string `json:"jwks_uri"`
		EndSessionEndpoint         string `json:"end_session_endpoint"`
		IssuerParameterSupported   bool   `json:"authorization_response_iss_parameter_supported"`
		BackchannelLogoutSupported bool   `json:"backchannel_logout_supported"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: discovery document: %v", ErrProvider, err)
	}
	if doc.Issuer != issuer {
		return nil, fmt.Errorf("%w: discovery document names %q, configured %q", ErrIssuerMismatch, doc.Issuer, issuer)
	}
	p := &Provider{
		Issuer:                     issuer,
		AuthorizationEndpoint:      doc.AuthorizationEndpoint,
		TokenEndpoint:              doc.TokenEndpoint,
		UserInfoEndpoint:           doc.UserInfoEndpoint,
		JWKSURI:                    doc.JWKSURI,
		EndSessionEndpoint:         doc.EndSessionEndpoint,
		IssuerParameterSupported:   doc.IssuerParameterSupported,
		BackchannelLogoutSupported: doc.BackchannelLogoutSupported,
	}
	required := map[string]string{
		"authorization_endpoint": p.AuthorizationEndpoint,
		"token_endpoint":         p.TokenEndpoint,
		"jwks_uri":               p.JWKSURI,
	}
	for name, value := range required {
		if value == "" {
			return nil, fmt.Errorf("%w: discovery document has no %s", ErrProvider, name)
		}
	}
	for name, value := range map[string]string{
		"authorization_endpoint": p.AuthorizationEndpoint,
		"token_endpoint":         p.TokenEndpoint,
		"userinfo_endpoint":      p.UserInfoEndpoint,
		"jwks_uri":               p.JWKSURI,
		"end_session_endpoint":   p.EndSessionEndpoint,
	} {
		if value == "" {
			continue
		}
		if err := checkEndpointURL(value); err != nil {
			return nil, fmt.Errorf("%w: discovery document %s: %v", ErrProvider, name, err)
		}
	}
	return p, nil
}

// defaultHTTPClient is used when the caller supplies none. It refuses
// redirects: none of the endpoints this package talks to may redirect, and
// following one could carry a client secret or an access token elsewhere.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// checkIssuerURL accepts an absolute https URL without query, fragment or
// user information, or an http one on a loopback host.
func checkIssuerURL(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil {
		return err
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return errors.New("must be an absolute URL without query, fragment or user information")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return errors.New("plain http is accepted for loopback hosts only")
	default:
		return fmt.Errorf("scheme %q is not http(s)", u.Scheme)
	}
}

// checkEndpointURL accepts an absolute http(s) URL without user information.
// Plain http is accepted for loopback hosts only, as for the issuer.
func checkEndpointURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Host == "" || u.User != nil {
		return errors.New("not an absolute URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return errors.New("plain http is accepted for loopback hosts only")
	default:
		return fmt.Errorf("scheme %q is not http(s)", u.Scheme)
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// getJSON GETs url and returns the body of a 200 answer, bounded. The
// content type is not checked: providers vary, and the caller parses the
// body anyway.
func getJSON(ctx context.Context, hc *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProvider, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProvider, err)
	}
	defer resp.Body.Close()
	body, err := readBody(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: GET %s: status %d", ErrProvider, url, resp.StatusCode)
	}
	return body, nil
}

// readBody reads at most maxResponseBytes and refuses a longer body.
func readBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %v", ErrProvider, err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("%w: response larger than %d bytes", ErrProvider, maxResponseBytes)
	}
	return body, nil
}

// remoteAddr parses an http.Request.RemoteAddr, which is host:port for TCP
// listeners. A bare address is accepted too; anything else, such as a Unix
// socket's name, yields no address.
func remoteAddr(s string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
