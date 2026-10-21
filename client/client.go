package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Client authentication methods at the token endpoint (OpenID Connect Core
// 1.0 section 9), the values Config.AuthMethod takes.
const (
	AuthMethodBasic = "client_secret_basic"
	AuthMethodPost  = "client_secret_post"
	AuthMethodNone  = "none"
)

// defaultClockSkew is tolerated on exp, iat and nbf when Config.ClockSkew is
// zero. Provider and application clocks are rarely more than seconds apart.
const defaultClockSkew = time.Minute

// Config describes the application as registered at the provider.
type Config struct {
	// Issuer is the provider's issuer URL, e.g. https://id.example.com,
	// exactly as the provider states it.
	Issuer   string
	ClientID string
	// ClientSecret is empty for a public client, which then authenticates
	// with PKCE alone (AuthMethod none).
	ClientSecret string
	// RedirectURL is where the provider sends the browser back; it must be
	// registered with the application. The callback handler serves its path.
	RedirectURL string
	// Scopes defaults to openid profile email. openid is required.
	Scopes []string
	// AuthMethod is client_secret_basic (default when a secret is set),
	// client_secret_post, or none (default and only choice without a secret).
	AuthMethod string
	// HTTPClient is used for every request to the provider. The default has
	// a ten-second timeout and does not follow redirects. A client of your
	// own should refuse them too: none of the endpoints used here may
	// redirect, and following one would carry the client secret or an
	// access token to wherever it points.
	HTTPClient *http.Client
	// ClockSkew is tolerated on exp, iat and nbf; default one minute.
	ClockSkew time.Duration
}

// Client is a relying party for one application at one provider. It is safe
// for concurrent use.
type Client struct {
	cfg      Config
	provider *Provider
	http     *http.Client
	keys     *keySet
	jtis     *jtiCache
	secure   bool   // the RedirectURL is https
	cookie   string // the login cookie's default name
	now      func() time.Time
}

// New validates cfg, runs Discover against cfg.Issuer and returns a Client.
// The provider's keys are fetched on the first verification, not here.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("client: Issuer, ClientID and RedirectURL are required")
	}
	redirect, err := url.Parse(cfg.RedirectURL)
	if err != nil || (redirect.Scheme != "https" && redirect.Scheme != "http") || redirect.Host == "" {
		return nil, errors.New("client: RedirectURL must be an absolute http(s) URL")
	}
	if cfg.Scopes == nil {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	if !slices.Contains(cfg.Scopes, "openid") {
		return nil, errors.New("client: Scopes must include openid")
	}
	switch cfg.AuthMethod {
	case "":
		cfg.AuthMethod = AuthMethodNone
		if cfg.ClientSecret != "" {
			cfg.AuthMethod = AuthMethodBasic
		}
	case AuthMethodBasic, AuthMethodPost:
		if cfg.ClientSecret == "" {
			return nil, fmt.Errorf("client: AuthMethod %s needs a ClientSecret", cfg.AuthMethod)
		}
	case AuthMethodNone:
		if cfg.ClientSecret != "" {
			return nil, errors.New("client: AuthMethod none cannot be combined with a ClientSecret")
		}
	default:
		return nil, fmt.Errorf("client: unknown AuthMethod %q", cfg.AuthMethod)
	}
	if cfg.ClockSkew < 0 {
		return nil, errors.New("client: ClockSkew must not be negative")
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = defaultClockSkew
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = defaultHTTPClient()
	}
	p, err := Discover(ctx, cfg.Issuer, WithHTTPClient(hc))
	if err != nil {
		return nil, err
	}
	secure := redirect.Scheme == "https"
	return &Client{
		cfg:      cfg,
		provider: p,
		http:     hc,
		keys:     &keySet{url: p.JWKSURI, http: hc, now: time.Now},
		jtis:     newJTICache(),
		secure:   secure,
		cookie:   defaultCookieName(cfg.Issuer, cfg.ClientID, secure),
		now:      time.Now,
	}, nil
}

// Provider returns what discovery found, for callers that want to know
// whether the provider offers end_session or back-channel logout.
func (c *Client) Provider() *Provider {
	p := *c.provider
	return &p
}

// RandomString returns 32 bytes from crypto/rand as 43 base64url characters,
// suitable for state and nonce.
func RandomString() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("client: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewPKCEVerifier returns a code verifier for RFC 7636: 43 characters of the
// unreserved alphabet from 32 random bytes. Keep it until Exchange.
func NewPKCEVerifier() string {
	return RandomString()
}

// pkceChallenge is the S256 code challenge for a verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthOption adds a parameter to the authorization request.
type AuthOption func(url.Values)

// WithPrompt sets prompt, e.g. "login" to force re-authentication or
// "none" to only succeed silently.
func WithPrompt(prompt string) AuthOption {
	return func(q url.Values) { q.Set("prompt", prompt) }
}

// WithMaxAge sets max_age: the provider re-authenticates a person whose
// session is older than this. Check auth_time in the claims afterwards.
func WithMaxAge(d time.Duration) AuthOption {
	return func(q url.Values) { q.Set("max_age", strconv.FormatInt(int64(d/time.Second), 10)) }
}

// WithACRValues sets acr_values, e.g. urn:fireid:loa:2 to ask Fire ID for
// two factors. The provider may answer with a lower acr; check the claim.
func WithACRValues(values ...string) AuthOption {
	return func(q url.Values) { q.Set("acr_values", strings.Join(values, " ")) }
}

// WithLoginHint sets login_hint, pre-filling the identifier on the sign-in page.
func WithLoginHint(hint string) AuthOption {
	return func(q url.Values) { q.Set("login_hint", hint) }
}

// WithExtra sets any other parameter. The parameters the protocol relies on
// — response_type, client_id, redirect_uri, scope, state, nonce and the PKCE
// pair — cannot be changed this way.
func WithExtra(key, value string) AuthOption {
	return func(q url.Values) { q.Set(key, value) }
}

// AuthCodeURL builds the authorization request to redirect the browser to.
// It always carries PKCE (S256 over codeVerifier) and the configured scopes.
// state and nonce should come from RandomString, codeVerifier from
// NewPKCEVerifier; keep all three for the callback.
func (c *Client) AuthCodeURL(state, nonce, codeVerifier string, opts ...AuthOption) string {
	q := url.Values{}
	for _, o := range opts {
		o(q)
	}
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", c.cfg.RedirectURL)
	q.Set("scope", strings.Join(c.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", pkceChallenge(codeVerifier))
	q.Set("code_challenge_method", "S256")
	return appendQuery(c.provider.AuthorizationEndpoint, q)
}

// appendQuery adds q to a URL that may already carry a query string.
func appendQuery(endpoint string, q url.Values) string {
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}
	return endpoint + sep + q.Encode()
}

// Tokens is a token endpoint response.
type Tokens struct {
	AccessToken  string
	TokenType    string
	RefreshToken string // empty unless offline_access was granted
	IDToken      string // the raw ID token, for id_token_hint at logout
	// Expiry is when the access token expires; zero when the provider did
	// not say.
	Expiry time.Time
	// Claims are the verified ID token claims. They are nil only after a
	// Refresh in which the provider sent no ID token.
	Claims *IDTokenClaims
}

// TokenOption adjusts the checks Exchange and Refresh make on the ID token.
type TokenOption func(*tokenChecks)

type tokenChecks struct {
	nonce   string
	subject string
}

// WithNonce makes Exchange require the ID token's nonce to equal the one
// sent in the authorization request. Always pass it when a nonce was sent;
// it binds the token to this login.
func WithNonce(nonce string) TokenOption {
	return func(t *tokenChecks) { t.nonce = nonce }
}

// WithExpectedSubject makes Refresh require the refreshed ID token's sub to
// equal the original one's (OpenID Connect Core 1.0 section 12.2).
func WithExpectedSubject(sub string) TokenOption {
	return func(t *tokenChecks) { t.subject = sub }
}

// Exchange redeems an authorization code, authenticating as configured and
// proving the PKCE verifier. The ID token in the answer is verified, with
// its at_hash against the access token; it must be present since openid is
// always requested. Pass WithNonce with the nonce from the authorization
// request.
func (c *Client) Exchange(ctx context.Context, code, codeVerifier string, opts ...TokenOption) (*Tokens, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.cfg.RedirectURL},
		"code_verifier": {codeVerifier},
	}
	tokens, err := c.token(ctx, form, opts, true)
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

// Refresh redeems a refresh token. A provider may or may not return an ID
// token; when it does, it is verified (without a nonce, which refreshed
// tokens need not carry) and, with WithExpectedSubject, its sub compared.
// The refresh token in the answer replaces the one passed in: Fire ID
// rotates them on every use.
func (c *Client) Refresh(ctx context.Context, refreshToken string, opts ...TokenOption) (*Tokens, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	return c.token(ctx, form, opts, false)
}

// tokenResponse is the wire form of a token endpoint answer (RFC 6749
// section 5.1, OpenID Connect Core 1.0 section 3.1.3.3).
type tokenResponse struct {
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    seconds `json:"expires_in"`
	RefreshToken string  `json:"refresh_token"`
	IDToken      string  `json:"id_token"`
	Error        string  `json:"error"`
	ErrorDesc    string  `json:"error_description"`
}

// maxExpiresIn caps expires_in. An access token that lasts a year or more
// is, for every purpose here, one that lasts; the cap keeps the arithmetic
// on the value defined whatever number the provider sends.
const maxExpiresIn = 365 * 24 * time.Hour

// seconds is expires_in: a number, or a numeric string from providers that
// get the type wrong. Zero or less, infinity and NaN all become zero, which
// Tokens reports as no expiry given; anything above maxExpiresIn is capped.
type seconds int64

func (s *seconds) UnmarshalJSON(data []byte) error {
	str := strings.Trim(string(data), `"`)
	if str == "" || str == "null" {
		*s = 0
		return nil
	}
	n, err := strconv.ParseFloat(str, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return fmt.Errorf("expires_in %q is not a number", str)
	}
	switch {
	case math.IsNaN(n) || n <= 0:
		*s = 0
	case n >= maxExpiresIn.Seconds():
		*s = seconds(maxExpiresIn / time.Second)
	default:
		*s = seconds(n)
	}
	return nil
}

// token posts form to the token endpoint with client authentication and
// verifies the ID token in the answer. requireIDToken is the rule for the
// code grant: openid was requested, so one must come back.
func (c *Client) token(ctx context.Context, form url.Values, opts []TokenOption, requireIDToken bool) (*Tokens, error) {
	var checks tokenChecks
	for _, o := range opts {
		o(&checks)
	}
	switch c.cfg.AuthMethod {
	case AuthMethodPost:
		form.Set("client_id", c.cfg.ClientID)
		form.Set("client_secret", c.cfg.ClientSecret)
	case AuthMethodNone:
		form.Set("client_id", c.cfg.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.provider.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProvider, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.cfg.AuthMethod == AuthMethodBasic {
		// RFC 6749 section 2.3.1: both values are form-encoded before they
		// go into the Basic credentials.
		req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProvider, err)
	}
	defer resp.Body.Close()
	body, err := readBody(resp.Body)
	if err != nil {
		return nil, err
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("%w: token endpoint: status %d, body is not JSON", ErrProvider, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		if tr.Error != "" {
			return nil, &TokenError{Code: tr.Error, Description: tr.ErrorDesc}
		}
		return nil, fmt.Errorf("%w: token endpoint: status %d", ErrProvider, resp.StatusCode)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("%w: token endpoint: no access_token", ErrProvider)
	}
	tokens := &Tokens{
		AccessToken:  tr.AccessToken,
		TokenType:    tr.TokenType,
		RefreshToken: tr.RefreshToken,
		IDToken:      tr.IDToken,
	}
	if tr.ExpiresIn > 0 {
		tokens.Expiry = c.now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	if tr.IDToken == "" {
		if requireIDToken {
			return nil, fmt.Errorf("%w: token endpoint: no id_token", ErrProvider)
		}
		return tokens, nil
	}
	claims, err := c.VerifyIDTokenWithAccessToken(ctx, tr.IDToken, checks.nonce, tr.AccessToken)
	if err != nil {
		return nil, err
	}
	if checks.subject != "" && claims.Subject != checks.subject {
		return nil, invalid("sub %q is not the expected %q", claims.Subject, checks.subject)
	}
	tokens.Claims = claims
	return tokens, nil
}

// EndSessionURL builds an RP-initiated logout request (OpenID Connect
// RP-Initiated Logout 1.0) to redirect the browser to. idTokenHint is the
// raw ID token from the login; postLogoutRedirectURL, when set, must be
// registered with the application; state is echoed back there. It fails
// when the provider has no end_session_endpoint.
func (c *Client) EndSessionURL(idTokenHint, postLogoutRedirectURL, state string) (string, error) {
	if c.provider.EndSessionEndpoint == "" {
		return "", errors.New("client: the provider has no end_session_endpoint")
	}
	q := url.Values{"client_id": {c.cfg.ClientID}}
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirectURL != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirectURL)
	}
	if state != "" {
		q.Set("state", state)
	}
	return appendQuery(c.provider.EndSessionEndpoint, q), nil
}
