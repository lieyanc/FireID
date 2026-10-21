package oidc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/lieyanc/FireID/internal/secretbox"
	"github.com/lieyanc/FireID/internal/store"
)

// Settings are the token lifetimes and algorithm the provider runs with. They
// come from the oidc block of the configuration.
type Settings struct {
	CodeTTL          time.Duration
	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration
	IDTokenTTL       time.Duration
	SigningAlgorithm string
}

// Storage implements op.Storage over the store.Store backend.
type Storage struct {
	store    *store.Store
	box      *secretbox.Box
	settings Settings
	log      *slog.Logger

	// endBrowserSession signs the browser out of Fire ID after a validated
	// RP-initiated logout. It is set by the provider, which can reach the
	// request; nil disables it. clientID names the relying party that asked.
	endBrowserSession func(ctx context.Context, subject, clientID string)
}

var (
	_ op.Storage                        = (*Storage)(nil)
	_ op.CanSetUserinfoFromRequest      = (*Storage)(nil)
	_ op.CanTerminateSessionFromRequest = (*Storage)(nil)
)

// NewStorage returns a Storage that implements op.Storage.
func NewStorage(st *store.Store, box *secretbox.Box, settings Settings) *Storage {
	return &Storage{store: st, box: box, settings: settings, log: slog.Default()}
}

// Health implements op.Storage.
func (s *Storage) Health(ctx context.Context) error {
	return s.store.DB().PingContext(ctx)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  AuthStorage: authorization requests, codes, tokens
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// CreateAuthRequest implements op.AuthStorage. The request is stored
// unapproved: the library would pre-fill userID from an id_token_hint, but a
// hint only says who the client thinks is signed in, so the login page decides.
func (s *Storage) CreateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	app, err := s.store.AppByClientID(authReq.ClientID)
	if err != nil {
		return nil, err
	}
	// The library has already accepted the redirect URI, but for native
	// clients it lets any loopback URI with the same path through, whatever
	// the host, scheme or registered port. Fire ID's rule is stricter and is
	// decided in one place. This error is never redirected to the URI.
	if !store.MatchesRedirectURI(app.RedirectURIs, authReq.RedirectURI) {
		return nil, oidc.ErrInvalidRequestRedirectURI().WithDescription("the redirect_uri is not registered for this client")
	}

	if !slices.Contains(authReq.Scopes, oidc.ScopeOpenID) {
		return nil, oidc.ErrInvalidScope().WithDescription("the openid scope is required")
	}
	scopes := allowedScopes(app, authReq.Scopes)

	switch {
	case authReq.CodeChallenge == "" && app.RequirePKCE:
		return nil, oidc.ErrInvalidRequest().WithDescription("this client must use PKCE (code_challenge with S256)")
	case authReq.CodeChallenge != "" && authReq.CodeChallengeMethod != oidc.CodeChallengeMethodS256:
		// "plain" offers no protection against an intercepted code.
		return nil, oidc.ErrInvalidRequest().WithDescription("code_challenge_method must be S256")
	}

	maxAge := int64(-1)
	if authReq.MaxAge != nil {
		maxAge = int64(*authReq.MaxAge)
	}
	req := &store.AuthRequest{
		AppID:               app.ID,
		RedirectURI:         authReq.RedirectURI,
		Scope:               joinSpaceList(scopes),
		State:               authReq.State,
		Nonce:               authReq.Nonce,
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: string(authReq.CodeChallengeMethod),
		Prompt:              joinSpaceList(authReq.Prompt),
		MaxAge:              maxAge,
		ACRValues:           joinSpaceList(authReq.ACRValues),
	}
	if err := s.store.CreateAuthRequest(req); err != nil {
		return nil, err
	}
	return &authRequest{req: req, clientID: app.ClientID}, nil
}

// allowedScopes keeps the requested scopes the app is registered for, in the
// order requested. openid is always kept (it was checked above);
// offline_access is kept when the app may use refresh tokens, since that is
// what it asks for. The library's own filter lets every standard scope through
// regardless of registration, which is why this exists.
func allowedScopes(app *store.App, requested []string) []string {
	out := make([]string, 0, len(requested))
	for _, sc := range requested {
		if slices.Contains(out, sc) {
			continue
		}
		switch {
		case sc == oidc.ScopeOpenID:
		case sc == oidc.ScopeOfflineAccess:
			if !slices.Contains(app.GrantTypes, string(oidc.GrantTypeRefreshToken)) {
				continue
			}
		case !slices.Contains(app.Scopes, sc):
			continue
		}
		out = append(out, sc)
	}
	return out
}

// AuthRequestByID implements op.AuthStorage.
func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	req, err := s.store.AuthRequestByID(id)
	if err != nil {
		return nil, err
	}
	app, err := s.store.AppByID(req.AppID)
	if err != nil {
		return nil, err
	}
	return &authRequest{req: req, clientID: app.ClientID}, nil
}

// AuthRequestByCode implements op.AuthStorage. The code is consumed here, at
// the first step of the exchange: a failed exchange cannot be retried with the
// same code, and a second exchange revokes what the first one produced.
func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	ac, err := s.store.ConsumeAuthCode(code)
	if err != nil {
		return nil, err
	}
	app, err := s.store.AppByID(ac.AppID)
	if err != nil {
		return nil, err
	}
	return &authRequest{
		req: &store.AuthRequest{
			ID:                  ac.AuthRequestID,
			AppID:               ac.AppID,
			UserID:              sql.NullInt64{Int64: ac.UserID, Valid: true},
			RedirectURI:         ac.RedirectURI,
			Scope:               ac.Scope,
			Nonce:               ac.Nonce,
			CodeChallenge:       ac.CodeChallenge,
			CodeChallengeMethod: ac.CodeChallengeMethod,
			Resource:            ac.Resource,
			AuthTime:            ac.AuthTime,
			AMR:                 ac.AMR,
			ACR:                 ac.ACR,
			SID:                 ac.SID,
			ExpiresAt:           ac.ExpiresAt,
		},
		clientID: app.ClientID,
	}, nil
}

// SaveAuthCode implements op.AuthStorage.
func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	return s.store.SaveAuthCode(id, code, s.settings.CodeTTL)
}

// DeleteAuthRequest implements op.AuthStorage.
func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.store.DeleteAuthRequest(id)
}

// tokenGrant is what both token-request kinds have in common once resolved to
// rows in the database.
type tokenGrant struct {
	appID         int64
	userID        int64
	authRequestID string
	scopes        []string
}

func (s *Storage) grantOf(request op.TokenRequest) (*tokenGrant, error) {
	switch r := request.(type) {
	case *authRequest:
		if !r.req.UserID.Valid {
			return nil, fmt.Errorf("auth request %s is not approved", r.req.ID)
		}
		return &tokenGrant{appID: r.req.AppID, userID: r.req.UserID.Int64,
			authRequestID: r.req.ID, scopes: r.GetScopes()}, nil
	case *refreshTokenRequest:
		return &tokenGrant{appID: r.rt.AppID, userID: r.rt.UserID,
			authRequestID: r.rt.AuthRequestID, scopes: r.scopes}, nil
	default:
		return nil, fmt.Errorf("unsupported token request type %T", request)
	}
}

// CreateAccessToken implements op.AuthStorage. The token itself is minted by
// the library as an encrypted "id:subject"; the row recorded here is what
// userinfo, introspection and revocation consult.
func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	g, err := s.grantOf(request)
	if err != nil {
		return "", time.Time{}, err
	}
	return s.createAccessToken(g)
}

func (s *Storage) createAccessToken(g *tokenGrant) (string, time.Time, error) {
	id, err := randomTokenID(24)
	if err != nil {
		return "", time.Time{}, err
	}
	exp, err := s.store.CreateAccessToken(id, g.appID, g.userID, joinSpaceList(g.scopes),
		g.authRequestID, s.settings.AccessTokenTTL)
	if err != nil {
		return "", time.Time{}, err
	}
	return id, exp, nil
}

// CreateAccessAndRefreshTokens implements op.AuthStorage. A first grant opens a
// new refresh-token family; a refresh rotates within the family, and the store
// rejects (and revokes the family for) a token that was already rotated.
func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	g, err := s.grantOf(request)
	if err != nil {
		return "", "", time.Time{}, err
	}
	newRefresh, err := randomTokenID(32)
	if err != nil {
		return "", "", time.Time{}, err
	}

	if currentRefreshToken == "" {
		ar, ok := request.(*authRequest)
		if !ok {
			return "", "", time.Time{}, fmt.Errorf("a new refresh token needs an authorization request, got %T", request)
		}
		_, err = s.store.CreateRefreshToken(newRefresh, store.RefreshTokenSpec{
			AppID:         g.appID,
			UserID:        g.userID,
			Scope:         joinSpaceList(g.scopes),
			AuthRequestID: g.authRequestID,
			AuthTime:      ar.req.AuthTime,
			AMR:           ar.req.AMR,
			ACR:           ar.req.ACR,
			SID:           ar.req.SID,
			TTL:           s.settings.RefreshTokenTTL,
		})
	} else {
		_, err = s.store.RotateRefreshToken(currentRefreshToken, newRefresh, s.settings.RefreshTokenTTL)
		if errors.Is(err, store.ErrRefreshReplayed) {
			// Two exchanges raced on the same token; the store rotated it for
			// one and revoked the family for the other.
			s.auditRefreshReplay(g.appID, g.userID)
		}
	}
	if err != nil {
		return "", "", time.Time{}, refreshError(err)
	}

	accessID, exp, err := s.createAccessToken(g)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return accessID, newRefresh, exp, nil
}

// refreshError maps store failures to the OAuth error a client should see.
// Anything about the token itself is invalid_grant; only real faults are 500s.
func refreshError(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound),
		errors.Is(err, store.ErrRefreshRevoked),
		errors.Is(err, store.ErrRefreshReplayed),
		errors.Is(err, store.ErrRefreshExpired):
		return oidc.ErrInvalidGrant().WithDescription("the refresh token is invalid, expired or revoked").WithParent(err)
	}
	return err
}

// TokenRequestByRefreshToken implements op.AuthStorage. It refuses tokens that
// are revoked, tokens that were already rotated (and revokes the
// family, as a replay), and tokens whose user may no longer use the app.
func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	rt, err := s.store.RefreshTokenByToken(refreshToken)
	if err != nil {
		return nil, err
	}
	switch {
	case !rt.RevokedAt.IsZero():
		return nil, store.ErrRefreshRevoked
	case !rt.RotatedAt.IsZero():
		if err := s.store.RevokeRefreshTokenFamily(rt.FamilyID, "replay_detected"); err != nil {
			return nil, err
		}
		s.auditRefreshReplay(rt.AppID, rt.UserID)
		return nil, store.ErrRefreshReplayed
	}
	// Expiry is checked by the store when the token is rotated, against the
	// store clock, so it is not repeated here.
	app, err := s.store.AppByID(rt.AppID)
	if err != nil {
		return nil, err
	}
	if err := s.requireAccess(app, rt.UserID); err != nil {
		return nil, err
	}
	return &refreshTokenRequest{rt: rt, clientID: app.ClientID, scopes: parseSpaceList(rt.Scope)}, nil
}

// auditRefreshReplay records a replayed refresh token. The family is already
// revoked by the time this is called; the entry is for the administrator.
func (s *Storage) auditRefreshReplay(appID, userID int64) {
	if err := s.store.Audit(store.AuditEvent{
		Event: "oauth.refresh_replay", Severity: store.SeverityCritical, ActorType: store.ActorClient,
		AppID: appID, UserID: userID,
	}); err != nil {
		s.log.Warn("could not record audit event", "event", "oauth.refresh_replay", "err", err)
	}
}

// errAccessDenied is returned when the user may no longer use the app.
var errAccessDenied = errors.New("access to this app is no longer permitted")

// requireAccess re-asks store.CanUseApp at every point a token is used, so a
// blocked membership or a disabled account stops working without waiting for
// tokens to expire.
func (s *Storage) requireAccess(app *store.App, userID int64) error {
	user, err := s.store.UserByID(userID)
	if err != nil {
		return err
	}
	access, err := s.store.CanUseApp(app, user)
	if err != nil {
		return err
	}
	if !access.Allowed {
		return fmt.Errorf("%w (%s)", errAccessDenied, access.Reason)
	}
	return nil
}

// TerminateSession implements op.AuthStorage. It is only reached through
// TerminateSessionFromRequest, which the library prefers.
func (s *Storage) TerminateSession(ctx context.Context, subject string, clientID string) error {
	if subject == "" || clientID == "" {
		return nil
	}
	userID, err := userIDFromSubject(subject)
	if err != nil {
		return nil
	}
	app, err := s.store.AppByClientID(clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if err := s.store.RevokeAllRefreshTokens(userID, app.ID, "rp_logout"); err != nil {
		return err
	}
	return s.store.RevokeAccessTokensForUserApp(userID, app.ID)
}

// TerminateSessionFromRequest implements op.CanTerminateSessionFromRequest.
// Without a valid id_token_hint the library leaves the subject empty; such a
// request could come from any page, so it signs nobody out and only performs
// the redirect.
func (s *Storage) TerminateSessionFromRequest(ctx context.Context, req *op.EndSessionRequest) (string, error) {
	if req.UserID == "" {
		return req.RedirectURI, nil
	}
	if err := s.TerminateSession(ctx, req.UserID, req.ClientID); err != nil {
		return "", err
	}
	if s.endBrowserSession != nil {
		s.endBrowserSession(ctx, req.UserID, req.ClientID)
	}
	return req.RedirectURI, nil
}

// refreshTokenIDPrefix marks a token ID handed out by GetRefreshTokenInfo, so
// RevokeToken can tell it from an access token ID.
const refreshTokenIDPrefix = "rt:"

// RevokeToken implements op.AuthStorage (RFC 7009). The library hands over
// either a refresh-token ID from GetRefreshTokenInfo, an access-token ID it
// decrypted, or — when neither worked — the raw value. A token that belongs to
// another client or that we do not know is ignored, as RFC 7009 asks.
//
// The subject must match the stored owner. The raw-value path passes an empty
// subject, so a client cannot revoke by guessing a token ID.
func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID string, subject string, clientID string) *oidc.Error {
	if subject == "" {
		return nil
	}
	userID, err := userIDFromSubject(subject)
	if err != nil {
		return nil
	}
	app, err := s.store.AppByClientID(clientID)
	if err != nil {
		return nil
	}

	if idText, ok := strings.CutPrefix(tokenOrTokenID, refreshTokenIDPrefix); ok {
		id, err := strconv.ParseInt(idText, 10, 64)
		if err != nil {
			return nil
		}
		rt, err := s.store.RefreshTokenByID(id)
		if err != nil || rt.AppID != app.ID || rt.UserID != userID {
			return nil
		}
		// Revoking one link of a rotating chain is meaningless; the whole
		// grant goes, together with the access tokens it produced.
		if err := s.store.RevokeRefreshTokenFamily(rt.FamilyID, "revoked_by_client"); err != nil {
			return oidc.ErrServerError().WithParent(err)
		}
		if rt.AuthRequestID != "" {
			if err := s.store.RevokeAccessTokensByAuthRequest(rt.AuthRequestID); err != nil {
				return oidc.ErrServerError().WithParent(err)
			}
		}
		return nil
	}

	at, err := s.store.AccessTokenByID(tokenOrTokenID)
	if err != nil || at.AppID != app.ID || at.UserID != userID {
		return nil
	}
	if err := s.store.RevokeAccessToken(at.TokenID); err != nil {
		return oidc.ErrServerError().WithParent(err)
	}
	return nil
}

// GetRefreshTokenInfo implements op.AuthStorage. It must return
// op.ErrInvalidRefreshToken for anything that is not one of our refresh
// tokens, or the revocation endpoint answers 500 instead of trying the value
// as an access token.
func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (string, string, error) {
	rt, err := s.store.RefreshTokenByToken(token)
	if errors.Is(err, store.ErrNotFound) {
		return "", "", op.ErrInvalidRefreshToken
	}
	if err != nil {
		return "", "", err
	}
	return subjectOf(rt.UserID), refreshTokenIDPrefix + strconv.FormatInt(rt.ID, 10), nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  OPStorage: clients, userinfo, introspection, JWT profile
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GetClientByClientID implements op.OPStorage.
func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	app, err := s.store.AppByClientID(clientID)
	if err != nil {
		return nil, err
	}
	return NewClient(app, s.settings.IDTokenTTL), nil
}

// AuthorizeClientIDSecret implements op.OPStorage. A suspended app cannot
// authenticate at all, so none of its outstanding grants can be exchanged.
func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	app, err := s.store.AppByClientID(clientID)
	if err != nil {
		return oidc.ErrInvalidClient().WithDescription("invalid client credentials")
	}
	if app.ClientType != store.ClientConfidential || app.SecretHash == "" ||
		!store.VerifyTokenHash(clientSecret, app.SecretHash) {
		return oidc.ErrInvalidClient().WithDescription("invalid client credentials")
	}
	if app.Status != store.AppActive {
		return oidc.ErrInvalidClient().WithDescription("this client is suspended")
	}
	return nil
}

// SetUserinfoFromScopes implements op.OPStorage. The library marks it
// deprecated in favour of SetUserinfoFromRequest, which does the work.
func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return nil
}

// SetUserinfoFromRequest implements op.CanSetUserinfoFromRequest: the claims
// placed in an ID token. Besides the scoped claims it adds sid, the browser
// session the token was issued for, which is what a back-channel logout token
// later refers to. A refreshed token keeps the sid of the original grant.
// The library copies the extra claims into the ID token and never sets sid
// itself; /userinfo goes through SetUserinfoFromToken and does not get it.
func (s *Storage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, request op.IDTokenRequest, scopes []string) error {
	userID, err := userIDFromSubject(request.GetSubject())
	if err != nil {
		return err
	}
	user, err := s.store.UserByID(userID)
	if err != nil {
		return err
	}
	fillUserinfo(userinfo, user, scopes)
	var sid string
	switch r := request.(type) {
	case *authRequest:
		sid = r.req.SID
	case *refreshTokenRequest:
		sid = r.rt.SID
	}
	if sid != "" {
		userinfo.AppendClaims("sid", sid)
	}
	return nil
}

// SetUserinfoFromToken implements op.OPStorage: the /userinfo endpoint. The
// claims follow the scopes recorded with the token, not those of the app.
func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	at, err := s.liveAccessToken(tokenID, subject)
	if err != nil {
		return err
	}
	app, err := s.store.AppByID(at.AppID)
	if err != nil {
		return err
	}
	if err := s.requireAccess(app, at.UserID); err != nil {
		return err
	}
	user, err := s.store.UserByID(at.UserID)
	if err != nil {
		return err
	}
	fillUserinfo(userinfo, user, parseSpaceList(at.Scope))
	return nil
}

// liveAccessToken resolves a decrypted access token to its row and checks the
// subject embedded in the ciphertext against the owner on record.
func (s *Storage) liveAccessToken(tokenID, subject string) (*store.AccessToken, error) {
	at, err := s.store.AccessTokenByID(tokenID)
	if err != nil {
		return nil, err
	}
	if subjectOf(at.UserID) != subject {
		return nil, errBadSubject
	}
	return at, nil
}

// fillUserinfo sets the standard claims a scope grants. The subject is always
// present; everything else only when its scope was granted.
func fillUserinfo(info *oidc.UserInfo, user *store.User, scopes []string) {
	info.Subject = subjectOf(user.ID)
	if slices.Contains(scopes, oidc.ScopeProfile) {
		info.PreferredUsername = user.Username
		info.Name = user.DisplayName
		if info.Name == "" {
			info.Name = user.Username
		}
		if !user.UpdatedAt.IsZero() {
			info.UpdatedAt = oidc.FromTime(user.UpdatedAt)
		}
	}
	if slices.Contains(scopes, oidc.ScopeEmail) && user.Email != "" {
		info.Email = user.Email
		// Matches what the account API reports: an active account's address
		// counts as verified until email verification exists.
		info.EmailVerified = oidc.Bool(user.Status == store.UserActive)
	}
}

// SetIntrospectionFromToken implements op.OPStorage (RFC 7662). A client may
// only introspect its own tokens; anything else, and anything expired, revoked
// or no longer permitted, is reported inactive by returning an error.
func (s *Storage) SetIntrospectionFromToken(ctx context.Context, resp *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	at, err := s.liveAccessToken(tokenID, subject)
	if err != nil {
		return err
	}
	app, err := s.store.AppByID(at.AppID)
	if err != nil {
		return err
	}
	if app.ClientID != clientID {
		return errors.New("token belongs to another client")
	}
	if err := s.requireAccess(app, at.UserID); err != nil {
		return err
	}
	user, err := s.store.UserByID(at.UserID)
	if err != nil {
		return err
	}
	resp.Scope = oidc.SpaceDelimitedArray(parseSpaceList(at.Scope))
	resp.ClientID = app.ClientID
	resp.TokenType = oidc.BearerToken
	resp.Expiration = oidc.FromTime(at.ExpiresAt)
	resp.IssuedAt = oidc.FromTime(at.CreatedAt)
	resp.Audience = oidc.Audience{app.ClientID}
	resp.Subject = subjectOf(at.UserID)
	resp.Username = user.Username
	resp.Issuer = op.IssuerFromContext(ctx)
	return nil
}

// GetPrivateClaimsFromScopes implements op.OPStorage. Group claims arrive with
// the group-mapping stage.
func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	return nil, nil
}

// ValidateJWTProfileScopes implements op.OPStorage. The JWT bearer grant is not
// offered.
func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return nil, errors.New("the JWT bearer grant is not supported")
}
