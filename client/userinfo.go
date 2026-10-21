package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
)

// UserInfo is a userinfo response. Raw holds every claim as decoded JSON.
type UserInfo struct {
	Subject           string
	Email             string
	EmailVerified     bool
	Name              string
	PreferredUsername string
	Raw               map[string]any
}

// UserInfo fetches the userinfo endpoint with the access token (OpenID
// Connect Core 1.0 section 5.3). Only a JSON answer is accepted; a signed or
// encrypted one is refused. The response is not tied to any ID token: a
// caller that has one must compare sub, which UserInfoFor does.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if c.provider.UserInfoEndpoint == "" {
		return nil, errors.New("client: the provider has no userinfo_endpoint")
	}
	if accessToken == "" {
		return nil, errors.New("client: no access token")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.provider.UserInfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProvider, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProvider, err)
	}
	defer resp.Body.Close()
	body, err := readBody(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// RFC 6750 section 3: the error is in WWW-Authenticate. Some
		// providers also put it in a JSON body; either way it is reported
		// as a TokenError so a caller can see invalid_token and re-login.
		if code, desc := bearerError(resp.Header.Get("WWW-Authenticate")); code != "" {
			return nil, &TokenError{Code: code, Description: desc}
		}
		var te struct {
			Error string `json:"error"`
			Desc  string `json:"error_description"`
		}
		if json.Unmarshal(body, &te) == nil && te.Error != "" {
			return nil, &TokenError{Code: te.Error, Description: te.Desc}
		}
		return nil, fmt.Errorf("%w: userinfo: status %d", ErrProvider, resp.StatusCode)
	}
	if ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); ct == "application/jwt" {
		return nil, fmt.Errorf("%w: userinfo: signed responses are not supported", ErrProvider)
	}
	members, err := decodeObject(body)
	if err != nil {
		return nil, fmt.Errorf("%w: userinfo: body %v", ErrProvider, err)
	}
	cl, err := parseClaims(members)
	if err != nil {
		return nil, fmt.Errorf("%w: userinfo: %v", ErrProvider, err)
	}
	if cl.Sub == "" {
		return nil, fmt.Errorf("%w: userinfo: no sub", ErrProvider)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("%w: userinfo: %v", ErrProvider, err)
	}
	return &UserInfo{
		Subject:           cl.Sub,
		Email:             cl.Email,
		EmailVerified:     cl.Verified,
		Name:              cl.Name,
		PreferredUsername: cl.Username,
		Raw:               raw,
	}, nil
}

// UserInfoFor is UserInfo for an access token that came with an ID token
// whose sub is expectedSub. A response about anyone else is an error
// (OpenID Connect Core 1.0 section 5.3.2).
func (c *Client) UserInfoFor(ctx context.Context, accessToken, expectedSub string) (*UserInfo, error) {
	if expectedSub == "" {
		return nil, errors.New("client: no expected subject")
	}
	ui, err := c.UserInfo(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	if ui.Subject != expectedSub {
		return nil, fmt.Errorf("%w: userinfo sub %q is not the ID token's %q", ErrInvalidToken, ui.Subject, expectedSub)
	}
	return ui, nil
}

// bearerError pulls error and error_description out of a WWW-Authenticate
// Bearer challenge. Enough of RFC 6750 section 3 for the few values a
// provider sends; anything it does not understand yields no code.
func bearerError(header string) (code, desc string) {
	if !strings.HasPrefix(strings.ToLower(header), "bearer") {
		return "", ""
	}
	for _, part := range strings.Split(header[len("bearer"):], ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch strings.TrimSpace(k) {
		case "error":
			code = v
		case "error_description":
			desc = v
		}
	}
	return code, desc
}
