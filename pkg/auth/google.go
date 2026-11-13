package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// maxUserInfoBytes caps the userinfo response read from the provider.
const maxUserInfoBytes = 1 << 20

type googleProvider struct {
	userinfoEndpoint  string
	oauth2            oauth2.Config
	allowedUsers      []string
	allowedWorkspaces []string
}

func NewGoogleProvider(externalURL, clientID, clientSecret string, allowedUsers []string, allowedWorkspaces []string) (Provider, error) {
	r, err := url.JoinPath(externalURL, GoogleCallbackEndpoint)
	if err != nil {
		return nil, err
	}
	return &googleProvider{
		userinfoEndpoint: "https://openidconnect.googleapis.com/v1/userinfo",
		oauth2: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  r,
			Scopes:       []string{"openid profile email"},
			Endpoint:     google.Endpoint,
		},
		allowedUsers:      lowerAll(allowedUsers),
		allowedWorkspaces: lowerAll(allowedWorkspaces),
	}, nil
}

func lowerAll(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (p *googleProvider) SetUserinfoEndpoint(u string) {
	p.userinfoEndpoint = u
}

func (p *googleProvider) SetOAuth2Endpoint(cfg oauth2.Endpoint) {
	p.oauth2.Endpoint = cfg
}

func (p *googleProvider) Name() string {
	return "Google"
}

func (p *googleProvider) Type() string {
	return "google"
}

func (p *googleProvider) RedirectURL() string {
	return GoogleCallbackEndpoint
}

// AuthCodeURL requests offline access so Google issues a refresh token. The
// proxy keeps it (encrypted) to re-verify the user with Google on every token
// refresh; prompt=consent makes Google issue a new one on every sign-in.
func (p *googleProvider) AuthCodeURL(state string) (string, error) {
	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
	}
	if len(p.allowedUsers) == 0 && len(p.allowedWorkspaces) == 1 {
		opts = append(opts, oauth2.SetAuthURLParam("hd", p.allowedWorkspaces[0]))
	}
	authURL := p.oauth2.AuthCodeURL(state, opts...)
	return authURL, nil
}

func (p *googleProvider) AuthURL() string {
	return GoogleAuthEndpoint
}

func (p *googleProvider) Exchange(c *gin.Context, state string) (*oauth2.Token, error) {
	if c.Query("state") != state {
		return nil, errors.New("invalid OAuth state")
	}
	code := c.Query("code")
	token, err := p.oauth2.Exchange(c, code)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// fetchUserInfo returns the userinfo and the HTTP status of the response.
func (p *googleProvider) fetchUserInfo(ctx context.Context, token *oauth2.Token) (map[string]any, int, error) {
	client := p.oauth2.Client(ctx, token)
	resp, err := client.Get(p.userinfoEndpoint)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, errors.New("failed to get user info from Google API: " + resp.Status)
	}
	var userInfoMap map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxUserInfoBytes)).Decode(&userInfoMap); err != nil {
		return nil, resp.StatusCode, err
	}
	return userInfoMap, resp.StatusCode, nil
}

// allowed applies the allowlist to a userinfo response. Only verified email
// addresses are trusted; the returned user ID is the lower-cased email.
func (p *googleProvider) allowed(userInfo map[string]any) (bool, string) {
	email, _ := userInfo["email"].(string)
	email = strings.ToLower(email)
	if !emailVerified(userInfo) {
		return false, email
	}
	if len(p.allowedUsers) == 0 && len(p.allowedWorkspaces) == 0 {
		return true, email
	}
	if slices.Contains(p.allowedUsers, email) {
		return true, email
	}
	hd, _ := userInfo["hd"].(string)
	if hd != "" && slices.Contains(p.allowedWorkspaces, strings.ToLower(hd)) {
		return true, email
	}
	return false, email
}

func emailVerified(userInfo map[string]any) bool {
	switch v := userInfo["email_verified"].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}

func (p *googleProvider) Authorization(ctx context.Context, token *oauth2.Token) (bool, string, map[string]any, error) {
	userInfoMap, _, err := p.fetchUserInfo(ctx, token)
	if err != nil {
		return false, "", nil, err
	}
	ok, email := p.allowed(userInfoMap)
	return ok, email, userInfoMap, nil
}

// VerifyUpstream redeems the Google refresh token recorded at login and
// re-checks the user. Google refuses the refresh token (invalid_grant) once the
// account is deleted or suspended, or the grant is revoked; userinfo then
// re-checks the workspace and the allowlist.
func (p *googleProvider) VerifyUpstream(ctx context.Context, userID, refreshToken string) (UpstreamResult, error) {
	tok, err := p.oauth2.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.ErrorCode == "invalid_grant" {
			return UpstreamResult{Reason: "Google refused the refresh token (account removed, suspended or access revoked)"}, nil
		}
		return UpstreamResult{}, fmt.Errorf("google token refresh failed: %w", err)
	}
	userInfo, status, err := p.fetchUserInfo(ctx, tok)
	if err != nil {
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			return UpstreamResult{Reason: "Google refused the userinfo request"}, nil
		}
		return UpstreamResult{}, err
	}
	ok, email := p.allowed(userInfo)
	if !ok {
		return UpstreamResult{Reason: "user is no longer allowed by the Google allowlist"}, nil
	}
	if !strings.EqualFold(email, userID) {
		return UpstreamResult{Reason: "the Google account email changed"}, nil
	}
	res := UpstreamResult{Allowed: true}
	if tok.RefreshToken != "" && tok.RefreshToken != refreshToken {
		res.RefreshToken = tok.RefreshToken
	}
	return res, nil
}
