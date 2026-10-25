package idp

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestParseTokenLifespans(t *testing.T) {
	l, err := ParseTokenLifespans("2m", "5m", "30s", "0", "0s")
	require.NoError(t, err)
	require.Equal(t, TokenLifespans{AccessToken: 2 * time.Minute, RefreshToken: 5 * time.Minute, AuthorizeCode: 30 * time.Second}, l)

	l, err = ParseTokenLifespans("2m", "5m", "30s", "168h", "10s")
	require.NoError(t, err)
	require.Equal(t, 168*time.Hour, l.MaxSessionAge)
	require.Equal(t, 10*time.Second, l.RefreshTokenGracePeriod)

	for _, tc := range [][5]string{
		{"", "5m", "30s", "0", "0s"},
		{"2m", "abc", "30s", "0", "0s"},
		{"2m", "5m", "0", "0", "0s"},
		{"-1h", "5m", "30s", "0", "0s"},
		{"2m", "5m", "30s", "", "0s"},
		{"2m", "5m", "30s", "-1h", "0s"},
		{"2m", "5m", "30s", "0", "-1s"},
		{"2m", "5m", "30s", "0", "x"},
	} {
		_, err := ParseTokenLifespans(tc[0], tc[1], tc[2], tc[3], tc[4])
		require.Error(t, err, "%v", tc)
	}
}

func TestDefaultTokenLifespansMatchUpstream(t *testing.T) {
	require.Equal(t, TokenLifespans{AccessToken: 24 * time.Hour, RefreshToken: 30 * 24 * time.Hour, AuthorizeCode: 15 * time.Minute}, DefaultTokenLifespans())
	require.NoError(t, DefaultTokenLifespans().Validate())
}

func TestNewIDPRouterRejectsInvalidLifespans(t *testing.T) {
	_, err := NewIDPRouter(nil, nil, nil, "http://localhost", nil, nil, Branding{}, TokenLifespans{})
	require.ErrorContains(t, err, "must be positive")
}

func lifespanTestTokens(t *testing.T, lifespans TokenLifespans, codeDelay time.Duration) (string, registrationResponse, *http.Response) {
	t.Helper()
	server, _, _ := setupTestServerWith(t, Branding{}, lifespans)
	regResp := registerTestClient(t, server.URL)
	config := &oauth2.Config{
		ClientID:     regResp.ClientID,
		ClientSecret: regResp.ClientSecret,
		RedirectURL:  "http://localhost:8080/callback",
		Endpoint:     oauth2.Endpoint{AuthURL: server.URL + AuthorizationEndpoint, TokenURL: server.URL + TokenEndpoint},
	}
	callbackURL := testAuthFlowWithURL(t, server.URL, config.AuthCodeURL("test-state"))
	time.Sleep(codeDelay)
	resp, err := http.PostForm(server.URL+TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {callbackURL.Query().Get("code")},
		"redirect_uri":  {"http://localhost:8080/callback"},
		"client_id":     {regResp.ClientID},
		"client_secret": {regResp.ClientSecret},
	})
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return server.URL, regResp, resp
}

func refresh(t *testing.T, serverURL string, reg registrationResponse, rt string) *http.Response {
	t.Helper()
	resp, err := http.PostForm(serverURL+TokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {reg.ClientID},
		"client_secret": {reg.ClientSecret},
	})
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestTokenLifespansAppliedToIssuedTokens(t *testing.T) {
	lifespans := TokenLifespans{AccessToken: 2 * time.Minute, RefreshToken: 3 * time.Second, AuthorizeCode: time.Minute}
	serverURL, reg, resp := lifespanTestTokens(t, lifespans, 0)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tok map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tok))
	require.InDelta(t, 120, tok["expires_in"], 2)

	parts := strings.Split(tok["access_token"].(string), ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.InDelta(t, time.Now().Add(2*time.Minute).Unix(), claims["exp"], 2)

	// Refreshed tokens get the configured lifespans too.
	r := refresh(t, serverURL, reg, tok["refresh_token"].(string))
	require.Equal(t, http.StatusOK, r.StatusCode)
	var tok2 map[string]any
	require.NoError(t, json.NewDecoder(r.Body).Decode(&tok2))
	require.InDelta(t, 120, tok2["expires_in"], 2)

	// The rotated refresh token expires after REFRESH_TOKEN_LIFESPAN.
	time.Sleep(4 * time.Second)
	r = refresh(t, serverURL, reg, tok2["refresh_token"].(string))
	require.Equal(t, http.StatusBadRequest, r.StatusCode)
	var errBody map[string]any
	require.NoError(t, json.NewDecoder(r.Body).Decode(&errBody))
	require.Equal(t, "invalid_grant", errBody["error"])
}

func TestAuthorizeCodeLifespanApplied(t *testing.T) {
	lifespans := TokenLifespans{AccessToken: time.Hour, RefreshToken: time.Hour, AuthorizeCode: time.Second}
	_, _, resp := lifespanTestTokens(t, lifespans, 2*time.Second)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errBody map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	require.Equal(t, "invalid_grant", errBody["error"])
}
