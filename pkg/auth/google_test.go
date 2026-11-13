package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const (
	TestGoogleClientID     = "test-client-id"
	TestGoogleClientSecret = "test-client-secret"
	TestGoogleExternalURL  = "http://localhost:8080"
)

func setupGoogleTest(allowedUsers, allowedWorkspaces []string) (Provider, gin.IRoutes) {
	p, _ := NewGoogleProvider(TestGoogleExternalURL, TestGoogleClientID, TestGoogleClientSecret, allowedUsers, allowedWorkspaces)

	goog := gin.New()
	goog.POST("/token", func(c *gin.Context) {
		switch c.PostForm("refresh_token") {
		case "revoked-refresh-token":
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "Token has been expired or revoked."})
			return
		case "outage-refresh-token":
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "backendError"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"access_token":  "test-access-token",
			"refresh_token": "test-refresh-token",
			"token_type":    "Bearer",
		})
	})
	tsgoog := httptest.NewServer(goog)
	gp := p.(*googleProvider)
	gp.SetOAuth2Endpoint(oauth2.Endpoint{
		AuthURL:  tsgoog.URL + "/auth",
		TokenURL: tsgoog.URL + "/token",
	})

	googapi := gin.New()
	tsgoogapi := httptest.NewServer(googapi)
	gp.SetUserinfoEndpoint(tsgoogapi.URL + "/userinfo")

	return p, googapi
}

func TestGoogleProvider(t *testing.T) {
	p, _ := setupGoogleTest([]string{}, []string{})
	require.Equal(t, p.Name(), "Google")
	require.Equal(t, p.Type(), "google")
	require.Equal(t, p.RedirectURL(), GoogleCallbackEndpoint)
	require.Equal(t, p.AuthURL(), GoogleAuthEndpoint)

	authCodeURL, err := p.AuthCodeURL("test-state")
	require.NoError(t, err)
	require.NotEmpty(t, authCodeURL)
	authCodeURLObj, err := url.Parse(authCodeURL)
	require.NoError(t, err)
	require.Equal(t, authCodeURLObj.Path, "/auth")
	require.Equal(t, authCodeURLObj.Query().Get("client_id"), TestGoogleClientID)
	require.Equal(t, authCodeURLObj.Query().Get("redirect_uri"), TestGoogleExternalURL+"/.auth/google/callback")
	require.Equal(t, authCodeURLObj.Query().Get("response_type"), "code")
	require.Equal(t, authCodeURLObj.Query().Get("state"), "test-state")
	require.Equal(t, "offline", authCodeURLObj.Query().Get("access_type"))
	require.Equal(t, "consent", authCodeURLObj.Query().Get("prompt"))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest("GET", "/?state=test-state&code=test-code", nil)
	c.Request = req
	_, err = p.Exchange(c, "invalid-state")
	require.Error(t, err)
	token, err := p.Exchange(c, "test-state")
	require.NoError(t, err)
	require.NotNil(t, token)
	require.Equal(t, token.AccessToken, "test-access-token")
}

func TestGoogleProviderWithWorkspace(t *testing.T) {
	p, _ := setupGoogleTest([]string{}, []string{"example.com"})

	authCodeURL, err := p.AuthCodeURL("test-state")
	require.NoError(t, err)
	require.NotEmpty(t, authCodeURL)
	authCodeURLObj, err := url.Parse(authCodeURL)
	require.NoError(t, err)
	require.Equal(t, authCodeURLObj.Query().Get("hd"), "example.com")
}

func TestGoogleProviderAuthorization(t *testing.T) {
	tc := []struct {
		name              string
		allowedUsers      []string
		allowedWorkspaces []string
		userResp          string
		expect            bool
	}{
		{
			name:              "allow all users",
			allowedUsers:      []string{},
			allowedWorkspaces: []string{},
			userResp:          `{"email_verified": true, "sub": "12345", "name": "Test User", "email": "user1@gmail.com"}`,
			expect:            true,
		},
		{
			name:              "allow single user",
			allowedUsers:      []string{"user1@gmail.com", "user2@gmail.com"},
			allowedWorkspaces: []string{},
			userResp:          `{"email_verified": true, "sub": "12345", "name": "Test User", "email": "user1@gmail.com"}`,
			expect:            true,
		},
		{
			name:              "deny single user",
			allowedUsers:      []string{"user1@gmail.com"},
			allowedWorkspaces: []string{},
			userResp:          `{"email_verified": true, "sub": "12345", "name": "Test User", "email": "user2@gmail.com"}`,
			expect:            false,
		},
		{
			name:              "allow by workspace",
			allowedUsers:      []string{},
			allowedWorkspaces: []string{"example.com"},
			userResp:          `{"email_verified": true, "sub": "12345", "name": "Test User", "email": "user1@example.com", "hd": "example.com"}`,
			expect:            true,
		},
		{
			name:              "deny by workspace",
			allowedUsers:      []string{},
			allowedWorkspaces: []string{"example.com"},
			userResp:          `{"email_verified": true, "sub": "12345", "name": "Test User", "email": "user1@gmail.com"}`,
			expect:            false,
		},
		{
			name:              "deny by other workspace",
			allowedUsers:      []string{},
			allowedWorkspaces: []string{"example.com"},
			userResp:          `{"email_verified": true, "sub": "12345", "name": "Test User", "email": "test@other.com", "hd": "other.com"}`,
			expect:            false,
		},
		{
			name:              "allow user without workspace domain",
			allowedUsers:      []string{},
			allowedWorkspaces: []string{},
			userResp:          `{"email_verified": true, "sub": "12345", "name": "Test User", "email": "test@gmail.com"}`,
			expect:            true,
		},
		{
			name:              "deny unverified email",
			allowedUsers:      []string{"user1@gmail.com"},
			allowedWorkspaces: []string{},
			userResp:          `{"email_verified": false, "sub": "12345", "email": "user1@gmail.com"}`,
			expect:            false,
		},
		{
			name:              "deny missing email_verified",
			allowedUsers:      []string{},
			allowedWorkspaces: []string{"example.com"},
			userResp:          `{"sub": "12345", "email": "user1@example.com", "hd": "example.com"}`,
			expect:            false,
		},
		{
			name:              "allow user case-insensitively",
			allowedUsers:      []string{"User1@Gmail.com"},
			allowedWorkspaces: []string{},
			userResp:          `{"email_verified": true, "sub": "12345", "email": "user1@GMAIL.com"}`,
			expect:            true,
		},
		{
			name:              "allow specific user with workspace",
			allowedUsers:      []string{"test@example.com"},
			allowedWorkspaces: []string{"other.com"},
			userResp:          `{"email_verified": true, "sub": "12345", "name": "Test User", "email": "test@example.com", "hd": "example.com"}`,
			expect:            true,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			p, googapi := setupGoogleTest(tt.allowedUsers, tt.allowedWorkspaces)

			googapi.GET("/userinfo", func(c *gin.Context) {
				c.Data(http.StatusOK, "application/json", []byte(tt.userResp))
			})

			ok, _, _, err := p.Authorization(context.Background(), &oauth2.Token{AccessToken: "test-access-token"})
			require.NoError(t, err)
			require.Equal(t, tt.expect, ok)
		})
	}
}

func TestGoogleProviderAuthorizationAPIError(t *testing.T) {
	p, googapi := setupGoogleTest([]string{}, []string{})

	googapi.GET("/userinfo", func(c *gin.Context) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	})

	ok, user, _, err := p.Authorization(context.Background(), &oauth2.Token{AccessToken: "test-access-token"})
	require.Error(t, err)
	require.False(t, ok)
	require.Empty(t, user)
	require.Contains(t, err.Error(), "failed to get user info from Google API")
}

func TestGoogleProviderAuthorizationInvalidJSON(t *testing.T) {
	p, googapi := setupGoogleTest([]string{}, []string{})

	googapi.GET("/userinfo", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/json", []byte(`invalid json`))
	})

	ok, user, _, err := p.Authorization(context.Background(), &oauth2.Token{AccessToken: "test-access-token"})
	require.Error(t, err)
	require.False(t, ok)
	require.Empty(t, user)
}

func TestGoogleVerifyUpstream(t *testing.T) {
	ctx := context.Background()
	p, googapi := setupGoogleTest(nil, []string{"example.com"})
	hd := "example.com"
	googapi.GET("/userinfo", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"email": "alice@example.com", "email_verified": true, "hd": hd})
	})
	v := p.(UpstreamVerifier)

	res, err := v.VerifyUpstream(ctx, "alice@example.com", "good-refresh-token")
	require.NoError(t, err)
	require.True(t, res.Allowed)
	require.Equal(t, "test-refresh-token", res.RefreshToken, "rotated token is returned")

	// Account deleted/suspended or grant revoked at Google.
	res, err = v.VerifyUpstream(ctx, "alice@example.com", "revoked-refresh-token")
	require.NoError(t, err)
	require.False(t, res.Allowed)

	// Google outage is transient, not a refusal.
	_, err = v.VerifyUpstream(ctx, "alice@example.com", "outage-refresh-token")
	require.Error(t, err)

	// Email changed.
	res, err = v.VerifyUpstream(ctx, "bob@example.com", "good-refresh-token")
	require.NoError(t, err)
	require.False(t, res.Allowed)

	// Moved out of the workspace.
	hd = "other.com"
	res, err = v.VerifyUpstream(ctx, "alice@example.com", "good-refresh-token")
	require.NoError(t, err)
	require.False(t, res.Allowed)
}
