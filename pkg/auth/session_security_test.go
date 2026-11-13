package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestRequireAuthExpiresOldLogin(t *testing.T) {
	authRouter, err := NewAuthRouter([]string{"x"}, false, nil)
	require.NoError(t, err)
	router := gin.New()
	router.Use(sessions.Sessions("session", memstore.NewStore([]byte("test-secret"))))
	var loginAge time.Duration
	router.GET("/seed", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set(SessionKeyAuthorized, true)
		s.Set(SessionKeyUserID, "alice@example.com")
		s.Set(SessionKeyAuthTime, time.Now().Add(-loginAge).Unix())
		require.NoError(t, s.Save())
	})
	router.GET("/protected", authRouter.RequireAuth(), func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	server := httptest.NewServer(router)
	defer server.Close()

	for _, tc := range []struct {
		age  time.Duration
		want int
	}{
		{time.Minute, http.StatusOK},
		{LoginSessionMaxAge + time.Minute, http.StatusFound},
	} {
		client := setupClient()
		loginAge = tc.age
		resp, err := client.Get(server.URL + "/seed")
		require.NoError(t, err)
		resp.Body.Close()
		resp, err = client.Get(server.URL + "/protected")
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, tc.want, resp.StatusCode, "login age %s", tc.age)
		if tc.want == http.StatusFound {
			require.Equal(t, LoginEndpoint, resp.Header.Get("Location"))
		}
	}
}

func TestLogoutClearsWholeSession(t *testing.T) {
	authRouter, err := NewAuthRouter([]string{"x"}, false, nil)
	require.NoError(t, err)
	router := gin.New()
	router.Use(sessions.Sessions("session", memstore.NewStore([]byte("test-secret"))))
	authRouter.SetupRoutes(router)
	var remaining []any
	router.GET("/seed", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set(SessionKeyAuthorized, true)
		s.Set(SessionKeyUserID, "alice@example.com")
		s.Set(SessionKeyUpstreamToken, "rt")
		require.NoError(t, s.Save())
	})
	router.GET("/check", func(c *gin.Context) {
		s := sessions.Default(c)
		remaining = []any{s.Get(SessionKeyAuthorized), s.Get(SessionKeyUserID), s.Get(SessionKeyUpstreamToken)}
	})
	server := httptest.NewServer(router)
	defer server.Close()
	client := setupClient()
	for _, p := range []string{"/seed", LogoutEndpoint, "/check"} {
		resp, err := client.Get(server.URL + p)
		require.NoError(t, err)
		resp.Body.Close()
	}
	require.Equal(t, []any{nil, nil, nil}, remaining)
}

func TestGoogleLoginStoresUpstreamTokenAndConsumesState(t *testing.T) {
	provider, googleAPI := setupGoogleTest(nil, []string{"corp.example.com"})
	googleAPI.GET("/userinfo", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"email": "carol@corp.example.com", "email_verified": true, "hd": "corp.example.com"})
	})
	authRouter, err := NewAuthRouter(nil, false, nil, provider)
	require.NoError(t, err)
	router := gin.New()
	router.Use(sessions.Sessions("session", memstore.NewStore([]byte("test-secret"))))
	authRouter.SetupRoutes(router)
	var upstream any
	router.GET("/check", func(c *gin.Context) { upstream = sessions.Default(c).Get(SessionKeyUpstreamToken) })
	server := httptest.NewServer(router)
	defer server.Close()
	client := setupClient()

	resp, err := client.Get(server.URL + GoogleAuthEndpoint)
	require.NoError(t, err)
	resp.Body.Close()
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	callback := server.URL + GoogleCallbackEndpoint + "?code=c&state=" + url.QueryEscape(location.Query().Get("state"))

	resp, err = client.Get(callback)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	resp, err = client.Get(server.URL + "/check")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, "test-refresh-token", upstream)

	// Replaying the callback fails: the state was consumed.
	resp, err = client.Get(callback)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	require.Contains(t, string(body), "Sign-in failed")
	require.NotContains(t, string(body), "OAuth state")
}
