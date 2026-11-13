package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/gobwas/glob"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func newTestGoogleProvider(t *testing.T, users, workspaces []string) Provider {
	t.Helper()
	p, err := NewGoogleProvider("https://proxy.example.com", "id", "secret", users, workspaces)
	require.NoError(t, err)
	return p
}

func newTestRouter(t *testing.T, password bool, providers ...Provider) *AuthRouter {
	t.Helper()
	var hashes []string
	if password {
		hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
		require.NoError(t, err)
		hashes = append(hashes, string(hash))
	}
	r, err := NewAuthRouter(hashes, false, nil, providers...)
	require.NoError(t, err)
	return r
}

func TestReauthorizeGoogle(t *testing.T) {
	r := newTestRouter(t, false, newTestGoogleProvider(t, []string{"alice@example.com"}, []string{"corp.example.com"}))
	tests := []struct {
		name string
		id   Identity
		want bool
	}{
		{"allowed user", Identity{Provider: "google", UserID: "alice@example.com"}, true},
		{"removed user", Identity{Provider: "google", UserID: "bob@example.com"}, false},
		{"allowed workspace", Identity{Provider: "google", UserID: "carol@corp.example.com", Facts: map[string]any{"hd": "corp.example.com"}}, true},
		{"other workspace", Identity{Provider: "google", UserID: "dave@other.example.com", Facts: map[string]any{"hd": "other.example.com"}}, false},
		{"no workspace recorded", Identity{Provider: "google", UserID: "carol@corp.example.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, r.Reauthorize(tt.id))
		})
	}
}

func TestReauthorizeGoogleWithoutRestrictions(t *testing.T) {
	r := newTestRouter(t, false, newTestGoogleProvider(t, nil, nil))
	require.True(t, r.Reauthorize(Identity{Provider: "google", UserID: "anyone@example.com"}))
}

func TestReauthorizeGitHub(t *testing.T) {
	newRouter := func(users, orgs []string) *AuthRouter {
		p, err := NewGithubProvider("", "", "id", "secret", "https://proxy.example.com", users, orgs)
		require.NoError(t, err)
		return newTestRouter(t, false, p)
	}

	r := newRouter([]string{"alice"}, nil)
	require.True(t, r.Reauthorize(Identity{Provider: "github", UserID: "alice"}))
	require.False(t, r.Reauthorize(Identity{Provider: "github", UserID: "bob"}))

	// Organization membership cannot be re-checked offline.
	r = newRouter([]string{"alice"}, []string{"acme"})
	require.True(t, r.Reauthorize(Identity{Provider: "github", UserID: "bob"}))
}

func TestReauthorizeOIDC(t *testing.T) {
	p := &oidcProvider{
		userIDField:           "/email",
		allowedUsers:          []string{"alice@example.com"},
		allowedUsersGlob:      []glob.Glob{glob.MustCompile("*@corp.example.com")},
		allowedAttributes:     map[string][]string{"/groups": {"mcp-users"}},
		allowedAttributesGlob: map[string][]glob.Glob{"/department": {glob.MustCompile("eng-*")}},
	}
	r := newTestRouter(t, false, p)

	facts := p.AuthzFacts(map[string]any{
		"email":      "erin@example.com",
		"groups":     []any{"staff", "mcp-users"},
		"department": "sales",
		"name":       "Erin",
	})
	require.Equal(t, map[string]any{"/groups": []any{"staff", "mcp-users"}, "/department": "sales"}, facts)

	tests := []struct {
		name string
		id   Identity
		want bool
	}{
		{"allowed user", Identity{Provider: "oidc", UserID: "alice@example.com"}, true},
		{"allowed glob", Identity{Provider: "oidc", UserID: "bob@corp.example.com"}, true},
		{"allowed attribute", Identity{Provider: "oidc", UserID: "erin@example.com", Facts: facts}, true},
		{"allowed attribute glob", Identity{Provider: "oidc", UserID: "frank@example.com", Facts: map[string]any{"/department": "eng-platform"}}, true},
		{"removed from group", Identity{Provider: "oidc", UserID: "erin@example.com", Facts: map[string]any{"/groups": []any{"staff"}}}, false},
		{"no match", Identity{Provider: "oidc", UserID: "mallory@example.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, r.Reauthorize(tt.id))
		})
	}
}

func TestReauthorizePassword(t *testing.T) {
	require.True(t, newTestRouter(t, true).Reauthorize(Identity{Provider: PasswordProvider, UserID: PasswordUserID}))
	require.False(t, newTestRouter(t, false).Reauthorize(Identity{Provider: PasswordProvider, UserID: PasswordUserID}))
	// Sessions without a recorded provider are recognized by the password user ID.
	require.True(t, newTestRouter(t, true).Reauthorize(Identity{UserID: PasswordUserID}))
	require.False(t, newTestRouter(t, false, newTestGoogleProvider(t, nil, nil)).Reauthorize(Identity{UserID: PasswordUserID}))
}

func TestReauthorizeProviderNoLongerConfigured(t *testing.T) {
	r := newTestRouter(t, true, newTestGoogleProvider(t, nil, nil))
	require.False(t, r.Reauthorize(Identity{Provider: "github", UserID: "alice"}))
}

func TestReauthorizeSessionWithoutRecordedProvider(t *testing.T) {
	r := newTestRouter(t, false, newTestGoogleProvider(t, []string{"alice@example.com"}, []string{"corp.example.com"}))
	require.True(t, r.Reauthorize(Identity{UserID: "alice@example.com"}))
	require.True(t, r.Reauthorize(Identity{UserID: "carol@corp.example.com", UserInfo: map[string]any{"hd": "corp.example.com"}}))
	require.False(t, r.Reauthorize(Identity{UserID: "bob@example.com", UserInfo: map[string]any{"email": "bob@example.com"}}))
}

func TestGoogleLoginRecordsWorkspaceDespiteUserInfoFilter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	provider, googleAPI := setupGoogleTest(nil, []string{"corp.example.com"})
	googleAPI.GET("/userinfo", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"email": "carol@corp.example.com", "email_verified": true, "hd": "corp.example.com"})
	})
	authRouter, err := NewAuthRouter(nil, false, []string{"email"}, provider)
	require.NoError(t, err)

	var gotProvider, gotUserInfo string
	var gotFacts map[string]any
	router := gin.New()
	router.Use(sessions.Sessions("session", memstore.NewStore([]byte("test-secret"))))
	authRouter.SetupRoutes(router)
	router.GET("/check-session", func(c *gin.Context) {
		session := sessions.Default(c)
		gotProvider, gotFacts = SessionIdentity(session)
		gotUserInfo, _ = session.Get(SessionKeyUserInfo).(string)
		c.Status(http.StatusOK)
	})
	server := httptest.NewServer(router)
	defer server.Close()
	client := setupClient()

	resp, err := client.Get(server.URL + GoogleAuthEndpoint)
	require.NoError(t, err)
	resp.Body.Close()
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	resp, err = client.Get(server.URL + GoogleCallbackEndpoint + "?code=test-code&state=" + url.QueryEscape(location.Query().Get("state")))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	resp, err = client.Get(server.URL + "/check-session")
	require.NoError(t, err)
	resp.Body.Close()

	require.JSONEq(t, `{"email":"carol@corp.example.com"}`, gotUserInfo, "userinfo is filtered")
	require.Equal(t, "google", gotProvider)
	require.Equal(t, map[string]any{"hd": "corp.example.com"}, gotFacts, "workspace is kept for re-checks")
	require.True(t, authRouter.Reauthorize(Identity{Provider: gotProvider, UserID: "carol@corp.example.com", Facts: gotFacts}))
}

func TestSessionIdentityRoundTrip(t *testing.T) {
	gin.SetMode(gin.TestMode)
	provider := newTestGoogleProvider(t, nil, []string{"corp.example.com"})
	router := gin.New()
	router.Use(sessions.Sessions("session", memstore.NewStore([]byte("test-secret"))))

	var gotProvider string
	var gotFacts map[string]any
	router.GET("/", func(c *gin.Context) {
		session := sessions.Default(c)
		setSessionIdentity(session, provider, map[string]any{"email": "carol@corp.example.com", "hd": "corp.example.com"})
		require.NoError(t, session.Save())
		gotProvider, gotFacts = SessionIdentity(session)
		c.Status(http.StatusOK)
	})
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, "google", gotProvider)
	require.Equal(t, map[string]any{"hd": "corp.example.com"}, gotFacts)
}
