package mcpproxy

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/idp"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestRequireAllowlists(t *testing.T) {
	require.Error(t, requireAllowlists(true, nil, nil, false, nil, nil, false, nil, nil, nil, nil))
	require.NoError(t, requireAllowlists(true, nil, []string{"example.com"}, false, nil, nil, false, nil, nil, nil, nil))
	require.NoError(t, requireAllowlists(true, []string{"a@example.com"}, nil, false, nil, nil, false, nil, nil, nil, nil))
	require.Error(t, requireAllowlists(false, nil, nil, true, nil, nil, false, nil, nil, nil, nil))
	require.Error(t, requireAllowlists(false, nil, nil, false, nil, nil, true, nil, nil, nil, nil))
	require.NoError(t, requireAllowlists(false, nil, nil, false, nil, nil, true, nil, nil, map[string][]string{"/groups": {"x"}}, nil))
	require.NoError(t, requireAllowlists(false, nil, nil, false, nil, nil, false, nil, nil, nil, nil))
}

func TestRunRefusesGoogleWithoutAllowlist(t *testing.T) {
	err := Run(
		":0", ":0", false, "", "", false, "", "",
		t.TempDir(), "local", "",
		"https://example.com",
		"client-id", "client-secret", nil, nil,
		"", "", "", "", nil, nil,
		"", "", "", nil, "", "", nil, nil, nil, nil,
		false, "", "", nil, nil, "", false,
		[]string{"http://example.com"}, false, nil, "/userinfo",
		"", "", "", "",
		idp.DefaultTokenLifespans(),
		nil,
	)
	require.ErrorContains(t, err, "GOOGLE_ALLOWED_WORKSPACES")
}

func TestSessionCookieIsEncryptedAndExpiresServerSide(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	store, err := newSessionStore(secret, true)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(sessions.Sessions("__Host-session", store))
	r.GET("/set", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("user_info", "alice@example.com")
		require.NoError(t, s.Save())
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/set", nil))
	setCookie := w.Header().Get("Set-Cookie")
	require.Contains(t, setCookie, "__Host-session=")
	require.Contains(t, setCookie, "Secure")
	require.Contains(t, setCookie, "HttpOnly")
	require.Contains(t, setCookie, "SameSite=Lax")
	require.Contains(t, setCookie, "Max-Age=600")

	value := strings.TrimPrefix(strings.SplitN(setCookie, ";", 2)[0], "__Host-session=")
	raw, err := base64.URLEncoding.DecodeString(value)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "alice", "cookie payload must be encrypted")

	// The master secret itself is not the signing key.
	authKey, _ := utils.DeriveKey(secret, utils.KeyPurposeCookieAuth)
	encKey, _ := utils.DeriveKey(secret, utils.KeyPurposeCookieEncrypt)
	var decoded map[any]any
	require.Error(t, securecookie.New(secret, nil).Decode("__Host-session", value, &decoded))

	codec := securecookie.New(authKey, encKey)
	require.NoError(t, codec.Decode("__Host-session", value, &decoded))
	require.Equal(t, "alice@example.com", decoded["user_info"])
}

func TestHTTPSRedirectUsesExternalHost(t *testing.T) {
	ext, _ := url.Parse("https://mcp.example.com/")
	h := httpsRedirectHandler(ext)
	req := httptest.NewRequest(http.MethodGet, "http://evil.example/path?q=1", nil)
	req.Host = "evil.example"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusMovedPermanently, w.Code)
	require.Equal(t, "https://mcp.example.com/path?q=1", w.Header().Get("Location"))
}

func TestSecurityHeadersAndBodyLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(securityHeadersMiddleware(true), bodyLimitMiddleware(10))
	r.POST("/x", func(c *gin.Context) {
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			c.Status(http.StatusRequestEntityTooLarge)
			return
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("small")))
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "max-age=31536000", w.Header().Get("Strict-Transport-Security"))
	require.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	require.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("this body is too large")))
	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestRateLimitAppliesToRegistrationOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(rateLimitMiddleware())
	r.POST(idp.RegistrationEndpoint, func(c *gin.Context) { c.Status(http.StatusCreated) })
	r.POST("/mcp", func(c *gin.Context) { c.Status(http.StatusOK) })

	limited := false
	for i := 0; i < 50; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, idp.RegistrationEndpoint, nil))
		if w.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	require.True(t, limited, "registration is rate limited")
	for i := 0; i < 50; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp", nil))
		require.Equal(t, http.StatusOK, w.Code, "authenticated MCP traffic is not limited")
	}
}
