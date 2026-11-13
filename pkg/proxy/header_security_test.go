package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// proxyThroughReverseProxy sends req through the proxy router to a real
// httputil.ReverseProxy (configured like the transparent backend) and returns
// the headers the backend received.
func proxyThroughReverseProxy(t *testing.T, proxyHeaders http.Header, headerMapping map[string]string, stripCookies []string, mutate func(*http.Request)) (int, http.Header) {
	t.Helper()
	var got http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	t.Cleanup(backend.Close)
	target, err := url.Parse(backend.URL)
	require.NoError(t, err)
	rp := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) { pr.SetURL(target) }}

	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)
	pr, err := NewProxyRouter("https://example.com", rp, publicKey, proxyHeaders, false, false, headerMapping, "/userinfo")
	require.NoError(t, err)
	pr.SetStripCookies(stripCookies...)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	pr.SetupRoutes(router)
	front := httptest.NewServer(router)
	t.Cleanup(front.Close)

	token, err := createJWT(privateKey, jwt.MapClaims{
		"sub":      "alice@example.com",
		"exp":      time.Now().Add(time.Hour).Unix(),
		"userinfo": map[string]any{"email": "alice@example.com"},
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, front.URL+"/mcp", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	mutate(req)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode, got
}

func TestProxyHeadersOverrideClientValues(t *testing.T) {
	ph := http.Header{}
	ph.Set("X-Trino-User", "svc")
	status, got := proxyThroughReverseProxy(t, ph, nil, nil, func(r *http.Request) {
		r.Header.Set("X-Trino-User", "admin")
	})
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, []string{"svc"}, got.Values("X-Trino-User"))
}

func TestConnectionHeaderCannotStripIdentityHeaders(t *testing.T) {
	ph := http.Header{}
	ph.Set("X-Static", "v")
	status, got := proxyThroughReverseProxy(t, ph, map[string]string{"/email": "X-Forwarded-Email"}, nil, func(r *http.Request) {
		r.Header.Set("Connection", "X-Forwarded-Email, X-Static")
	})
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, []string{"alice@example.com"}, got.Values("X-Forwarded-Email"))
	require.Equal(t, []string{"v"}, got.Values("X-Static"))
}

func TestSessionCookieNotForwarded(t *testing.T) {
	status, got := proxyThroughReverseProxy(t, http.Header{}, nil, []string{"__Host-session"}, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: "__Host-session", Value: "secret"})
		r.AddCookie(&http.Cookie{Name: "app", Value: "keep"})
	})
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "app=keep", got.Get("Cookie"))
}

func TestTokenWithoutExpiryRejected(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)
	pr, err := NewProxyRouter("https://example.com", http.NotFoundHandler(), publicKey, http.Header{}, false, false, nil, "/userinfo")
	require.NoError(t, err)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	pr.SetupRoutes(router)

	token, err := createJWT(privateKey, jwt.MapClaims{"sub": "alice"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}
