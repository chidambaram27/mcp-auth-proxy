package idp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// getAuthorizePage registers a client, starts an authorization request and
// returns the consent page body and its Content-Security-Policy.
func getAuthorizePage(t *testing.T, serverURL string) (string, string) {
	t.Helper()

	redirectURI := "http://127.0.0.1:19876/callback"
	reqBody, err := json.Marshal(registrationRequest{
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{redirectURI},
	})
	require.NoError(t, err)
	resp, err := http.Post(serverURL+RegistrationEndpoint, "application/json", bytes.NewReader(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var regResp registrationResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&regResp))

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	authResp, err := client.Get(fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state",
		serverURL, AuthorizationEndpoint, regResp.ClientID, url.QueryEscape(redirectURI)))
	require.NoError(t, err)
	defer authResp.Body.Close()

	pageResp, err := client.Get(serverURL + authResp.Header.Get("Location"))
	require.NoError(t, err)
	defer pageResp.Body.Close()
	require.Equal(t, http.StatusOK, pageResp.StatusCode)
	require.Equal(t, "text/html; charset=utf-8", pageResp.Header.Get("Content-Type"))
	require.Equal(t, "no-store", pageResp.Header.Get("Cache-Control"))
	require.Equal(t, "DENY", pageResp.Header.Get("X-Frame-Options"))

	body, err := io.ReadAll(pageResp.Body)
	require.NoError(t, err)
	return string(body), pageResp.Header.Get("Content-Security-Policy")
}

func TestAuthorizePageWithoutLogo(t *testing.T) {
	server, _, _ := setupTestServer(t)

	body, csp := getAuthorizePage(t, server.URL)

	require.Contains(t, body, `<form method="post">`)
	require.Contains(t, body, "localhost:8080")
	require.NotContains(t, body, "<img")
	require.Contains(t, csp, "img-src 'none'")
}

func TestAuthorizePageWithLogo(t *testing.T) {
	server, _, _ := setupTestServerWithLogo(t, "https://cdn.example.com/brand/logo.png")

	body, csp := getAuthorizePage(t, server.URL)

	require.Contains(t, body, `src="https://cdn.example.com/brand/logo.png"`)
	require.Contains(t, csp, "img-src https://cdn.example.com;")
}

// form-action would also apply to the 303 to the client's callback and block it.
func TestAuthorizePageCSPDoesNotRestrictFormAction(t *testing.T) {
	server, _, _ := setupTestServer(t)

	_, csp := getAuthorizePage(t, server.URL)

	require.Contains(t, csp, "default-src 'none'")
	require.Contains(t, csp, "frame-ancestors 'none'")
	require.NotContains(t, csp, "form-action")
}

func TestValidateLogoURL(t *testing.T) {
	for _, ok := range []string{"", "https://cdn.example.com/logo.png", "http://localhost:8080/logo.svg"} {
		require.NoError(t, validateLogoURL(ok), ok)
	}
	for _, bad := range []string{
		"javascript:alert(1)",
		"data:image/png;base64,AAAA",
		"/logo.png",
		"https://user:pass@cdn.example.com/logo.png",
		"ftp://cdn.example.com/logo.png",
	} {
		require.Error(t, validateLogoURL(bad), bad)
	}
}
