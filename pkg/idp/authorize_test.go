package idp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// renderAuthorizePage registers a client, starts an authorization request and
// returns the consent page body.
func renderAuthorizePage(t *testing.T, serverURL, clientName, redirectURI string) string {
	t.Helper()

	reqBody, err := json.Marshal(registrationRequest{
		ClientName:              clientName,
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
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state",
		serverURL, AuthorizationEndpoint, regResp.ClientID, url.QueryEscape(redirectURI))
	authResp, err := client.Get(authURL)
	require.NoError(t, err)
	defer authResp.Body.Close()
	location := authResp.Header.Get("Location")
	require.NotEmpty(t, location)

	pageResp, err := client.Get(serverURL + location)
	require.NoError(t, err)
	defer pageResp.Body.Close()
	require.Equal(t, http.StatusOK, pageResp.StatusCode)
	require.Equal(t, "text/html; charset=utf-8", pageResp.Header.Get("Content-Type"))
	require.Equal(t, "no-store", pageResp.Header.Get("Cache-Control"))
	require.Equal(t, "DENY", pageResp.Header.Get("X-Frame-Options"))
	require.Contains(t, pageResp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'")

	body, err := io.ReadAll(pageResp.Body)
	require.NoError(t, err)
	return string(body)
}

func TestAuthorizePageShowsRequestDetails(t *testing.T) {
	server, _, _ := setupTestServer(t)

	body := renderAuthorizePage(t, server.URL, "opencode", "http://127.0.0.1:19876/mcp/oauth/callback")

	require.Contains(t, body, "opencode")
	require.Contains(t, body, "Name provided by the application")
	require.Contains(t, body, "localhost:8080", "server host from the external URL")
	require.Contains(t, body, "test-user@example.com", "signed-in user from the session")
	require.Contains(t, body, "127.0.0.1:19876")
	require.Contains(t, body, "An app on this computer")
	require.NotContains(t, body, "A website")
	require.Contains(t, body, `<form method="post">`)
}

func TestAuthorizePageMarksRemoteRedirect(t *testing.T) {
	server, _, _ := setupTestServer(t)

	body := renderAuthorizePage(t, server.URL, "LibreChat", "https://chat.example.com/api/mcp/trino/oauth/callback")

	require.Contains(t, body, "chat.example.com")
	require.NotContains(t, body, "/api/mcp/trino/oauth/callback", "only the host is shown")
	require.Contains(t, body, "A website")
	require.NotContains(t, body, "An app on this computer")
}

func TestAuthorizePageWithoutClientName(t *testing.T) {
	server, _, _ := setupTestServer(t)

	body := renderAuthorizePage(t, server.URL, "", "http://localhost:3000/callback")

	require.Contains(t, body, "An\n        application")
	require.NotContains(t, body, "Name provided by the application")
}

func TestAuthorizePageEscapesClientName(t *testing.T) {
	server, _, _ := setupTestServer(t)

	body := renderAuthorizePage(t, server.URL, `<script>alert(1)</script>`, "http://localhost:3000/callback")

	require.NotContains(t, body, "<script>alert(1)</script>")
	require.Contains(t, body, "&lt;script&gt;alert(1)&lt;/script&gt;")
}

func TestRegisterTruncatesClientName(t *testing.T) {
	server, repo, _ := setupTestServer(t)

	long := ""
	for i := 0; i < maxClientNameLength+20; i++ {
		long += "é"
	}
	reqBody, err := json.Marshal(registrationRequest{
		ClientName:              long,
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{"http://localhost:3000/callback"},
	})
	require.NoError(t, err)
	resp, err := http.Post(server.URL+RegistrationEndpoint, "application/json", bytes.NewReader(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	var regResp registrationResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&regResp))

	name, err := repo.GetClientName(t.Context(), regResp.ClientID)
	require.NoError(t, err)
	require.Len(t, []rune(name), maxClientNameLength)
}

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost":        true,
		"LOCALHOST":        true,
		"127.0.0.1":        true,
		"127.1.2.3":        true,
		"::1":              true,
		"chat.example.com": false,
		"10.0.0.1":         false,
		"localhost.evil":   false,
		"":                 false,
	} {
		require.Equal(t, want, isLoopbackHost(host), host)
	}
}

// TestWriteAuthorizePreviews writes sample renders of the consent page for
// manual review. Run with AUTHORIZE_PREVIEW_DIR=<dir>.
func TestWriteAuthorizePreviews(t *testing.T) {
	dir := os.Getenv("AUTHORIZE_PREVIEW_DIR")
	if dir == "" {
		t.Skip("AUTHORIZE_PREVIEW_DIR not set")
	}
	server, _, _ := setupTestServer(t)
	for file, c := range map[string][2]string{
		"authorize-local.html":   {"opencode", "http://127.0.0.1:19876/mcp/oauth/callback"},
		"authorize-website.html": {"LibreChat", "https://chat.internal.adjoe.zone/api/mcp/trino-staging/oauth/callback"},
		"authorize-unnamed.html": {"", "http://localhost:3000/callback"},
	} {
		body := renderAuthorizePage(t, server.URL, c[0], c[1])
		require.NoError(t, os.WriteFile(filepath.Join(dir, file), []byte(body), 0o644))
	}

	branded, _, _ := setupTestServerWithBranding(t, Branding{
		ServerName: "Trino (staging)",
		Banner:     `<strong>adjoe MCP</strong> — authorize access to Trino (staging).`,
		Footer:     `Need help? Ask in <a href="#">#data-platform</a>.`,
	})
	brandedServer := branded
	body := renderAuthorizePage(t, brandedServer.URL, "opencode", "http://127.0.0.1:19876/mcp/oauth/callback")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "authorize-branded.html"), []byte(body), 0o644))
}

func TestAuthorizePageUsesServerName(t *testing.T) {
	server, _, _ := setupTestServerWithBranding(t, Branding{ServerName: "Trino (staging)"})

	body := renderAuthorizePage(t, server.URL, "opencode", "http://127.0.0.1:19876/mcp/oauth/callback")

	require.Contains(t, body, "Trino (staging)", "friendly server name is shown")
	require.NotContains(t, body, "localhost:8080", "bare host is replaced by the friendly name")
}

func TestAuthorizePageRendersCustomBannerAndFooter(t *testing.T) {
	server, _, _ := setupTestServerWithBranding(t, Branding{
		Banner: `<strong class="brand">adjoe MCP</strong>`,
		Footer: `<a href="https://example.com/help">Help</a>`,
	})

	body := renderAuthorizePage(t, server.URL, "opencode", "http://localhost:3000/callback")

	require.Contains(t, body, `<strong class="brand">adjoe MCP</strong>`, "banner HTML is rendered unescaped")
	require.Contains(t, body, `<a href="https://example.com/help">Help</a>`, "footer HTML is rendered unescaped")
	require.NotContains(t, body, "wants to access", "custom banner replaces the default lead")
	require.NotContains(t, body, "Close this tab to cancel", "custom footer replaces the default footer")
}

func TestAuthorizePageHidesBannerAndFooterWithDash(t *testing.T) {
	server, _, _ := setupTestServerWithBranding(t, Branding{Banner: "-", Footer: "-"})

	body := renderAuthorizePage(t, server.URL, "opencode", "http://localhost:3000/callback")

	require.NotContains(t, body, "wants to access", "default lead is hidden")
	require.NotContains(t, body, "Close this tab to cancel", "default footer is hidden")
}

func TestAuthorizePageShowsURLLogo(t *testing.T) {
	branding, err := LoadBranding("", "https://cdn.example.com/logo.svg", "", "")
	require.NoError(t, err)
	server, _, _ := setupTestServerWithBranding(t, branding)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	body, csp := renderWithClient(t, client, server.URL, "opencode", "http://localhost:3000/callback")

	require.Contains(t, body, `src="https://cdn.example.com/logo.svg"`, "URL logo is used in <img>")
	require.NotContains(t, body, "🔐", "built-in icon is replaced")
	require.Contains(t, csp, "img-src https://cdn.example.com", "CSP widened to the logo origin")
}

func TestAuthorizePageInlinesFileLogo(t *testing.T) {
	dir := t.TempDir()
	logoPath := filepath.Join(dir, "logo.svg")
	require.NoError(t, os.WriteFile(logoPath, []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`), 0o644))

	branding, err := LoadBranding("", logoPath, "", "")
	require.NoError(t, err)
	server, _, _ := setupTestServerWithBranding(t, branding)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	body, csp := renderWithClient(t, client, server.URL, "opencode", "http://localhost:3000/callback")

	require.Contains(t, body, "src=\"data:image/svg", "file logo is inlined as a data URI")
	require.Contains(t, body, "base64,", "file logo is base64-encoded")
	require.Contains(t, csp, "img-src data:", "CSP allows data: for the inlined logo")
}

func TestAuthorizePageDisabledLogo(t *testing.T) {
	branding, err := LoadBranding("", "-", "", "")
	require.NoError(t, err)
	server, _, _ := setupTestServerWithBranding(t, branding)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	body, csp := renderWithClient(t, client, server.URL, "opencode", "http://localhost:3000/callback")

	require.NotContains(t, body, "🔐", "default icon is hidden")
	require.NotContains(t, body, "<img", "no logo image is rendered")
	require.Contains(t, csp, "img-src 'none'", "CSP keeps img-src locked down")
}

func TestLoadBrandingRejectsUnknownLogoType(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "logo.txt")
	require.NoError(t, os.WriteFile(bad, []byte("nope"), 0o644))

	_, err := LoadBranding("", bad, "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported logo type")
}

func TestLoadBrandingRejectsOversizeLogo(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "logo.png")
	require.NoError(t, os.WriteFile(big, make([]byte, maxLogoBytes+1), 0o644))

	_, err := LoadBranding("", big, "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "over the")
}

// renderWithClient runs the authorize flow with a caller-supplied client (used
// when the CSP header must also be inspected) and returns the body and CSP.
func renderWithClient(t *testing.T, client *http.Client, serverURL, clientName, redirectURI string) (string, string) {
	t.Helper()

	reqBody, err := json.Marshal(registrationRequest{
		ClientName:              clientName,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{redirectURI},
	})
	require.NoError(t, err)
	resp, err := http.Post(serverURL+RegistrationEndpoint, "application/json", bytes.NewReader(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	var regResp registrationResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&regResp))

	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state",
		serverURL, AuthorizationEndpoint, regResp.ClientID, url.QueryEscape(redirectURI))
	authResp, err := client.Get(authURL)
	require.NoError(t, err)
	defer authResp.Body.Close()
	location := authResp.Header.Get("Location")
	require.NotEmpty(t, location)

	pageResp, err := client.Get(serverURL + location)
	require.NoError(t, err)
	defer pageResp.Body.Close()
	require.Equal(t, http.StatusOK, pageResp.StatusCode)

	body, err := io.ReadAll(pageResp.Body)
	require.NoError(t, err)
	return string(body), pageResp.Header.Get("Content-Security-Policy")
}
