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
	"strings"
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
	require.Contains(t, body, `<form method="post" class="actions">`)
}

func TestAuthorizePageMarksRemoteRedirect(t *testing.T) {
	server, _, _ := setupTestServer(t)

	body := renderAuthorizePage(t, server.URL, "LibreChat", "https://chat.example.com/api/mcp/trino/oauth/callback")

	require.Contains(t, body, "chat.example.com")
	require.NotContains(t, body, "/api/mcp/trino/oauth/callback", "only the host is shown")
	require.Contains(t, body, "A website")
	require.NotContains(t, body, "An app on this computer")
}

func TestAuthorizePageMarksCustomSchemeRedirect(t *testing.T) {
	server, _, _ := setupTestServer(t)

	body := renderAuthorizePage(t, server.URL, "Cursor", "cursor://anysphere.cursor-retrieval/oauth/callback")

	require.Contains(t, body, `<span class="mono">cursor:</span>`)
	require.NotContains(t, body, "anysphere.cursor-retrieval", "custom-scheme authority is not a network host")
	require.Contains(t, body, "An installed app")
	require.NotContains(t, body, "A website")
}

func TestDescribeRedirect(t *testing.T) {
	for raw, want := range map[string][2]string{
		"http://127.0.0.1:19876/cb":              {"127.0.0.1:19876", "local"},
		"http://localhost:3000/cb":               {"localhost:3000", "local"},
		"http://[::1]:3000/cb":                   {"[::1]:3000", "local"},
		"https://chat.example.com/cb":            {"chat.example.com", "remote"},
		"https://localhost.attacker.example/cb":  {"localhost.attacker.example", "remote"},
		"cursor://anysphere.cursor-retrieval/cb": {"cursor:", "app"},
		"VSCode://vscode.github-authentication/": {"vscode:", "app"},
		"com.example.app:/oauth/callback":        {"com.example.app:", "app"},
	} {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		label, kind := describeRedirect(u)
		require.Equal(t, want, [2]string{label, kind}, raw)
	}
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

func TestSanitizeClientName(t *testing.T) {
	for in, want := range map[string]string{
		"opencode":                      "opencode",
		"  Claude   Code ":              "Claude Code",
		"opencode\u202e lmth.exe\u202c": "opencode lmth.exe",
		"a\u200bb\u2066c\u2069\ufeffd":  "abcd",
		"line\nbreak\ttab\x00nul":       "line break tabnul",
		"Clïent 🔐 数据 Ωμέγα — ✅":         "Clïent 🔐 数据 Ωμέγα — ✅",
		"\u202e\u202c":                  "",
	} {
		require.Equal(t, want, sanitizeClientName(in), "%q", in)
	}
}

func TestRegisterStripsBidiFromClientName(t *testing.T) {
	server, _, _ := setupTestServer(t)

	body := renderAuthorizePage(t, server.URL, "opencode\u202e lmth.exe\u202c", "http://localhost:3000/callback")

	require.Contains(t, body, "opencode lmth.exe")
	require.NotContains(t, body, "\u202e")
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
	require.NotContains(t, body, "Choose Deny", "custom footer replaces the default footer")
}

func TestAuthorizePageHidesBannerAndFooterWithDash(t *testing.T) {
	server, _, _ := setupTestServerWithBranding(t, Branding{Banner: "-", Footer: "-"})

	body := renderAuthorizePage(t, server.URL, "opencode", "http://localhost:3000/callback")

	require.NotContains(t, body, "wants to access", "default lead is hidden")
	require.NotContains(t, body, "Choose Deny", "default footer is hidden")
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

// Browsers apply form-action to the redirect after the Authorize POST, so the
// CSP must allow the client's callback origin or the code is never delivered.
func TestAuthorizePageCSPAllowsRedirectOrigin(t *testing.T) {
	for redirectURI, want := range map[string]string{
		"http://127.0.0.1:19876/mcp/oauth/callback":             "form-action 'self' http://127.0.0.1:19876;",
		"https://chat.example.com/api/mcp/trino/oauth/callback": "form-action 'self' https://chat.example.com;",
		"http://localhost:3000/callback":                        "form-action 'self' http://localhost:3000;",
	} {
		server, _, _ := setupTestServer(t)
		jar, _ := cookiejar.New(nil)
		client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		_, csp := renderWithClient(t, client, server.URL, "opencode", redirectURI)
		require.Contains(t, csp, want, redirectURI)
	}
}

func TestRedirectCSPSource(t *testing.T) {
	for raw, want := range map[string]string{
		"http://127.0.0.1:19876/callback":        "http://127.0.0.1:19876",
		"https://chat.example.com/cb?x=1":        "https://chat.example.com",
		"HTTPS://Chat.Example.com/cb":            "https://Chat.Example.com",
		"cursor://anysphere.cursor-retrieval/cb": "cursor:",
		"vscode://vscode.github-authentication/": "vscode:",
		"CURSOR://Host/cb":                       "cursor:",
		"com.example.app:/oauth/callback":        "com.example.app:",
		"http://[::1]:3000/callback":             "http:",
	} {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		require.Equal(t, want, redirectCSPSource(u), raw)
	}
	require.Equal(t, "", redirectCSPSource(nil))
	require.Equal(t, "", redirectCSPSource(&url.URL{Scheme: "http;script-src", Host: "x"}))
	require.Equal(t, "http:", redirectCSPSource(&url.URL{Scheme: "http", Host: "a.com; script-src *"}))
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

func TestLoadBrandingFallsBackOnBadLogo(t *testing.T) {
	dir := t.TempDir()
	for name, logo := range map[string]string{
		"missing file":   filepath.Join(dir, "nope.png"),
		"javascript url": "javascript:alert(1)",
		"data url":       "data:image/png;base64,AAAA",
		"ftp url":        "ftp://example.com/logo.png",
	} {
		b, err := LoadBranding("Trino (staging)", logo, "<b>banner</b>", "footer")
		require.Error(t, err, name)
		require.Contains(t, err.Error(), "using the default icon", name)
		require.Equal(t, "Trino (staging)", b.ServerName, name)
		require.Equal(t, "<b>banner</b>", b.Banner, name)
		require.Empty(t, b.logoSrc, name)
		require.False(t, b.logoDisabled, name)
		require.Contains(t, b.contentSecurityPolicy(""), "img-src 'none'", name)
	}
}

func TestAuthorizePageWithBadLogoShowsDefaultIcon(t *testing.T) {
	branding, err := LoadBranding("Trino (staging)", "javascript:alert(1)", "", "")
	require.Error(t, err)
	server, _, _ := setupTestServerWithBranding(t, branding)

	body := renderAuthorizePage(t, server.URL, "opencode", "http://localhost:3000/callback")
	require.Contains(t, body, "🔐")
	require.NotContains(t, body, "javascript:")
	require.Contains(t, body, "Trino (staging)")
}

func TestBrandingInsecureLogoURL(t *testing.T) {
	b, err := LoadBranding("", "http://cdn.example.com/logo.png", "", "")
	require.NoError(t, err)
	require.True(t, b.InsecureLogoURL())
	b, err = LoadBranding("", "https://cdn.example.com/logo.png", "", "")
	require.NoError(t, err)
	require.False(t, b.InsecureLogoURL())
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

func TestAuthorizePageDenyRedirectsWithAccessDenied(t *testing.T) {
	server, repo, _ := setupTestServer(t)
	const redirectURI = "http://localhost:3000/callback"

	reqBody, err := json.Marshal(registrationRequest{
		ClientName:              "opencode",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{redirectURI},
	})
	require.NoError(t, err)
	resp, err := http.Post(server.URL+RegistrationEndpoint, "application/json", bytes.NewReader(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	var regResp registrationResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&regResp))

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authResp, err := client.Get(fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=deny-state-123",
		server.URL, AuthorizationEndpoint, regResp.ClientID, url.QueryEscape(redirectURI)))
	require.NoError(t, err)
	authResp.Body.Close()
	location := authResp.Header.Get("Location")

	page, err := client.Get(server.URL + location)
	require.NoError(t, err)
	body, _ := io.ReadAll(page.Body)
	page.Body.Close()
	require.Contains(t, string(body), `name="action" value="deny"`)

	denyResp, err := client.PostForm(server.URL+location, url.Values{"action": {"deny"}})
	require.NoError(t, err)
	denyResp.Body.Close()
	require.Equal(t, http.StatusSeeOther, denyResp.StatusCode)
	cb, err := url.Parse(denyResp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "localhost:3000", cb.Host)
	require.Equal(t, "access_denied", cb.Query().Get("error"))
	require.Equal(t, "deny-state-123", cb.Query().Get("state"))
	require.Equal(t, "The user denied the request. The user chose Deny on the consent page.", cb.Query().Get("error_description"))
	require.Empty(t, cb.Query().Get("code"))

	// The authorize request is consumed: approving afterwards is refused.
	arID := location[strings.LastIndex(location, "/")+1:]
	_, err = repo.GetAuthorizeRequest(t.Context(), arID)
	require.Error(t, err)
	again, err := client.PostForm(server.URL+location, url.Values{"action": {"approve"}})
	require.NoError(t, err)
	again.Body.Close()
	require.Equal(t, http.StatusForbidden, again.StatusCode)
}
