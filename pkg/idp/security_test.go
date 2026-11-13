package idp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/auth"
	"github.com/stretchr/testify/require"
)

func TestRedirectPolicy(t *testing.T) {
	p, err := NewRedirectPolicy([]string{"https://claude.ai/api/mcp/auth_callback", "https://*.example.com/oauth/**"})
	require.NoError(t, err)
	for uri, ok := range map[string]bool{
		"http://localhost:3000/callback":            true,
		"http://127.0.0.1:53682/cb":                 true,
		"http://[::1]:8080/cb":                      true,
		"https://localhost/cb":                      true,
		"cursor://anysphere.cursor-retrieval/cb":    true,
		"vscode://vscode.github-authentication/did": true,
		"com.example.app:/oauth2redirect":           true,
		"https://claude.ai/api/mcp/auth_callback":   true,
		"https://chat.example.com/oauth/a/b":        true,
		"https://attacker.example/cb":               false,
		"http://attacker.example/cb":                false,
		"http://localhost.attacker.example/cb":      false,
		"https://claude.ai/api/mcp/other":           false,
		"https://evil.com/x.example.com/oauth/cb":   false,
		"https://user@localhost/cb":                 false,
		"http://localhost/cb#frag":                  false,
		"javascript:alert(1)":                       false,
		"data:text/html,hi":                         false,
		"file:///etc/passwd":                        false,
		"/relative":                                 false,
		"":                                          false,
	} {
		err := p.Check(uri)
		if ok {
			require.NoError(t, err, uri)
		} else {
			require.Error(t, err, uri)
		}
	}
}

func register(t *testing.T, serverURL string, req registrationRequest) (*http.Response, map[string]any) {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)
	resp, err := http.Post(serverURL+RegistrationEndpoint, "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func TestRegistrationValidation(t *testing.T) {
	server, _, _ := setupTestServer(t)
	cases := []struct {
		name string
		req  registrationRequest
		code string
	}{
		{"remote redirect not allowlisted", registrationRequest{RedirectURIs: []string{"https://attacker.example/cb"}}, "invalid_redirect_uri"},
		{"javascript redirect", registrationRequest{RedirectURIs: []string{"javascript:alert(1)"}}, "invalid_redirect_uri"},
		{"no redirect", registrationRequest{}, "invalid_redirect_uri"},
		{"too many redirects", registrationRequest{RedirectURIs: strings.Split(strings.Repeat("http://localhost/cb,", 11), ",")[:11]}, "invalid_redirect_uri"},
		{"client_credentials", registrationRequest{RedirectURIs: []string{"http://localhost/cb"}, GrantTypes: []string{"client_credentials"}}, "invalid_client_metadata"},
		{"implicit", registrationRequest{RedirectURIs: []string{"http://localhost/cb"}, ResponseTypes: []string{"token"}}, "invalid_client_metadata"},
		{"auth method", registrationRequest{RedirectURIs: []string{"http://localhost/cb"}, TokenEndpointAuthMethod: "private_key_jwt"}, "invalid_client_metadata"},
		{"long scope", registrationRequest{RedirectURIs: []string{"http://localhost/cb"}, Scope: strings.Repeat("a", maxScopeLength+1)}, "invalid_client_metadata"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, out := register(t, server.URL, tc.req)
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			require.Equal(t, tc.code, out["error"])
		})
	}

	t.Run("oversized body", func(t *testing.T) {
		big := `{"client_name":"` + strings.Repeat("a", maxRegistrationBodyBytes) + `","redirect_uris":["http://localhost/cb"]}`
		resp, err := http.Post(server.URL+RegistrationEndpoint, "application/json", strings.NewReader(big))
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("defaults filled in", func(t *testing.T) {
		resp, out := register(t, server.URL, registrationRequest{RedirectURIs: []string{"http://localhost/cb"}})
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		require.Equal(t, []any{"authorization_code", "refresh_token"}, out["grant_types"])
		require.Equal(t, []any{"code"}, out["response_types"])
		require.Equal(t, "client_secret_basic", out["token_endpoint_auth_method"])
	})
}

func TestAuthorizeRefusesLegacyClientWithDisallowedRedirect(t *testing.T) {
	server, repo, _ := setupTestServer(t)
	require.NoError(t, repo.RegisterClient(context.Background(), &fosite.DefaultClient{
		ID:            "legacy-client",
		RedirectURIs:  []string{"https://attacker.example/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Public:        true,
		Audience:      []string{"http://localhost:8080"},
	}))
	client := &http.Client{Jar: mustCookieJar(t), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(withPKCE(t, fmt.Sprintf("%s%s?response_type=code&client_id=legacy-client&redirect_uri=%s&state=test-state",
		server.URL, AuthorizationEndpoint, url.QueryEscape("https://attacker.example/cb"))))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Empty(t, resp.Header.Get("Location"), "never redirect to a disallowed URI")
}

// startConsent registers a client and starts an authorization, returning the
// client, the consent page location and its CSRF token.
func startConsent(t *testing.T, serverURL string) (*http.Client, string, string) {
	t.Helper()
	reg := registerTestClient(t, serverURL)
	client := &http.Client{Jar: mustCookieJar(t), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(withPKCE(t, fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state",
		serverURL, AuthorizationEndpoint, reg.ClientID, url.QueryEscape("http://localhost:8080/callback"))))
	require.NoError(t, err)
	resp.Body.Close()
	location := resp.Header.Get("Location")
	page, err := client.Get(serverURL + location)
	require.NoError(t, err)
	body, _ := io.ReadAll(page.Body)
	page.Body.Close()
	m := csrfInputPattern.FindStringSubmatch(string(body))
	require.Len(t, m, 2)
	return client, location, m[1]
}

func TestConsentRequiresCSRFTokenAndSameOrigin(t *testing.T) {
	server, _, _ := setupTestServer(t)
	post := func(client *http.Client, location string, form url.Values, headers map[string]string) int {
		req, err := http.NewRequest(http.MethodPost, server.URL+location, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}

	client, location, token := startConsent(t, server.URL)
	require.Equal(t, http.StatusForbidden, post(client, location, url.Values{"action": {"approve"}}, nil), "missing token")
	require.Equal(t, http.StatusForbidden, post(client, location, url.Values{"action": {"approve"}, "csrf_token": {"00" + token[2:]}}, nil), "wrong token")
	require.Equal(t, http.StatusForbidden, post(client, location, url.Values{"action": {"approve"}, "csrf_token": {token}}, map[string]string{"Sec-Fetch-Site": "same-site"}), "sibling subdomain")
	require.Equal(t, http.StatusForbidden, post(client, location, url.Values{"action": {"approve"}, "csrf_token": {token}}, map[string]string{"Origin": "https://evil.example"}), "foreign origin")
	require.Equal(t, http.StatusBadRequest, post(client, location, url.Values{"csrf_token": {token}}, nil), "no explicit action")
	require.Equal(t, http.StatusSeeOther, post(client, location, url.Values{"action": {"approve"}, "csrf_token": {token}},
		map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://localhost:8080"}), "legitimate submission")
}

// upstreamTestProvider is a login provider that supports upstream
// re-verification with a controllable outcome.
type upstreamTestProvider struct {
	testProvider
	mu      sync.Mutex
	calls   int
	tokens  []string
	result  auth.UpstreamResult
	failErr error
	initial string
}

func (p *upstreamTestProvider) upstreamToken() string { return p.initial }

func (p *upstreamTestProvider) VerifyUpstream(_ context.Context, userID, refreshToken string) (auth.UpstreamResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	p.tokens = append(p.tokens, refreshToken)
	if p.failErr != nil {
		return auth.UpstreamResult{}, p.failErr
	}
	return p.result, nil
}

func (p *upstreamTestProvider) set(result auth.UpstreamResult, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.result, p.failErr = result, err
}

func (p *upstreamTestProvider) seen() (int, []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls, append([]string(nil), p.tokens...)
}

func TestUpstreamVerificationOnRefresh(t *testing.T) {
	provider := &upstreamTestProvider{initial: "google-rt-1", result: auth.UpstreamResult{Allowed: true, RefreshToken: "google-rt-2"}}
	serverURL, reg, resp := issueTestTokens(t, provider, DefaultTokenLifespans(), func() {})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tok := decodeToken(t, resp)
	calls, _ := provider.seen()
	require.Zero(t, calls, "the code exchange follows a fresh upstream login")
	require.NotContains(t, tok["access_token"], "google-rt", "upstream token never in tokens")
	require.NotContains(t, fmt.Sprint(jwtClaims(t, tok["access_token"].(string))), "upstream")

	// Allowed: refresh works and the rotated upstream token is kept.
	r := refresh(t, serverURL, reg, tok["refresh_token"].(string))
	require.Equal(t, http.StatusOK, r.StatusCode)
	tok = decodeToken(t, r)
	provider.set(auth.UpstreamResult{Allowed: true}, nil)
	r = refresh(t, serverURL, reg, tok["refresh_token"].(string))
	require.Equal(t, http.StatusOK, r.StatusCode)
	tok = decodeToken(t, r)
	_, tokens := provider.seen()
	require.Equal(t, []string{"google-rt-1", "google-rt-2"}, tokens)

	// Upstream outage: 503, the refresh token stays usable.
	provider.set(auth.UpstreamResult{}, errors.New("google unreachable"))
	r = refresh(t, serverURL, reg, tok["refresh_token"].(string))
	require.Equal(t, http.StatusServiceUnavailable, r.StatusCode)
	require.Equal(t, "temporarily_unavailable", decodeToken(t, r)["error"])
	provider.set(auth.UpstreamResult{Allowed: true}, nil)
	r = refresh(t, serverURL, reg, tok["refresh_token"].(string))
	require.Equal(t, http.StatusOK, r.StatusCode, "same refresh token works after the outage")
	tok = decodeToken(t, r)

	// User removed upstream: refused and the whole grant is revoked.
	provider.set(auth.UpstreamResult{Reason: "suspended"}, nil)
	r = refresh(t, serverURL, reg, tok["refresh_token"].(string))
	require.Equal(t, http.StatusBadRequest, r.StatusCode)
	body := decodeToken(t, r)
	require.Equal(t, "invalid_grant", body["error"])
	require.Contains(t, body["error_description"], "no longer authorized")
	provider.set(auth.UpstreamResult{Allowed: true}, nil)
	r = refresh(t, serverURL, reg, tok["refresh_token"].(string))
	require.Equal(t, http.StatusBadRequest, r.StatusCode, "revoked even if upstream allows again")
}

func TestUpstreamRecheckInterval(t *testing.T) {
	provider := &upstreamTestProvider{initial: "google-rt", result: auth.UpstreamResult{Allowed: true}}
	lifespans := DefaultTokenLifespans()
	lifespans.UpstreamRecheckInterval = time.Hour
	serverURL, reg, resp := issueTestTokens(t, provider, lifespans, func() {})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	r := refresh(t, serverURL, reg, decodeToken(t, resp)["refresh_token"].(string))
	require.Equal(t, http.StatusOK, r.StatusCode)
	calls, _ := provider.seen()
	require.Zero(t, calls, "verified at login less than an hour ago")
}

func TestRefreshRefusedWithoutUpstreamGrant(t *testing.T) {
	// A session created before upstream verification existed (or without a
	// recorded upstream token) cannot be refreshed; the user signs in again.
	provider := &upstreamTestProvider{result: auth.UpstreamResult{Allowed: true}}
	serverURL, reg, resp := issueTestTokens(t, provider, DefaultTokenLifespans(), func() {})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	r := refresh(t, serverURL, reg, decodeToken(t, resp)["refresh_token"].(string))
	require.Equal(t, http.StatusBadRequest, r.StatusCode)
	require.Equal(t, "invalid_grant", decodeToken(t, r)["error"])
}
