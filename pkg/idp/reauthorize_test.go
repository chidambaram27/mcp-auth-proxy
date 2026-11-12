package idp

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testUser = "test-user@example.com"

func TestRefreshRefusedAfterUserRemovedFromAllowlist(t *testing.T) {
	provider := &testProvider{}
	serverURL, reg, resp := issueTestTokens(t, provider, DefaultTokenLifespans(), func() {})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tok := decodeToken(t, resp)

	// A refreshed session must keep the recorded provider for later checks.
	r := refresh(t, serverURL, reg, tok["refresh_token"].(string))
	require.Equal(t, http.StatusOK, r.StatusCode)
	tok = decodeToken(t, r)

	provider.remove(testUser)
	r = refresh(t, serverURL, reg, tok["refresh_token"].(string))
	require.Equal(t, http.StatusBadRequest, r.StatusCode)
	body := decodeToken(t, r)
	require.Equal(t, "invalid_grant", body["error"])
	require.Contains(t, body["error_description"], "no longer authorized")
}

func TestCodeExchangeRefusedAfterUserRemovedFromAllowlist(t *testing.T) {
	provider := &testProvider{}
	_, _, resp := issueTestTokens(t, provider, DefaultTokenLifespans(), func() { provider.remove(testUser) })
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Equal(t, "invalid_grant", decodeToken(t, resp)["error"])
}

func TestRefreshAllowedForOtherUsers(t *testing.T) {
	provider := &testProvider{}
	serverURL, reg, resp := issueTestTokens(t, provider, DefaultTokenLifespans(), func() {})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tok := decodeToken(t, resp)

	provider.remove("someone-else@example.com")
	r := refresh(t, serverURL, reg, tok["refresh_token"].(string))
	require.Equal(t, http.StatusOK, r.StatusCode)
}

func TestSessionIdentitySurvivesStorage(t *testing.T) {
	_, s := policyRequest(time.Now(), time.Now())
	s.Provider = "oidc"
	s.AuthzFacts = map[string]any{"/groups": []any{"admins"}}

	data, err := json.Marshal(s)
	require.NoError(t, err)
	restored := &Session{}
	require.NoError(t, json.Unmarshal(data, restored))
	require.Equal(t, "oidc", restored.Provider)
	require.Equal(t, s.AuthzFacts, restored.AuthzFacts)

	clone := restored.Clone().(*Session)
	require.Equal(t, "oidc", clone.Provider)
	require.Equal(t, s.AuthzFacts, clone.AuthzFacts)
}

func TestIssuedTokensDoNotContainSessionIdentity(t *testing.T) {
	_, _, resp := issueTestTokens(t, &testProvider{}, DefaultTokenLifespans(), func() {})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	claims := jwtClaims(t, decodeToken(t, resp)["access_token"].(string))
	require.NotContains(t, claims, "provider")
	require.NotContains(t, claims, "authz_facts")
}
