package idp

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/require"
)

func policyRequest(authTime, iat time.Time) (*fosite.AccessRequest, *Session) {
	s := &Session{
		DefaultSession: &fosite.DefaultSession{ExpiresAt: map[fosite.TokenType]time.Time{}},
		JWTClaims:      &jwt.JWTClaims{IssuedAt: iat, NotBefore: iat, Extra: map[string]any{"userinfo": map[string]any{"email": "a@b"}}},
		JWTHeader:      &jwt.Headers{Extra: map[string]any{}},
		AuthTime:       authTime,
	}
	req := fosite.NewAccessRequest(s)
	return req, s
}

func TestApplySessionPolicy_RefreshesIssuedAtAndSetsAuthTime(t *testing.T) {
	login := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	now := login.Add(3 * time.Hour).Add(400 * time.Millisecond)
	req, s := policyRequest(login, login)
	extraBefore := s.JWTClaims.Extra
	s.SetExpiresAt(fosite.RefreshToken, now.Add(720*time.Hour))

	require.NoError(t, applySessionPolicy(req, now, time.Hour, 0))
	require.Equal(t, now.Truncate(time.Second), s.JWTClaims.IssuedAt)
	require.Equal(t, now.Truncate(time.Second), s.JWTClaims.NotBefore)
	require.Equal(t, now.Truncate(time.Second).Add(time.Hour), s.GetExpiresAt(fosite.AccessToken))
	require.Equal(t, now.Add(720*time.Hour), s.GetExpiresAt(fosite.RefreshToken), "no cap without MAX_SESSION_AGE")
	require.Equal(t, login.Unix(), s.JWTClaims.Extra["auth_time"])
	require.NotContains(t, extraBefore, "auth_time", "claims map shared with the stored session must not be mutated")
}

func TestApplySessionPolicy_LegacySessionUsesIssuedAt(t *testing.T) {
	login := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	req, s := policyRequest(time.Time{}, login)
	require.NoError(t, applySessionPolicy(req, login.Add(time.Hour), time.Hour, 2*time.Hour))
	require.Equal(t, login, s.AuthTime)
	require.Equal(t, login.Unix(), s.JWTClaims.Extra["auth_time"])
	require.ErrorIs(t, applySessionPolicy(req, login.Add(3*time.Hour), time.Hour, 2*time.Hour), fosite.ErrInvalidGrant)
}

func TestApplySessionPolicy_MaxSessionAge(t *testing.T) {
	login := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	max := 8 * time.Hour

	t.Run("caps token expiry at session end", func(t *testing.T) {
		now := login.Add(7*time.Hour + 30*time.Minute)
		req, s := policyRequest(login, login)
		s.SetExpiresAt(fosite.RefreshToken, now.Add(720*time.Hour))
		require.NoError(t, applySessionPolicy(req, now, 24*time.Hour, max))
		require.Equal(t, login.Add(max), s.GetExpiresAt(fosite.AccessToken))
		require.Equal(t, login.Add(max), s.GetExpiresAt(fosite.RefreshToken))
	})

	t.Run("does not extend shorter tokens", func(t *testing.T) {
		now := login.Add(time.Hour)
		req, s := policyRequest(login, login)
		s.SetExpiresAt(fosite.RefreshToken, now.Add(time.Hour))
		require.NoError(t, applySessionPolicy(req, now, 30*time.Minute, max))
		require.Equal(t, now.Add(30*time.Minute), s.GetExpiresAt(fosite.AccessToken))
		require.Equal(t, now.Add(time.Hour), s.GetExpiresAt(fosite.RefreshToken))
	})

	t.Run("refuses after session end", func(t *testing.T) {
		req, _ := policyRequest(login, login)
		err := applySessionPolicy(req, login.Add(max), time.Hour, max)
		require.ErrorIs(t, err, fosite.ErrInvalidGrant)
	})
}

func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

func decodeToken(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body
}

func TestRefreshedAccessTokenHasFreshIssuedAtAndAuthTime(t *testing.T) {
	serverURL, reg, resp := lifespanTestTokens(t, DefaultTokenLifespans(), 0)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tok := decodeToken(t, resp)
	c0 := jwtClaims(t, tok["access_token"].(string))
	require.Contains(t, c0, "auth_time")
	require.InDelta(t, c0["iat"], c0["auth_time"], 1)

	time.Sleep(2100 * time.Millisecond)
	r := refresh(t, serverURL, reg, tok["refresh_token"].(string))
	require.Equal(t, http.StatusOK, r.StatusCode)
	c1 := jwtClaims(t, decodeToken(t, r)["access_token"].(string))
	require.Equal(t, c0["auth_time"], c1["auth_time"], "auth_time stays the login time")
	require.GreaterOrEqual(t, c1["iat"].(float64)-c0["iat"].(float64), 2.0, "iat is the refresh time")
	require.Equal(t, c1["iat"], c1["nbf"])
	require.Equal(t, float64(24*60*60), c1["exp"].(float64)-c1["iat"].(float64))
}

func TestMaxSessionAgeRefusesRefresh(t *testing.T) {
	lifespans := DefaultTokenLifespans()
	lifespans.MaxSessionAge = 5 * time.Second
	serverURL, reg, resp := lifespanTestTokens(t, lifespans, 0)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tok := decodeToken(t, resp)
	require.LessOrEqual(t, tok["expires_in"].(float64), 5.0, "access token capped at session end")
	c0 := jwtClaims(t, tok["access_token"].(string))
	require.Equal(t, 5.0, c0["exp"].(float64)-c0["auth_time"].(float64))
	sessionEnd := time.Unix(int64(c0["auth_time"].(float64))+5, 0)

	r := refresh(t, serverURL, reg, tok["refresh_token"].(string))
	require.Equal(t, http.StatusOK, r.StatusCode)
	tok = decodeToken(t, r)

	time.Sleep(time.Until(sessionEnd) + 500*time.Millisecond)
	r = refresh(t, serverURL, reg, tok["refresh_token"].(string))
	require.Equal(t, http.StatusBadRequest, r.StatusCode)
	require.Equal(t, "invalid_grant", decodeToken(t, r)["error"])
}

func TestSessionAuthTimeSurvivesStorage(t *testing.T) {
	login := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	_, s := policyRequest(login, login.Add(time.Hour))
	data, err := json.Marshal(s)
	require.NoError(t, err)

	restored := &Session{}
	require.NoError(t, json.Unmarshal(data, restored))
	require.True(t, login.Equal(restored.AuthTime))
	require.True(t, login.Equal(restored.Clone().(*Session).AuthTime))
}

func TestMaxSessionAgeCountsFromLoginAcrossRefreshes(t *testing.T) {
	const maxAge = 6
	lifespans := DefaultTokenLifespans()
	lifespans.MaxSessionAge = maxAge * time.Second
	serverURL, reg, resp := lifespanTestTokens(t, lifespans, 0)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tok := decodeToken(t, resp)
	authTime := jwtClaims(t, tok["access_token"].(string))["auth_time"]
	sessionEnd := time.Unix(int64(authTime.(float64))+maxAge, 0)

	// Each refresh moves iat forward; the cap must still count from login.
	for i := 0; i < 2; i++ {
		time.Sleep(time.Second)
		if time.Until(sessionEnd) < time.Second {
			t.Skip("runner too slow to refresh inside the session window")
		}
		r := refresh(t, serverURL, reg, tok["refresh_token"].(string))
		require.Equal(t, http.StatusOK, r.StatusCode, "refresh %d", i)
		tok = decodeToken(t, r)
		require.Equal(t, authTime, jwtClaims(t, tok["access_token"].(string))["auth_time"])
	}
	time.Sleep(time.Until(sessionEnd) + 500*time.Millisecond)
	r := refresh(t, serverURL, reg, tok["refresh_token"].(string))
	require.Equal(t, http.StatusBadRequest, r.StatusCode)
}
