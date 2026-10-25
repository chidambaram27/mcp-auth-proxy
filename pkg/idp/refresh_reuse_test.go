package idp

import (
	"net/http"
	"testing"
	"time"

	"github.com/sigbit/mcp-auth-proxy/v2/pkg/repository"
	"github.com/stretchr/testify/require"
)

func TestRefreshTokenReuseRevokesFamily(t *testing.T) {
	old := repository.RefreshTokenGracePeriod
	repository.RefreshTokenGracePeriod = 0
	t.Cleanup(func() { repository.RefreshTokenGracePeriod = old })

	serverURL, reg, resp := lifespanTestTokens(t, DefaultTokenLifespans(), 0)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	rt1 := decodeToken(t, resp)["refresh_token"].(string)

	r := refresh(t, serverURL, reg, rt1)
	require.Equal(t, http.StatusOK, r.StatusCode)
	rt2 := decodeToken(t, r)["refresh_token"].(string)

	// Reusing RT1 (e.g. stolen and replayed) is refused ...
	r = refresh(t, serverURL, reg, rt1)
	require.Equal(t, http.StatusBadRequest, r.StatusCode)
	body := decodeToken(t, r)
	require.Equal(t, "invalid_grant", body["error"])
	require.Contains(t, body["error_description"], "already used")

	// ... and revokes the whole family: the legitimate RT2 no longer works.
	r = refresh(t, serverURL, reg, rt2)
	require.Equal(t, http.StatusBadRequest, r.StatusCode)
	require.Equal(t, "invalid_grant", decodeToken(t, r)["error"])
}

func TestRefreshTokenGracePeriodAllowsRetry(t *testing.T) {
	old := repository.RefreshTokenGracePeriod
	repository.RefreshTokenGracePeriod = time.Minute
	t.Cleanup(func() { repository.RefreshTokenGracePeriod = old })

	serverURL, reg, resp := lifespanTestTokens(t, DefaultTokenLifespans(), 0)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	rt1 := decodeToken(t, resp)["refresh_token"].(string)

	r := refresh(t, serverURL, reg, rt1)
	require.Equal(t, http.StatusOK, r.StatusCode)
	rt2 := decodeToken(t, r)["refresh_token"].(string)

	// A client that lost the response may retry with RT1 inside the grace period.
	r = refresh(t, serverURL, reg, rt1)
	require.Equal(t, http.StatusOK, r.StatusCode)
	rt2b := decodeToken(t, r)["refresh_token"].(string)

	for _, rt := range []string{rt2, rt2b} {
		r = refresh(t, serverURL, reg, rt)
		require.Equal(t, http.StatusOK, r.StatusCode)
	}
}
