package repository

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
)

func expiringReq(id string, tokenType fosite.TokenType, exp time.Time) *fosite.Request {
	r := tokenReq(id)
	s := &fosite.DefaultSession{Subject: "alice"}
	s.SetExpiresAt(tokenType, exp)
	r.Session = s
	return r
}

func TestPurgeExpired(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	past, future := now.Add(-time.Minute), now.Add(time.Hour)
	eachRepo(t, func(t *testing.T, repo Repository) {
		require.NoError(t, repo.CreateAuthorizeCodeSession(ctx, "code-old", expiringReq("r1", fosite.AuthorizeCode, past)))
		require.NoError(t, repo.CreateAuthorizeCodeSession(ctx, "code-new", expiringReq("r2", fosite.AuthorizeCode, future)))
		require.NoError(t, repo.CreatePKCERequestSession(ctx, "pkce-old", expiringReq("r1", fosite.AuthorizeCode, past)))
		require.NoError(t, repo.CreateAccessTokenSession(ctx, "at-old", expiringReq("r3", fosite.AccessToken, past)))
		require.NoError(t, repo.CreateAccessTokenSession(ctx, "at-new", expiringReq("r4", fosite.AccessToken, future)))
		require.NoError(t, repo.CreateRefreshTokenSession(ctx, "rt-old", "at-old", expiringReq("r3", fosite.RefreshToken, past)))
		require.NoError(t, repo.CreateRefreshTokenSession(ctx, "rt-new", "at-new", expiringReq("r4", fosite.RefreshToken, future)))

		ar := &fosite.AuthorizeRequest{RedirectURI: &url.URL{Scheme: "http", Host: "localhost"}, Request: *tokenReq("ar-new")}
		require.NoError(t, repo.CreateAuthorizeRequest(ctx, ar))

		// Abandoned authorize requests expire after AuthorizeRequestTTL.
		n, err := repo.PurgeExpired(ctx, now)
		require.NoError(t, err)
		require.Equal(t, 4, n)

		_, err = repo.GetAuthorizeCodeSession(ctx, "code-old", &fosite.DefaultSession{})
		require.ErrorIs(t, err, fosite.ErrNotFound)
		_, err = repo.GetPKCERequestSession(ctx, "pkce-old", &fosite.DefaultSession{})
		require.ErrorIs(t, err, fosite.ErrNotFound)
		_, err = repo.GetAccessTokenSession(ctx, "at-old", &fosite.DefaultSession{})
		require.ErrorIs(t, err, fosite.ErrNotFound)
		_, err = repo.GetRefreshTokenSession(ctx, "rt-old", &fosite.DefaultSession{})
		require.ErrorIs(t, err, fosite.ErrNotFound)

		_, err = repo.GetAuthorizeCodeSession(ctx, "code-new", &fosite.DefaultSession{})
		require.NoError(t, err)
		_, err = repo.GetAccessTokenSession(ctx, "at-new", &fosite.DefaultSession{})
		require.NoError(t, err)
		_, err = repo.GetRefreshTokenSession(ctx, "rt-new", &fosite.DefaultSession{})
		require.NoError(t, err)
		_, err = repo.GetAuthorizeRequest(ctx, "ar-new")
		require.NoError(t, err)

		// The token family index still revokes the live tokens.
		require.NoError(t, repo.RevokeRefreshToken(ctx, "r4"))
		_, err = repo.GetRefreshTokenSession(ctx, "rt-new", &fosite.DefaultSession{})
		require.ErrorIs(t, err, fosite.ErrNotFound)
	})
}

func TestPurgeExpiredAuthorizeRequests(t *testing.T) {
	ctx := context.Background()
	eachRepo(t, func(t *testing.T, repo Repository) {
		ar := &fosite.AuthorizeRequest{RedirectURI: &url.URL{Scheme: "http", Host: "localhost"}, Request: *tokenReq("ar-1")}
		require.NoError(t, repo.CreateAuthorizeRequest(ctx, ar))
		n, err := repo.PurgeExpired(ctx, time.Now().Add(AuthorizeRequestTTL+time.Minute))
		require.NoError(t, err)
		require.Equal(t, 1, n)
		_, err = repo.GetAuthorizeRequest(ctx, "ar-1")
		require.Error(t, err)
	})
}

func TestAuthorizeCodeCanOnlyBeInvalidatedOnce(t *testing.T) {
	ctx := context.Background()
	eachRepo(t, func(t *testing.T, repo Repository) {
		require.NoError(t, repo.CreateAuthorizeCodeSession(ctx, "code", tokenReq("r1")))
		require.NoError(t, repo.InvalidateAuthorizeCodeSession(ctx, "code"))
		require.ErrorIs(t, repo.InvalidateAuthorizeCodeSession(ctx, "code"), fosite.ErrNotFound,
			"a concurrent second redemption must fail")
	})
}

func TestPurgeExpiredAcrossBatches(t *testing.T) {
	old := purgeBatchSize
	purgeBatchSize = 2
	t.Cleanup(func() { purgeBatchSize = old })
	ctx := context.Background()
	past := time.Now().Add(-time.Minute)
	eachRepo(t, func(t *testing.T, repo Repository) {
		for i := 0; i < 7; i++ {
			sig := "at-" + string(rune('a'+i))
			require.NoError(t, repo.CreateAccessTokenSession(ctx, sig, expiringReq("r", fosite.AccessToken, past)))
		}
		n, err := repo.PurgeExpired(ctx, time.Now())
		require.NoError(t, err)
		require.Equal(t, 7, n)
	})
}
