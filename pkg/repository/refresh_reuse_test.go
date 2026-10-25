package repository

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
)

func eachRepo(t *testing.T, fn func(t *testing.T, repo Repository)) {
	t.Helper()
	backends := map[string]func(t *testing.T) Repository{
		"kvs": func(t *testing.T) Repository {
			repo, err := NewKVSRepository(filepath.Join(t.TempDir(), "db"), "test")
			require.NoError(t, err)
			return repo
		},
		"sqlite": func(t *testing.T) Repository {
			repo, err := NewSQLRepository("sqlite", "file:"+filepath.Join(t.TempDir(), "db.sqlite")+"?_busy_timeout=5000")
			require.NoError(t, err)
			return repo
		},
	}
	for name, open := range backends {
		t.Run(name, func(t *testing.T) {
			repo := open(t)
			t.Cleanup(func() { repo.Close() })
			fn(t, repo)
		})
	}
}

func withGrace(t *testing.T, d time.Duration) {
	t.Helper()
	old := RefreshTokenGracePeriod
	RefreshTokenGracePeriod = d
	t.Cleanup(func() { RefreshTokenGracePeriod = old })
}

func tokenReq(requestID string) *fosite.Request {
	return &fosite.Request{
		ID:          requestID,
		RequestedAt: time.Now().UTC().Round(time.Second),
		Client:      &fosite.DefaultClient{ID: "client-1"},
		Session:     &fosite.DefaultSession{Subject: "alice"},
	}
}

func TestRefreshTokenRotationAndReuse(t *testing.T) {
	ctx := context.Background()
	eachRepo(t, func(t *testing.T, repo Repository) {
		withGrace(t, 0)
		require.NoError(t, repo.CreateRefreshTokenSession(ctx, "rt1", "at1", tokenReq("req-1")))

		got, err := repo.GetRefreshTokenSession(ctx, "rt1", &fosite.DefaultSession{})
		require.NoError(t, err)
		require.Equal(t, "req-1", got.GetID())

		require.NoError(t, repo.RotateRefreshToken(ctx, "req-1", "rt1"))

		got, err = repo.GetRefreshTokenSession(ctx, "rt1", &fosite.DefaultSession{})
		require.ErrorIs(t, err, fosite.ErrInactiveToken)
		require.NotNil(t, got, "reuse must return the request so fosite can revoke the family")
		require.Equal(t, "req-1", got.GetID())

		require.ErrorIs(t, repo.RotateRefreshToken(ctx, "req-1", "rt1"), fosite.ErrInactiveToken, "second rotation is refused")
		require.ErrorIs(t, repo.RotateRefreshToken(ctx, "req-1", "missing"), fosite.ErrNotFound)
	})
}

func TestRefreshTokenGracePeriod(t *testing.T) {
	ctx := context.Background()
	eachRepo(t, func(t *testing.T, repo Repository) {
		withGrace(t, time.Hour)
		require.NoError(t, repo.CreateRefreshTokenSession(ctx, "rt1", "at1", tokenReq("req-1")))
		require.NoError(t, repo.RotateRefreshToken(ctx, "req-1", "rt1"))

		_, err := repo.GetRefreshTokenSession(ctx, "rt1", &fosite.DefaultSession{})
		require.NoError(t, err, "still valid within the grace period")
		require.NoError(t, repo.RotateRefreshToken(ctx, "req-1", "rt1"), "retry within the grace period")

		RefreshTokenGracePeriod = 0
		_, err = repo.GetRefreshTokenSession(ctx, "rt1", &fosite.DefaultSession{})
		require.ErrorIs(t, err, fosite.ErrInactiveToken, "grace period counts from the first rotation")
	})
}

func TestConcurrentRotationOnlyOneWins(t *testing.T) {
	ctx := context.Background()
	eachRepo(t, func(t *testing.T, repo Repository) {
		withGrace(t, 0)
		require.NoError(t, repo.CreateRefreshTokenSession(ctx, "rt1", "at1", tokenReq("req-1")))

		const n = 8
		var wg sync.WaitGroup
		errs := make([]error, n)
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = repo.RotateRefreshToken(ctx, "req-1", "rt1")
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else {
				require.True(t, errors.Is(err, fosite.ErrInactiveToken), "unexpected error %v", err)
			}
		}
		require.Equal(t, 1, ok)
	})
}

func TestRevokeTokenFamilyByRequestID(t *testing.T) {
	ctx := context.Background()
	eachRepo(t, func(t *testing.T, repo Repository) {
		for _, sig := range []string{"at1", "at2"} {
			require.NoError(t, repo.CreateAccessTokenSession(ctx, sig, tokenReq("req-1")))
		}
		for _, sig := range []string{"rt1", "rt2"} {
			require.NoError(t, repo.CreateRefreshTokenSession(ctx, sig, "at", tokenReq("req-1")))
		}
		require.NoError(t, repo.CreateAccessTokenSession(ctx, "other-at", tokenReq("req-2")))
		require.NoError(t, repo.CreateRefreshTokenSession(ctx, "other-rt", "other-at", tokenReq("req-2")))

		require.NoError(t, repo.RevokeRefreshToken(ctx, "req-1"))
		require.NoError(t, repo.RevokeAccessToken(ctx, "req-1"))
		require.NoError(t, repo.RevokeRefreshToken(ctx, "unknown"))
		require.NoError(t, repo.RevokeAccessToken(ctx, ""))

		for _, sig := range []string{"rt1", "rt2"} {
			_, err := repo.GetRefreshTokenSession(ctx, sig, &fosite.DefaultSession{})
			require.ErrorIs(t, err, fosite.ErrNotFound, sig)
		}
		for _, sig := range []string{"at1", "at2"} {
			_, err := repo.GetAccessTokenSession(ctx, sig, &fosite.DefaultSession{})
			require.ErrorIs(t, err, fosite.ErrNotFound, sig)
		}
		_, err := repo.GetRefreshTokenSession(ctx, "other-rt", &fosite.DefaultSession{})
		require.NoError(t, err, "other grants are untouched")
		_, err = repo.GetAccessTokenSession(ctx, "other-at", &fosite.DefaultSession{})
		require.NoError(t, err)

		// Revoking again (e.g. second reuse) is a no-op.
		require.NoError(t, repo.RevokeRefreshToken(ctx, "req-1"))
	})
}
