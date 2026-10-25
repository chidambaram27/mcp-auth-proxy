package idp

import (
	"fmt"
	"time"
)

const (
	DefaultAccessTokenLifespan   = 24 * time.Hour
	DefaultRefreshTokenLifespan  = 30 * 24 * time.Hour
	DefaultAuthorizeCodeLifespan = 15 * time.Minute
)

// TokenLifespans configures how long tokens issued by the built-in
// authorization server stay valid.
type TokenLifespans struct {
	AccessToken   time.Duration
	RefreshToken  time.Duration
	AuthorizeCode time.Duration
	// MaxSessionAge caps the total session length counted from the user's
	// login; 0 disables the cap.
	MaxSessionAge time.Duration
	// RefreshTokenGracePeriod is how long an already used refresh token is
	// still accepted (0 = single use; reuse revokes the token family).
	RefreshTokenGracePeriod time.Duration
}

// DefaultTokenLifespans returns the upstream lifespans (24h access token,
// 30d refresh token, 15m authorization code).
func DefaultTokenLifespans() TokenLifespans {
	return TokenLifespans{
		AccessToken:   DefaultAccessTokenLifespan,
		RefreshToken:  DefaultRefreshTokenLifespan,
		AuthorizeCode: DefaultAuthorizeCodeLifespan,
	}
}

// ParseTokenLifespans parses Go duration strings (e.g. "1h", "720h", "90s").
// Token lifespans must be positive; maxSessionAge and the grace period may be 0.
func ParseTokenLifespans(accessToken, refreshToken, authorizeCode, maxSessionAge, refreshTokenGracePeriod string) (TokenLifespans, error) {
	var l TokenLifespans
	for _, f := range []struct {
		name  string
		value string
		dst   *time.Duration
	}{
		{"access token lifespan", accessToken, &l.AccessToken},
		{"refresh token lifespan", refreshToken, &l.RefreshToken},
		{"authorize code lifespan", authorizeCode, &l.AuthorizeCode},
		{"max session age", maxSessionAge, &l.MaxSessionAge},
		{"refresh token grace period", refreshTokenGracePeriod, &l.RefreshTokenGracePeriod},
	} {
		d, err := time.ParseDuration(f.value)
		if err != nil {
			return TokenLifespans{}, fmt.Errorf("invalid %s %q: %w", f.name, f.value, err)
		}
		*f.dst = d
	}
	return l, l.Validate()
}

func (l TokenLifespans) Validate() error {
	if l.AccessToken <= 0 {
		return fmt.Errorf("access token lifespan must be positive, got %s", l.AccessToken)
	}
	if l.RefreshToken <= 0 {
		return fmt.Errorf("refresh token lifespan must be positive, got %s", l.RefreshToken)
	}
	if l.AuthorizeCode <= 0 {
		return fmt.Errorf("authorize code lifespan must be positive, got %s", l.AuthorizeCode)
	}
	if l.RefreshTokenGracePeriod < 0 {
		return fmt.Errorf("refresh token grace period must not be negative, got %s", l.RefreshTokenGracePeriod)
	}
	if l.MaxSessionAge < 0 {
		return fmt.Errorf("max session age must not be negative, got %s", l.MaxSessionAge)
	}
	return nil
}
