package idp

import (
	"maps"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/ory/fosite"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/auth"
)

// sessionAuthTime returns the login time recorded in the proxy session, or
// now if none was recorded (e.g. a session created by an older version).
func sessionAuthTime(session sessions.Session, now time.Time) time.Time {
	var v int64
	switch t := session.Get(auth.SessionKeyAuthTime).(type) {
	case int64:
		v = t
	case int:
		v = int64(t)
	case float64:
		v = int64(t)
	}
	if v > 0 && v <= now.Unix() {
		return time.Unix(v, 0).UTC()
	}
	return now.UTC().Truncate(time.Second)
}

// applySessionPolicy runs for every token request after fosite has validated
// it and before tokens are issued:
//   - iat/nbf are set to the issue time (refreshes used to keep the login iat)
//     and the access token expires exactly accessTokenLifespan after iat,
//   - the auth_time claim carries the login time,
//   - with maxSessionAge > 0, requests are refused once the session is older
//     than maxSessionAge, and no token expires after the session ends.
func applySessionPolicy(req fosite.AccessRequester, now time.Time, accessTokenLifespan, maxSessionAge time.Duration) error {
	s, ok := req.GetSession().(*Session)
	if !ok || s.JWTClaims == nil {
		return nil
	}
	now = now.UTC().Truncate(time.Second)

	authTime := s.AuthTime
	if authTime.IsZero() {
		// Sessions issued before auth_time was tracked kept the login time in iat.
		authTime = s.JWTClaims.IssuedAt
		s.AuthTime = authTime
	}

	if accessTokenLifespan > 0 {
		s.SetExpiresAt(fosite.AccessToken, now.Add(accessTokenLifespan))
	}

	if maxSessionAge > 0 && !authTime.IsZero() {
		end := authTime.Add(maxSessionAge)
		if !now.Before(end) {
			return fosite.ErrInvalidGrant.
				WithHint("The session exceeded the maximum session age. The user must sign in again.").
				WithDebugf("auth_time=%s max_session_age=%s", authTime.Format(time.RFC3339), maxSessionAge)
		}
		for _, tt := range []fosite.TokenType{fosite.AccessToken, fosite.RefreshToken} {
			if exp := s.GetExpiresAt(tt); exp.IsZero() || exp.After(end) {
				s.SetExpiresAt(tt, end)
			}
		}
	}

	s.JWTClaims.IssuedAt = now
	s.JWTClaims.NotBefore = now
	if !authTime.IsZero() {
		extra := maps.Clone(s.JWTClaims.Extra)
		if extra == nil {
			extra = map[string]any{}
		}
		extra["auth_time"] = authTime.Unix()
		s.JWTClaims.Extra = extra
	}
	return nil
}
