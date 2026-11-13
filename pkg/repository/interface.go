package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"
)

type Repository interface {
	fosite.Storage
	oauth2.CoreStorage
	oauth2.TokenRevocationStorage
	pkce.PKCERequestStorage
	DynamicClientStorage
	AuthorizeRequestStorage
	// PurgeExpired deletes expired authorization codes, PKCE sessions, access
	// and refresh tokens, and abandoned authorize requests. It returns the
	// number of deleted records.
	PurgeExpired(ctx context.Context, now time.Time) (int, error)
	Close() error
}

// AuthorizeRequestTTL is how long a pending (not yet approved or denied)
// authorize request is kept.
const AuthorizeRequestTTL = time.Hour

// sessionExpiry returns the expiry recorded in stored session data for the
// token type ("access_token", "refresh_token", "authorize_code"), or zero.
func sessionExpiry(sessionData json.RawMessage, tokenType fosite.TokenType) time.Time {
	if len(sessionData) == 0 {
		return time.Time{}
	}
	var s struct {
		ExpiresAt map[fosite.TokenType]time.Time `json:"expires_at"`
	}
	if json.Unmarshal(sessionData, &s) != nil {
		return time.Time{}
	}
	return s.ExpiresAt[tokenType]
}

type DynamicClientStorage interface {
	RegisterClient(ctx context.Context, client fosite.Client) error
	// SetClientName stores the client_name sent at dynamic registration. It is
	// display-only (shown on the consent page) and kept apart from the fosite
	// client so the stored client format does not change.
	SetClientName(ctx context.Context, clientID string, name string) error
	// GetClientName returns "" when no name was stored.
	GetClientName(ctx context.Context, clientID string) (string, error)
}

type AuthorizeRequestStorage interface {
	CreateAuthorizeRequest(ctx context.Context, request fosite.AuthorizeRequester) error
	GetAuthorizeRequest(ctx context.Context, requestID string) (fosite.AuthorizeRequester, error)
	DeleteAuthorizeRequest(ctx context.Context, requestID string) error
}

func restoreSession(req *fosite.Request, sessionData json.RawMessage, sess fosite.Session) error {
	if len(sessionData) > 0 && sess != nil {
		if err := json.Unmarshal(sessionData, sess); err != nil {
			return fmt.Errorf("failed to unmarshal session data: %w", err)
		}
		req.SetSession(sess)
	}
	return nil
}
