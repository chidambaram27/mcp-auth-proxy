package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	time "time"

	"github.com/ory/fosite"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/models"
	"go.etcd.io/bbolt"
)

type kvsRepository struct {
	db         *bbolt.DB
	bucketName string
}

// RefreshTokenGracePeriod is how long a rotated (already used) refresh token
// is still accepted, e.g. for a client retrying a refresh whose response it
// lost. After it, using the token again counts as reuse: fosite rejects it and
// revokes the whole token family. 0 means a refresh token works exactly once.
var RefreshTokenGracePeriod time.Duration

// refreshTokenInactive reports whether a refresh token rotated at rotatedAt
// must be treated as reused.
func refreshTokenInactive(rotatedAt time.Time, now time.Time) bool {
	if rotatedAt.IsZero() {
		return false
	}
	// A concurrent request may have rotated the token after now was taken.
	return max(now.Sub(rotatedAt), 0) >= RefreshTokenGracePeriod
}

// requestTokens indexes the token signatures issued for one request ID (one
// authorization grant and all its refreshes), so the whole family can be
// revoked by request ID.
type requestTokens struct {
	Access  []string `json:"access,omitempty"`
	Refresh []string `json:"refresh,omitempty"`
}

const (
	accessTokenPrefix   = "access_token-"
	refreshTokenPrefix  = "refresh_token-"
	requestTokensPrefix = "request_tokens-"
)

func NewKVSRepository(path string, bucketName string) (Repository, error) {
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	}); err != nil {
		return nil, fmt.Errorf("failed to create bucket: %w", err)
	}
	return &kvsRepository{
		db:         db,
		bucketName: bucketName,
	}, nil
}

func (r *kvsRepository) create(ctx context.Context, key string, value any) error {
	return r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal value: %w", err)
		}
		return bucket.Put([]byte(key), data)
	})
}

func (r *kvsRepository) get(ctx context.Context, key string, value any) error {
	return r.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		data := bucket.Get([]byte(key))
		if data == nil {
			return fosite.ErrNotFound
		}
		return json.Unmarshal(data, value)
	})
}

func (r *kvsRepository) delete(ctx context.Context, key string) error {
	return r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		return bucket.Delete([]byte(key))
	})
}

func (r *kvsRepository) update(ctx context.Context, key string, value any) error {
	return r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		if bucket.Get([]byte(key)) == nil {
			return fosite.ErrNotFound
		}
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal value: %w", err)
		}
		return bucket.Put([]byte(key), data)
	})
}

func (r *kvsRepository) CreateAuthorizeCodeSession(ctx context.Context, code string, fositeReq fosite.Requester) error {
	return r.create(ctx, "authorize_code-"+code, models.FromFositeReq(fositeReq))
}

func (r *kvsRepository) GetAuthorizeCodeSession(ctx context.Context, code string, sess fosite.Session) (fosite.Requester, error) {
	var req models.Request
	if err := r.get(ctx, "authorize_code-"+code, &req); err != nil {
		return nil, err
	}
	fositeReq := req.ToFositeReq()
	if err := restoreSession(fositeReq, req.SessionData, sess); err != nil {
		return nil, err
	}
	return fositeReq, nil
}

func (r *kvsRepository) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return r.delete(ctx, "authorize_code-"+code)
}

// createIndexed stores a token record and adds its signature to the request's
// token index in the same transaction.
func (r *kvsRepository) createIndexed(prefix, signature string, fositeReq fosite.Requester) error {
	return r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		data, err := json.Marshal(models.FromFositeReq(fositeReq))
		if err != nil {
			return fmt.Errorf("failed to marshal value: %w", err)
		}
		if err := bucket.Put([]byte(prefix+signature), data); err != nil {
			return err
		}
		requestID := fositeReq.GetID()
		if requestID == "" {
			return nil
		}
		var idx requestTokens
		if raw := bucket.Get([]byte(requestTokensPrefix + requestID)); raw != nil {
			if err := json.Unmarshal(raw, &idx); err != nil {
				return fmt.Errorf("failed to unmarshal token index: %w", err)
			}
		}
		if prefix == accessTokenPrefix {
			idx.Access = append(idx.Access, signature)
		} else {
			idx.Refresh = append(idx.Refresh, signature)
		}
		raw, err := json.Marshal(idx)
		if err != nil {
			return fmt.Errorf("failed to marshal token index: %w", err)
		}
		return bucket.Put([]byte(requestTokensPrefix+requestID), raw)
	})
}

// revokeFamily deletes all tokens of the given kind issued for requestID.
// Tokens stored before the index existed are not found.
func (r *kvsRepository) revokeFamily(prefix, requestID string) error {
	if requestID == "" {
		return nil
	}
	return r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		key := []byte(requestTokensPrefix + requestID)
		raw := bucket.Get(key)
		if raw == nil {
			return nil
		}
		var idx requestTokens
		if err := json.Unmarshal(raw, &idx); err != nil {
			return fmt.Errorf("failed to unmarshal token index: %w", err)
		}
		sigs := &idx.Refresh
		if prefix == accessTokenPrefix {
			sigs = &idx.Access
		}
		for _, sig := range *sigs {
			if err := bucket.Delete([]byte(prefix + sig)); err != nil {
				return err
			}
		}
		*sigs = nil
		if len(idx.Access) == 0 && len(idx.Refresh) == 0 {
			return bucket.Delete(key)
		}
		raw, err := json.Marshal(idx)
		if err != nil {
			return fmt.Errorf("failed to marshal token index: %w", err)
		}
		return bucket.Put(key, raw)
	})
}

func (r *kvsRepository) CreateAccessTokenSession(ctx context.Context, signature string, fositeReq fosite.Requester) error {
	return r.createIndexed(accessTokenPrefix, signature, fositeReq)
}

func (r *kvsRepository) GetAccessTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	var req models.Request
	if err := r.get(ctx, "access_token-"+signature, &req); err != nil {
		return nil, err
	}
	fositeReq := req.ToFositeReq()
	if err := restoreSession(fositeReq, req.SessionData, sess); err != nil {
		return nil, err
	}
	return fositeReq, nil
}

func (r *kvsRepository) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return r.delete(ctx, "access_token-"+signature)
}

func (r *kvsRepository) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, req fosite.Requester) (err error) {
	return r.createIndexed(refreshTokenPrefix, signature, req)
}

// GetRefreshTokenSession returns fosite.ErrInactiveToken together with the
// request for a token that was already rotated (outside the grace period), so
// fosite detects the reuse and revokes the token family.
func (r *kvsRepository) GetRefreshTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	var req models.Request
	if err := r.get(ctx, refreshTokenPrefix+signature, &req); err != nil {
		return nil, err
	}
	fositeReq := req.ToFositeReq()
	if err := restoreSession(fositeReq, req.SessionData, sess); err != nil {
		return nil, err
	}
	if refreshTokenInactive(req.RotatedAt, time.Now()) {
		return fositeReq, fosite.ErrInactiveToken
	}
	return fositeReq, nil
}

func (r *kvsRepository) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return r.delete(ctx, "refresh_token-"+signature)
}

// RotateRefreshToken marks the token as used. It keeps the first rotation time
// (so retries can't extend the grace period) and fails with
// fosite.ErrInactiveToken if a concurrent request already rotated it outside
// the grace period, so one refresh token can't be redeemed twice.
func (r *kvsRepository) RotateRefreshToken(ctx context.Context, requestID string, signature string) error {
	return r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		key := []byte(refreshTokenPrefix + signature)
		raw := bucket.Get(key)
		if raw == nil {
			return fosite.ErrNotFound
		}
		var req models.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("failed to unmarshal refresh token: %w", err)
		}
		now := time.Now()
		if refreshTokenInactive(req.RotatedAt, now) {
			return fosite.ErrInactiveToken
		}
		if !req.RotatedAt.IsZero() {
			return nil
		}
		req.RotatedAt = now
		data, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("failed to marshal value: %w", err)
		}
		return bucket.Put(key, data)
	})
}

// RevokeRefreshToken revokes a refresh token as specified in:
// https://tools.ietf.org/html/rfc7009#section-2.1
// If the particular
// token is a refresh token and the authorization server supports the
// revocation of access tokens, then the authorization server SHOULD
// also invalidate all access tokens based on the same authorization
// grant (see Implementation Note).
func (r *kvsRepository) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return r.revokeFamily(refreshTokenPrefix, requestID)
}

// RevokeAccessToken revokes an access token as specified in:
// https://tools.ietf.org/html/rfc7009#section-2.1
// If the token passed to the request
// is an access token, the server MAY revoke the respective refresh
// token as well.
func (r *kvsRepository) RevokeAccessToken(ctx context.Context, requestID string) error {
	return r.revokeFamily(accessTokenPrefix, requestID)
}

func (r *kvsRepository) RegisterClient(ctx context.Context, fositeClient fosite.Client) error {
	return r.create(ctx, "client-"+fositeClient.GetID(), models.FromFositeClient(fositeClient))
}

// GetClient loads the client by its ID or returns an error
// if the client does not exist or another error occurred.
func (r *kvsRepository) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var client models.Client
	if err := r.get(ctx, "client-"+id, &client); err != nil {
		return nil, err
	}
	return client.ToFositeClient(), nil
}

func (r *kvsRepository) SetClientName(ctx context.Context, clientID string, name string) error {
	return r.create(ctx, "client_name-"+clientID, name)
}

func (r *kvsRepository) GetClientName(ctx context.Context, clientID string) (string, error) {
	var name string
	if err := r.get(ctx, "client_name-"+clientID, &name); err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			return "", nil
		}
		return "", err
	}
	return name, nil
}

// ClientAssertionJWTValid returns an error if the JTI is
// known or the DB check failed and nil if the JTI is not known.
func (r *kvsRepository) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return errors.New("not implemented")
}

// SetClientAssertionJWT marks a JTI as known for the given
// expiry time. Before inserting the new JTI, it will clean
// up any existing JTIs that have expired as those tokens can
// not be replayed due to the expiry.
func (r *kvsRepository) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return errors.New("not implemented")
}

func (r *kvsRepository) CreatePKCERequestSession(ctx context.Context, signature string, req fosite.Requester) error {
	return r.create(ctx, "pkce_request-"+signature, models.FromFositeReq(req))
}

func (r *kvsRepository) GetPKCERequestSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	var req models.Request
	if err := r.get(ctx, "pkce_request-"+signature, &req); err != nil {
		return nil, err
	}
	fositeReq := req.ToFositeReq()
	if err := restoreSession(fositeReq, req.SessionData, sess); err != nil {
		return nil, err
	}
	return fositeReq, nil
}

func (r *kvsRepository) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return r.delete(ctx, "pkce_request-"+signature)
}

func (r *kvsRepository) CreateAuthorizeRequest(ctx context.Context, fositeAR fosite.AuthorizeRequester) error {
	return r.create(ctx, "authorize_request-"+fositeAR.GetID(), models.FromFositeAuthorizeRequest(fositeAR))
}

func (r *kvsRepository) GetAuthorizeRequest(ctx context.Context, requestID string) (fosite.AuthorizeRequester, error) {
	var ar models.AuthorizeRequest
	if err := r.get(ctx, "authorize_request-"+requestID, &ar); err != nil {
		return nil, err
	}
	return ar.ToFositeAuthorizeRequest(), nil
}

func (r *kvsRepository) DeleteAuthorizeRequest(ctx context.Context, requestID string) error {
	return r.delete(ctx, "authorize_request-"+requestID)
}

func (r *kvsRepository) Close() error {
	return r.db.Close()
}
