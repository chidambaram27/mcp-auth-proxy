package idp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"go.uber.org/zap"
)

// ensureCSRFToken returns the session's consent CSRF token, creating it if
// needed. The caller must save the session.
func ensureCSRFToken(session sessions.Session) (string, error) {
	if t, ok := session.Get(sessionKeyCSRFToken).(string); ok && len(t) >= 32 {
		return t, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	t := hex.EncodeToString(b)
	session.Set(sessionKeyCSRFToken, t)
	if err := session.Save(); err != nil {
		return "", err
	}
	return t, nil
}

// validConsentSubmission checks that the consent form was posted by the
// consent page itself. SameSite=Lax cookies are still sent by sibling
// subdomains (same site), so the session binding alone does not stop a
// compromised *.example.com page from approving a grant for the user.
func (a *IDPRouter) validConsentSubmission(c *gin.Context, session sessions.Session) bool {
	if site := c.GetHeader("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	if origin := c.GetHeader("Origin"); origin != "" && origin != "null" && !sameOrigin(origin, a.externalURL) {
		return false
	}
	want, ok := session.Get(sessionKeyCSRFToken).(string)
	got := c.PostForm(csrfFormField)
	return ok && want != "" && subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

func sameOrigin(origin, externalURL string) bool {
	o, err := url.Parse(origin)
	if err != nil {
		return false
	}
	e, err := url.Parse(externalURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(o.Scheme, e.Scheme) && strings.EqualFold(o.Host, e.Host)
}

var (
	allowedGrantTypes    = []string{"authorization_code", "refresh_token"}
	allowedResponseTypes = []string{"code"}
	allowedAuthMethods   = []string{"", "none", "client_secret_basic", "client_secret_post"}
)

// validateRegistration validates (and normalises) a dynamic client
// registration request. It returns an RFC 7591 error code and description, or
// "" if the request is acceptable.
func (a *IDPRouter) validateRegistration(req *registrationRequest) (string, string) {
	if len(req.RedirectURIs) == 0 {
		return "invalid_redirect_uri", "at least one redirect_uri is required"
	}
	if len(req.RedirectURIs) > maxRedirectURIs {
		return "invalid_redirect_uri", fmt.Sprintf("at most %d redirect_uris are allowed", maxRedirectURIs)
	}
	for _, u := range req.RedirectURIs {
		if err := a.redirectPolicy.Check(u); err != nil {
			return "invalid_redirect_uri", err.Error()
		}
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = slices.Clone(allowedGrantTypes)
	}
	for _, g := range req.GrantTypes {
		if !slices.Contains(allowedGrantTypes, g) {
			return "invalid_client_metadata", fmt.Sprintf("unsupported grant_type %q", g)
		}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = slices.Clone(allowedResponseTypes)
	}
	for _, r := range req.ResponseTypes {
		if !slices.Contains(allowedResponseTypes, r) {
			return "invalid_client_metadata", fmt.Sprintf("unsupported response_type %q", r)
		}
	}
	if !slices.Contains(allowedAuthMethods, req.TokenEndpointAuthMethod) {
		return "invalid_client_metadata", fmt.Sprintf("unsupported token_endpoint_auth_method %q", req.TokenEndpointAuthMethod)
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}
	if len(req.Scope) > maxScopeLength {
		return "invalid_client_metadata", "scope is too long"
	}
	return "", ""
}

// upstreamVerifyTimeout bounds the calls to the upstream identity provider
// made while answering a token refresh.
const upstreamVerifyTimeout = 15 * time.Second

// verifyUpstream re-verifies the user with the upstream identity provider on
// refresh (at most once per UpstreamRecheckInterval), so that users deleted,
// suspended or removed from the workspace upstream lose access at their next
// refresh. Transient upstream failures return a 503 without consuming the
// refresh token, so clients can retry.
func (a *IDPRouter) verifyUpstream(ctx context.Context, req fosite.AccessRequester, now time.Time) error {
	if !req.GetGrantTypes().ExactOne("refresh_token") || a.authRouter == nil {
		// Authorization codes are only issued right after an upstream login.
		return nil
	}
	s, ok := req.GetSession().(*Session)
	if !ok {
		return nil
	}
	verifier, ok := a.authRouter.UpstreamVerifier(s.Provider)
	if !ok {
		return nil
	}
	subject := s.GetSubject()
	if s.UpstreamToken == "" {
		a.logger.Info("Token refresh refused: session has no upstream grant", zap.String("subject", subject))
		return fosite.ErrInvalidGrant.WithHint("The session must be re-established. The user must sign in again.")
	}
	if !s.UpstreamCheckedAt.IsZero() && now.Sub(s.UpstreamCheckedAt) < a.lifespans.UpstreamRecheckInterval {
		return nil
	}
	refreshToken, err := a.upstreamSealer.Open(s.UpstreamToken, subject)
	if err != nil {
		a.logger.Warn("Token refresh refused: cannot decrypt upstream grant", zap.String("subject", subject), zap.Error(err))
		return fosite.ErrInvalidGrant.WithHint("The session must be re-established. The user must sign in again.")
	}
	verifyCtx, cancel := context.WithTimeout(ctx, upstreamVerifyTimeout)
	defer cancel()
	res, err := verifier.VerifyUpstream(verifyCtx, subject, refreshToken)
	if err != nil {
		a.logger.Warn("Upstream verification unavailable", zap.String("subject", subject), zap.Error(err))
		return fosite.ErrTemporarilyUnavailable.WithHint("The identity provider could not be reached. Try again later.")
	}
	if !res.Allowed {
		a.logger.Info("Token refresh refused by upstream identity provider", zap.String("subject", subject), zap.String("reason", res.Reason))
		return fosite.ErrInvalidGrant.WithHint("The user is no longer authorized. The user must sign in again.")
	}
	s.UpstreamCheckedAt = now.UTC()
	if res.RefreshToken != "" {
		sealed, err := a.upstreamSealer.Seal(res.RefreshToken, subject)
		if err != nil {
			return fosite.ErrServerError.WithWrap(err)
		}
		s.UpstreamToken = sealed
	}
	return nil
}

// revokeGrant deletes every access and refresh token issued for the grant, so
// a refused user cannot retry with sibling tokens.
func (a *IDPRouter) revokeGrant(ctx context.Context, req fosite.AccessRequester) {
	id := req.GetID()
	if id == "" {
		return
	}
	if err := a.repo.RevokeRefreshToken(ctx, id); err != nil {
		a.logger.Warn("Failed to revoke refresh tokens", zap.Error(err))
	}
	if err := a.repo.RevokeAccessToken(ctx, id); err != nil {
		a.logger.Warn("Failed to revoke access tokens", zap.Error(err))
	}
}
