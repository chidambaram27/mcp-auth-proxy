package auth

import "context"

// UpstreamResult is the outcome of an upstream re-verification.
type UpstreamResult struct {
	// Allowed is false when the upstream identity provider says the user no
	// longer exists, is suspended, revoked the grant, or no longer matches the
	// allowlist.
	Allowed bool
	// Reason explains a refusal (for logs).
	Reason string
	// RefreshToken is set when the upstream provider rotated its refresh token.
	RefreshToken string
}

// UpstreamVerifier is implemented by providers that issue a refresh token at
// login and can use it later to re-check the user with the upstream identity
// provider, so that users removed there lose access at their next token
// refresh instead of when the proxy's refresh token expires.
type UpstreamVerifier interface {
	// VerifyUpstream returns an error only for transient failures (network,
	// upstream outage); a definitive refusal is reported as Allowed=false.
	VerifyUpstream(ctx context.Context, userID, refreshToken string) (UpstreamResult, error)
}

// UpstreamVerifier returns the verifier for the provider type, if the
// provider supports upstream re-verification.
func (a *AuthRouter) UpstreamVerifier(providerType string) (UpstreamVerifier, bool) {
	for _, p := range a.providers {
		if p.Type() != providerType {
			continue
		}
		v, ok := p.(UpstreamVerifier)
		return v, ok
	}
	return nil, false
}
