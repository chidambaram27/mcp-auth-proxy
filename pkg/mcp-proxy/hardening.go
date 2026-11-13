package mcpproxy

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/auth"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/idp"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/ratelimit"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/repository"
	"go.uber.org/zap"
)

const (
	// maxRequestBodyBytes caps every request body (MCP JSON-RPC requests are
	// small; responses are not limited).
	maxRequestBodyBytes = 10 << 20
	maxHeaderBytes      = 64 << 10
	readHeaderTimeout   = 10 * time.Second
	idleTimeout         = 120 * time.Second
	// sessionCookieMaxAge is the lifetime of the browser session cookie used
	// only during sign-in and consent (sliding; see auth.LoginSessionMaxAge
	// for the absolute cap).
	sessionCookieMaxAge = 600
	purgeInterval       = time.Hour
)

// newServer returns an http.Server with timeouts that protect against slow
// clients (Slowloris). ReadTimeout and WriteTimeout are not set because MCP
// responses may stream for a long time.
func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

// httpsRedirectHandler redirects to the external host rather than the
// client-supplied Host header.
func httpsRedirectHandler(externalURL *url.URL) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + externalURL.Host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

func securityHeadersMiddleware(https bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if https {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		c.Next()
	}
}

func bodyLimitMiddleware(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil && c.Request.Body != http.NoBody {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		}
		c.Next()
	}
}

// requestLogger logs requests without the query string, which carries
// authorization codes and state on the OAuth callbacks.
func requestLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		fields := []zap.Field{
			zap.Int("status", c.Writer.Status()),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("ip", c.ClientIP()),
			zap.String("user-agent", c.Request.UserAgent()),
			zap.Duration("latency", time.Since(start)),
		}
		if len(c.Errors) > 0 {
			logger.Error(c.Errors.String(), fields...)
			return
		}
		logger.Info(c.Request.URL.Path, fields...)
	}
}

// rateLimitMiddleware limits the unauthenticated endpoints per client IP.
// With the proxy behind a load balancer, set TRUSTED_PROXIES so the real
// client IP is used.
func rateLimitMiddleware() gin.HandlerFunc {
	register := ratelimit.New(10, 20)
	authorize := ratelimit.New(60, 60)
	token := ratelimit.New(120, 60)
	login := ratelimit.New(20, 20)
	return func(c *gin.Context) {
		var l *ratelimit.Limiter
		switch path := c.Request.URL.Path; {
		case path == idp.RegistrationEndpoint:
			l = register
		case path == idp.TokenEndpoint:
			l = token
		case path == idp.AuthorizationEndpoint:
			l = authorize
		case path == auth.LoginEndpoint && c.Request.Method == http.MethodPost:
			l = login
		case path == auth.GoogleCallbackEndpoint, path == auth.GitHubCallbackEndpoint, path == auth.OIDCCallbackEndpoint:
			l = login
		}
		if l == nil {
			c.Next()
			return
		}
		l.Middleware()(c)
	}
}

// runPurgeLoop deletes expired codes, tokens and abandoned authorize requests
// periodically until ctx is done.
func runPurgeLoop(ctx context.Context, repo repository.Repository, logger *zap.Logger) {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		n, err := repo.PurgeExpired(ctx, time.Now())
		switch {
		case err != nil && !errors.Is(err, context.Canceled):
			logger.Warn("Failed to purge expired records", zap.Error(err))
		case n > 0:
			logger.Info("Purged expired records", zap.Int("count", n))
		}
		timer.Reset(purgeInterval)
	}
}

// requireAllowlists refuses a login provider configured without any
// allowlist, which would let every account of that provider in.
func requireAllowlists(googleEnabled bool, googleUsers, googleWorkspaces []string,
	githubEnabled bool, githubUsers, githubOrgs []string,
	oidcEnabled bool, oidcUsers, oidcUsersGlob []string, oidcAttributes, oidcAttributesGlob map[string][]string,
) error {
	if googleEnabled && len(googleUsers) == 0 && len(googleWorkspaces) == 0 {
		return errors.New("google login requires GOOGLE_ALLOWED_WORKSPACES or GOOGLE_ALLOWED_USERS; without them any Google account could sign in")
	}
	if githubEnabled && len(githubUsers) == 0 && len(githubOrgs) == 0 {
		return errors.New("github login requires GITHUB_ALLOWED_ORGS or GITHUB_ALLOWED_USERS; without them any GitHub account could sign in")
	}
	if oidcEnabled && len(oidcUsers) == 0 && len(oidcUsersGlob) == 0 && len(oidcAttributes) == 0 && len(oidcAttributesGlob) == 0 {
		return errors.New("OIDC login requires OIDC_ALLOWED_USERS, OIDC_ALLOWED_USERS_GLOB, OIDC_ALLOWED_ATTRIBUTES or OIDC_ALLOWED_ATTRIBUTES_GLOB; without them any account of the provider could sign in")
	}
	return nil
}
