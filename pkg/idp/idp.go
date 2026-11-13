package idp

import (
	"context"
	"crypto/rsa"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/token/jwt"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/auth"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/repository"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*
var templateFS embed.FS

type IDPRouter struct {
	repo              repository.Repository
	privKey           *rsa.PrivateKey
	logger            *zap.Logger
	externalURL       string
	hasher            fosite.Hasher
	provider          fosite.OAuth2Provider
	signer            *jwt.DefaultSigner
	authRouter        *auth.AuthRouter
	authorizeTemplate *template.Template
	branding          Branding
	lifespans         TokenLifespans
	redirectPolicy    RedirectPolicy
	upstreamSealer    *utils.Sealer
}

// SetRedirectPolicy sets the redirect URIs allowed for registered clients.
func (a *IDPRouter) SetRedirectPolicy(p RedirectPolicy) {
	a.redirectPolicy = p
}

func NewIDPRouter(
	repo repository.Repository,
	privKey *rsa.PrivateKey,
	logger *zap.Logger,
	externalURL string,
	secret []byte,
	authRouter *auth.AuthRouter,
	branding Branding,
	lifespans TokenLifespans,
) (*IDPRouter, error) {
	if err := lifespans.Validate(); err != nil {
		return nil, err
	}
	upstreamKey, err := utils.DeriveKey(secret, utils.KeyPurposeUpstreamTokens)
	if err != nil {
		return nil, err
	}
	upstreamSealer, err := utils.NewSealer(upstreamKey)
	if err != nil {
		return nil, err
	}
	hasher := &fosite.BCrypt{
		Config: &fosite.Config{
			HashCost: bcrypt.DefaultCost,
		},
	}
	config := &fosite.Config{
		GlobalSecret:          secret,
		AccessTokenLifespan:   lifespans.AccessToken,
		RefreshTokenLifespan:  lifespans.RefreshToken,
		AuthorizeCodeLifespan: lifespans.AuthorizeCode,
		RefreshTokenScopes:    []string{},
		AccessTokenIssuer:     externalURL,
		// OAuth 2.1 / MCP authorization: PKCE (S256) for every client.
		EnforcePKCE:                    true,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
		ScopeStrategy:                  fosite.HierarchicScopeStrategy,
		MinParameterEntropy:            fosite.MinParameterEntropy,
		ClientSecretsHasher:            hasher,
	}
	provider, signer := customCompose(config, repo, privKey)

	authorizeTemplate, err := template.ParseFS(templateFS, "templates/authorize.html")
	if err != nil {
		return nil, err
	}

	return &IDPRouter{
		repo:              repo,
		privKey:           privKey,
		logger:            logger,
		externalURL:       externalURL,
		hasher:            hasher,
		provider:          provider,
		signer:            signer,
		authRouter:        authRouter,
		authorizeTemplate: authorizeTemplate,
		branding:          branding,
		lifespans:         lifespans,
		upstreamSealer:    upstreamSealer,
	}, nil
}

func customCompose(config *fosite.Config, storage any, key any) (fosite.OAuth2Provider, *jwt.DefaultSigner) {
	keyGetter := func(context.Context) (any, error) { return key, nil }
	signer := &jwt.DefaultSigner{GetPrivateKey: keyGetter}

	provider := compose.Compose(
		config,
		storage,
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2JWTStrategy(keyGetter, compose.NewOAuth2HMACStrategy(config), config),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, config),
			Signer:                     signer,
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2PKCEFactory,
	)
	return provider, signer
}

const (
	AuthorizationEndpoint            = "/.idp/auth"
	AuthorizationReturnEndpoint      = "/.idp/auth/:ar_id"
	TokenEndpoint                    = "/.idp/token"
	RegistrationEndpoint             = "/.idp/register"
	OauthAuthorizationServerEndpoint = "/.well-known/oauth-authorization-server"
	JWKSEndpoint                     = "/.well-known/jwks.json"
	sessionKeyAuthorizeRequestIDs    = "idp_authorize_request_ids"
	sessionKeyCSRFToken              = "idp_csrf_token"
	csrfFormField                    = "csrf_token"
	maxClientNameLength              = 100
	maxRegistrationBodyBytes         = 64 << 10
	maxRedirectURIs                  = 10
	maxScopeLength                   = 1000
)

func (a *IDPRouter) SetupRoutes(router gin.IRouter) {
	router.GET(AuthorizationEndpoint, a.handleAuth)
	router.GET(AuthorizationReturnEndpoint, a.authRouter.RequireAuth(), a.handleAuthorizationReturnForm)
	router.POST(AuthorizationReturnEndpoint, a.authRouter.RequireAuth(), a.handleAuthorizationReturn)
	router.POST(TokenEndpoint, a.handleToken)
	router.POST(RegistrationEndpoint, a.handleRegister)
	router.GET(OauthAuthorizationServerEndpoint, a.handleOauthAuthorizationServer)
	router.GET(JWKSEndpoint, a.handleJWKS)
}

func (a *IDPRouter) handleAuth(c *gin.Context) {
	ctx := c.Request.Context()

	// RFC 6749 makes state RECOMMENDED, not REQUIRED, but fosite enforces
	// minimum entropy (8 chars). Generate a server-side state for clients
	// that omit it (e.g., MCP Inspector, Cursor CLI) so they can complete
	// the OAuth flow. The generated state is echoed back in the redirect;
	// clients that didn't send state will simply ignore it.
	if c.Request.URL.Query().Get("state") == "" {
		state, err := utils.GenerateState()
		if err != nil {
			a.provider.WriteAuthorizeError(ctx, c.Writer, nil, fosite.ErrServerError.WithWrap(err))
			return
		}
		q := c.Request.URL.Query()
		q.Set("state", state)
		c.Request.URL.RawQuery = q.Encode()
	}

	ar, err := a.provider.NewAuthorizeRequest(ctx, c.Request)
	if err != nil {
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}
	// Clients registered before the redirect policy existed may hold any
	// redirect URI. Refuse without redirecting to it.
	if redirectURI := ar.GetRedirectURI(); redirectURI == nil || a.redirectPolicy.Check(redirectURI.String()) != nil {
		a.logger.Warn("Authorization refused: redirect URI not allowed", zap.String("client_id", ar.GetClient().GetID()))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "The redirect URI is not allowed by this server."})
		return
	}
	// fosite only enforces PKCE after the consent step; refuse up front so the
	// user is not asked to approve a request that cannot succeed.
	if ar.GetRequestForm().Get("code_challenge") == "" {
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrInvalidRequest.WithHint("Clients must use PKCE (code_challenge with code_challenge_method=S256)."))
		return
	}

	if err := a.repo.CreateAuthorizeRequest(ctx, ar); err != nil {
		a.logger.Error("Failed to create authorize requester", zap.Error(err))
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrServerError.WithWrap(err))
		return
	}
	session := sessions.Default(c)
	addAuthorizeRequestID(session, ar.GetID())
	if err := session.Save(); err != nil {
		a.logger.Error("Failed to save authorize request in session", zap.Error(err))
		_ = a.repo.DeleteAuthorizeRequest(ctx, ar.GetID())
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrServerError.WithWrap(err))
		return
	}
	c.Redirect(302, strings.ReplaceAll(AuthorizationReturnEndpoint, ":ar_id", ar.GetID()))
}

func (a *IDPRouter) handleAuthorizationReturnForm(c *gin.Context) {
	ctx := c.Request.Context()
	arID := c.Param("ar_id")
	session := sessions.Default(c)
	if !hasAuthorizeRequestID(session, arID) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid authorization session"})
		return
	}

	ar, err := a.repo.GetAuthorizeRequest(ctx, arID)
	if err != nil {
		a.logger.Error("Failed to get authorize requester", zap.Error(err))
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal Server Error"})
		return
	}

	clientName, err := a.repo.GetClientName(ctx, ar.GetClient().GetID())
	if err != nil {
		// Display-only; render the page without it.
		a.logger.Warn("Failed to get client name", zap.Error(err))
	}

	data := authorizePageData{
		ClientName:     clientName,
		ServerHost:     hostOf(a.externalURL),
		ServerName:     a.branding.ServerName,
		User:           sessionUser(session),
		Scopes:         ar.GetRequestedScopes(),
		LogoSrc:        a.branding.logoURL(),
		HideIcon:       a.branding.logoDisabled,
		Banner:         a.branding.effectiveBanner(),
		BannerDisabled: a.branding.bannerDisabled(),
		Footer:         a.branding.effectiveFooter(),
		FooterDisabled: a.branding.footerDisabled(),
	}
	csrfToken, err := ensureCSRFToken(session)
	if err != nil {
		a.logger.Error("Failed to create CSRF token", zap.Error(err))
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal Server Error"})
		return
	}
	data.CSRFToken = csrfToken
	formActionSource := ""
	if redirectURI := ar.GetRedirectURI(); redirectURI != nil {
		data.RedirectHost, data.RedirectKind = describeRedirect(redirectURI)
		formActionSource = redirectCSPSource(redirectURI)
	}

	c.Header("Cache-Control", "no-store")
	c.Header("X-Frame-Options", "DENY")
	c.Header("Content-Security-Policy", a.branding.contentSecurityPolicy(formActionSource))
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	if err := a.authorizeTemplate.Execute(c.Writer, data); err != nil {
		a.logger.Error("Failed to render authorize page", zap.Error(err))
	}
}

type authorizePageData struct {
	CSRFToken    string
	ClientName   string
	ServerHost   string
	ServerName   string
	User         string
	RedirectHost string
	// RedirectKind is "local" (loopback http), "app" (custom scheme, handled
	// by an installed application) or "remote" (any other http(s) host).
	RedirectKind string
	Scopes       []string
	// LogoSrc is a safe <img src> value (data URI or http(s) URL) resolved
	// at startup from trusted operator config; empty means no logo image.
	LogoSrc template.URL
	// HideIcon suppresses the built-in fallback icon (set when the operator
	// disabled the logo with "-").
	HideIcon bool
	// Banner and Footer are operator-supplied HTML, trusted and rendered
	// unescaped (same contract as oauth2-proxy's --banner/--footer).
	Banner         template.HTML
	BannerDisabled bool
	Footer         template.HTML
	FooterDisabled bool
}

// ServerLabel is the friendly server name when set, otherwise the host.
func (d authorizePageData) ServerLabel() string {
	if d.ServerName != "" {
		return d.ServerName
	}
	return d.ServerHost
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Host
}

// sanitizeClientName drops control and format characters (Unicode Cc/Cf,
// e.g. bidi overrides like U+202E that make "opencode\u202e lmth.exe" render
// as "opencodeexe.html") from the display-only DCR client_name, collapses
// whitespace and trims it.
func sanitizeClientName(name string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case unicode.Is(unicode.Cc, r), unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, name)
	return strings.Join(strings.Fields(cleaned), " ")
}

// describeRedirect returns the label and kind shown for a redirect URI.
// Custom schemes (cursor://host/..., com.example.app:/...) are labelled with
// the scheme only: the browser hands them to whichever app registered the
// scheme, so the "host" part is not a network destination.
func describeRedirect(u *url.URL) (label, kind string) {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return scheme + ":", "app"
	}
	if isLoopbackHost(u.Hostname()) {
		return u.Host, "local"
	}
	return u.Host, "remote"
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// sessionUser prefers the email from the provider's userinfo, falling back to
// the user ID. The password provider's placeholder ID is not shown.
func sessionUser(session sessions.Session) string {
	if userInfoJSON, ok := session.Get(auth.SessionKeyUserInfo).(string); ok && userInfoJSON != "" {
		var userInfo map[string]any
		if json.Unmarshal([]byte(userInfoJSON), &userInfo) == nil {
			if email, ok := userInfo["email"].(string); ok && email != "" {
				return email
			}
		}
	}
	if userID, ok := session.Get(auth.SessionKeyUserID).(string); ok && userID != auth.PasswordUserID {
		return userID
	}
	return ""
}

func (a *IDPRouter) handleAuthorizationReturn(c *gin.Context) {
	ctx := c.Request.Context()
	arID := c.Param("ar_id")
	session := sessions.Default(c)
	if !hasAuthorizeRequestID(session, arID) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid authorization session"})
		return
	}
	if !a.validConsentSubmission(c, session) {
		a.logger.Warn("Consent submission refused: failed CSRF/origin check")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid consent submission"})
		return
	}
	action := c.PostForm("action")
	if action != "approve" && action != "deny" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid consent action"})
		return
	}

	ar, err := a.repo.GetAuthorizeRequest(ctx, arID)
	if err != nil {
		a.logger.Error("Failed to get authorize requester", zap.Error(err))
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal Server Error"})
		return
	}
	defer func() {
		if err := a.repo.DeleteAuthorizeRequest(ctx, arID); err != nil {
			a.logger.Error("Failed to delete authorize requester", zap.Error(err))
		}
	}()

	if action == "deny" {
		removeAuthorizeRequestID(session, arID)
		if err := session.Save(); err != nil {
			a.logger.Error("Failed to remove authorize request from session", zap.Error(err))
		}
		// RFC 6749 4.1.2.1: tell the client the user declined, so it can stop
		// waiting instead of hanging until the user closes the tab.
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrAccessDenied.WithDescription("The user denied the request.").WithHint("The user chose Deny on the consent page."))
		return
	}

	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}
	ar.GrantAudience(a.externalURL)

	subject := "user"
	if userID, ok := session.Get(auth.SessionKeyUserID).(string); ok && userID != "" {
		subject = userID
	}
	var userInfo map[string]any
	if userInfoJSON, ok := session.Get(auth.SessionKeyUserInfo).(string); ok && userInfoJSON != "" {
		json.Unmarshal([]byte(userInfoJSON), &userInfo)
	}

	jwtSession, err := NewJWTSessionWithKey(a.externalURL, subject, a.privKey, userInfo)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create JWT session", zap.Error(err))
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}
	jwtSession.AuthTime = sessionAuthTime(session, time.Now())
	jwtSession.Provider, jwtSession.AuthzFacts = auth.SessionIdentity(session)
	if upstream, ok := session.Get(auth.SessionKeyUpstreamToken).(string); ok && upstream != "" {
		sealed, err := a.upstreamSealer.Seal(upstream, subject)
		if err != nil {
			a.logger.Error("Failed to encrypt upstream token", zap.Error(err))
			a.provider.WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrServerError.WithWrap(err))
			return
		}
		jwtSession.UpstreamToken = sealed
		jwtSession.UpstreamCheckedAt = jwtSession.AuthTime
	}

	response, err := a.provider.NewAuthorizeResponse(ctx, ar, jwtSession)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to generate authorization response", zap.Error(err))
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	removeAuthorizeRequestID(session, arID)
	if err := session.Save(); err != nil {
		a.logger.Error("Failed to remove authorize request from session", zap.Error(err))
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrServerError.WithWrap(err))
		return
	}

	a.provider.WriteAuthorizeResponse(ctx, c.Writer, ar, response)
}

func authorizeRequestIDs(session sessions.Session) []string {
	value, ok := session.Get(sessionKeyAuthorizeRequestIDs).(string)
	if !ok || value == "" {
		return nil
	}
	var ids []string
	if err := json.Unmarshal([]byte(value), &ids); err != nil {
		return nil
	}
	return ids
}

func addAuthorizeRequestID(session sessions.Session, arID string) {
	ids := authorizeRequestIDs(session)
	if hasAuthorizeRequestID(session, arID) {
		return
	}
	ids = append(ids, arID)
	data, _ := json.Marshal(ids)
	session.Set(sessionKeyAuthorizeRequestIDs, string(data))
}

func hasAuthorizeRequestID(session sessions.Session, arID string) bool {
	for _, id := range authorizeRequestIDs(session) {
		if id == arID {
			return true
		}
	}
	return false
}

func removeAuthorizeRequestID(session sessions.Session, arID string) {
	ids := authorizeRequestIDs(session)
	remaining := ids[:0]
	for _, id := range ids {
		if id != arID {
			remaining = append(remaining, id)
		}
	}
	if len(remaining) == 0 {
		session.Delete(sessionKeyAuthorizeRequestIDs)
		return
	}
	data, _ := json.Marshal(remaining)
	session.Set(sessionKeyAuthorizeRequestIDs, string(data))
}

func (a *IDPRouter) handleToken(c *gin.Context) {
	ctx := c.Request.Context()

	session, err := NewJWTSessionWithKey("", "", a.privKey, nil)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create JWT session for token", zap.Error(err))
		a.provider.WriteAccessError(ctx, c.Writer, nil, fosite.ErrServerError.WithWrap(err))
		return
	}

	accessRequest, err := a.provider.NewAccessRequest(ctx, c.Request, session)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create access request", zap.String("grant_type", c.PostForm("grant_type")))
		a.provider.WriteAccessError(ctx, c.Writer, accessRequest, err)
		return
	}

	if !a.stillAuthorized(accessRequest) {
		a.logger.Info("Token request refused: user is no longer allowed by the current configuration",
			zap.String("grant_type", c.PostForm("grant_type")), zap.String("subject", accessRequest.GetSession().GetSubject()))
		a.revokeGrant(ctx, accessRequest)
		a.provider.WriteAccessError(ctx, c.Writer, accessRequest, fosite.ErrInvalidGrant.
			WithHint("The user is no longer authorized. The user must sign in again."))
		return
	}

	if err := a.verifyUpstream(ctx, accessRequest, time.Now()); err != nil {
		if errors.Is(err, fosite.ErrInvalidGrant) {
			a.revokeGrant(ctx, accessRequest)
		}
		a.provider.WriteAccessError(ctx, c.Writer, accessRequest, err)
		return
	}

	if err := applySessionPolicy(accessRequest, time.Now(), a.lifespans.AccessToken, a.lifespans.MaxSessionAge); err != nil {
		a.logger.Info("Token request refused: session exceeded the maximum session age",
			zap.String("grant_type", c.PostForm("grant_type")), zap.String("subject", accessRequest.GetSession().GetSubject()))
		a.provider.WriteAccessError(ctx, c.Writer, accessRequest, err)
		return
	}

	response, err := a.provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create access response", zap.String("grant_type", c.PostForm("grant_type")), zap.Error(err))
		a.provider.WriteAccessError(ctx, c.Writer, accessRequest, err)
		return
	}

	a.provider.WriteAccessResponse(ctx, c.Writer, accessRequest, response)
}

type registrationRequest struct {
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	RedirectURIs            []string `json:"redirect_uris"`
}

type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
}

func (a *IDPRouter) handleRegister(c *gin.Context) {
	ctx := c.Request.Context()

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxRegistrationBodyBytes)
	var req registrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_client_metadata", "error_description": "invalid registration request"})
		return
	}
	if code, desc := a.validateRegistration(&req); code != "" {
		a.logger.Info("Client registration refused", zap.String("reason", desc))
		c.JSON(400, gin.H{"error": code, "error_description": desc})
		return
	}

	clientID, err := utils.GenerateClientID()
	if err != nil {
		a.logger.Error("Failed to generate client ID", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	var clientSecret string
	var hashedSecret []byte
	isPublic := req.TokenEndpointAuthMethod == "none"

	if !isPublic {
		// Generate client secret for confidential clients
		clientSecret, err = utils.GenerateClientSecret()
		if err != nil {
			a.logger.Error("Failed to generate client secret", zap.Error(err))
			c.JSON(500, gin.H{"error": "server_error"})
			return
		}

		hashedSecret, err = a.hasher.Hash(ctx, []byte(clientSecret))
		if err != nil {
			a.logger.Error("Failed to hash client secret", zap.Error(err))
			c.JSON(500, gin.H{"error": "server_error"})
			return
		}
	}

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  req.RedirectURIs,
		GrantTypes:    req.GrantTypes,
		ResponseTypes: req.ResponseTypes,
		Scopes:        strings.Fields(req.Scope),
		Audience:      []string{a.externalURL},
		Public:        isPublic,
	}
	if err := a.repo.RegisterClient(ctx, client); err != nil {
		a.logger.Error("Failed to register client", zap.String("client_id", clientID), zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	if name := sanitizeClientName(req.ClientName); name != "" {
		if r := []rune(name); len(r) > maxClientNameLength {
			name = string(r[:maxClientNameLength])
		}
		if err := a.repo.SetClientName(ctx, clientID, name); err != nil {
			// Display-only; the client is already usable without it.
			a.logger.Warn("Failed to store client name", zap.String("client_id", clientID), zap.Error(err))
		}
	}

	registrationClientURI, err := url.JoinPath(RegistrationEndpoint, clientID)
	if err != nil {
		a.logger.Error("Failed to create registration client URI", zap.String("client_id", clientID), zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	response := registrationResponse{
		ClientID:                clientID,
		RedirectURIs:            req.RedirectURIs,
		ClientName:              sanitizeClientName(req.ClientName),
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		RegistrationClientURI:   registrationClientURI,
		ClientIDIssuedAt:        time.Now().Unix(),
	}

	if !isPublic {
		response.ClientSecret = clientSecret
	}

	c.JSON(201, response)
}

type authorizationServerResponse struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

func (a *IDPRouter) handleOauthAuthorizationServer(c *gin.Context) {
	authorizationEndpoint, err := url.JoinPath(a.externalURL, AuthorizationEndpoint)
	if err != nil {
		a.logger.Error("Failed to create authorization endpoint URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	tokenEndpoint, err := url.JoinPath(a.externalURL, TokenEndpoint)
	if err != nil {
		a.logger.Error("Failed to create token endpoint URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	registrationEndpoint, err := url.JoinPath(a.externalURL, RegistrationEndpoint)
	if err != nil {
		a.logger.Error("Failed to create registration endpoint URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	res := &authorizationServerResponse{
		Issuer:                            a.externalURL,
		AuthorizationEndpoint:             authorizationEndpoint,
		TokenEndpoint:                     tokenEndpoint,
		RegistrationEndpoint:              registrationEndpoint,
		ScopesSupported:                   []string{},
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
	}
	c.JSON(200, res)
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func (a *IDPRouter) handleJWKS(c *gin.Context) {
	publicKey := &a.privKey.PublicKey

	// Convert RSA public key components to base64url
	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()

	n := base64.RawURLEncoding.EncodeToString(nBytes)
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	keyID, err := utils.GenerateKeyID(&a.privKey.PublicKey)
	if err != nil {
		a.logger.Error("Failed to generate key ID for JWKS", zap.Error(err))
		c.JSON(500, gin.H{"error": "failed to generate key ID"})
		return
	}

	k := jwk{
		Kty: "RSA",
		Use: "sig",
		Kid: keyID,
		Alg: "RS256",
		N:   n,
		E:   e,
	}

	ks := jwks{Keys: []jwk{k}}
	c.JSON(200, ks)
}

func NewJWTSessionWithKey(iss string, subject string, privateKey *rsa.PrivateKey, userInfo map[string]any) (*Session, error) {
	keyID, err := utils.GenerateKeyID(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	var extra map[string]any
	if userInfo != nil {
		extra = map[string]any{"userinfo": userInfo}
	}
	return &Session{
		DefaultSession: &fosite.DefaultSession{
			Username: subject,
			Subject:  subject,
		},
		JWTClaims: &jwt.JWTClaims{
			Issuer:    iss,
			Subject:   subject,
			Audience:  []string{},
			ExpiresAt: time.Now().Add(time.Hour),
			IssuedAt:  time.Now(),
			NotBefore: time.Now(),
			Extra:     extra,
		},
		JWTHeader: &jwt.Headers{
			Extra: map[string]any{
				"kid": keyID,
			},
		},
	}, nil
}

type Session struct {
	*fosite.DefaultSession
	JWTClaims *jwt.JWTClaims
	JWTHeader *jwt.Headers
	// AuthTime is when the user logged in at the upstream identity provider.
	// It is carried unchanged through refreshes.
	AuthTime time.Time `json:"auth_time"`
	// Provider and AuthzFacts identify the login so it can be re-checked
	// against the current allowlist on every token request. They are stored
	// server-side only and never put in the issued tokens.
	Provider   string         `json:"provider,omitempty"`
	AuthzFacts map[string]any `json:"authz_facts,omitempty"`
	// UpstreamToken is the upstream identity provider's refresh token,
	// encrypted and bound to the subject. It is used to re-verify the user
	// with the upstream provider on token refresh and is never put in tokens.
	UpstreamToken string `json:"upstream_token,omitempty"`
	// UpstreamCheckedAt is when the user was last verified upstream.
	UpstreamCheckedAt time.Time `json:"upstream_checked_at,omitzero"`
}

func (s *Session) GetJWTClaims() jwt.JWTClaimsContainer {
	return s.JWTClaims
}

func (s *Session) GetJWTHeader() *jwt.Headers {
	return s.JWTHeader
}

func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}

	clone := &Session{
		DefaultSession: &fosite.DefaultSession{
			Username:  s.DefaultSession.Username,
			Subject:   s.DefaultSession.Subject,
			ExpiresAt: s.DefaultSession.ExpiresAt,
		},
		JWTClaims: &jwt.JWTClaims{
			Issuer:    s.JWTClaims.Issuer,
			Subject:   s.JWTClaims.Subject,
			Audience:  s.JWTClaims.Audience,
			ExpiresAt: s.JWTClaims.ExpiresAt,
			IssuedAt:  s.JWTClaims.IssuedAt,
			NotBefore: s.JWTClaims.NotBefore,
			Extra:     s.JWTClaims.Extra,
		},
		JWTHeader: &jwt.Headers{
			Extra: make(map[string]any),
		},
		AuthTime:          s.AuthTime,
		Provider:          s.Provider,
		AuthzFacts:        maps.Clone(s.AuthzFacts),
		UpstreamToken:     s.UpstreamToken,
		UpstreamCheckedAt: s.UpstreamCheckedAt,
	}

	for k, v := range s.JWTHeader.Extra {
		clone.JWTHeader.Extra[k] = v
	}

	return clone
}
