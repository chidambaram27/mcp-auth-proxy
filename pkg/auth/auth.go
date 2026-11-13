package auth

import (
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// LoginSessionMaxAge is how long a browser login is reused for new
// authorizations before the user has to sign in again. It does not affect the
// OAuth tokens issued to MCP clients, which are refreshed on their own.
var LoginSessionMaxAge = time.Hour

//go:embed templates/*
var templateFS embed.FS

type AuthRouter struct {
	passwordHash         []string
	providers            []Provider
	loginTemplate        *template.Template
	unauthorizedTemplate *template.Template
	errorTemplate        *template.Template
	// When true, do not auto-redirect to the sole provider even if
	// there is only one provider and no password is set.
	noProviderAutoSelect bool
	// userInfoFields is a list of top-level keys to retain from the
	// provider's userinfo response. When non-empty, all other keys are
	// stripped before the data is stored in the session cookie. This
	// prevents oversized cookies when the provider returns many claims.
	userInfoFields []string
	branding       PageBranding
	logger         *zap.Logger
}

// SetLogger sets the logger used for errors that are not shown to the user.
func (a *AuthRouter) SetLogger(logger *zap.Logger) {
	if logger != nil {
		a.logger = logger
	}
}

func NewAuthRouter(passwordHash []string, noProviderAutoSelect bool, userInfoFields []string, providers ...Provider) (*AuthRouter, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/login.html")
	if err != nil {
		return nil, err
	}

	unauthorizedTmpl, err := template.ParseFS(templateFS, "templates/unauthorized.html")
	if err != nil {
		return nil, err
	}

	errorTmpl, err := template.ParseFS(templateFS, "templates/error.html")
	if err != nil {
		return nil, err
	}

	return &AuthRouter{
		passwordHash:         passwordHash,
		providers:            providers,
		loginTemplate:        tmpl,
		unauthorizedTemplate: unauthorizedTmpl,
		errorTemplate:        errorTmpl,
		noProviderAutoSelect: noProviderAutoSelect,
		userInfoFields:       userInfoFields,
		logger:               zap.NewNop(),
	}, nil
}

const (
	LoginEndpoint          = "/.auth/login"
	LogoutEndpoint         = "/.auth/logout"
	GoogleAuthEndpoint     = "/.auth/google"
	GoogleCallbackEndpoint = "/.auth/google/callback"
	GitHubAuthEndpoint     = "/.auth/github"
	GitHubCallbackEndpoint = "/.auth/github/callback"
	OIDCAuthEndpoint       = "/.auth/oidc"
	OIDCCallbackEndpoint   = "/.auth/oidc/callback"

	PasswordProvider = "password"
	PasswordUserID   = "password_user"

	SessionKeyAuthorized  = "authorized"
	SessionKeyRedirectURL = "redirect_url"
	SessionKeyOAuthState  = "oauth_state"
	SessionKeyUserID      = "user_id"
	SessionKeyUserInfo    = "user_info"
	// SessionKeyAuthTime holds the Unix time of the last successful login.
	SessionKeyAuthTime = "auth_time"
	// SessionKeyProvider holds the type of the provider used to log in.
	SessionKeyProvider = "provider"
	// SessionKeyAuthzFacts holds the JSON-encoded allowlist inputs recorded
	// at login (see Reauthorizer).
	SessionKeyAuthzFacts = "authz_facts"
	// SessionKeyUpstreamToken holds the upstream provider's refresh token for
	// providers implementing UpstreamVerifier. The session cookie is encrypted.
	SessionKeyUpstreamToken = "upstream_token"
)

func (a *AuthRouter) SetupRoutes(router gin.IRouter) {
	router.GET(LoginEndpoint, a.handleLogin)
	router.POST(LoginEndpoint, a.handleLoginPost)
	router.GET(LogoutEndpoint, a.handleLogout)
	for _, provider := range a.providers {
		router.GET(provider.RedirectURL(), func(c *gin.Context) {
			session := sessions.Default(c)
			state := session.Get(SessionKeyOAuthState)
			if state == nil {
				a.renderError(c, errors.New("OAuth state is missing"))
				return
			}
			// The state is single use.
			session.Delete(SessionKeyOAuthState)
			token, err := provider.Exchange(c, state.(string))
			if err != nil {
				a.renderError(c, err)
				return
			}
			ok, user, userInfo, err := provider.Authorization(c, token)
			if err != nil {
				a.renderError(c, err)
				return
			}
			if !ok {
				_ = session.Save()
				a.renderUnauthorized(c, user, provider.Name())
				return
			}
			if _, verifies := provider.(UpstreamVerifier); verifies {
				if token.RefreshToken == "" {
					a.renderError(c, errors.New("the identity provider did not issue a refresh token"))
					return
				}
				session.Set(SessionKeyUpstreamToken, token.RefreshToken)
			} else {
				session.Delete(SessionKeyUpstreamToken)
			}
			session.Set(SessionKeyAuthorized, true)
			session.Set(SessionKeyUserID, user)
			session.Set(SessionKeyAuthTime, time.Now().Unix())
			setSessionIdentity(session, provider, userInfo)
			if userInfo != nil {
				if len(a.userInfoFields) > 0 {
					userInfo = filterUserInfo(userInfo, a.userInfoFields)
				}
				if userInfoJSON, err := json.Marshal(userInfo); err == nil {
					session.Set(SessionKeyUserInfo, string(userInfoJSON))
				}
			}
			redirectURL := session.Get(SessionKeyRedirectURL)
			if redirectURL != nil {
				session.Delete(SessionKeyRedirectURL)
			}
			if err := session.Save(); err != nil {
				a.renderError(c, err)
				return
			}

			if redirectURL == nil {
				c.Redirect(http.StatusFound, "/")
			} else {
				c.Redirect(http.StatusFound, redirectURL.(string))
			}
		})

		router.GET(provider.AuthURL(), func(c *gin.Context) {
			session := sessions.Default(c)

			state, err := utils.GenerateState()
			if err != nil {
				a.renderError(c, err)
				return
			}
			url, err := provider.AuthCodeURL(state)
			if err != nil {
				a.renderError(c, err)
				return
			}
			session.Set(SessionKeyOAuthState, state)
			if err := session.Save(); err != nil {
				a.renderError(c, err)
				return
			}
			c.Redirect(http.StatusFound, url)
		})
	}
}

func (a *AuthRouter) handleLogin(c *gin.Context) {
	if c.Request.Method == "POST" {
		a.handleLoginPost(c)
		return
	}
	// Auto-redirect to the sole provider if enabled and no password is set
	if !a.noProviderAutoSelect && len(a.passwordHash) == 0 && len(a.providers) == 1 {
		c.Redirect(http.StatusFound, a.providers[0].AuthURL())
		return
	}
	a.renderLogin(c, "")
}

func (a *AuthRouter) handleLoginPost(c *gin.Context) {
	password := c.PostForm("password")
	var errorMessage string

	if password == "" {
		errorMessage = "Password is required"
	} else {
		var isValid bool
		for _, hash := range a.passwordHash {
			err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
			if err == nil {
				isValid = true
				break
			}
		}

		if !isValid {
			errorMessage = "Invalid password"
		}
	}

	if errorMessage != "" {
		a.renderLogin(c, errorMessage)
		return
	}

	session := sessions.Default(c)
	session.Set(SessionKeyAuthorized, true)
	session.Set(SessionKeyUserID, PasswordUserID)
	session.Set(SessionKeyAuthTime, time.Now().Unix())
	session.Set(SessionKeyProvider, PasswordProvider)
	session.Delete(SessionKeyAuthzFacts)
	session.Delete(SessionKeyUpstreamToken)
	redirectURL := session.Get(SessionKeyRedirectURL)
	if redirectURL != nil {
		session.Delete(SessionKeyRedirectURL)
	}
	if err := session.Save(); err != nil {
		a.renderError(c, err)
		return
	}

	if redirectURL == nil {
		c.Redirect(http.StatusFound, "/")
	} else {
		c.Redirect(http.StatusFound, redirectURL.(string))
	}
}

func (a *AuthRouter) handleLogout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Options(sessions.Options{Path: "/", MaxAge: -1})
	if err := session.Save(); err != nil {
		a.renderError(c, err)
		return
	}
	c.Redirect(http.StatusFound, LoginEndpoint)
}

func (a *AuthRouter) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		authorized := session.Get(SessionKeyAuthorized)
		if authorized != nil && loginExpired(session, time.Now()) {
			for _, k := range []string{SessionKeyAuthorized, SessionKeyUserID, SessionKeyUserInfo, SessionKeyAuthTime, SessionKeyProvider, SessionKeyAuthzFacts, SessionKeyUpstreamToken} {
				session.Delete(k)
			}
			authorized = nil
		}
		if authorized == nil {
			session.Set(SessionKeyRedirectURL, c.Request.URL.String())
			if err := session.Save(); err != nil {
				a.renderError(c, err)
				return
			}
			c.Redirect(http.StatusFound, LoginEndpoint)
			return
		}

		if !authorized.(bool) {
			// not expected
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		c.Next()
	}
}

// loginExpired reports whether the browser login is older than
// LoginSessionMaxAge (or has no recorded login time).
func loginExpired(session sessions.Session, now time.Time) bool {
	var v int64
	switch t := session.Get(SessionKeyAuthTime).(type) {
	case int64:
		v = t
	case int:
		v = int64(t)
	case float64:
		v = int64(t)
	}
	if v <= 0 {
		return true
	}
	return now.Sub(time.Unix(v, 0)) > LoginSessionMaxAge
}

type loginTemplateData struct {
	Providers     []Provider
	HasPassword   bool
	PasswordError string
}

type unauthorizedTemplateData struct {
	UserID   string
	Provider string
	Branding PageBranding
}

// ServerLabel is the friendly server name, or the product name by default.
func (d unauthorizedTemplateData) ServerLabel() string {
	if d.Branding.ServerName != "" {
		return d.Branding.ServerName
	}
	return "MCP Auth Proxy"
}

type errorTemplateData struct {
	ErrorMessage string
}

func (a *AuthRouter) renderLogin(c *gin.Context, passwordError string) {
	data := loginTemplateData{
		Providers:     a.providers,
		HasPassword:   len(a.passwordHash) > 0,
		PasswordError: passwordError,
	}
	a.setPageSecurityHeaders(c)
	if passwordError != "" {
		c.Status(http.StatusBadRequest)
	} else {
		c.Status(http.StatusOK)
	}
	if err := a.loginTemplate.Execute(c.Writer, data); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
}

func (a *AuthRouter) renderUnauthorized(c *gin.Context, userID, providerName string) {
	data := unauthorizedTemplateData{
		UserID:   userID,
		Provider: providerName,
		Branding: a.branding,
	}
	a.setPageSecurityHeaders(c)
	c.Status(http.StatusForbidden)
	if err := a.unauthorizedTemplate.Execute(c.Writer, data); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
}

// filterUserInfo returns a copy of m containing only the listed keys.
func filterUserInfo(m map[string]any, keys []string) map[string]any {
	filtered := make(map[string]any, len(keys))
	for _, k := range keys {
		if v, ok := m[k]; ok {
			filtered[k] = v
		}
	}
	return filtered
}

// genericErrorMessage is shown instead of internal error details, which can
// include upstream provider responses.
const genericErrorMessage = "Sign-in failed. Please close this page and start again from your MCP client."

func (a *AuthRouter) renderError(c *gin.Context, err error) {
	a.logger.Warn("Authentication error", zap.String("path", c.Request.URL.Path), zap.Error(err))
	data := errorTemplateData{
		ErrorMessage: genericErrorMessage,
	}
	a.setPageSecurityHeaders(c)
	c.Status(http.StatusInternalServerError)
	if templateErr := a.errorTemplate.Execute(c.Writer, data); templateErr != nil {
		c.AbortWithError(http.StatusInternalServerError, templateErr)
		return
	}
	c.Abort()
}
