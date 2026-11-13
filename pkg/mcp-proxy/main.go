package mcpproxy

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blendle/zapdriver"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/auth"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/backend"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/idp"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/proxy"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/repository"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/tlsreload"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

var ServerShutdownTimeout = 5 * time.Second

var newProxyRouter = proxy.NewProxyRouter

func Run(
	listen string,
	tlsListen string,
	autoTLS bool,
	tlsHost string,
	tlsDirectoryURL string,
	tlsAcceptTOS bool,
	tlsCertFile string,
	tlsKeyFile string,
	dataPath string,
	repositoryBackend string,
	repositoryDSN string,
	externalURL string,
	googleClientID string,
	googleClientSecret string,
	googleAllowedUsers []string,
	googleAllowedWorkspaces []string,
	githubURL string,
	githubAPIURL string,
	githubClientID string,
	githubClientSecret string,
	githubAllowedUsers []string,
	githubAllowedOrgs []string,
	oidcConfigurationURL string,
	oidcClientID string,
	oidcClientSecret string,
	oidcScopes []string,
	oidcUserIDField string,
	oidcProviderName string,
	oidcAllowedUsers []string,
	oidcAllowedUsersGlob []string,
	oidcAllowedAttributes map[string][]string,
	oidcAllowedAttributesGlob map[string][]string,
	noProviderAutoSelect bool,
	password string,
	passwordHash string,
	trustedProxy []string,
	proxyHeaders []string,
	proxyBearerToken string,
	forwardAuthorizationHeader bool,
	proxyTarget []string,
	httpStreamingOnly bool,
	headerMapping map[string]string,
	headerMappingBase string,
	authorizeServerName string,
	authorizeLogo string,
	authorizeBanner string,
	authorizeFooter string,
	tokenLifespans idp.TokenLifespans,
	allowedRedirectURIs []string,
) error {
	// SIGTERM is what Kubernetes and Docker send on shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	parsedExternalURL, err := url.Parse(externalURL)
	if err != nil {
		return fmt.Errorf("failed to parse external URL: %w", err)
	}
	if parsedExternalURL.Path != "" && parsedExternalURL.Path != "/" {
		return fmt.Errorf("external URL must not have a path, got: %s", parsedExternalURL.Path)
	}
	parsedExternalURL.Path = "/"
	externalURL = parsedExternalURL.String()

	if (tlsCertFile == "") != (tlsKeyFile == "") {
		return fmt.Errorf("both TLS certificate and key files must be provided together")
	}
	var manualTLS bool
	if tlsCertFile != "" && tlsKeyFile != "" {
		manualTLS = true
	}
	if manualTLS && tlsHost != "" {
		return fmt.Errorf("tlsHost cannot be used when TLS certificate and key files are provided")
	}
	if !manualTLS && !autoTLS && tlsHost != "" {
		return fmt.Errorf("tlsHost requires automatic TLS; remove noAutoTLS or provide certificate files instead")
	}

	if err := requireAllowlists(
		googleClientID != "" && googleClientSecret != "", googleAllowedUsers, googleAllowedWorkspaces,
		githubClientID != "" && githubClientSecret != "", githubAllowedUsers, githubAllowedOrgs,
		oidcConfigurationURL != "" && oidcClientID != "" && oidcClientSecret != "", oidcAllowedUsers, oidcAllowedUsersGlob, oidcAllowedAttributes, oidcAllowedAttributesGlob,
	); err != nil {
		return err
	}
	redirectPolicy, err := idp.NewRedirectPolicy(allowedRedirectURIs)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dataPath, 0o700); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	var secret []byte
	secretFromEnv := os.Getenv("AUTH_HMAC_SECRET") != ""
	if envSecret := os.Getenv("AUTH_HMAC_SECRET"); envSecret != "" {
		secret, err = utils.SecretFromBase64(envSecret)
		if err != nil {
			return fmt.Errorf("failed to parse AUTH_HMAC_SECRET environment variable: %w", err)
		}
	} else {
		secret, err = utils.LoadOrGenerateSecret(path.Join(dataPath, "secret"))
		if err != nil {
			return fmt.Errorf("failed to load or generate secret: %w", err)
		}
	}

	var config zap.Config
	if os.Getenv("MODE") == "debug" {
		gin.SetMode(gin.DebugMode)
		config = zap.NewDevelopmentConfig()
	} else {
		gin.SetMode(gin.ReleaseMode)
		config = zapdriver.NewProductionConfig()
	}
	logger, err := config.Build()
	if err != nil {
		return fmt.Errorf("failed to build logger: %w", err)
	}
	if !secretFromEnv {
		logger.Warn("AUTH_HMAC_SECRET is not set; using a secret stored in the data directory. Set it from a secret manager in production (it must be identical on all replicas)")
	}
	if os.Getenv("JWT_PRIVATE_KEY") == "" {
		logger.Warn("JWT_PRIVATE_KEY is not set; using a key stored in the data directory. Set it from a secret manager in production (it must be identical on all replicas)")
	}
	if password != "" || passwordHash != "" {
		logger.Warn("Password login is enabled; anyone with the shared password gets access and it cannot be revoked per user")
	}

	if len(proxyTarget) == 0 {
		return fmt.Errorf("proxy target must be specified")
	}
	var be backend.Backend
	var beHandler http.Handler
	if proxyURL, err := url.Parse(proxyTarget[0]); err == nil && (proxyURL.Scheme == "http" || proxyURL.Scheme == "https") {
		var err error
		be, err = backend.NewTransparentBackend(logger, proxyURL, trustedProxy)
		if err != nil {
			return fmt.Errorf("failed to create transparent backend: %w", err)
		}
		beHandler, err = be.Run(ctx)
		if err != nil {
			return fmt.Errorf("failed to create transparent backend: %w", err)
		}
	} else {
		be = backend.NewProxyBackend(logger, proxyTarget)
		beHandler, err = be.Run(ctx)
		if err != nil {
			return fmt.Errorf("failed to create proxy backend: %w", err)
		}
	}

	// Convert headers slice to map and integrate bearer token
	proxyHeadersMap := http.Header{}
	for _, header := range proxyHeaders {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return fmt.Errorf("invalid proxy header format: %s", header)
		}
		proxyHeadersMap.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}

	// Add bearer token as Authorization header if provided
	if proxyBearerToken != "" {
		if proxyHeadersMap.Get("Authorization") != "" {
			logger.Warn("Authorization header already set, overwriting with bearer token")
		}
		proxyHeadersMap.Set("Authorization", "Bearer "+proxyBearerToken)
	}

	var repo repository.Repository
	switch backend := strings.ToLower(repositoryBackend); backend {
	case "", "local":
		repo, err = repository.NewKVSRepository(path.Join(dataPath, "db"), "mcp-oauth-proxy")
		if err != nil {
			return fmt.Errorf("failed to create repository: %w", err)
		}
	case "sqlite":
		if repositoryDSN == "" {
			return fmt.Errorf("repository DSN must be provided for sqlite backend")
		}
		repo, err = repository.NewSQLRepository("sqlite", repositoryDSN)
		if err != nil {
			return fmt.Errorf("failed to create repository: %w", err)
		}
	case "postgres", "postgresql":
		if repositoryDSN == "" {
			return fmt.Errorf("repository DSN must be provided for postgres backend")
		}
		repo, err = repository.NewSQLRepository("postgres", repositoryDSN)
		if err != nil {
			return fmt.Errorf("failed to create repository: %w", err)
		}
	case "mysql":
		if repositoryDSN == "" {
			return fmt.Errorf("repository DSN must be provided for mysql backend")
		}
		repo, err = repository.NewSQLRepository("mysql", repositoryDSN)
		if err != nil {
			return fmt.Errorf("failed to create repository: %w", err)
		}
	default:
		return fmt.Errorf("unsupported repository backend: %s", repositoryBackend)
	}
	defer func() {
		if err := repo.Close(); err != nil {
			logger.Warn("failed to close repository", zap.Error(err))
		}
	}()
	purgeCtx, stopPurge := context.WithCancel(ctx)
	purgeDone := make(chan struct{})
	go func() {
		defer close(purgeDone)
		runPurgeLoop(purgeCtx, repo, logger)
	}()
	// Stop purging before the repository is closed.
	defer func() {
		stopPurge()
		<-purgeDone
	}()

	var privKey *rsa.PrivateKey
	if envKey := os.Getenv("JWT_PRIVATE_KEY"); envKey != "" {
		privKey, err = utils.PrivateKeyFromPEM(envKey)
		if err != nil {
			return fmt.Errorf("failed to parse JWT_PRIVATE_KEY environment variable: %w", err)
		}
	} else {
		privKey, err = utils.LoadOrGeneratePrivateKey(path.Join(dataPath, "private_key.pem"))
		if err != nil {
			return fmt.Errorf("failed to load or generate private key: %w", err)
		}
	}
	var providers []auth.Provider

	// Add Google provider if configured
	if googleClientID != "" && googleClientSecret != "" {
		googleProvider, err := auth.NewGoogleProvider(externalURL, googleClientID, googleClientSecret, googleAllowedUsers, googleAllowedWorkspaces)
		if err != nil {
			return fmt.Errorf("failed to create Google provider: %w", err)
		}
		providers = append(providers, googleProvider)
	}

	// Add GitHub provider if configured
	if githubClientID != "" && githubClientSecret != "" {
		githubProvider, err := auth.NewGithubProvider(githubURL, githubAPIURL, githubClientID, githubClientSecret, externalURL, githubAllowedUsers, githubAllowedOrgs)
		if err != nil {
			return fmt.Errorf("failed to create GitHub provider: %w", err)
		}
		providers = append(providers, githubProvider)
	}

	// Add OIDC provider if configured
	if oidcConfigurationURL != "" && oidcClientID != "" && oidcClientSecret != "" {
		oidcProvider, err := auth.NewOIDCProvider(
			oidcConfigurationURL,
			oidcScopes,
			oidcUserIDField,
			oidcProviderName,
			externalURL,
			oidcClientID,
			oidcClientSecret,
			oidcAllowedUsers,
			oidcAllowedUsersGlob,
			oidcAllowedAttributes,
			oidcAllowedAttributesGlob,
		)
		if err != nil {
			return fmt.Errorf("failed to create OIDC provider: %w", err)
		}
		providers = append(providers, oidcProvider)
	}

	var hashes []string

	// Handle password argument - generate bcrypt hash if provided
	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to generate password hash: %w", err)
		}
		hashes = append(hashes, string(hash))
	}

	// Handle password-hash argument - use directly if provided
	if passwordHash != "" {
		hashes = append(hashes, passwordHash)
	}

	// Collect the top-level userinfo keys that are actually needed so the
	// session cookie doesn't store the entire provider response.
	userInfoFields := userInfoFieldsFromConfig(oidcUserIDField, headerMapping)

	authRouter, err := auth.NewAuthRouter(hashes, noProviderAutoSelect, userInfoFields, providers...)
	if err != nil {
		return fmt.Errorf("failed to create auth router: %w", err)
	}
	authRouter.SetLogger(logger)
	branding, err := idp.LoadBranding(authorizeServerName, authorizeLogo, authorizeBanner, authorizeFooter)
	if err != nil {
		// Cosmetic setting: keep serving with the default icon rather than
		// crash-looping the proxy over a typo.
		logger.Error("Invalid consent page logo (AUTHORIZE_LOGO), using the default icon", zap.Error(err))
	} else if branding.InsecureLogoURL() {
		logger.Warn("Consent page logo (AUTHORIZE_LOGO) uses http://; browsers block it on an https consent page")
	}
	authRouter.SetPageBranding(branding.PageBranding())
	repository.RefreshTokenGracePeriod = tokenLifespans.RefreshTokenGracePeriod
	idpRouter, err := idp.NewIDPRouter(repo, privKey, logger, externalURL, secret, authRouter, branding, tokenLifespans)
	if err != nil {
		return fmt.Errorf("failed to create IDP router: %w", err)
	}
	idpRouter.SetRedirectPolicy(redirectPolicy)
	proxyRouter, err := newProxyRouter(externalURL, beHandler, &privKey.PublicKey, proxyHeadersMap, httpStreamingOnly, forwardAuthorizationHeader, headerMapping, headerMappingBase)
	if err != nil {
		return fmt.Errorf("failed to create proxy router: %w", err)
	}
	cookieName := sessionCookieName(parsedExternalURL)
	proxyRouter.SetStripCookies(cookieName)

	router := gin.New()
	if err := router.SetTrustedProxies(trustedProxy); err != nil {
		return fmt.Errorf("invalid trusted proxies: %w", err)
	}

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	router.Use(requestLogger(logger))
	router.Use(recoveryMiddleware(logger))
	router.Use(securityHeadersMiddleware(parsedExternalURL.Scheme == "https"))
	router.Use(bodyLimitMiddleware(maxRequestBodyBytes))
	router.Use(rateLimitMiddleware())
	store, err := newSessionStore(secret, sessionCookieSecure(parsedExternalURL))
	if err != nil {
		return fmt.Errorf("failed to create session store: %w", err)
	}
	router.Use(sessions.Sessions(cookieName, store))
	authRouter.SetupRoutes(router)
	idpRouter.SetupRoutes(router)
	proxyRouter.SetupRoutes(router)

	var tlsHostDetected bool
	if autoTLS && !manualTLS &&
		tlsHost == "" &&
		parsedExternalURL.Scheme == "https" &&
		parsedExternalURL.Host != "localhost" {
		tlsHost = parsedExternalURL.Host
		tlsHostDetected = true
	}

	exit := make(chan struct{}, 3)
	var wg sync.WaitGroup
	errs := []error{}
	lock := sync.Mutex{}

	if manualTLS {
		certReloader, err := tlsreload.NewFileReloader(tlsCertFile, tlsKeyFile, logger)
		if err != nil {
			return fmt.Errorf("failed to prepare TLS certificate reloader: %w", err)
		}

		logger.Info("Starting server with provided TLS certificate")
		httpServer := newServer(listen, httpsRedirectHandler(parsedExternalURL))
		httpsServer := newServer(tlsListen, router)
		httpsServer.TLSConfig = &tls.Config{GetCertificate: certReloader.GetCertificate, MinVersion: tls.VersionTLS12}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := httpServer.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			logger.Debug("HTTP server closed")
			exit <- struct{}{}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
			defer shutdownCancel()
			if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
				logger.Warn("HTTP server shutdown error", zap.Error(shutdownErr))
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := httpsServer.ListenAndServeTLS("", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			logger.Debug("HTTPS server closed")
			exit <- struct{}{}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
			defer shutdownCancel()
			if shutdownErr := httpsServer.Shutdown(shutdownCtx); shutdownErr != nil {
				logger.Warn("HTTPS server shutdown error", zap.Error(shutdownErr))
			}
		}()
	} else if tlsHost != "" {
		if !tlsAcceptTOS {
			if tlsHostDetected {
				return errors.New("TLS host is auto-detected, but tlsAcceptTOS is not set to true. Please agree to the TOS or set noAutoTLS to true")
			}
			return errors.New("TLS is enabled, but tlsAcceptTOS is not set to true. Please explicitly agree to the TOS")
		}

		m := autocert.Manager{
			Prompt: func(tosURL string) bool {
				return tlsAcceptTOS
			},
			HostPolicy: autocert.HostWhitelist(tlsHost),
			Cache:      autocert.DirCache(path.Join(dataPath, "certs")),
			Client: &acme.Client{
				DirectoryURL: tlsDirectoryURL,
			},
		}

		httpServer := newServer(listen, m.HTTPHandler(httpsRedirectHandler(parsedExternalURL)))
		httpsServer := newServer(tlsListen, router)
		httpsServer.TLSConfig = m.TLSConfig()
		httpsServer.TLSConfig.MinVersion = tls.VersionTLS12
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := httpServer.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			logger.Debug("HTTP server closed")
			exit <- struct{}{}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
			defer shutdownCancel()
			if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
				logger.Warn("HTTP server shutdown error", zap.Error(shutdownErr))
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := httpsServer.ListenAndServeTLS("", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			logger.Debug("HTTPS server closed")
			exit <- struct{}{}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
			defer shutdownCancel()
			if shutdownErr := httpsServer.Shutdown(shutdownCtx); shutdownErr != nil {
				logger.Warn("HTTPS server shutdown error", zap.Error(shutdownErr))
			}
		}()
	} else {
		httpServer := newServer(listen, router)
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := httpServer.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			exit <- struct{}{}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
			defer shutdownCancel()
			if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
				logger.Warn("HTTP server shutdown error", zap.Error(shutdownErr))
			}
		}()
	}

	if be != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := be.Wait(); err != nil && !errors.Is(ctx.Err(), context.Canceled) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			logger.Debug("proxy backend closed")
			exit <- struct{}{}
		}()
	}

	if manualTLS || tlsHost != "" {
		logger.Info("Starting server", zap.Strings("listen", []string{listen, tlsListen}))
	} else {
		logger.Info("Starting server", zap.Strings("listen", []string{listen}))
	}
	<-exit
	stop()
	wg.Wait()
	return errors.Join(errs...)
}

func sessionCookieSecure(externalURL *url.URL) bool {
	return externalURL.Scheme == "https"
}

// sessionCookieName uses the __Host- prefix on https, which browsers only
// accept for Secure, host-only cookies with Path=/ (no subdomain can set or
// overwrite it).
func sessionCookieName(externalURL *url.URL) string {
	if sessionCookieSecure(externalURL) {
		return "__Host-session"
	}
	return "session"
}

// newSessionStore returns the cookie store for the browser session. Cookies
// are signed and encrypted with keys derived from the master secret, and
// their server-side lifetime matches the cookie's.
func newSessionStore(secret []byte, secure bool) (cookie.Store, error) {
	authKey, err := utils.DeriveKey(secret, utils.KeyPurposeCookieAuth)
	if err != nil {
		return nil, err
	}
	encKey, err := utils.DeriveKey(secret, utils.KeyPurposeCookieEncrypt)
	if err != nil {
		return nil, err
	}
	store := cookie.NewStore(authKey, encKey)
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   sessionCookieMaxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	// Options only sets the browser expiry; MaxAge also bounds how long the
	// signed cookie is accepted by the server (default would be 30 days).
	if m, ok := store.(interface{ MaxAge(int) }); ok {
		m.MaxAge(sessionCookieMaxAge)
	} else {
		return nil, errors.New("session store does not support MaxAge")
	}
	return store, nil
}

// userInfoFieldsFromConfig extracts the top-level userinfo keys referenced
// by the OIDC user-ID field and the header mapping. JSON pointers like
// "/email" or "/preferred_username" yield "email" or "preferred_username".
func userInfoFieldsFromConfig(oidcUserIDField string, headerMapping map[string]string) []string {
	seen := map[string]struct{}{}
	add := func(pointer string) {
		pointer = strings.TrimPrefix(pointer, "/")
		if i := strings.IndexByte(pointer, '/'); i != -1 {
			pointer = pointer[:i]
		}
		if pointer != "" {
			seen[pointer] = struct{}{}
		}
	}
	add(oidcUserIDField)
	for pointer := range headerMapping {
		add(pointer)
	}
	fields := make([]string, 0, len(seen))
	for k := range seen {
		fields = append(fields, k)
	}
	return fields
}
