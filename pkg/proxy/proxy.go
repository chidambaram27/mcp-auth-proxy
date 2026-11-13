package proxy

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/textproto"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mattn/go-jsonpointer"
)

type ProxyRouter struct {
	externalURL                string
	proxy                      http.Handler
	publicKey                  *rsa.PublicKey
	proxyHeaders               http.Header
	httpStreamingOnly          bool
	forwardAuthorizationHeader bool
	headerMapping              map[string]string
	headerMappingBase          string
	stripCookies               []string
}

func NewProxyRouter(
	externalURL string,
	proxy http.Handler,
	publicKey *rsa.PublicKey,
	proxyHeaders http.Header,
	httpStreamingOnly bool,
	forwardAuthorizationHeader bool,
	headerMapping map[string]string,
	headerMappingBase string,
) (*ProxyRouter, error) {
	return &ProxyRouter{
		externalURL:                externalURL,
		proxy:                      proxy,
		publicKey:                  publicKey,
		proxyHeaders:               proxyHeaders,
		httpStreamingOnly:          httpStreamingOnly,
		forwardAuthorizationHeader: forwardAuthorizationHeader,
		headerMapping:              headerMapping,
		headerMappingBase:          headerMappingBase,
	}, nil
}

// SetStripCookies sets the cookie names (the proxy's own session cookie) that
// are removed from requests before they reach the backend.
func (p *ProxyRouter) SetStripCookies(names ...string) {
	p.stripCookies = names
}

const (
	OauthProtectedResourceEndpoint = "/.well-known/oauth-protected-resource"
)

func (p *ProxyRouter) SetupRoutes(router gin.IRouter) {
	router.GET(OauthProtectedResourceEndpoint, p.handleProtectedResource)
	router.Use(p.handleProxy)
}

type protectedResourceResponse struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

func (p *ProxyRouter) handleProtectedResource(c *gin.Context) {
	c.JSON(http.StatusOK, protectedResourceResponse{
		Resource:             p.externalURL,
		AuthorizationServers: []string{p.externalURL},
	})
}

func (p *ProxyRouter) handleProxy(c *gin.Context) {
	authHeader := c.Request.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	bearerToken := strings.TrimPrefix(authHeader, "Bearer ")

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(bearerToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.publicKey, nil
	},
		jwt.WithIssuer(p.externalURL),
		jwt.WithAudience(p.externalURL),
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)

	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	if p.httpStreamingOnly && isSSEGetRequest(c.Request) {
		c.AbortWithStatusJSON(http.StatusMethodNotAllowed, gin.H{"error": "SSE (GET) streaming is not supported by this backend; use POST-based HTTP streaming instead"})
		return
	}

	// The reverse proxy strips every header named in Connection after this
	// handler runs, so a client could use it to drop the identity headers set
	// below. Apply hop-by-hop removal now, before any header is injected.
	stripConnectionHeaders(c.Request.Header)
	stripCookie(c.Request, p.stripCookies)

	if !p.forwardAuthorizationHeader {
		c.Request.Header.Del("Authorization")
	}
	for _, headerName := range p.headerMapping {
		c.Request.Header.Del(headerName)
	}
	// Configured headers replace any client-supplied value; appending would
	// let the client's value come first and win at the backend.
	for key := range p.proxyHeaders {
		c.Request.Header.Del(key)
	}
	for key, values := range p.proxyHeaders {
		for _, value := range values {
			c.Request.Header.Add(key, value)
		}
	}

	if len(p.headerMapping) > 0 {
		var source any = map[string]any(claims)
		if p.headerMappingBase != "/" {
			val, err := jsonpointer.Get(source, p.headerMappingBase)
			if err != nil {
				source = nil
			} else {
				source = val
			}
		}
		if source != nil {
			for pointer, headerName := range p.headerMapping {
				val, err := jsonpointer.Get(source, pointer)
				if err != nil {
					continue
				}
				switch v := val.(type) {
				case string:
					c.Request.Header.Set(headerName, v)
				case []any:
					var parts []string
					for _, item := range v {
						if s, ok := item.(string); ok {
							parts = append(parts, s)
						}
					}
					c.Request.Header.Set(headerName, strings.Join(parts, ","))
				default:
					c.Request.Header.Set(headerName, fmt.Sprintf("%v", v))
				}
			}
		}
	}

	p.proxy.ServeHTTP(c.Writer, c.Request)
}

// stripConnectionHeaders removes the Connection header and every header it
// names (RFC 9110 7.6.1), as a proxy must.
func stripConnectionHeaders(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = textproto.TrimString(name); name != "" {
				h.Del(name)
			}
		}
	}
	h.Del("Connection")
}

// stripCookie removes the named cookies (the proxy's own session cookie) from
// the request so they are never sent to the backend.
func stripCookie(r *http.Request, names []string) {
	if len(names) == 0 || r.Header.Get("Cookie") == "" {
		return
	}
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, ck := range cookies {
		if slices.Contains(names, ck.Name) {
			continue
		}
		r.AddCookie(ck)
	}
}

func isSSEGetRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	for _, value := range strings.Split(accept, ",") {
		mediaType := strings.TrimSpace(strings.ToLower(value))
		if idx := strings.Index(mediaType, ";"); idx != -1 {
			mediaType = strings.TrimSpace(mediaType[:idx])
		}
		if mediaType == "text/event-stream" {
			return true
		}
	}
	return false
}
