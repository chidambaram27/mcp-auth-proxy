package idp

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/gobwas/glob"
)

// RedirectPolicy decides which redirect URIs dynamically registered clients
// may use. Anyone can register a client, so without this an attacker could
// register https://attacker.example/callback and phish users into approving
// a grant that delivers their authorization code to the attacker.
//
// Allowed without configuration (RFC 8252 native-app redirects, which only
// reach an application on the user's own machine):
//   - http/https loopback URIs (localhost, 127.0.0.0/8, [::1]), any port
//   - private-use (custom) schemes such as cursor:// or vscode://, except
//     schemes browsers treat specially (javascript:, data:, file:, ...)
//
// Any other URI (in practice https:// web callbacks such as hosted MCP
// clients) must match one of the configured glob patterns. In patterns, "*"
// matches within one path segment (it never crosses "/") and "**" matches
// anything, e.g. "https://claude.ai/api/mcp/auth_callback" or
// "https://*.example.com/oauth/**".
type RedirectPolicy struct {
	patterns []glob.Glob
}

const maxRedirectURILength = 2000

var blockedRedirectSchemes = map[string]bool{
	"javascript": true, "data": true, "file": true, "vbscript": true,
	"blob": true, "about": true, "filesystem": true, "view-source": true,
	"ws": true, "wss": true, "ftp": true, "mailto": true, "tel": true, "sms": true,
	"chrome": true, "chrome-extension": true, "moz-extension": true, "intent": true,
}

func NewRedirectPolicy(patterns []string) (RedirectPolicy, error) {
	var p RedirectPolicy
	for _, raw := range patterns {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		g, err := glob.Compile(raw, '/')
		if err != nil {
			return RedirectPolicy{}, fmt.Errorf("invalid allowed redirect URI pattern %q: %w", raw, err)
		}
		p.patterns = append(p.patterns, g)
	}
	return p, nil
}

// Check returns an error describing why rawURI is not an allowed redirect URI.
func (p RedirectPolicy) Check(rawURI string) error {
	if rawURI == "" {
		return errors.New("redirect URI must not be empty")
	}
	if len(rawURI) > maxRedirectURILength {
		return errors.New("redirect URI is too long")
	}
	u, err := url.Parse(rawURI)
	if err != nil || !u.IsAbs() {
		return fmt.Errorf("redirect URI %q must be an absolute URI", rawURI)
	}
	if u.Fragment != "" || strings.Contains(rawURI, "#") {
		return fmt.Errorf("redirect URI %q must not contain a fragment", rawURI)
	}
	if u.User != nil {
		return fmt.Errorf("redirect URI %q must not contain user info", rawURI)
	}
	scheme := strings.ToLower(u.Scheme)
	if blockedRedirectSchemes[scheme] {
		return fmt.Errorf("redirect URI scheme %q is not allowed", scheme)
	}

	for _, g := range p.patterns {
		if g.Match(rawURI) {
			return nil
		}
	}

	switch scheme {
	case "http", "https":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("redirect URI %q is not a loopback URI and does not match ALLOWED_REDIRECT_URIS", rawURI)
	default:
		// Private-use scheme handled by an installed application.
		return nil
	}
}
