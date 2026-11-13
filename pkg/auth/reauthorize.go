package auth

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/mattn/go-jsonpointer"
)

// Reauthorizer is implemented by providers that can re-check a user against
// the current allowlist without contacting the upstream identity provider.
type Reauthorizer interface {
	// AuthzFacts returns the userinfo values the provider's allowlist rules
	// depend on. They are recorded at login, before userinfo filtering.
	AuthzFacts(userInfo map[string]any) map[string]any
	// Reauthorize reports whether the user is allowed by the current config.
	Reauthorize(userID string, facts map[string]any) bool
}

// Identity is what the proxy remembers about a login so it can be re-checked
// when tokens are issued.
type Identity struct {
	// Provider is the provider Type(), PasswordProvider, or "" for sessions
	// created by versions that did not record it.
	Provider string
	UserID   string
	// Facts are the values recorded by Reauthorizer.AuthzFacts at login.
	Facts map[string]any
	// UserInfo is the stored (possibly filtered) userinfo. It is only used
	// for sessions that have no recorded provider.
	UserInfo map[string]any
}

// Reauthorize reports whether the identity is still allowed by the current
// configuration. Providers that cannot re-check offline are trusted.
func (a *AuthRouter) Reauthorize(id Identity) bool {
	if id.Provider == PasswordProvider || (id.Provider == "" && id.UserID == PasswordUserID) {
		return len(a.passwordHash) > 0
	}

	if id.Provider != "" {
		for _, p := range a.providers {
			if p.Type() != id.Provider {
				continue
			}
			r, ok := p.(Reauthorizer)
			if !ok {
				return true
			}
			return r.Reauthorize(id.UserID, id.Facts)
		}
		// The provider the user logged in with is no longer configured.
		return false
	}

	for _, p := range a.providers {
		r, ok := p.(Reauthorizer)
		if !ok {
			return true
		}
		if r.Reauthorize(id.UserID, r.AuthzFacts(id.UserInfo)) {
			return true
		}
	}
	return false
}

// SessionIdentity returns the provider and allowlist facts recorded in the
// login session.
func SessionIdentity(session sessions.Session) (string, map[string]any) {
	provider, _ := session.Get(SessionKeyProvider).(string)
	var facts map[string]any
	if s, ok := session.Get(SessionKeyAuthzFacts).(string); ok && s != "" {
		_ = json.Unmarshal([]byte(s), &facts)
	}
	return provider, facts
}

func setSessionIdentity(session sessions.Session, provider Provider, userInfo map[string]any) {
	session.Set(SessionKeyProvider, provider.Type())
	session.Delete(SessionKeyAuthzFacts)
	r, ok := provider.(Reauthorizer)
	if !ok {
		return
	}
	if facts := r.AuthzFacts(userInfo); len(facts) > 0 {
		if data, err := json.Marshal(facts); err == nil {
			session.Set(SessionKeyAuthzFacts, string(data))
		}
	}
}

func (p *googleProvider) AuthzFacts(userInfo map[string]any) map[string]any {
	if hd, ok := userInfo["hd"].(string); ok && hd != "" {
		return map[string]any{"hd": hd}
	}
	return nil
}

func (p *googleProvider) Reauthorize(userID string, facts map[string]any) bool {
	if len(p.allowedUsers) == 0 && len(p.allowedWorkspaces) == 0 {
		return true
	}
	if slices.Contains(p.allowedUsers, strings.ToLower(userID)) {
		return true
	}
	hd, _ := facts["hd"].(string)
	return hd != "" && slices.Contains(p.allowedWorkspaces, strings.ToLower(hd))
}

func (p *githubProvider) AuthzFacts(map[string]any) map[string]any {
	return nil
}

// Reauthorize re-checks GITHUB_ALLOWED_USERS only. Organization and team
// membership needs a GitHub API call, so users are trusted while any
// organization or team is allowed.
func (p *githubProvider) Reauthorize(userID string, _ map[string]any) bool {
	if len(p.allowedUsers) == 0 && len(p.allowedOrgs) == 0 {
		return true
	}
	if slices.Contains(p.allowedUsers, userID) {
		return true
	}
	return len(p.allowedOrgs) > 0
}

// AuthzFacts records the attributes referenced by the allowed-attribute
// rules, keyed by their JSON pointer.
func (p *oidcProvider) AuthzFacts(userInfo map[string]any) map[string]any {
	if userInfo == nil {
		return nil
	}
	facts := map[string]any{}
	record := func(pointer string) {
		if _, done := facts[pointer]; done {
			return
		}
		if v, err := jsonpointer.Get(map[string]any(userInfo), pointer); err == nil {
			facts[pointer] = v
		}
	}
	for pointer := range p.allowedAttributes {
		record(pointer)
	}
	for pointer := range p.allowedAttributesGlob {
		record(pointer)
	}
	if len(facts) == 0 {
		return nil
	}
	return facts
}

func (p *oidcProvider) Reauthorize(userID string, facts map[string]any) bool {
	if len(p.allowedUsers) == 0 && len(p.allowedUsersGlob) == 0 && len(p.allowedAttributes) == 0 && len(p.allowedAttributesGlob) == 0 {
		return true
	}
	if slices.Contains(p.allowedUsers, userID) {
		return true
	}
	for _, g := range p.allowedUsersGlob {
		if g.Match(userID) {
			return true
		}
	}
	for pointer, allowedValues := range p.allowedAttributes {
		if v, ok := facts[pointer]; ok && matchAttributeValue(v, allowedValues) {
			return true
		}
	}
	for pointer, globs := range p.allowedAttributesGlob {
		if v, ok := facts[pointer]; ok && matchAttributeGlob(v, globs) {
			return true
		}
	}
	return false
}
