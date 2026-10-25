package auth

import (
	"html/template"

	"github.com/gin-gonic/gin"
)

// PageBranding is the subset of the consent page branding (see
// idp.Branding) that the auth pages reuse, so a denied user sees the same
// server name, logo and footer as on the consent page.
type PageBranding struct {
	ServerName string
	// LogoSrc is a safe <img src> value resolved at startup from trusted
	// operator config; empty means no logo image.
	LogoSrc template.URL
	// HideIcon suppresses the built-in fallback icon.
	HideIcon bool
	// Footer is trusted operator HTML; FooterDisabled hides the default.
	Footer         template.HTML
	FooterDisabled bool
	// ImgSrc is the CSP img-src value matching LogoSrc ("'none'" if unset).
	ImgSrc string
}

// SetPageBranding applies consent page branding to the auth pages.
func (a *AuthRouter) SetPageBranding(b PageBranding) {
	a.branding = b
}

// setPageSecurityHeaders sets the headers shared by the HTML auth pages: no
// caching (they show the user's identity), no framing and a CSP without
// scripts.
func (a *AuthRouter) setPageSecurityHeaders(c *gin.Context) {
	imgSrc := a.branding.ImgSrc
	if imgSrc == "" {
		imgSrc = "'none'"
	}
	c.Header("Cache-Control", "no-store")
	c.Header("X-Frame-Options", "DENY")
	c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src "+imgSrc+"; form-action 'self'; frame-ancestors 'none'")
	c.Header("Content-Type", "text/html; charset=utf-8")
}
