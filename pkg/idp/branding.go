package idp

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Branding holds the optional customisation of the consent (authorize) page.
// It mirrors oauth2-proxy's sign-in page knobs (custom logo, banner, footer)
// adapted to this proxy's single consent page.
//
// A value of "-" disables the corresponding default, matching oauth2-proxy.
type Branding struct {
	// ServerName is a friendly label shown instead of the bare external
	// host, e.g. "Trino (staging)".
	ServerName string
	// Banner is custom HTML rendered above the request details. "-" hides
	// the default lead sentence.
	Banner string
	// Footer is custom HTML rendered at the bottom. "-" hides the default
	// footer.
	Footer string

	// logoSrc is the resolved value for the <img src> attribute: either a
	// data URI (file logo, inlined at startup) or the passthrough URL.
	logoSrc string
	// logoCSPSource is the CSP img-src token the logo needs: "data:" for an
	// inlined file, or the URL's scheme://host for a remote logo.
	logoCSPSource string
	// logoDisabled is set when the operator passed "-".
	logoDisabled bool
}

const (
	// brandingDisable is the sentinel (same as oauth2-proxy) that turns a
	// default element off instead of customising it.
	brandingDisable = "-"
	// maxLogoBytes caps an inlined file logo so a huge file cannot bloat
	// every rendered page.
	maxLogoBytes = 512 * 1024
)

// LoadBranding resolves the branding options once at startup. The logo is a
// file path or a URL, like oauth2-proxy's --custom-sign-in-logo: a path is
// read and inlined as a data URI (so it survives a read-only filesystem and
// needs no request-time file access), a URL is passed through to <img src>.
func LoadBranding(serverName, logo, banner, footer string) (Branding, error) {
	b := Branding{
		ServerName: strings.TrimSpace(serverName),
		Banner:     banner,
		Footer:     footer,
	}

	logo = strings.TrimSpace(logo)
	switch {
	case logo == "":
		// No logo configured; the template shows a built-in icon.
	case logo == brandingDisable:
		b.logoDisabled = true
	case isHTTPURL(logo):
		b.logoSrc = logo
		b.logoCSPSource = cspSourceForURL(logo)
	default:
		src, err := inlineLogoFile(logo)
		if err != nil {
			return Branding{}, err
		}
		b.logoSrc = src
		b.logoCSPSource = "data:"
	}

	return b, nil
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func cspSourceForURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func inlineLogoFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("failed to read logo %q: %w", path, err)
	}
	if info.Size() > maxLogoBytes {
		return "", fmt.Errorf("logo %q is %d bytes, over the %d byte limit", path, info.Size(), maxLogoBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read logo %q: %w", path, err)
	}
	mediaType, err := logoMediaType(path)
	if err != nil {
		return "", err
	}
	return "data:" + mediaType + ";base64," + base64.StdEncoding.EncodeToString(data), nil
}

// logoMediaType maps the supported image extensions, matching the formats
// oauth2-proxy documents for its logo (PNG, JPG/JPEG, SVG).
func logoMediaType(path string) (string, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png":
		return "image/png", nil
	case ".jpg", ".jpeg":
		return "image/jpeg", nil
	case ".svg":
		return "image/svg+xml", nil
	case ".gif":
		return "image/gif", nil
	case ".webp":
		return "image/webp", nil
	default:
		return "", fmt.Errorf("unsupported logo type %q (want .png, .jpg, .jpeg, .svg, .gif or .webp)", filepath.Ext(path))
	}
}

// contentSecurityPolicy builds the consent page CSP, widening img-src only for
// the configured logo source.
func (b Branding) contentSecurityPolicy() string {
	imgSrc := "'none'"
	if !b.logoDisabled && b.logoSrc != "" && b.logoCSPSource != "" {
		imgSrc = b.logoCSPSource
	}
	return "default-src 'none'; style-src 'unsafe-inline'; img-src " + imgSrc + "; form-action 'self'; frame-ancestors 'none'"
}

// logoURL returns the <img src> as a template.URL. The value is resolved at
// startup from trusted operator config (a data URI for an inlined file, or an
// http(s) URL), so it is safe to mark as a URL rather than let html/template
// reject the data: scheme. Returns "" when there is no logo.
func (b Branding) logoURL() template.URL {
	if b.logoDisabled {
		return ""
	}
	return template.URL(b.logoSrc)
}

// effectiveBanner returns the custom banner HTML, or "" to show the default
// lead sentence. "-" hides it entirely.
func (b Branding) effectiveBanner() template.HTML {
	switch strings.TrimSpace(b.Banner) {
	case "":
		return ""
	case brandingDisable:
		// Rendered: suppresses the default lead without adding content.
		return template.HTML("")
	default:
		return template.HTML(b.Banner)
	}
}

// bannerDisabled reports whether the operator passed "-" to hide the lead.
func (b Branding) bannerDisabled() bool {
	return strings.TrimSpace(b.Banner) == brandingDisable
}

// effectiveFooter returns the custom footer HTML, or "" to show the default
// footer. "-" hides it entirely.
func (b Branding) effectiveFooter() template.HTML {
	switch strings.TrimSpace(b.Footer) {
	case "":
		return ""
	case brandingDisable:
		return template.HTML("")
	default:
		return template.HTML(b.Footer)
	}
}

// footerDisabled reports whether the operator passed "-" to hide the footer.
func (b Branding) footerDisabled() bool {
	return strings.TrimSpace(b.Footer) == brandingDisable
}
