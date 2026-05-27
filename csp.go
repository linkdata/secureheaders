package secureheaders

import (
	"maps"
	"mime"
	"net/url"
	"path"
	"slices"
	"strings"
)

// BuildContentSecurityPolicy returns a CSP header value based on resource URLs.
//
// The default policy includes style-src 'unsafe-inline'.
//
// Resource URLs contribute external source expressions to script, style, image,
// font and connect directives according to their type.
//
// The resource URLs are expected to come from trusted application configuration,
// not from arbitrary user input. This function classifies known resources; it is
// not a URL sanitizer.
func BuildContentSecurityPolicy(resourceURLs []*url.URL) (value string) {
	scriptSrc := make(map[string]struct{})
	styleSrc := make(map[string]struct{})
	imgSrc := make(map[string]struct{})
	fontSrc := make(map[string]struct{})
	connectSrc := make(map[string]struct{})

	for _, u := range resourceURLs {
		if u != nil {
			if source := cspSourceExpr(u); source != "" {
				switch cspDirectiveForURL(u) {
				case "script":
					scriptSrc[source] = struct{}{}
				case "style":
					styleSrc[source] = struct{}{}
					// Stylesheets commonly reference webfonts via relative URLs.
					fontSrc[source] = struct{}{}
				case "img":
					imgSrc[source] = struct{}{}
				case "font":
					fontSrc[source] = struct{}{}
				case "connect":
					connectSrc[source] = struct{}{}
				}
			}
		}
	}

	value = strings.Join([]string{
		"default-src 'self'",
		"frame-ancestors 'none'",
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
		cspDirective("script-src", []string{"'self'"}, scriptSrc),
		cspDirective("style-src", []string{"'self'", "'unsafe-inline'"}, styleSrc),
		cspDirective("img-src", []string{"'self'", "data:"}, imgSrc),
		cspDirective("font-src", []string{"'self'"}, fontSrc),
		cspDirective("connect-src", []string{"'self'"}, connectSrc),
	}, "; ")

	return
}

func cspDirective(name string, defaults []string, extras map[string]struct{}) string {
	values := slices.Sorted(maps.Keys(extras))
	// slices.Concat allocates a fresh slice, so defaults is never mutated even
	// when a caller passes a slice with spare capacity.
	return name + " " + strings.Join(slices.Concat(defaults, values), " ")
}

// cspExtDirective maps a lowercased file extension (including the leading dot)
// to the CSP directive group whose origin list should allow the resource.
//
// It is consulted before mime.TypeByExtension so that detection is deterministic
// for these extensions regardless of the host's MIME database, which is
// incomplete for web fonts (for example, .otf and .eot) and varies across
// operating systems and minimal container images. Extensions not listed here
// fall back to MIME-based detection.
var cspExtDirective = map[string]string{
	".js":    "script",
	".mjs":   "script",
	".css":   "style",
	".png":   "img",
	".jpg":   "img",
	".jpeg":  "img",
	".gif":   "img",
	".webp":  "img",
	".avif":  "img",
	".svg":   "img",
	".ico":   "img",
	".bmp":   "img",
	".woff":  "font",
	".woff2": "font",
	".ttf":   "font",
	".otf":   "font",
	".ttc":   "font",
	".eot":   "font",
}

func cspDirectiveForURL(u *url.URL) string {
	switch strings.ToLower(u.Scheme) {
	case "ws", "wss":
		return "connect"
	}

	ext := strings.ToLower(path.Ext(u.Path))
	if directive, ok := cspExtDirective[ext]; ok {
		return directive
	}

	// Fall back to the host's MIME database for extensions not in the explicit map.
	switch mimetype := mime.TypeByExtension(ext); {
	case strings.HasPrefix(mimetype, "text/css"):
		return "style"
	case strings.HasPrefix(mimetype, "text/javascript"),
		strings.HasPrefix(mimetype, "application/javascript"),
		strings.HasPrefix(mimetype, "application/ecmascript"):
		return "script"
	case strings.HasPrefix(mimetype, "image/"):
		return "img"
	case strings.HasPrefix(mimetype, "font/"):
		return "font"
	}
	return ""
}

func cspSourceExpr(u *url.URL) (src string) {
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https", "ws", "wss":
		if u.Host != "" {
			// Hosts are case-insensitive in CSP source matching, so lowercase
			// to keep the scheme handling consistent and avoid emitting two
			// redundant entries for sources that differ only in host case.
			src = scheme + "://" + strings.ToLower(u.Host)
		}
	}
	return
}
