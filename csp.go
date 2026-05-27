package secureheaders

import (
	"maps"
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
// The mapping is explicit rather than derived from mime.TypeByExtension so that
// detection is deterministic and does not depend on the host's MIME database,
// which is incomplete for web fonts (for example, .otf and .eot) and varies
// across operating systems and minimal container images.
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
	switch u.Scheme {
	case "ws", "wss":
		return "connect"
	}
	return cspExtDirective[strings.ToLower(path.Ext(u.Path))]
}

func cspSourceExpr(u *url.URL) (src string) {
	if u.Host != "" {
		switch u.Scheme {
		case "http", "https", "ws", "wss":
			src = u.Scheme + "://" + u.Host
		}
	}
	return
}
