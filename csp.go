package secureheaders

import (
	"maps"
	"mime"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
)

// BuildContentSecurityPolicy returns a Content-Security-Policy header value.
//
// Each resource contributes a host source expression according to its
// destination. [ResourceDestinationAuto] infers a destination from the URL;
// inferred stylesheet sources are also permitted for fonts. The same URL may
// be listed more than once with different explicit destinations.
//
// With no resources, the function returns the default policy, which includes
// style-src 'unsafe-inline'. HTTP, HTTPS, WebSocket and scheme-relative URLs
// with hosts are supported. A scheme-relative URL produces a schemeless
// source. For an HTTP protected resource it permits HTTP and HTTPS; for HTTPS
// it permits HTTPS only. It does not permit WebSocket connections; use an
// explicit ws:// or wss:// URL for those. Resources with nil URLs, hosts
// outside the CSP host-source grammar, unsupported schemes or unknown
// destinations do not contribute a source.
//
// Resources must come from trusted application configuration. Callers are
// responsible for parsing and validating URLs; this function does not sanitize
// them.
func BuildContentSecurityPolicy(resources ...Resource) (value string) {
	scriptSrc := make(map[string]struct{})
	styleSrc := make(map[string]struct{})
	imgSrc := make(map[string]struct{})
	fontSrc := make(map[string]struct{})
	connectSrc := make(map[string]struct{})

	for _, resource := range resources {
		if resource.URL != nil {
			if source := cspSourceExpr(resource.URL); source != "" {
				destination := resource.Destination
				inferred := destination == ResourceDestinationAuto
				if inferred {
					destination = resourceDestinationForURL(resource.URL)
				}
				switch destination {
				case ResourceDestinationScript:
					scriptSrc[source] = struct{}{}
				case ResourceDestinationStyle:
					styleSrc[source] = struct{}{}
					if inferred {
						// Inferred stylesheets may load relative fonts from the same source.
						fontSrc[source] = struct{}{}
					}
				case ResourceDestinationImage:
					imgSrc[source] = struct{}{}
				case ResourceDestinationFont:
					fontSrc[source] = struct{}{}
				case ResourceDestinationConnect:
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

// cspExtDestination maps a lowercased file extension (including the leading
// dot) to the inferred browser destination.
//
// It is consulted before mime.TypeByExtension so that detection is deterministic
// for these extensions regardless of the host's MIME database, which is
// incomplete for web fonts (for example, .otf and .eot) and varies across
// operating systems and minimal container images. Extensions not listed here
// fall back to MIME-based detection.
var cspExtDestination = map[string]ResourceDestination{
	".js":    ResourceDestinationScript,
	".mjs":   ResourceDestinationScript,
	".css":   ResourceDestinationStyle,
	".png":   ResourceDestinationImage,
	".jpg":   ResourceDestinationImage,
	".jpeg":  ResourceDestinationImage,
	".gif":   ResourceDestinationImage,
	".webp":  ResourceDestinationImage,
	".avif":  ResourceDestinationImage,
	".svg":   ResourceDestinationImage,
	".ico":   ResourceDestinationImage,
	".bmp":   ResourceDestinationImage,
	".woff":  ResourceDestinationFont,
	".woff2": ResourceDestinationFont,
	".ttf":   ResourceDestinationFont,
	".otf":   ResourceDestinationFont,
	".ttc":   ResourceDestinationFont,
	".eot":   ResourceDestinationFont,
}

func resourceDestinationForURL(u *url.URL) (destination ResourceDestination) {
	switch strings.ToLower(u.Scheme) {
	case "ws", "wss":
		destination = ResourceDestinationConnect
		return
	}

	ext := strings.ToLower(path.Ext(u.Path))
	if inferred, ok := cspExtDestination[ext]; ok {
		destination = inferred
		return
	}

	// Fall back to the host's MIME database for extensions not in the explicit map.
	switch mimetype := mime.TypeByExtension(ext); {
	case strings.HasPrefix(mimetype, "text/css"):
		destination = ResourceDestinationStyle
	case strings.HasPrefix(mimetype, "text/javascript"),
		strings.HasPrefix(mimetype, "application/javascript"),
		strings.HasPrefix(mimetype, "application/ecmascript"):
		destination = ResourceDestinationScript
	case strings.HasPrefix(mimetype, "image/"):
		destination = ResourceDestinationImage
	case strings.HasPrefix(mimetype, "font/"):
		destination = ResourceDestinationFont
	}
	return
}

func cspSourceExpr(u *url.URL) (src string) {
	if validCSPHost(u.Host) {
		switch scheme := strings.ToLower(u.Scheme); scheme {
		case "":
			src = strings.ToLower(u.Host)
		case "http", "https", "ws", "wss":
			// Hosts are case-insensitive in CSP source matching, so lowercase
			// to keep the scheme handling consistent and avoid emitting two
			// redundant entries for sources that differ only in host case.
			src = scheme + "://" + strings.ToLower(u.Host)
		}
	}
	return
}

var cspHostPattern = regexp.MustCompile(`^(?:\*|(?:\*\.)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.?)(?::(?:[0-9]+|\*))?$`)

func validCSPHost(host string) (valid bool) {
	valid = cspHostPattern.MatchString(host)
	return
}
