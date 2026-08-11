package secureheaders

import (
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// BuildContentSecurityPolicy returns a Content-Security-Policy header value.
//
// Each resource contributes a host source expression according to its
// destination. [ResourceDestinationAuto] infers a primary destination;
// auto-inferred stylesheets also permit the same source for images and fonts.
// The same URL may be listed more than once with different explicit
// destinations.
//
// With no resources, the function returns the default policy, which includes
// style-src 'unsafe-inline'. HTTP, HTTPS, WebSocket and scheme-relative URLs
// with hosts are supported. A scheme-relative URL produces a schemeless
// source. For an HTTP protected resource it permits HTTP and HTTPS; for HTTPS
// it permits HTTPS only. It does not permit WebSocket connections; use an
// explicit ws:// or wss:// URL for those. A scheme-relative * host without a
// port is ignored. Internationalized hostnames must use their ASCII A-label
// (Punycode) form. Resources with nil URLs, hosts outside the CSP host-source
// grammar, unsupported schemes or unrecognized destination values do not
// contribute a source.
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
					destination, _ = InferResourceDestination(resource.URL)
				}
				switch destination {
				case ResourceDestinationScript:
					scriptSrc[source] = struct{}{}
				case ResourceDestinationStyle:
					styleSrc[source] = struct{}{}
					if inferred {
						// Relative stylesheet images and fonts resolve against the
						// stylesheet URL, so Auto permits the same source for them.
						imgSrc[source] = struct{}{}
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

func cspSourceExpr(u *url.URL) (src string) {
	if cspHostPattern.MatchString(u.Host) {
		switch scheme := strings.ToLower(u.Scheme); scheme {
		case "":
			// CSP gives the exact source expression "*" broader wildcard
			// semantics than a schemeless host-source, so do not emit it.
			if u.Host != "*" {
				src = strings.ToLower(u.Host)
			}
		case "http", "https", "ws", "wss":
			// Hosts are case-insensitive in CSP source matching, so lowercase
			// to keep the scheme handling consistent and avoid emitting two
			// redundant entries for sources that differ only in host case.
			src = scheme + "://" + strings.ToLower(u.Host)
		}
	}
	return
}

// cspHostPattern matches a CSP Level 3 host-part and optional port-part:
//
//	host-part = "*" / [ "*." ] 1*host-char *( "." 1*host-char ) [ "." ]
//	host-char = ALPHA / DIGIT / "-"
//	port-part = 1*DIGIT / "*"
//
// The grammar permits CSP wildcards and a trailing FQDN root dot. Its
// ASCII-only host-char requires A-label (Punycode) internationalized names.
var cspHostPattern = regexp.MustCompile(`^(?:\*|(?:\*\.)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.?)(?::(?:[0-9]+|\*))?$`)
