package secureheaders

import "net/url"

// Resource describes a URL used by a generated Content-Security-Policy.
//
// URL supplies the CSP source expression. Destination selects the directives
// that permit the resource.
type Resource struct {
	// URL identifies the resource.
	//
	// Its scheme, host and port form the CSP source expression. Its path, query
	// and fragment do not restrict that expression. A nil URL causes the
	// resource to be ignored.
	URL *url.URL

	// Destination selects the directives that permit the resource.
	//
	// Its zero value, [ResourceDestinationAuto], infers destinations from URL.
	// Other values may be combined with bitwise OR.
	Destination ResourceDestination
}

// ResourceDestination is a bitmask selecting CSP directives for a [Resource].
//
// Combine explicit destinations with bitwise OR. A resource whose destination
// contains an unknown bit does not contribute a source.
type ResourceDestination uint32

// ResourceDestinationAuto infers destinations from the resource URL.
//
// As the zero value, it applies when no explicit destination bits are set and
// has no effect when combined with explicit bits. To extend inference, combine
// the nonzero destinations returned by [InferResource] with explicit bits.
// WebSocket URLs select [ResourceDestinationConnect]. Conventional scripts,
// stylesheets, images and fonts are inferred from the path extension and
// registered MIME type; MIME matching is case-insensitive. When ordinary
// extension inference fails, a trailing @version suffix in the final path
// segment is ignored, so app.js@4.4.1 is inferred as JavaScript. An inferred
// stylesheet selects
// [ResourceDestinationStyle], [ResourceDestinationImage] and
// [ResourceDestinationFont]. An otherwise-unclassified HTTP, HTTPS or
// scheme-relative URL with a hostname selects [ResourceDestinationConnect].
//
// Inference uses URL conventions, not the actual request context. Hosted script
// and stylesheet URLs without a recognized asset extension fall back to
// [ResourceDestinationConnect] and need explicit destinations. A fetched URL
// with a recognized asset extension also needs [ResourceDestinationConnect].
// The builder does not generate worker-src, media-src, frame-src or manifest-src
// directives.
const ResourceDestinationAuto ResourceDestination = 0

const (
	// ResourceDestinationScript selects script-src.
	ResourceDestinationScript ResourceDestination = 1 << iota

	// ResourceDestinationStyle selects style-src.
	ResourceDestinationStyle

	// ResourceDestinationImage selects img-src.
	ResourceDestinationImage

	// ResourceDestinationFont selects font-src.
	ResourceDestinationFont

	// ResourceDestinationConnect selects connect-src.
	//
	// Use an HTTP, HTTPS or scheme-relative URL for fetch, XMLHttpRequest,
	// EventSource and navigator.sendBeacon. WebSocket connections require a ws
	// or wss URL.
	ResourceDestinationConnect
)
