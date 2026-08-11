package secureheaders

import "net/url"

// Resource describes a URL used by a generated Content-Security-Policy.
//
// URL supplies the CSP source expression. Destination selects the directive
// that permits the resource.
type Resource struct {
	// URL identifies the resource.
	//
	// Its scheme, host and port form the CSP source expression. Its path, query
	// and fragment do not restrict that expression. A nil URL causes the
	// resource to be ignored.
	URL *url.URL

	// Destination selects the directive that permits the resource.
	//
	// Its zero value, [ResourceDestinationAuto], infers the destination from URL.
	Destination ResourceDestination
}

// ResourceDestination selects the CSP directive for a [Resource].
type ResourceDestination uint8

const (
	// ResourceDestinationAuto infers the destination from the resource URL.
	//
	// [InferPrimaryResourceDestination] reports the inferred primary destination.
	// WebSocket URLs select [ResourceDestinationConnect]. Conventional script,
	// stylesheet, image and font resources are inferred from the path extension
	// and registered MIME type; MIME matching is case-insensitive. The stylesheet
	// source expression is also added to font-src. Unclassified resources do not
	// contribute a source.
	ResourceDestinationAuto ResourceDestination = iota

	// ResourceDestinationScript selects script-src.
	ResourceDestinationScript

	// ResourceDestinationStyle selects style-src.
	//
	// It does not also select font-src. List the resource with
	// [ResourceDestinationFont] to permit both directives.
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
