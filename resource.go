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
	// It uses [InferResourceDestination] to select its primary destination.
	//
	// WebSocket URLs select [ResourceDestinationConnect]. Other conventional
	// script, stylesheet, image and font resources are inferred from the URL's
	// path extension and registered MIME type. MIME type matching is
	// case-insensitive. An inferred stylesheet source is also permitted for
	// fonts. Unclassified resources are ignored.
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
	// It permits fetch, XMLHttpRequest, EventSource, navigator.sendBeacon and
	// WebSocket requests to the URL's source.
	ResourceDestinationConnect
)
