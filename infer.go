package secureheaders

import (
	"mime"
	"net/url"
	"path"
	"strings"
)

// InferResourceDestinations reports the destinations inferred for u.
//
// A recognized result selects the same directives when used explicitly as
// [Resource.Destination]. A nil or unclassified URL returns
// ([ResourceDestinationAuto], false). Inference does not validate CSP source
// support or determine the application's request context; use explicit
// destinations when the request context is known.
func InferResourceDestinations(u *url.URL) (destinations ResourceDestination, recognized bool) {
	if u != nil {
		switch strings.ToLower(u.Scheme) {
		case "ws", "wss":
			return ResourceDestinationConnect, true
		}

		ext := strings.ToLower(path.Ext(u.Path))
		if destinations, recognized = resourceExtensionDestinations[ext]; recognized {
			return
		}

		// ParseMediaType normalizes the MIME type and removes parameters before
		// matching extensions not in the explicit map.
		if mimetype, _, err := mime.ParseMediaType(mime.TypeByExtension(ext)); err == nil {
			switch mimetype {
			case "text/css":
				destinations = resourceDestinationsStylesheet
			case "text/javascript", "application/javascript", "application/ecmascript":
				destinations = ResourceDestinationScript
			default:
				switch {
				case strings.HasPrefix(mimetype, "image/"):
					destinations = ResourceDestinationImage
				case strings.HasPrefix(mimetype, "font/"):
					destinations = ResourceDestinationFont
				}
			}
			recognized = destinations != ResourceDestinationAuto
		}
	}
	return
}

// Stylesheets can resolve relative image and font references against their own
// origin. CSP source expressions grant the entire matching origin.
const resourceDestinationsStylesheet = ResourceDestinationStyle |
	ResourceDestinationImage |
	ResourceDestinationFont

// resourceExtensionDestinations maps a lowercased file extension (including
// the leading dot) to its conventional browser destinations.
//
// Extensions are consulted before the host MIME database so common resource
// inference stays deterministic across operating systems and minimal images.
var resourceExtensionDestinations = map[string]ResourceDestination{
	".js":    ResourceDestinationScript,
	".mjs":   ResourceDestinationScript,
	".css":   resourceDestinationsStylesheet,
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
