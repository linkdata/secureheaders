package secureheaders

import (
	"mime"
	"net/url"
	"path"
	"strings"
)

// InferPrimaryResourceDestination reports the primary destination inferred for u.
//
// A nil or unclassified URL returns ([ResourceDestinationAuto], false).
// Recognition does not validate CSP source support or determine the
// application's request context; use an explicit destination when the request
// context is known. [ResourceDestinationAuto] may grant permissions beyond the
// primary destination.
func InferPrimaryResourceDestination(u *url.URL) (destination ResourceDestination, recognized bool) {
	if u != nil {
		switch strings.ToLower(u.Scheme) {
		case "ws", "wss":
			return ResourceDestinationConnect, true
		}

		ext := strings.ToLower(path.Ext(u.Path))
		if destination, recognized = resourceExtensionDestination[ext]; recognized {
			return
		}

		// ParseMediaType normalizes the MIME type and removes parameters before
		// matching extensions not in the explicit map.
		if mimetype, _, err := mime.ParseMediaType(mime.TypeByExtension(ext)); err == nil {
			switch mimetype {
			case "text/css":
				destination = ResourceDestinationStyle
			case "text/javascript", "application/javascript", "application/ecmascript":
				destination = ResourceDestinationScript
			default:
				switch {
				case strings.HasPrefix(mimetype, "image/"):
					destination = ResourceDestinationImage
				case strings.HasPrefix(mimetype, "font/"):
					destination = ResourceDestinationFont
				}
			}
			recognized = destination != ResourceDestinationAuto
		}
	}
	return
}

// resourceExtensionDestination maps a lowercased file extension (including
// the leading dot) to its conventional browser destination.
//
// Extensions are consulted before the host MIME database so common resource
// inference stays deterministic across operating systems and minimal images.
var resourceExtensionDestination = map[string]ResourceDestination{
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
