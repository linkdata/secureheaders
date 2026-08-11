package secureheaders

import (
	"mime"
	"net/url"
	"path"
	"strings"
)

// InferResourceDestination reports the conventional destination inferred for u.
//
// It returns the primary destination used by [ResourceDestinationAuto], which
// may add supplementary permissions when building a policy. The URL-based
// inference does not determine how an application actually requests a resource;
// callers that know the request context should use an explicit destination.
//
// It recognizes WebSocket schemes, common path extensions and registered MIME
// types. A nil or unclassified URL returns ([ResourceDestinationAuto], false).
// Inference does not validate whether the URL supplies a supported CSP host
// source.
func InferResourceDestination(u *url.URL) (destination ResourceDestination, ok bool) {
	if u != nil {
		switch strings.ToLower(u.Scheme) {
		case "ws", "wss":
			destination = ResourceDestinationConnect
			ok = true
			return
		}

		ext := strings.ToLower(path.Ext(u.Path))
		if destination, ok = resourceExtensionDestination[ext]; ok {
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
			ok = destination != ResourceDestinationAuto
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
