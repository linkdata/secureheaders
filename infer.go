package secureheaders

import (
	"mime"
	"net/url"
	"path"
	"strings"
)

// InferResourceDestinations reports the destinations
// [ResourceDestinationAuto] infers for u.
//
// The result is ([ResourceDestinationAuto], false) for a nil URL or when no
// automatic rule matches. Inference does not otherwise validate CSP source
// support or determine the application's request context.
func InferResourceDestinations(u *url.URL) (destinations ResourceDestination, recognized bool) {
	if u != nil {
		scheme := strings.ToLower(u.Scheme)
		switch scheme {
		case "ws", "wss":
			return ResourceDestinationConnect, true
		}

		if destinations, recognized = inferResourceDestinationsFromExtension(path.Ext(u.Path)); recognized {
			return
		}

		// Some CDNs append @version to the final filename. Ordinary extension
		// inference runs first so names such as icon@2x.png retain their final
		// extension.
		_, name := path.Split(u.Path)
		if i := strings.LastIndexByte(name, '@'); i > 0 && i < len(name)-1 {
			if destinations, recognized = inferResourceDestinationsFromExtension(path.Ext(name[:i])); recognized {
				return
			}
		}
		if !recognized && u.Hostname() != "" {
			switch scheme {
			case "", "http", "https":
				destinations = ResourceDestinationConnect
				recognized = true
			}
		}
	}
	return
}

func inferResourceDestinationsFromExtension(ext string) (destinations ResourceDestination, recognized bool) {
	ext = strings.ToLower(ext)
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
