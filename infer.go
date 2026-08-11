package secureheaders

import (
	"mime"
	"net/url"
	"path"
	"strings"
)

// InferResource reports automatic destinations and the matching path extension.
//
// The extension result includes its leading dot and is lower-case. It is empty
// when inference is based on the URL scheme or the generic connection fallback.
// The result is ([ResourceDestinationAuto], "") for a nil URL or when no
// automatic rule matches. Inference does not otherwise validate CSP source
// support or determine the application's request context. Use
// [ContentSecurityPolicySource] to determine whether a URL can contribute an
// explicit source.
func InferResource(u *url.URL) (destinations ResourceDestination, matchedExtension string) {
	if u != nil {
		scheme := strings.ToLower(u.Scheme)
		switch scheme {
		case "ws", "wss":
			return ResourceDestinationConnect, ""
		}

		matchedExtension = strings.ToLower(path.Ext(u.Path))
		if destinations = inferResourceDestinationsFromExtension(matchedExtension); destinations != ResourceDestinationAuto {
			return
		}

		// Some CDNs append @version to the final filename. Ordinary extension
		// inference runs first so names such as icon@2x.png retain their final
		// extension.
		_, name := path.Split(u.Path)
		if i := strings.LastIndexByte(name, '@'); i > 0 && i < len(name)-1 {
			matchedExtension = strings.ToLower(path.Ext(name[:i]))
			if destinations = inferResourceDestinationsFromExtension(matchedExtension); destinations != ResourceDestinationAuto {
				return
			}
		}
		matchedExtension = ""
		if u.Hostname() != "" {
			switch scheme {
			case "", "http", "https":
				destinations = ResourceDestinationConnect
			}
		}
	}
	return
}

func inferResourceDestinationsFromExtension(ext string) (destinations ResourceDestination) {
	ext = strings.ToLower(ext)
	if destinations = resourceExtensionDestinations[ext]; destinations != ResourceDestinationAuto {
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
