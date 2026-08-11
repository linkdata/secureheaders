package secureheaders_test

import (
	"math/bits"
	"mime"
	"net/url"
	"strings"
	"testing"

	"github.com/linkdata/secureheaders"
)

const defaultCSP = "default-src 'self'; " +
	"frame-ancestors 'none'; " +
	"object-src 'none'; " +
	"base-uri 'self'; " +
	"form-action 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self'"

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestSecureHeaders_BuildContentSecurityPolicy_Default(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func() string
	}{
		{name: "nil resources", build: func() string {
			var resources []secureheaders.Resource
			return secureheaders.BuildContentSecurityPolicy(resources...)
		}},
		{name: "empty resources", build: func() string {
			return secureheaders.BuildContentSecurityPolicy([]secureheaders.Resource{}...)
		}},
		{name: "nil URLs", build: func() string {
			var urls []*url.URL
			return secureheaders.BuildContentSecurityPolicyForURLs(urls...)
		}},
		{name: "empty URLs", build: func() string {
			return secureheaders.BuildContentSecurityPolicyForURLs([]*url.URL{}...)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.build(); got != defaultCSP {
				t.Fatalf("unexpected default CSP:\nwant: %q\ngot:  %q", defaultCSP, got)
			}
		})
	}
}

func TestSecureHeaders_ResourceDestinationBits(t *testing.T) {
	if secureheaders.ResourceDestinationAuto != 0 {
		t.Fatalf("ResourceDestinationAuto = %d, want zero", secureheaders.ResourceDestinationAuto)
	}

	destinations := []secureheaders.ResourceDestination{
		secureheaders.ResourceDestinationScript,
		secureheaders.ResourceDestinationStyle,
		secureheaders.ResourceDestinationImage,
		secureheaders.ResourceDestinationFont,
		secureheaders.ResourceDestinationConnect,
	}
	var seen secureheaders.ResourceDestination
	for _, destination := range destinations {
		if bits.OnesCount64(uint64(destination)) != 1 {
			t.Fatalf("destination %d is not a single bit", destination)
		}
		if seen&destination != 0 {
			t.Fatalf("destination bit %d is reused", destination)
		}
		seen |= destination
	}
}

func TestSecureHeaders_InferredDestinationsMatchAuto(t *testing.T) {
	for _, rawURL := range []string{
		"https://scripts.example.com/module.mjs",
		"https://styles.example.com/app.css",
		"https://images.example.com/image.png",
		"https://fonts.example.com/font.woff2",
		"https://api.example.com/data",
		"wss://events.example.com/socket",
	} {
		t.Run(rawURL, func(t *testing.T) {
			u := mustParseURL(t, rawURL)
			destinations, recognized := secureheaders.InferResourceDestinations(u)
			if !recognized {
				t.Fatalf("InferResourceDestinations(%v) was not recognized", u)
			}
			got := secureheaders.BuildContentSecurityPolicy(secureheaders.Resource{URL: u})
			want := secureheaders.BuildContentSecurityPolicy(secureheaders.Resource{
				URL:         u,
				Destination: destinations,
			})
			if got != want {
				t.Fatalf("automatic and explicit policies differ:\nauto:     %q\nexplicit: %q", got, want)
			}
		})
	}
}

func TestSecureHeaders_BuildContentSecurityPolicyForURLs(t *testing.T) {
	urls := []*url.URL{
		nil,
		{},
		mustParseURL(t, "ftp://files.example.com/app.css"),
		mustParseURL(t, "https://scripts.example.com/module.mjs?version=1#fragment"),
		mustParseURL(t, "https://versioned.example.com/chart.js@4.4.1"),
		mustParseURL(t, "https://styles.example.com/app.css"),
		mustParseURL(t, "https://images.example.com/logo.png"),
		mustParseURL(t, "https://fonts.example.com/font.woff2"),
		{Scheme: "WSS", Host: "Events.Example.com:8443", Path: "/socket.js"},
		mustParseURL(t, "https://unclassified.example.com/module.wasm"),
		{Scheme: "https", Host: "*", Path: "/callback"},
		{Host: "*:*", Path: "/data"},
	}

	got := secureheaders.BuildContentSecurityPolicyForURLs(urls...)
	want := "default-src 'self'; " +
		"frame-ancestors 'none'; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"script-src 'self' https://scripts.example.com https://versioned.example.com; " +
		"style-src 'self' 'unsafe-inline' https://styles.example.com; " +
		"img-src 'self' data: https://images.example.com https://styles.example.com; " +
		"font-src 'self' https://fonts.example.com https://styles.example.com; " +
		"connect-src 'self' *:* https://* https://unclassified.example.com wss://events.example.com:8443"
	if got != want {
		t.Fatalf("unexpected automatic-destination CSP:\nwant: %q\ngot:  %q", want, got)
	}
}

func TestSecureHeaders_InferResourceDestinations(t *testing.T) {
	for _, tc := range []struct {
		name             string
		u                *url.URL
		wantDestinations secureheaders.ResourceDestination
	}{
		{name: "nil"},
		{name: "empty URL", u: &url.URL{}},
		{name: "WebSocket", u: &url.URL{Scheme: "WSS", Host: "events.example.com"}, wantDestinations: secureheaders.ResourceDestinationConnect},
		{name: "JavaScript", u: &url.URL{Path: "/app.JS"}, wantDestinations: secureheaders.ResourceDestinationScript},
		{name: "JavaScript module with query", u: mustParseURL(t, "/module.mjs?version=1"), wantDestinations: secureheaders.ResourceDestinationScript},
		{name: "versioned JavaScript", u: &url.URL{Path: "/chart.js@4.4.1"}, wantDestinations: secureheaders.ResourceDestinationScript},
		{name: "versioned stylesheet", u: &url.URL{Path: "/theme.css@2.1.0"}, wantDestinations: secureheaders.ResourceDestinationStyle | secureheaders.ResourceDestinationImage | secureheaders.ResourceDestinationFont},
		{name: "versioned image", u: &url.URL{Path: "/logo.png@2"}, wantDestinations: secureheaders.ResourceDestinationImage},
		{name: "versioned font", u: &url.URL{Path: "/font.woff2@1"}, wantDestinations: secureheaders.ResourceDestinationFont},
		{name: "versioned package directory", u: &url.URL{Path: "/pkg@4.4.1/app.js"}, wantDestinations: secureheaders.ResourceDestinationScript},
		{name: "at sign before extension", u: &url.URL{Path: "/logo@2x.png"}, wantDestinations: secureheaders.ResourceDestinationImage},
		{name: "last at sign starts version", u: &url.URL{Path: "/name@domain.js@1"}, wantDestinations: secureheaders.ResourceDestinationScript},
		{name: "recognized final extension wins", u: &url.URL{Path: "/archive.js@1.2.3.png"}, wantDestinations: secureheaders.ResourceDestinationImage},
		{name: "stylesheet final extension wins", u: &url.URL{Path: "/script.js@backup.css"}, wantDestinations: secureheaders.ResourceDestinationStyle | secureheaders.ResourceDestinationImage | secureheaders.ResourceDestinationFont},
		{name: "empty version suffix", u: &url.URL{Path: "/app.js@"}},
		{name: "versioned directory", u: &url.URL{Path: "/chart.js@4.4.1/"}},
		{name: "stylesheet", u: &url.URL{Path: "/app.css"}, wantDestinations: secureheaders.ResourceDestinationStyle | secureheaders.ResourceDestinationImage | secureheaders.ResourceDestinationFont},
		{name: "PNG image", u: &url.URL{Path: "/image.png"}, wantDestinations: secureheaders.ResourceDestinationImage},
		{name: "JPG image", u: &url.URL{Path: "/image.jpg"}, wantDestinations: secureheaders.ResourceDestinationImage},
		{name: "JPEG image", u: &url.URL{Path: "/image.jpeg"}, wantDestinations: secureheaders.ResourceDestinationImage},
		{name: "GIF image", u: &url.URL{Path: "/image.gif"}, wantDestinations: secureheaders.ResourceDestinationImage},
		{name: "WebP image", u: &url.URL{Path: "/image.webp"}, wantDestinations: secureheaders.ResourceDestinationImage},
		{name: "AVIF image", u: &url.URL{Path: "/image.avif"}, wantDestinations: secureheaders.ResourceDestinationImage},
		{name: "SVG image", u: &url.URL{Path: "/image.svg"}, wantDestinations: secureheaders.ResourceDestinationImage},
		{name: "ICO image", u: &url.URL{Path: "/image.ico"}, wantDestinations: secureheaders.ResourceDestinationImage},
		{name: "BMP image", u: &url.URL{Path: "/image.bmp"}, wantDestinations: secureheaders.ResourceDestinationImage},
		{name: "WOFF font", u: &url.URL{Path: "/font.woff"}, wantDestinations: secureheaders.ResourceDestinationFont},
		{name: "WOFF2 font", u: &url.URL{Path: "/font.WOFF2"}, wantDestinations: secureheaders.ResourceDestinationFont},
		{name: "TTF font", u: &url.URL{Path: "/font.ttf"}, wantDestinations: secureheaders.ResourceDestinationFont},
		{name: "OTF font", u: &url.URL{Path: "/font.otf"}, wantDestinations: secureheaders.ResourceDestinationFont},
		{name: "TTC font", u: &url.URL{Path: "/font.ttc"}, wantDestinations: secureheaders.ResourceDestinationFont},
		{name: "EOT font", u: &url.URL{Path: "/font.eot"}, wantDestinations: secureheaders.ResourceDestinationFont},
		{name: "stylesheet with unsupported source", u: mustParseURL(t, "ftp://files.example.com/app.css"), wantDestinations: secureheaders.ResourceDestinationStyle | secureheaders.ResourceDestinationImage | secureheaders.ResourceDestinationFont},
		{name: "unclassified HTTPS", u: mustParseURL(t, "https://api.example.com/module.wasm"), wantDestinations: secureheaders.ResourceDestinationConnect},
		{name: "unclassified HTTP", u: &url.URL{Scheme: "HTTP", Host: "api.example.com", Path: "/data"}, wantDestinations: secureheaders.ResourceDestinationConnect},
		{name: "unclassified scheme-relative", u: &url.URL{Host: "api.example.com", Path: "/data"}, wantDestinations: secureheaders.ResourceDestinationConnect},
		{name: "wildcard HTTPS", u: &url.URL{Scheme: "https", Host: "*", Path: "/data"}, wantDestinations: secureheaders.ResourceDestinationConnect},
		{name: "wildcard scheme-relative port", u: &url.URL{Host: "*:*", Path: "/data"}, wantDestinations: secureheaders.ResourceDestinationConnect},
		{name: "unclassified relative", u: &url.URL{Path: "/resource.unknown"}},
		{name: "unclassified scheme", u: mustParseURL(t, "ftp://files.example.com/resource.unknown")},
		{name: "hostless HTTPS", u: mustParseURL(t, "https:/api.example.com/data")},
		{name: "opaque HTTPS", u: mustParseURL(t, "https:opaque")},
		{name: "port-only scheme-relative", u: &url.URL{Host: ":8443", Path: "/data"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotDestinations, gotRecognized := secureheaders.InferResourceDestinations(tc.u)
			wantRecognized := tc.wantDestinations != secureheaders.ResourceDestinationAuto
			if gotDestinations != tc.wantDestinations || gotRecognized != wantRecognized {
				t.Fatalf("InferResourceDestinations(%v) = (%v, %t), want (%v, %t)",
					tc.u, gotDestinations, gotRecognized, tc.wantDestinations, wantRecognized)
			}
		})
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_MixedDestinations(t *testing.T) {
	shared := mustParseURL(t, "https://Shared.Example.com:8443/module.png")
	resources := []secureheaders.Resource{
		{URL: mustParseURL(t, "https://auto.example.com/app.js")},
		{URL: shared, Destination: secureheaders.ResourceDestinationScript |
			secureheaders.ResourceDestinationStyle |
			secureheaders.ResourceDestinationImage |
			secureheaders.ResourceDestinationFont |
			secureheaders.ResourceDestinationConnect},
		{URL: mustParseURL(t, "https://styles.example.com/app.js"), Destination: secureheaders.ResourceDestinationStyle},
		{URL: mustParseURL(t, "https://images.example.com/picture.woff2"), Destination: secureheaders.ResourceDestinationImage},
		{URL: mustParseURL(t, "https://fonts.example.com/font.css"), Destination: secureheaders.ResourceDestinationFont},
		{URL: mustParseURL(t, "http://api.example.com/data"), Destination: secureheaders.ResourceDestinationConnect},
		{URL: mustParseURL(t, "https://api.example.com/data"), Destination: secureheaders.ResourceDestinationConnect},
		{URL: mustParseURL(t, "ws://events.example.com/socket"), Destination: secureheaders.ResourceDestinationConnect},
		{URL: mustParseURL(t, "wss://events.example.com/socket"), Destination: secureheaders.ResourceDestinationConnect},
		{URL: mustParseURL(t, "//Protocol.Example.com:9443/resource"), Destination: secureheaders.ResourceDestinationConnect},
		{URL: mustParseURL(t, "https://api.example.com/duplicate"), Destination: secureheaders.ResourceDestinationConnect},
	}

	got := secureheaders.BuildContentSecurityPolicy(resources...)
	want := "default-src 'self'; " +
		"frame-ancestors 'none'; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"script-src 'self' https://auto.example.com https://shared.example.com:8443; " +
		"style-src 'self' 'unsafe-inline' https://shared.example.com:8443 https://styles.example.com; " +
		"img-src 'self' data: https://images.example.com https://shared.example.com:8443; " +
		"font-src 'self' https://fonts.example.com https://shared.example.com:8443; " +
		"connect-src 'self' http://api.example.com https://api.example.com https://shared.example.com:8443 " +
		"protocol.example.com:9443 ws://events.example.com wss://events.example.com"
	if got != want {
		t.Fatalf("unexpected mixed-destination CSP:\nwant: %q\ngot:  %q", want, got)
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_IgnoresInvalidResources(t *testing.T) {
	unknownDestination := secureheaders.ResourceDestination(1 << 31)
	tests := []struct {
		name     string
		resource secureheaders.Resource
	}{
		{name: "zero resource"},
		{name: "nil URL", resource: secureheaders.Resource{Destination: secureheaders.ResourceDestinationConnect}},
		{name: "relative URL", resource: secureheaders.Resource{URL: mustParseURL(t, "/relative/app.js")}},
		{name: "HTTPS without host", resource: secureheaders.Resource{URL: mustParseURL(t, "https:/app.js")}},
		{name: "WebSocket without host", resource: secureheaders.Resource{URL: mustParseURL(t, "ws:/socket")}},
		{name: "unsupported scheme", resource: secureheaders.Resource{URL: mustParseURL(t, "ftp://files.example.com/app.js")}},
		{name: "scheme-relative bare wildcard", resource: secureheaders.Resource{URL: &url.URL{Host: "*", Path: "/app.js"}}},
		{name: "unknown destination bit", resource: secureheaders.Resource{
			URL:         mustParseURL(t, "https://invalid.example.com/app.js"),
			Destination: unknownDestination,
		}},
		{name: "known and unknown destination bits", resource: secureheaders.Resource{
			URL:         mustParseURL(t, "https://invalid.example.com/app.js"),
			Destination: secureheaders.ResourceDestinationScript | unknownDestination,
		}},
		{name: "directive delimiter", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "cdn.example.com;script-src", Path: "/app.js"}}},
		{name: "policy delimiter", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "cdn.example.com,default-src", Path: "/app.js"}}},
		{name: "space", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "cdn.example.com evil.example.com", Path: "/app.js"}}},
		{name: "line break", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "cdn.example.com\r\nscript-src *", Path: "/app.js"}}},
		{name: "underscore", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "internal_host.example", Path: "/app.js"}}},
		{name: "IPv6", resource: secureheaders.Resource{URL: mustParseURL(t, "https://[2001:db8::1]:443/app.js")}},
		{name: "empty first label", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: ".example.com", Path: "/app.js"}}},
		{name: "empty label", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "cdn..example.com", Path: "/app.js"}}},
		{name: "invalid wildcard", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "*cdn.example.com", Path: "/app.js"}}},
		{name: "nested wildcard", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "cdn.*.example.com", Path: "/app.js"}}},
		{name: "empty host with port", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: ":443", Path: "/app.js"}}},
		{name: "dot host with port", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: ".:443", Path: "/app.js"}}},
		{name: "empty wildcard host with port", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "*.:443", Path: "/app.js"}}},
		{name: "empty port", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "cdn.example.com:", Path: "/app.js"}}},
		{name: "invalid port", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "cdn.example.com:http", Path: "/app.js"}}},
		{name: "invalid wildcard port", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "*:http", Path: "/app.js"}}},
		{name: "mixed wildcard port", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "cdn.example.com:*1", Path: "/app.js"}}},
		{name: "multiple ports", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "cdn.example.com:80:90", Path: "/app.js"}}},
		{name: "userinfo delimiter", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "user@cdn.example.com", Path: "/app.js"}}},
		{name: "path delimiter", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "cdn.example.com/path", Path: "/app.js"}}},
		{name: "Unicode host", resource: secureheaders.Resource{URL: &url.URL{Scheme: "https", Host: "café.example", Path: "/app.js"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := secureheaders.BuildContentSecurityPolicy(tc.resource); got != defaultCSP {
				t.Fatalf("unexpected CSP for ignored resource:\nwant: %q\ngot:  %q", defaultCSP, got)
			}
		})
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_CSPHostSources(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		source string
	}{
		{name: "hostname and port", host: "CDN.Example.com:8443", source: "https://cdn.example.com:8443"},
		{name: "wildcard hostname", host: "*.CDN.Example.com", source: "https://*.cdn.example.com"},
		{name: "bare wildcard", host: "*", source: "https://*"},
		{name: "wildcard host and port", host: "*:*", source: "https://*:*"},
		{name: "wildcard port", host: "CDN.Example.com:*", source: "https://cdn.example.com:*"},
		{name: "trailing dot", host: "CDN.Example.com.", source: "https://cdn.example.com."},
		{name: "combined wildcard", host: "*.CDN.Example.com.:*", source: "https://*.cdn.example.com.:*"},
		{name: "hyphen label", host: "-edge.Example.com", source: "https://-edge.example.com"},
		{name: "Punycode", host: "xn--bcher-kva.Example", source: "https://xn--bcher-kva.example"},
		{name: "IPv4", host: "192.0.2.1:8443", source: "https://192.0.2.1:8443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resource := secureheaders.Resource{
				URL:         &url.URL{Scheme: "https", Host: tc.host, Path: "/app.js"},
				Destination: secureheaders.ResourceDestinationScript,
			}
			want := strings.Replace(defaultCSP, "script-src 'self'", "script-src 'self' "+tc.source, 1)
			if got := secureheaders.BuildContentSecurityPolicy(resource); got != want {
				t.Fatalf("unexpected CSP host source:\nwant: %q\ngot:  %q", want, got)
			}
		})
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_SchemeRelativeResource(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		source string
	}{
		{name: "hostname", host: "CDN.Example.com:8443", source: "cdn.example.com:8443"},
		{name: "wildcard host and port", host: "*:*", source: "*:*"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u := &url.URL{Host: tc.host, Path: "/app.js"}
			got := secureheaders.BuildContentSecurityPolicyForURLs(u)
			want := strings.Replace(defaultCSP, "script-src 'self'", "script-src 'self' "+tc.source, 1)
			if got != want {
				t.Fatalf("unexpected scheme-relative CSP:\nwant: %q\ngot:  %q", want, got)
			}
		})
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_ValidSourcesWithPorts(t *testing.T) {
	urls := []*url.URL{
		mustParseURL(t, "https://cdn.example.com:8443/app.js"),
		mustParseURL(t, "wss://events.example.com:8443/socket"),
	}

	got := secureheaders.BuildContentSecurityPolicyForURLs(urls...)
	if !strings.Contains(got, "script-src 'self' https://cdn.example.com:8443") {
		t.Fatalf("expected HTTPS source with port, got: %q", got)
	}
	if !strings.Contains(got, "connect-src 'self' wss://events.example.com:8443") {
		t.Fatalf("expected WSS source with port, got: %q", got)
	}
}

func TestSecureHeaders_InferResourceDestinations_MIMEFallback(t *testing.T) {
	tests := []struct {
		name             string
		ext              string
		mimeType         string
		hosted           bool
		suffix           string
		wantDestinations secureheaders.ResourceDestination
	}{
		{name: "text JavaScript", ext: ".customjs", mimeType: "TEXT/JAVASCRIPT", hosted: true, wantDestinations: secureheaders.ResourceDestinationScript},
		{name: "application JavaScript", ext: ".customappjs", mimeType: "APPLICATION/JAVASCRIPT", hosted: true, wantDestinations: secureheaders.ResourceDestinationScript},
		{name: "application ECMAScript", ext: ".customes", mimeType: "APPLICATION/ECMASCRIPT", hosted: true, wantDestinations: secureheaders.ResourceDestinationScript},
		{name: "versioned stylesheet", ext: ".customcss", mimeType: "TeXt/CsS; ChArSeT=UTF-8", hosted: true, suffix: "@4.4.1", wantDestinations: secureheaders.ResourceDestinationStyle | secureheaders.ResourceDestinationImage | secureheaders.ResourceDestinationFont},
		{name: "image", ext: ".customimg", mimeType: "IMAGE/X-CUSTOM", hosted: true, wantDestinations: secureheaders.ResourceDestinationImage},
		{name: "font", ext: ".customfont", mimeType: "FONT/X-CUSTOM", hosted: true, wantDestinations: secureheaders.ResourceDestinationFont},
		{name: "image-like", ext: ".customimagery", mimeType: "IMAGERY/X-CUSTOM"},
		{name: "font-like", ext: ".customfontlike", mimeType: "FONTLIKE/X-CUSTOM"},
		{name: "stylesheet-like", ext: ".customcsslike", mimeType: "TEXT/CSSFOO"},
		{name: "JavaScript-like", ext: ".customjslike", mimeType: "TEXT/JAVASCRIPTFOO"},
		{name: "unmatched", ext: ".customjson", mimeType: "APPLICATION/JSON"},
		{name: "hosted unmatched", ext: ".customhostedjson", mimeType: "APPLICATION/JSON", hosted: true, wantDestinations: secureheaders.ResourceDestinationConnect},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// An extension absent from the explicit map must fall back to the
			// standard library's MIME database. Register one so the test is
			// deterministic across hosts.
			if err := mime.AddExtensionType(tc.ext, tc.mimeType); err != nil {
				t.Fatalf("AddExtensionType: %v", err)
			}
			u := &url.URL{Path: "/asset" + tc.ext + tc.suffix}
			if tc.hosted {
				u.Scheme = "https"
				u.Host = "mime.example.com"
			}
			gotDestinations, gotRecognized := secureheaders.InferResourceDestinations(u)
			wantRecognized := tc.wantDestinations != secureheaders.ResourceDestinationAuto
			if gotDestinations != tc.wantDestinations || gotRecognized != wantRecognized {
				t.Fatalf("InferResourceDestinations(%v) = (%v, %t), want (%v, %t)",
					u, gotDestinations, gotRecognized, tc.wantDestinations, wantRecognized)
			}
		})
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_HostCaseFolded(t *testing.T) {
	urls := []*url.URL{
		mustParseURL(t, "https://CDN.Example.com/a.js"),
		mustParseURL(t, "https://cdn.example.com/b.js"),
	}
	got := secureheaders.BuildContentSecurityPolicyForURLs(urls...)
	if !strings.Contains(got, "script-src 'self' https://cdn.example.com") {
		t.Fatalf("expected lowercased host source, got: %q", got)
	}
	// The two URLs differ only in host case, so they must collapse to a
	// single source rather than appearing twice.
	if n := strings.Count(got, "cdn.example.com"); n != 1 {
		t.Fatalf("expected host to appear once, appeared %d times: %q", n, got)
	}
	if strings.Contains(got, "CDN.Example.com") {
		t.Fatalf("expected host to be lowercased, got: %q", got)
	}
}
