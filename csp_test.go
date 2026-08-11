package secureheaders_test

import (
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

func autoResources(urls ...*url.URL) (resources []secureheaders.Resource) {
	for _, u := range urls {
		resources = append(resources, secureheaders.Resource{URL: u})
	}
	return
}

func TestSecureHeaders_BuildContentSecurityPolicy_Default(t *testing.T) {
	for _, tc := range []struct {
		name      string
		resources []secureheaders.Resource
	}{
		{name: "nil"},
		{name: "empty", resources: []secureheaders.Resource{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := secureheaders.BuildContentSecurityPolicy(tc.resources...); got != defaultCSP {
				t.Fatalf("unexpected default CSP:\nwant: %q\ngot:  %q", defaultCSP, got)
			}
		})
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_AutoDestinations(t *testing.T) {
	resources := autoResources(
		mustParseURL(t, "https://scripts.example.com/module.mjs?version=1#fragment"),
		mustParseURL(t, "https://styles.example.com/app.css"),
		mustParseURL(t, "https://images.example.com/logo.png"),
		mustParseURL(t, "https://fonts.example.com/font.woff2"),
		&url.URL{Scheme: "WSS", Host: "Events.Example.com:8443", Path: "/socket.js"},
		mustParseURL(t, "https://unclassified.example.com/module.wasm"),
	)

	got := secureheaders.BuildContentSecurityPolicy(resources...)
	want := "default-src 'self'; " +
		"frame-ancestors 'none'; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"script-src 'self' https://scripts.example.com; " +
		"style-src 'self' 'unsafe-inline' https://styles.example.com; " +
		"img-src 'self' data: https://images.example.com; " +
		"font-src 'self' https://fonts.example.com https://styles.example.com; " +
		"connect-src 'self' wss://events.example.com:8443"
	if got != want {
		t.Fatalf("unexpected automatic-destination CSP:\nwant: %q\ngot:  %q", want, got)
	}
}

func TestSecureHeaders_InferPrimaryResourceDestination(t *testing.T) {
	for _, tc := range []struct {
		name            string
		u               *url.URL
		wantDestination secureheaders.ResourceDestination
		wantRecognized  bool
	}{
		{name: "nil"},
		{name: "empty URL", u: &url.URL{}},
		{name: "WebSocket", u: &url.URL{Scheme: "WSS", Host: "events.example.com"}, wantDestination: secureheaders.ResourceDestinationConnect, wantRecognized: true},
		{name: "JavaScript", u: &url.URL{Path: "/app.JS"}, wantDestination: secureheaders.ResourceDestinationScript, wantRecognized: true},
		{name: "JavaScript module with query", u: mustParseURL(t, "/module.mjs?version=1"), wantDestination: secureheaders.ResourceDestinationScript, wantRecognized: true},
		{name: "stylesheet", u: &url.URL{Path: "/app.css"}, wantDestination: secureheaders.ResourceDestinationStyle, wantRecognized: true},
		{name: "PNG image", u: &url.URL{Path: "/image.png"}, wantDestination: secureheaders.ResourceDestinationImage, wantRecognized: true},
		{name: "JPG image", u: &url.URL{Path: "/image.jpg"}, wantDestination: secureheaders.ResourceDestinationImage, wantRecognized: true},
		{name: "JPEG image", u: &url.URL{Path: "/image.jpeg"}, wantDestination: secureheaders.ResourceDestinationImage, wantRecognized: true},
		{name: "GIF image", u: &url.URL{Path: "/image.gif"}, wantDestination: secureheaders.ResourceDestinationImage, wantRecognized: true},
		{name: "WebP image", u: &url.URL{Path: "/image.webp"}, wantDestination: secureheaders.ResourceDestinationImage, wantRecognized: true},
		{name: "AVIF image", u: &url.URL{Path: "/image.avif"}, wantDestination: secureheaders.ResourceDestinationImage, wantRecognized: true},
		{name: "SVG image", u: &url.URL{Path: "/image.svg"}, wantDestination: secureheaders.ResourceDestinationImage, wantRecognized: true},
		{name: "ICO image", u: &url.URL{Path: "/image.ico"}, wantDestination: secureheaders.ResourceDestinationImage, wantRecognized: true},
		{name: "BMP image", u: &url.URL{Path: "/image.bmp"}, wantDestination: secureheaders.ResourceDestinationImage, wantRecognized: true},
		{name: "WOFF font", u: &url.URL{Path: "/font.woff"}, wantDestination: secureheaders.ResourceDestinationFont, wantRecognized: true},
		{name: "WOFF2 font", u: &url.URL{Path: "/font.WOFF2"}, wantDestination: secureheaders.ResourceDestinationFont, wantRecognized: true},
		{name: "TTF font", u: &url.URL{Path: "/font.ttf"}, wantDestination: secureheaders.ResourceDestinationFont, wantRecognized: true},
		{name: "OTF font", u: &url.URL{Path: "/font.otf"}, wantDestination: secureheaders.ResourceDestinationFont, wantRecognized: true},
		{name: "TTC font", u: &url.URL{Path: "/font.ttc"}, wantDestination: secureheaders.ResourceDestinationFont, wantRecognized: true},
		{name: "EOT font", u: &url.URL{Path: "/font.eot"}, wantDestination: secureheaders.ResourceDestinationFont, wantRecognized: true},
		{name: "stylesheet with unsupported source", u: mustParseURL(t, "ftp://files.example.com/app.css"), wantDestination: secureheaders.ResourceDestinationStyle, wantRecognized: true},
		{name: "unclassified HTTPS", u: mustParseURL(t, "https://api.example.com/module.wasm")},
		{name: "unclassified relative", u: &url.URL{Path: "/resource.unknown"}},
		{name: "unclassified scheme", u: mustParseURL(t, "ftp://files.example.com/resource.unknown")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotDestination, gotRecognized := secureheaders.InferPrimaryResourceDestination(tc.u)
			if gotDestination != tc.wantDestination || gotRecognized != tc.wantRecognized {
				t.Fatalf("InferPrimaryResourceDestination(%v) = (%v, %t), want (%v, %t)",
					tc.u, gotDestination, gotRecognized, tc.wantDestination, tc.wantRecognized)
			}
		})
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_ExplicitDestinations(t *testing.T) {
	shared := mustParseURL(t, "https://Shared.Example.com:8443/module.png")
	resources := []secureheaders.Resource{
		{URL: shared, Destination: secureheaders.ResourceDestinationScript},
		{URL: shared, Destination: secureheaders.ResourceDestinationConnect},
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
		"script-src 'self' https://shared.example.com:8443; " +
		"style-src 'self' 'unsafe-inline' https://styles.example.com; " +
		"img-src 'self' data: https://images.example.com; " +
		"font-src 'self' https://fonts.example.com; " +
		"connect-src 'self' http://api.example.com https://api.example.com https://shared.example.com:8443 " +
		"protocol.example.com:9443 ws://events.example.com wss://events.example.com"
	if got != want {
		t.Fatalf("unexpected explicit-destination CSP:\nwant: %q\ngot:  %q", want, got)
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_IgnoresInvalidResources(t *testing.T) {
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
		{name: "unknown destination", resource: secureheaders.Resource{
			URL:         mustParseURL(t, "https://invalid.example.com/app.js"),
			Destination: secureheaders.ResourceDestination(255),
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
			got := secureheaders.BuildContentSecurityPolicy(autoResources(u)...)
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

	got := secureheaders.BuildContentSecurityPolicy(autoResources(urls...)...)
	if !strings.Contains(got, "script-src 'self' https://cdn.example.com:8443") {
		t.Fatalf("expected HTTPS source with port, got: %q", got)
	}
	if !strings.Contains(got, "connect-src 'self' wss://events.example.com:8443") {
		t.Fatalf("expected WSS source with port, got: %q", got)
	}
}

func TestSecureHeaders_InferPrimaryResourceDestination_MIMEFallback(t *testing.T) {
	tests := []struct {
		name            string
		ext             string
		mimeType        string
		wantDestination secureheaders.ResourceDestination
		wantRecognized  bool
	}{
		{name: "text JavaScript", ext: ".customjs", mimeType: "TEXT/JAVASCRIPT", wantDestination: secureheaders.ResourceDestinationScript, wantRecognized: true},
		{name: "application JavaScript", ext: ".customappjs", mimeType: "APPLICATION/JAVASCRIPT", wantDestination: secureheaders.ResourceDestinationScript, wantRecognized: true},
		{name: "application ECMAScript", ext: ".customes", mimeType: "APPLICATION/ECMASCRIPT", wantDestination: secureheaders.ResourceDestinationScript, wantRecognized: true},
		{name: "stylesheet", ext: ".customcss", mimeType: "TeXt/CsS; ChArSeT=UTF-8", wantDestination: secureheaders.ResourceDestinationStyle, wantRecognized: true},
		{name: "image", ext: ".customimg", mimeType: "IMAGE/X-CUSTOM", wantDestination: secureheaders.ResourceDestinationImage, wantRecognized: true},
		{name: "font", ext: ".customfont", mimeType: "FONT/X-CUSTOM", wantDestination: secureheaders.ResourceDestinationFont, wantRecognized: true},
		{name: "image-like", ext: ".customimagery", mimeType: "IMAGERY/X-CUSTOM"},
		{name: "font-like", ext: ".customfontlike", mimeType: "FONTLIKE/X-CUSTOM"},
		{name: "stylesheet-like", ext: ".customcsslike", mimeType: "TEXT/CSSFOO"},
		{name: "JavaScript-like", ext: ".customjslike", mimeType: "TEXT/JAVASCRIPTFOO"},
		{name: "unmatched", ext: ".customjson", mimeType: "APPLICATION/JSON"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// An extension absent from the explicit map must fall back to the
			// standard library's MIME database. Register one so the test is
			// deterministic across hosts.
			if err := mime.AddExtensionType(tc.ext, tc.mimeType); err != nil {
				t.Fatalf("AddExtensionType: %v", err)
			}
			u := &url.URL{Path: "/asset" + tc.ext}
			gotDestination, gotRecognized := secureheaders.InferPrimaryResourceDestination(u)
			if gotDestination != tc.wantDestination || gotRecognized != tc.wantRecognized {
				t.Fatalf("InferPrimaryResourceDestination(%v) = (%v, %t), want (%v, %t)",
					u, gotDestination, gotRecognized, tc.wantDestination, tc.wantRecognized)
			}
		})
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_HostCaseFolded(t *testing.T) {
	urls := []*url.URL{
		mustParseURL(t, "https://CDN.Example.com/a.js"),
		mustParseURL(t, "https://cdn.example.com/b.js"),
	}
	got := secureheaders.BuildContentSecurityPolicy(autoResources(urls...)...)
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
