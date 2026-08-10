package secureheaders_test

import (
	"mime"
	"net/url"
	"strings"
	"testing"

	"github.com/linkdata/secureheaders"
)

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
	want := "default-src 'self'; " +
		"frame-ancestors 'none'; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"script-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"font-src 'self'; " +
		"connect-src 'self'"
	for _, tc := range []struct {
		name      string
		resources []secureheaders.Resource
	}{
		{name: "nil"},
		{name: "empty", resources: []secureheaders.Resource{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := secureheaders.BuildContentSecurityPolicy(tc.resources); got != want {
				t.Fatalf("unexpected default CSP:\nwant: %q\ngot:  %q", want, got)
			}
		})
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_AutoDestinations(t *testing.T) {
	resources := autoResources(
		mustParseURL(t, "https://scripts.example.com/app.js?version=1#fragment"),
		mustParseURL(t, "https://styles.example.com/app.css"),
		mustParseURL(t, "https://images.example.com/logo.png"),
		mustParseURL(t, "https://fonts.example.com/font.woff2"),
		&url.URL{Scheme: "WSS", Host: "Events.Example.com:8443", Path: "/socket.js"},
		mustParseURL(t, "https://ignored.example.com/module.wasm"),
	)

	got := secureheaders.BuildContentSecurityPolicy(resources)
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
		{},
		{URL: nil, Destination: secureheaders.ResourceDestinationConnect},
		{URL: mustParseURL(t, "/relative/resource"), Destination: secureheaders.ResourceDestinationConnect},
		{URL: mustParseURL(t, "https:/missing-host"), Destination: secureheaders.ResourceDestinationConnect},
		{URL: mustParseURL(t, "ws:/missing-host"), Destination: secureheaders.ResourceDestinationConnect},
		{URL: mustParseURL(t, "ftp://files.example.com/resource"), Destination: secureheaders.ResourceDestinationConnect},
		{URL: mustParseURL(t, "https://invalid.example.com/app.js"), Destination: secureheaders.ResourceDestination(255)},
	}

	got := secureheaders.BuildContentSecurityPolicy(resources)
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

func TestSecureHeaders_BuildContentSecurityPolicy_SchemeRelativeResource(t *testing.T) {
	u := mustParseURL(t, "//CDN.Example.com:8443/app.js")
	got := secureheaders.BuildContentSecurityPolicy(autoResources(u))
	if !strings.Contains(got, "script-src 'self' cdn.example.com:8443") {
		t.Fatalf("expected scheme-relative script source, got: %q", got)
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_ValidSourcesWithPorts(t *testing.T) {
	urls := []*url.URL{
		mustParseURL(t, "https://cdn.example.com:8443/app.js"),
		mustParseURL(t, "https://[2001:db8::1]:443/font.woff2"),
		mustParseURL(t, "wss://events.example.com:8443/socket"),
	}

	got := secureheaders.BuildContentSecurityPolicy(autoResources(urls...))
	if !strings.Contains(got, "script-src 'self' https://cdn.example.com:8443") {
		t.Fatalf("expected HTTPS source with port, got: %q", got)
	}
	if !strings.Contains(got, "font-src 'self' https://[2001:db8::1]:443") {
		t.Fatalf("expected IPv6 source with port, got: %q", got)
	}
	if !strings.Contains(got, "connect-src 'self' wss://events.example.com:8443") {
		t.Fatalf("expected WSS source with port, got: %q", got)
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_StyleSourceAlsoAllowsFonts(t *testing.T) {
	urls := []*url.URL{
		mustParseURL(t, "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.min.css"),
	}
	got := secureheaders.BuildContentSecurityPolicy(autoResources(urls...))
	if !strings.Contains(got, "font-src 'self' https://cdn.jsdelivr.net") {
		t.Fatalf("expected stylesheet source to be added to font-src, got: %q", got)
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_FontExtensionWithQuery(t *testing.T) {
	urls := []*url.URL{
		mustParseURL(t, "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/fonts/bootstrap-icons.woff2?1fa40e"),
	}
	got := secureheaders.BuildContentSecurityPolicy(autoResources(urls...))
	if !strings.Contains(got, "font-src 'self' https://cdn.jsdelivr.net") {
		t.Fatalf("expected explicit .woff2 source in font-src, got: %q", got)
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_FontByExtension(t *testing.T) {
	urls := []*url.URL{
		mustParseURL(t, "https://cdn.jsdelivr.net/fonts/family.ttc"),
	}
	got := secureheaders.BuildContentSecurityPolicy(autoResources(urls...))
	if !strings.Contains(got, "font-src 'self' https://cdn.jsdelivr.net") {
		t.Fatalf("expected .ttc source in font-src, got: %q", got)
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_MIMEFallback(t *testing.T) {
	const host = "https://cdn.example.com"
	tests := []struct {
		name     string
		ext      string
		mimeType string
		wantSub  string // substring that must appear; "" means the host must be absent
	}{
		{"script", ".customjs", "text/javascript", "script-src 'self' " + host},
		{"script-application-javascript", ".customappjs", "application/javascript", "script-src 'self' " + host},
		{"script-application-ecmascript", ".customes", "application/ecmascript", "script-src 'self' " + host},
		{"style", ".customcss", "text/css", "style-src 'self' 'unsafe-inline' " + host},
		{"image", ".customimg", "image/x-custom", "img-src 'self' data: " + host},
		{"font", ".customfont", "font/x-custom", "font-src 'self' " + host},
		{"unmatched", ".customjson", "application/json", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// An extension absent from the explicit map must fall back to the
			// standard library's MIME database. Register one so the test is
			// deterministic across hosts.
			if err := mime.AddExtensionType(tc.ext, tc.mimeType); err != nil {
				t.Fatalf("AddExtensionType: %v", err)
			}
			u := mustParseURL(t, host+"/asset"+tc.ext)
			got := secureheaders.BuildContentSecurityPolicy(autoResources(u))
			if tc.wantSub == "" {
				if strings.Contains(got, host) {
					t.Fatalf("expected unmatched MIME type to be dropped, got: %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.wantSub) {
				t.Fatalf("expected %q in CSP, got: %q", tc.wantSub, got)
			}
		})
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_ResourceTypeDetection(t *testing.T) {
	const host = "https://cdn.example.com"
	tests := []struct {
		name    string
		path    string
		wantSub string // substring that must appear in the resulting CSP
	}{
		{"js script", "/j/a.js", "script-src 'self' " + host},
		{"mjs script", "/j/a.mjs", "script-src 'self' " + host},
		{"css style", "/s/a.css", "style-src 'self' 'unsafe-inline' " + host},
		{"png image", "/i/a.png", "img-src 'self' data: " + host},
		{"svg image", "/i/a.svg", "img-src 'self' data: " + host},
		{"ico image", "/i/a.ico", "img-src 'self' data: " + host},
		{"woff font", "/f/a.woff", "font-src 'self' " + host},
		{"woff2 font", "/f/a.woff2", "font-src 'self' " + host},
		{"ttf font", "/f/a.ttf", "font-src 'self' " + host},
		{"otf font", "/f/a.otf", "font-src 'self' " + host},
		{"eot font", "/f/a.eot", "font-src 'self' " + host},
		{"uppercase extension", "/f/A.WOFF2", "font-src 'self' " + host},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u := mustParseURL(t, host+tc.path)
			got := secureheaders.BuildContentSecurityPolicy(autoResources(u))
			if !strings.Contains(got, tc.wantSub) {
				t.Fatalf("expected %q in CSP, got: %q", tc.wantSub, got)
			}
		})
	}
}

func TestSecureHeaders_BuildContentSecurityPolicy_HostCaseFolded(t *testing.T) {
	urls := []*url.URL{
		mustParseURL(t, "https://CDN.Example.com/a.js"),
		mustParseURL(t, "https://cdn.example.com/b.js"),
	}
	got := secureheaders.BuildContentSecurityPolicy(autoResources(urls...))
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

func TestSecureHeaders_BuildContentSecurityPolicy_UnknownExtensionDropped(t *testing.T) {
	urls := []*url.URL{
		mustParseURL(t, "https://cdn.example.com/asset.bogus"),
	}
	got := secureheaders.BuildContentSecurityPolicy(autoResources(urls...))
	if strings.Contains(got, "cdn.example.com") {
		t.Fatalf("expected unknown extension to be dropped, got: %q", got)
	}
}
