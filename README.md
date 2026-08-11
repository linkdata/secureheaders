[![build](https://github.com/linkdata/secureheaders/actions/workflows/build.yml/badge.svg)](https://github.com/linkdata/secureheaders/actions/workflows/build.yml)
[![coverage](https://github.com/linkdata/secureheaders/blob/coverage/main/badge.svg)](https://html-preview.github.io/?url=https://github.com/linkdata/secureheaders/blob/coverage/main/report.html)
[![Docs](https://godoc.org/github.com/linkdata/secureheaders?status.svg)](https://godoc.org/github.com/linkdata/secureheaders)

# secureheaders

`secureheaders` is an `http.Handler` middleware that writes a secure baseline of
HTTP response headers.

## Default headers

`SetHeaders` sets:

- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-Xss-Protection: 0`
- `Cross-Origin-Opener-Policy: same-origin-allow-popups`
- `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`

If the request is considered HTTPS, it also sets:

- `Strict-Transport-Security: max-age=31536000; includeSubDomains`

## Usage

```go
mux := http.NewServeMux()
mux.Handle("GET /", secureheaders.Middleware{
	Handler:               myHandler,
	TrustForwardedHeaders: true,
})
```

`TrustForwardedHeaders` controls whether forwarded headers are trusted when
checking if a request is secure.

Set it to `true` only when forwarding headers are set and sanitized by trusted
infrastructure (for example, your reverse proxy).

To customize the baseline, start from a copy of the defaults and pass it to the
middleware:

```go
headers := secureheaders.DefaultHeaders()
headers.Set("Content-Security-Policy", "default-src 'self'; object-src 'none'")

mux.Handle("GET /", secureheaders.Middleware{
	Handler: myHandler,
	Header:  headers,
})
```

## Security detection

`RequestIsSecure(r, trustForwardedHeaders)` always trusts `r.TLS != nil`.

When `trustForwardedHeaders` is `true`, it also checks:

- `X-Forwarded-Ssl: on`
- `Front-End-Https: on`
- `X-Forwarded-Proto`
- `Forwarded` (`proto=https`)

For list-valued forwarding headers, the first hop is used.

## CSP builder

`BuildContentSecurityPolicy(resources...)` builds a `Content-Security-Policy`
header value. Each `Resource` separates where a resource is located (`URL`)
from how the browser requests it (`Destination`). The URL's scheme, host and
port supply the CSP source expression; the destination selects the directive
that permits it. Paths, queries and fragments do not restrict the permission.

Behavior:

- Starts with a baseline policy:
  `default-src 'self'; frame-ancestors 'none'; object-src 'none';`
  `base-uri 'self'; form-action 'self'; script-src 'self';`
  `style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';`
  `connect-src 'self'`.
- Callers must parse and validate resource URLs from trusted application
  configuration; the builder does not sanitize them.
- `ResourceDestinationAuto`, the zero value, infers conventional resources:
  - `ws://`/`wss://` URLs select `connect-src`;
  - all other URLs are classified by their file extension:
    - an explicit list of common script, style, image and font extensions
      (including web fonts such as `.woff2`, `.otf` and `.eot`) is consulted
      first;
    - extensions not on that list fall back to the local MIME database
      (`mime.TypeByExtension`), matching media types case-insensitively and
      mapping `text/javascript`,
      `application/javascript` and `application/ecmascript` -> `script-src`,
      `text/css` -> `style-src`, `image/*` -> `img-src` and `font/*` ->
      `font-src`;
    - inferred stylesheet sources are also added to `img-src` and `font-src`,
      permitting relative images and fonts from the stylesheet's source;
    - other HTTP, HTTPS, scheme-relative and relative resources select
      `connect-src` as a generic fetch destination. Relative URLs are covered by
      the baseline `'self'` source.
- `InferResourceDestination` returns the primary destination that automatic
  inference would select without building a policy. Automatic stylesheet
  inference also permits same-source images and fonts. The function does not
  validate CSP source support. Its URL-based result is a conventional heuristic;
  applications that know how a resource is requested should use an explicit
  destination instead.
- An explicit destination bypasses inference and selects only its named CSP
  directive: script, style, image, font or connect. Connect permits fetches,
  XMLHttpRequest, EventSource, `navigator.sendBeacon` and WebSocket.
  `ResourceDestinationStyle` does not also select `img-src` or `font-src`; list
  a URL once per required destination.
- Automatic inference covers its selected destination and same-source relative
  image and font references from stylesheets. Other requests selected by
  resource contents require additional resources or explicit destinations.
- HTTP, HTTPS, WebSocket and scheme-relative URLs with hosts are supported.
  Nil URLs, URLs without hosts, unsupported schemes and unrecognized
  destination values are ignored.
- Hosts must match the CSP host-source grammar. IPv6 literals and hostnames
  containing underscores are ignored; internationalized hostnames must use
  their ASCII A-label (Punycode) form.
- A scheme-relative URL produces a schemeless source. For an HTTP protected
  resource it permits HTTP and HTTPS; for HTTPS it permits HTTPS only. It does
  not permit WebSocket connections; use an explicit `ws://` or `wss://` URL
  for those. A scheme-relative `*` host without a port is ignored.

Example:

```go
stylesheet := &url.URL{Scheme: "https", Host: "cdn.example.com", Path: "/site.css"}
module := &url.URL{Scheme: "https", Host: "modules.example.com", Path: "/module.wasm"}

csp := secureheaders.BuildContentSecurityPolicy(
	secureheaders.Resource{URL: stylesheet},
	secureheaders.Resource{URL: module},
)
w.Header().Set("Content-Security-Policy", csp)
```

## Extra headers

To add additional response headers, wrap your handler around the middleware
or set them in the wrapped handler itself after middleware processing.
