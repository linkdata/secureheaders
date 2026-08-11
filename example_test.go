package secureheaders_test

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/linkdata/secureheaders"
)

func ExampleBuildContentSecurityPolicyForURLs() {
	script := &url.URL{Scheme: "https", Host: "cdn.example.com", Path: "/app.js"}
	api := &url.URL{Scheme: "https", Host: "api.example.com", Path: "/data"}

	policy := secureheaders.BuildContentSecurityPolicyForURLs(script, api)
	for directive := range strings.SplitSeq(policy, "; ") {
		if strings.HasPrefix(directive, "script-src ") ||
			strings.HasPrefix(directive, "connect-src ") {
			fmt.Println(directive)
		}
	}

	// Output:
	// script-src 'self' https://cdn.example.com
	// connect-src 'self' https://api.example.com
}

func ExampleBuildContentSecurityPolicy() {
	stylesheet := &url.URL{Scheme: "https", Host: "cdn.example.com", Path: "/site.css"}
	api := &url.URL{Scheme: "https", Host: "api.example.com", Path: "/data"}

	policy := secureheaders.BuildContentSecurityPolicy(
		secureheaders.Resource{
			URL: stylesheet,
			Destination: secureheaders.ResourceDestinationStyle |
				secureheaders.ResourceDestinationFont,
		},
		secureheaders.Resource{URL: api, Destination: secureheaders.ResourceDestinationConnect},
	)
	for directive := range strings.SplitSeq(policy, "; ") {
		if strings.HasPrefix(directive, "style-src ") ||
			strings.HasPrefix(directive, "font-src ") ||
			strings.HasPrefix(directive, "connect-src ") {
			fmt.Println(directive)
		}
	}

	// Output:
	// style-src 'self' 'unsafe-inline' https://cdn.example.com
	// font-src 'self' https://cdn.example.com
	// connect-src 'self' https://api.example.com
}
