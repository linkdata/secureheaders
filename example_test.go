package secureheaders_test

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/linkdata/secureheaders"
)

func ExampleBuildContentSecurityPolicy() {
	stylesheet := &url.URL{Scheme: "https", Host: "cdn.example.com", Path: "/site.css"}
	module := &url.URL{Scheme: "https", Host: "modules.example.com", Path: "/module.wasm"}

	policy := secureheaders.BuildContentSecurityPolicy(
		secureheaders.Resource{URL: stylesheet},
		secureheaders.Resource{URL: module},
	)
	for directive := range strings.SplitSeq(policy, "; ") {
		if strings.HasPrefix(directive, "style-src ") ||
			strings.HasPrefix(directive, "img-src ") ||
			strings.HasPrefix(directive, "font-src ") ||
			strings.HasPrefix(directive, "connect-src ") {
			fmt.Println(directive)
		}
	}

	// Output:
	// style-src 'self' 'unsafe-inline' https://cdn.example.com
	// img-src 'self' data: https://cdn.example.com
	// font-src 'self' https://cdn.example.com
	// connect-src 'self' https://modules.example.com
}
