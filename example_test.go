package secureheaders_test

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/linkdata/secureheaders"
)

func ExampleBuildContentSecurityPolicy() {
	stylesheet, err := url.Parse("https://cdn.example.com/site.css")
	if err != nil {
		panic(err)
	}
	module, err := url.Parse("https://modules.example.com/module.wasm")
	if err != nil {
		panic(err)
	}

	policy := secureheaders.BuildContentSecurityPolicy(
		secureheaders.Resource{URL: stylesheet},
		secureheaders.Resource{URL: module, Destination: secureheaders.ResourceDestinationConnect},
	)
	for directive := range strings.SplitSeq(policy, "; ") {
		if strings.HasPrefix(directive, "style-src ") || strings.HasPrefix(directive, "connect-src ") {
			fmt.Println(directive)
		}
	}

	// Output:
	// style-src 'self' 'unsafe-inline' https://cdn.example.com
	// connect-src 'self' https://modules.example.com
}
