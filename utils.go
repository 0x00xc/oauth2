package oauth2

import (
	"net/url"
)

func checkRedirect(redirect *url.URL, redirects []string) bool {
	for _, v := range redirects {
		u2, err := url.Parse(v)
		if err != nil {
			continue
		}
		if redirect.Host == u2.Host && (redirect.Scheme == "https" || redirect.Scheme == u2.Scheme) {
			return true
		}
	}
	return false
}
