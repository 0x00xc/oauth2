package oauth2

import (
	"net/url"
	"testing"
)

func TestCheckRedirect(t *testing.T) {
	u1, _ := url.Parse("http://example.com/example?foo=bar#fragment")
	if checkRedirect(u1, []string{"http://a.example.com/foo/bar", "http://b.example.com/bar/foo", "http://foo.com/bar"}) {
		t.Fail()
	}
	if checkRedirect(u1, []string{"https://example.com", "http://another.com"}) {
		t.Fail()
	}
	if !checkRedirect(u1, []string{"http://example.com", "http://a.com"}) {
		t.Fail()
	}

	u2, _ := url.Parse("https://example.com/example?foo=bar#fragment")
	if !checkRedirect(u2, []string{"https://example.com", "http://another.com"}) {
		t.Fail()
	}
	if !checkRedirect(u2, []string{"http://example.com", "http://a.com"}) {
		t.Fail()
	}
}
