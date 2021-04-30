package oauth2

import (
	"net/http"
	"net/url"
)

type Options struct {
	CheckRedirect      bool
	AccessTokenExpire  int64 //second
	RefreshTokenExpire int64 //second

	Generator Generator
	Verify    func(c Client, header http.Header, val url.Values) error
}

func DefaultOptions() *Options {
	return &Options{
		CheckRedirect:      true,
		AccessTokenExpire:  86400 * 3,
		RefreshTokenExpire: 86400 * 30,
		Generator:          NewSimpleGenerator(),
	}
}
