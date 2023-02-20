package oidcmw

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// Middleware plugin implementation
type Middleware struct {
	CookieName string
	LoginURL   *url.URL

	*Verifier

	Next http.HandlerFunc
}

// New constructs a new Middleware instance
func New(ctx context.Context, next http.Handler, config *Config, name string) (_ http.Handler, err error) {
	fmt.Println("Configuring middleware plugin", config)
	cache := &KeyCache{}

	if config.AutoConfigure {
		info, err := AutoConfigure(ctx, config.Issuer)
		if err != nil {
			return nil, err
		}

		cache.Endpoint = info.KeysetEndpoint
	}

	if len(config.KeysetEndpoint) > 0 {
		cache.Endpoint = config.KeysetEndpoint
	}

	mw := &Middleware{
		CookieName: config.CookieName,
		Verifier: &Verifier{
			Issuer:   config.Issuer,
			ClientID: config.ClientID,

			Now:      time.Now,
			KeyCache: cache,

			SkipIssuerCheck:            config.SkipIssuerCheck,
			SkipClientIDCheck:          config.SkipClientIDCheck,
			SkipExpiryCheck:            config.SkipExpiryCheck,
			InsecureSkipSignatureCheck: config.InsecureSkipSignatureCheck,
		},
		Next: next.ServeHTTP,
	}

	err = mw.RefreshKeys(ctx)
	if err != nil {
		return
	}

	mw.LoginURL, err = url.Parse(config.LoginURL)
	if err != nil {
		return
	}

	return mw, nil
}

// ServeHTTP applies middleware logic to a request
func (plugin *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(plugin.CookieName)
	if err != nil {
		plugin.Login(w, r)
		return
	}

	raw, err := ParseToken(cookie.Value)
	if err != nil {
		plugin.Login(w, r)
		return
	}

	_, err = plugin.Verify(raw)
	if err != nil {
		fmt.Println(err)
		plugin.Login(w, r)
		return
	}

	// Successfully authenticated
	plugin.Next(w, r)
}

// Login redirects the user-agent to the configured login page
func (plugin *Middleware) Login(w http.ResponseWriter, r *http.Request) {
	// Construct an absolute URL from request parameters
	// TODO: Configure or detect whether downstream connection is over TLS
	referrer := "https://" + r.Host + r.URL.RequestURI()

	// Add referrer to login-url. Browsers do not consistently include a Referer
	// header in requests resulting from 302 responses
	referrer = "referrer_url=" + url.QueryEscape(referrer)

	login := *plugin.LoginURL

	// Resolve an absolute URL from the current request if LoginURL is relative
	if len(login.Host) == 0 {
		login.Host = r.Host
	}

	if !strings.HasPrefix(login.Path, "/") {
		login.Path = path.Join(r.URL.Path, login.Path)
	}

	// Append parameter to login URL's query string without parsing/copying map values
	if len(login.RawQuery) > 0 {
		login.RawQuery += "&" + referrer
	} else {
		login.RawQuery = referrer
	}

	// Redirect to the login page
	http.Redirect(w, r, login.String(), http.StatusFound)
}
