// Package ssrf provides an *http.Client for fetching URLs that users control,
// such as webhooks or image URLs, without server-side request forgery.
//
// The client resolves each hostname once, checks every resolved address,
// connects to a validated address and validates every redirect hop. It uses
// only the standard library.
//
// The package is imported as ssrf. The module path is
// github.com/yedoma-labs/tanur-ssrf-go.
package ssrf

import (
	"crypto/tls"
	"net/http"
)

// NewClient returns an *http.Client that enforces the SSRF policy on every
// request and every redirect hop. The returned client is safe for concurrent use.
//
// Limitations that the caller must know:
//   - Proxy environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY) are
//     ignored. A proxy would see the request without this policy applied.
//   - Connections are not reused (DisableKeepAlives). Every request resolves
//     and validates again, which is the price of the rebinding guarantee.
//   - The http.Client wraps errors in *url.Error, which includes the full URL
//     with its query string. Do not log that error text unredacted.
//   - Timeouts are enforced by http.Client.Timeout, which covers DNS, connect,
//     redirects and the body. Its error does not match ErrTimeout. Use
//     IsTimeout to detect a timeout.
//
// See the README for the full list of guarantees and limits.
func NewClient(opts ...Option) (*http.Client, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	pol, err := newPolicy(cfg)
	if err != nil {
		return nil, err
	}

	dialer := &pinnedDialer{
		policy:   pol,
		resolver: cfg.resolver,
		dial:     cfg.dial,
	}

	// Design decisions for the transport:
	//   - No static TLSClientConfig.ServerName. The transport derives SNI and
	//     certificate verification per connection from the request URL host.
	//     A fixed ServerName would be wrong for every other host that shares
	//     this transport. The Host header is taken from the URL as well.
	//   - No HTTP/2. ForceAttemptHTTP2 is not set, so a custom DialContext and
	//     TLSClientConfig keep the transport on HTTP/1.1. HTTP/2 would pool
	//     connections across requests and skip the per-request validation.
	//   - No connection reuse (DisableKeepAlives). Every request dials again,
	//     resolves again and validates again. This costs one handshake per
	//     request and removes any question about a connection validated under
	//     an earlier state.
	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       dialer.DialContext,
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    cfg.rootCAs,
		},
	}

	return &http.Client{
		Transport:     &guardedTransport{policy: pol, base: transport},
		CheckRedirect: newRedirectChecker(pol, cfg.maxRedirects),
		Timeout:       cfg.timeout,
	}, nil
}
