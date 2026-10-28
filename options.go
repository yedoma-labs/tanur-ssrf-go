package ssrf

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"time"
)

// Resolver resolves hostnames to IP addresses. *net.Resolver satisfies it.
// The resolver must be trusted: its answers decide which addresses are checked.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

var _ Resolver = (*net.Resolver)(nil)

// Option configures NewClient.
type Option func(*config)

type config struct {
	schemes      []string
	ports        []int
	allowPrivate bool
	maxRedirects int
	timeout      time.Duration
	resolver     Resolver
	blockedNames []string
	dial         dialFunc
	rootCAs      *x509.CertPool
}

func defaultConfig() config {
	return config{
		schemes:      []string{"http", "https"},
		ports:        []int{80, 443},
		maxRedirects: 5,
		timeout:      10 * time.Second,
		resolver:     net.DefaultResolver,
		blockedNames: []string{"localhost", "metadata.google.internal", ".localhost", ".internal"},
		dial:         (&net.Dialer{}).DialContext,
	}
}

func (c config) validate() error {
	if c.maxRedirects < 0 {
		return errors.New("ssrf: WithMaxRedirects must not be negative")
	}
	if c.timeout <= 0 {
		return errors.New("ssrf: WithTimeout must be greater than zero")
	}
	if c.resolver == nil {
		return errors.New("ssrf: WithResolver must not be nil")
	}
	return nil
}

// WithAllowedSchemes sets the accepted URL schemes. Only "http" and "https" are
// accepted values. Other values make NewClient fail. The default is http and https.
func WithAllowedSchemes(schemes ...string) Option {
	return func(c *config) {
		c.schemes = append([]string(nil), schemes...)
	}
}

// WithAllowPrivateNetworks disables the IP range checks for private, loopback,
// link-local and other reserved addresses. The hostname blocklist, the scheme
// and port allowlists and the credential check still apply. Use this only in
// tests, or for destinations you know and trust. The default is false.
func WithAllowPrivateNetworks(allow bool) Option {
	return func(c *config) {
		c.allowPrivate = allow
	}
}

// WithMaxRedirects sets how many redirects are followed. The redirect after
// that fails with ErrRedirectLimit. Zero means no redirects. The default is 5.
func WithMaxRedirects(n int) Option {
	return func(c *config) {
		c.maxRedirects = n
	}
}

// WithTimeout sets the deadline for the whole call. It covers DNS, connect,
// TLS, all redirect hops and reading the body. The default is 10 seconds.
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		c.timeout = d
	}
}

// WithAllowedPorts sets the ports that may be contacted. The default is 80 and 443.
func WithAllowedPorts(ports ...int) Option {
	return func(c *config) {
		c.ports = append([]int(nil), ports...)
	}
}

// WithResolver sets the resolver used for hostnames. The default is
// net.DefaultResolver.
func WithResolver(r Resolver) Option {
	return func(c *config) {
		c.resolver = r
	}
}

// WithBlockedHostnames replaces the default hostname blocklist. An entry with a
// leading "." matches the suffix and the bare name. Other entries match exactly.
// The default is localhost, metadata.google.internal, .localhost and .internal,
// so pass those again if you add your own entries.
func WithBlockedHostnames(names ...string) Option {
	return func(c *config) {
		c.blockedNames = append([]string(nil), names...)
	}
}

// withDialFunc replaces the raw dialer. Tests use it to observe the connected address.
func withDialFunc(dial dialFunc) Option {
	return func(c *config) {
		c.dial = dial
	}
}

// withRootCAs sets the trusted roots for TLS. Tests use it with httptest TLS servers.
func withRootCAs(pool *x509.CertPool) Option {
	return func(c *config) {
		c.rootCAs = pool
	}
}
