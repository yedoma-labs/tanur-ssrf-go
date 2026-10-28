package ssrf

import (
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestParseHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		raw       string
		want      string
		wantIP    bool
		wantError bool
	}{
		{"lowercases name", "Example.COM", "example.com", false, false},
		{"removes one trailing dot", "Example.COM.", "example.com", false, false},
		{"double trailing dot is invalid", "example.com..", "", false, true},
		{"single dot is invalid", ".", "", false, true},
		{"empty is invalid", "", "", false, true},
		{"space is invalid", "exa mple.com", "", false, true},
		{"non-ASCII is invalid", "bücher.de", "", false, true},
		{"empty label is invalid", "a..b", "", false, true},
		{"underscore is allowed", "a_b.example", "a_b.example", false, false},
		{"label longer than 63 is invalid", strings.Repeat("a", 64) + ".com", "", false, true},
		{"numeric hex form is invalid", "0x7f000001", "", false, true},
		{"single decimal number is invalid", "2130706433", "", false, true},
		{"octal IPv4 form is invalid", "0177.0.0.1", "", false, true},
		{"short IPv4 form is invalid", "127.1", "", false, true},
		{"zone identifier is invalid", "fe80::1%eth0", "", false, true},
		{"IPv4 literal", "127.0.0.1", "", true, false},
		{"IPv6 literal", "::1", "", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			name, addr, isIP, err := parseHost(tt.raw)
			if (err != nil) != tt.wantError {
				t.Fatalf("parseHost(%q) error = %v, want error %v", tt.raw, err, tt.wantError)
			}
			if err != nil {
				requireErrCode(t, err, ErrInvalidURL)
				return
			}
			if isIP != tt.wantIP {
				t.Fatalf("parseHost(%q) literal = %v, want %v", tt.raw, isIP, tt.wantIP)
			}
			if isIP {
				if !addr.IsValid() {
					t.Fatalf("parseHost(%q) returned invalid literal", tt.raw)
				}
				return
			}
			if name != tt.want {
				t.Fatalf("parseHost(%q) = %q, want %q", tt.raw, name, tt.want)
			}
		})
	}
}

func TestCheckURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rawURL    string
		wantCode  ErrCode
		wantHost  string
		wantPort  int
		noSecrets []string
	}{
		{name: "http default port", rawURL: "http://example.com/", wantHost: "example.com", wantPort: 80},
		{name: "https default port", rawURL: "https://example.com/", wantHost: "example.com", wantPort: 443},
		{name: "uppercase scheme", rawURL: "HTTP://example.com/", wantHost: "example.com", wantPort: 80},
		{name: "https on port 80 is in the allowlist", rawURL: "https://example.com:80/", wantHost: "example.com", wantPort: 80},
		{name: "explicit 443", rawURL: "http://example.com:443/", wantHost: "example.com", wantPort: 443},
		{name: "padded port is normalized", rawURL: "http://example.com:0080/", wantHost: "example.com", wantPort: 80},
		{name: "port outside allowlist", rawURL: "http://example.com:8080/", wantCode: ErrPortNotAllowed},
		{name: "port zero is invalid", rawURL: "http://example.com:0/", wantCode: ErrInvalidURL},
		{name: "port out of range", rawURL: "http://example.com:99999/", wantCode: ErrInvalidURL},
		{name: "ftp scheme", rawURL: "ftp://example.com/", wantCode: ErrProtocolNotAllowed},
		{name: "gopher scheme", rawURL: "gopher://example.com/", wantCode: ErrProtocolNotAllowed},
		{name: "file scheme", rawURL: "file:///etc/passwd", wantCode: ErrProtocolNotAllowed},
		//nolint:gosec // G101: intentional credentials fixture
		{name: "user and password", rawURL: "http://user:s3cretpw@example.com/", wantCode: ErrInvalidURL, noSecrets: []string{"s3cretpw", "user"}},
		{name: "user without password", rawURL: "http://user@example.com/", wantCode: ErrInvalidURL, noSecrets: []string{"user"}},
		{name: "empty userinfo", rawURL: "http://@example.com/", wantCode: ErrInvalidURL},
		{name: "no host", rawURL: "http:///path", wantCode: ErrInvalidURL},
		{name: "localhost", rawURL: "http://localhost/", wantCode: ErrBlockedHostname},
		{name: "localhost with trailing dot and case", rawURL: "http://LOCALHOST./", wantCode: ErrBlockedHostname},
		{name: "subdomain of localhost", rawURL: "http://a.localhost/", wantCode: ErrBlockedHostname},
		{name: "subdomain of internal", rawURL: "http://x.internal/", wantCode: ErrBlockedHostname},
		{name: "bare internal", rawURL: "http://internal/", wantCode: ErrBlockedHostname},
		{name: "metadata hostname", rawURL: "http://metadata.google.internal/", wantCode: ErrBlockedHostname},
		{name: "internal in the middle is allowed", rawURL: "http://internal.example.com/", wantHost: "internal.example.com", wantPort: 80},
		{name: "localhost as label prefix is allowed", rawURL: "http://notlocalhost.example/", wantHost: "notlocalhost.example", wantPort: 80},
		{name: "IPv4 loopback literal", rawURL: "http://127.0.0.1/", wantCode: ErrBlockedAddress},
		{name: "IPv6 loopback literal", rawURL: "http://[::1]/", wantCode: ErrBlockedAddress},
		{name: "IPv4-mapped private literal", rawURL: "http://[::ffff:10.0.0.1]/", wantCode: ErrBlockedAddress},
		{name: "metadata literal", rawURL: "http://169.254.169.254/latest/meta-data", wantCode: ErrBlockedAddress},
		{name: "public IPv4 literal", rawURL: "http://8.8.8.8/", wantHost: "8.8.8.8", wantPort: 80},
		{name: "hex IPv4 form", rawURL: "http://0x7f000001/", wantCode: ErrInvalidURL},
		{name: "decimal IPv4 form", rawURL: "http://2130706433/", wantCode: ErrInvalidURL},
		{name: "IPv6 zone", rawURL: "http://[fe80::1%25en0]/", wantCode: ErrInvalidURL},
		{name: "relative URL has no allowed scheme", rawURL: "/relative", wantCode: ErrProtocolNotAllowed},
	}

	p, err := newPolicy(defaultConfig())
	if err != nil {
		t.Fatalf("newPolicy: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("test fixture: url.Parse(%q): %v", tt.rawURL, err)
			}
			host, port, err := p.checkURL(u)
			if tt.wantCode != "" {
				requireErrCode(t, err, tt.wantCode)
				assertNoSecrets(t, err, tt.noSecrets)
				return
			}
			if err != nil {
				t.Fatalf("checkURL(%q) unexpected error: %v", tt.rawURL, err)
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Fatalf("checkURL(%q) = (%q, %d), want (%q, %d)", tt.rawURL, host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestCheckURLPrivateNetworks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rawURL   string
		wantCode ErrCode
	}{
		{name: "loopback literal allowed", rawURL: "http://127.0.0.1/"},
		{name: "IPv6 loopback allowed", rawURL: "http://[::1]/"},
		{name: "localhost stays blocked by hostname list", rawURL: "http://localhost/", wantCode: ErrBlockedHostname},
		{name: "scheme still checked", rawURL: "ftp://127.0.0.1/", wantCode: ErrProtocolNotAllowed},
	}

	cfg := defaultConfig()
	cfg.allowPrivate = true
	p, err := newPolicy(cfg)
	if err != nil {
		t.Fatalf("newPolicy: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("test fixture: %v", err)
			}
			_, _, err = p.checkURL(u)
			if tt.wantCode == "" {
				if err != nil {
					t.Fatalf("checkURL(%q) unexpected error: %v", tt.rawURL, err)
				}
				return
			}
			requireErrCode(t, err, tt.wantCode)
		})
	}
}

func TestCheckAddrRejectsZone(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.allowPrivate = true
	p, err := newPolicy(cfg)
	if err != nil {
		t.Fatalf("newPolicy: %v", err)
	}
	addr, err := netip.ParseAddr("2606:4700::1111%eth0")
	if err != nil {
		t.Fatalf("test fixture: %v", err)
	}
	requireErrCode(t, p.checkAddr(addr), ErrBlockedAddress)
	requireErrCode(t, p.checkAddr(netip.Addr{}), ErrBlockedAddress)
}

func TestCustomBlocklistReplacesDefaults(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.blockedNames = []string{"evil.test", ".corp"}
	p, err := newPolicy(cfg)
	if err != nil {
		t.Fatalf("newPolicy: %v", err)
	}

	tests := []struct {
		name     string
		rawURL   string
		wantCode ErrCode
	}{
		{name: "custom exact name", rawURL: "http://evil.test/", wantCode: ErrBlockedHostname},
		{name: "custom suffix", rawURL: "http://api.corp/", wantCode: ErrBlockedHostname},
		{name: "bare suffix name", rawURL: "http://corp/", wantCode: ErrBlockedHostname},
		{name: "subdomain of exact name is allowed", rawURL: "http://a.evil.test/", wantCode: ""},
		{name: "default localhost no longer in list", rawURL: "http://localhost/", wantCode: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("test fixture: %v", err)
			}
			_, _, err = p.checkURL(u)
			if tt.wantCode == "" {
				if err != nil {
					t.Fatalf("checkURL(%q) unexpected error: %v", tt.rawURL, err)
				}
				return
			}
			requireErrCode(t, err, tt.wantCode)
		})
	}
}

func TestNewPolicyRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*config)
	}{
		{"no schemes", func(c *config) { c.schemes = nil }},
		{"ftp scheme", func(c *config) { c.schemes = []string{"ftp"} }},
		{"no ports", func(c *config) { c.ports = nil }},
		{"port zero", func(c *config) { c.ports = []int{0} }},
		{"port too large", func(c *config) { c.ports = []int{65536} }},
		{"blocked entry is an IP", func(c *config) { c.blockedNames = []string{"10.0.0.1"} }},
		{"blocked entry is empty", func(c *config) { c.blockedNames = []string{""} }},
		{"blocked entry is a bare dot", func(c *config) { c.blockedNames = []string{"."} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			tt.mutate(&cfg)
			if _, err := newPolicy(cfg); err == nil {
				t.Fatal("newPolicy returned nil error for invalid config")
			}
		})
	}
}

func TestParsePort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want int
		ok   bool
	}{
		{"80", 80, true},
		{"0080", 80, true},
		{"65535", 65535, true},
		{"65536", 0, false},
		{"0", 0, false},
		{"", 0, false},
		{"+80", 0, false},
		{"-1", 0, false},
		{"8o", 0, false},
		{"123456", 0, false},
	}
	for _, tt := range tests {
		got, ok := parsePort(tt.raw)
		if got != tt.want || ok != tt.ok {
			t.Errorf("parsePort(%q) = (%d, %v), want (%d, %v)", tt.raw, got, ok, tt.want, tt.ok)
		}
	}
}

// requireErrCode fails unless err wraps a *SafeError with the given code, and
// that code is also matched by errors.Is.
func requireErrCode(t *testing.T, err error, want ErrCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error %s, got nil", want)
	}
	if !errors.Is(err, want) {
		t.Fatalf("want code %s, got error: %v", want, err)
	}
	var safeErr *SafeError
	if !errors.As(err, &safeErr) {
		t.Fatalf("error %v is not a *SafeError", err)
	}
	if safeErr.Code != want {
		t.Fatalf("code = %s, want %s", safeErr.Code, want)
	}
}

// assertNoSecrets fails if the SafeError message contains any of the values.
func assertNoSecrets(t *testing.T, err error, secrets []string) {
	t.Helper()
	var safeErr *SafeError
	if !errors.As(err, &safeErr) {
		t.Fatalf("error %v is not a *SafeError", err)
	}
	for _, secret := range secrets {
		if strings.Contains(safeErr.Error(), secret) {
			t.Fatalf("error message leaks %q: %s", secret, safeErr.Error())
		}
	}
}
