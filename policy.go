package ssrf

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// policy holds the URL and address rules. It is read-only after newPolicy.
type policy struct {
	schemes      map[string]bool
	ports        map[int]bool
	allowPrivate bool
	// blockedNames holds normalized names. An entry with a leading "." matches
	// the suffix and the bare name, so ".internal" matches "internal" and
	// "a.b.internal".
	blockedNames []string
}

// newPolicy validates the configured lists and normalizes them.
func newPolicy(cfg config) (*policy, error) {
	p := &policy{
		schemes:      make(map[string]bool, len(cfg.schemes)),
		ports:        make(map[int]bool, len(cfg.ports)),
		allowPrivate: cfg.allowPrivate,
	}

	if len(cfg.schemes) == 0 {
		return nil, errors.New("ssrf: at least one allowed scheme is required")
	}
	for _, raw := range cfg.schemes {
		scheme := strings.ToLower(raw)
		if scheme != "http" && scheme != "https" {
			return nil, fmt.Errorf("ssrf: unsupported scheme %q, only http and https are dispatched", raw)
		}
		p.schemes[scheme] = true
	}

	if len(cfg.ports) == 0 {
		return nil, errors.New("ssrf: at least one allowed port is required")
	}
	for _, port := range cfg.ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("ssrf: port %d is out of range", port)
		}
		p.ports[port] = true
	}

	for _, entry := range cfg.blockedNames {
		suffix := strings.HasPrefix(entry, ".")
		name, _, isLiteral, err := parseHost(strings.TrimPrefix(entry, "."))
		if err != nil || isLiteral {
			return nil, fmt.Errorf("ssrf: blocked hostname %q is not a valid name", entry)
		}
		if suffix {
			name = "." + name
		}
		p.blockedNames = append(p.blockedNames, name)
	}
	return p, nil
}

// checkURL validates a URL before any connection is made: scheme, credentials,
// host, port, hostname blocklist and, for IP literals, the address ranges. It
// returns the normalized hostname and the effective port. Hostnames that are
// not literals are checked against the address ranges at dial time, on the
// resolved addresses.
func (p *policy) checkURL(u *url.URL) (string, int, error) {
	if u == nil {
		return "", 0, newError(ErrInvalidURL, "missing URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if !p.schemes[scheme] {
		return "", 0, newError(ErrProtocolNotAllowed, "URL scheme is not allowed")
	}
	if u.User != nil {
		return "", 0, newError(ErrInvalidURL, "credentials in URL are not allowed")
	}
	if u.Opaque != "" || u.Host == "" {
		return "", 0, newError(ErrInvalidURL, "URL has no host")
	}

	port, err := effectivePort(scheme, u.Port())
	if err != nil {
		return "", 0, err
	}
	if !p.ports[port] {
		return "", 0, newError(ErrPortNotAllowed, fmt.Sprintf("port %d is not allowed", port))
	}

	name, addr, isLiteral, err := parseHost(u.Hostname())
	if err != nil {
		return "", 0, err
	}
	if isLiteral {
		if err := p.checkAddr(addr); err != nil {
			return "", 0, err
		}
		return addr.String(), port, nil
	}
	if p.hostnameBlocked(name) {
		return "", 0, newError(ErrBlockedHostname, fmt.Sprintf("hostname %q is blocked", name))
	}
	return name, port, nil
}

// checkAddr rejects invalid or zone-scoped addresses always, and blocked ranges
// unless private networks are allowed.
func (p *policy) checkAddr(addr netip.Addr) error {
	if !addr.IsValid() || addr.Zone() != "" {
		return newError(ErrBlockedAddress, "address is invalid or zone-scoped")
	}
	if p.allowPrivate {
		return nil
	}
	if reason, blocked := classify(addr); blocked {
		return newError(ErrBlockedAddress, fmt.Sprintf("address %s is blocked: %s", addr, reason))
	}
	return nil
}

// hostnameBlocked reports whether a normalized name matches the blocklist.
func (p *policy) hostnameBlocked(name string) bool {
	for _, blocked := range p.blockedNames {
		if strings.HasPrefix(blocked, ".") {
			if name == blocked[1:] || strings.HasSuffix(name, blocked) {
				return true
			}
			continue
		}
		if name == blocked {
			return true
		}
	}
	return false
}

func effectivePort(scheme, raw string) (int, error) {
	if raw == "" {
		if scheme == "https" {
			return 443, nil
		}
		return 80, nil
	}
	port, ok := parsePort(raw)
	if !ok {
		return 0, newError(ErrInvalidURL, "invalid port")
	}
	return port, nil
}

// parsePort accepts decimal digits only and a value from 1 to 65535.
func parsePort(raw string) (int, bool) {
	if raw == "" || len(raw) > 5 {
		return 0, false
	}
	port := 0
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		port = port*10 + int(c-'0')
	}
	if port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

// parseHost normalizes a host from a URL or a configuration entry. IP literals
// are returned parsed. Names are lowercased and lose one trailing dot. Names
// must be ASCII letters, digits, '-' and '_' separated by dots. The last
// label must not be all digits, which rejects non-canonical IPv4 forms such as
// "0x7f000001", "2130706433" or "0177.0.0.1" before any resolver sees them.
func parseHost(raw string) (string, netip.Addr, bool, error) {
	if raw == "" {
		return "", netip.Addr{}, false, newError(ErrInvalidURL, "empty host")
	}
	if strings.Contains(raw, "%") {
		return "", netip.Addr{}, false, newError(ErrInvalidURL, "zone identifiers are not allowed")
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		return "", addr, true, nil
	}

	name := strings.TrimSuffix(strings.ToLower(raw), ".")
	if !validDNSName(name) {
		return "", netip.Addr{}, false, newError(ErrInvalidURL, "invalid host name")
	}
	return name, netip.Addr{}, false, nil
}

func validDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			isAllowed := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !isAllowed {
				return false
			}
		}
	}
	return !isNumericLabel(labels[len(labels)-1])
}

// isNumericLabel reports whether a label is all decimal digits or a hex form
// with a 0x prefix. No public TLD has this shape.
func isNumericLabel(label string) bool {
	if allDigits(label) {
		return true
	}
	if len(label) >= 2 && label[0] == '0' && label[1] == 'x' {
		for i := 2; i < len(label); i++ {
			c := label[i]
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
			if !isHex {
				return false
			}
		}
		return true
	}
	return false
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
