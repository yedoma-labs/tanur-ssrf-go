package ssrf

import (
	"fmt"
	"net"
	"net/netip"
)

// blockedRange is a prefix that must never be a connection target.
type blockedRange struct {
	prefix netip.Prefix
	reason string
}

func rng(cidr, reason string) blockedRange {
	return blockedRange{prefix: netip.MustParsePrefix(cidr), reason: reason}
}

// blockedIPv4 lists the IPv4 ranges that are not valid public destinations.
var blockedIPv4 = []blockedRange{
	rng("0.0.0.0/8", "unspecified or 'this network' (0.0.0.0/8)"),
	rng("10.0.0.0/8", "private (10.0.0.0/8)"),
	rng("100.64.0.0/10", "shared address space (100.64.0.0/10)"),
	rng("127.0.0.0/8", "loopback (127.0.0.0/8)"),
	rng("169.254.0.0/16", "link-local, includes cloud metadata (169.254.0.0/16)"),
	rng("172.16.0.0/12", "private (172.16.0.0/12)"),
	rng("192.0.0.0/24", "IETF protocol assignments (192.0.0.0/24)"),
	rng("192.0.2.0/24", "documentation (192.0.2.0/24)"),
	rng("192.168.0.0/16", "private (192.168.0.0/16)"),
	rng("198.18.0.0/15", "benchmarking (198.18.0.0/15)"),
	rng("198.51.100.0/24", "documentation (198.51.100.0/24)"),
	rng("203.0.113.0/24", "documentation (203.0.113.0/24)"),
	rng("224.0.0.0/4", "multicast (224.0.0.0/4)"),
	rng("240.0.0.0/4", "reserved (240.0.0.0/4)"),
	rng("255.255.255.255/32", "limited broadcast (255.255.255.255)"),
}

// blockedIPv6 lists the native IPv6 ranges that are not valid public
// destinations. Ranges that embed an IPv4 address are handled in classifyIPv6.
var blockedIPv6 = []blockedRange{
	rng("::/128", "unspecified address (::/128)"),
	rng("::1/128", "loopback (::1/128)"),
	rng("::/96", "deprecated IPv4-compatible space (::/96)"),
	rng("100::/64", "discard-only (100::/64)"),
	rng("64:ff9b:1::/48", "local-use NAT64 (64:ff9b:1::/48)"),
	rng("2001:db8::/32", "documentation (2001:db8::/32)"),
	rng("3fff::/20", "documentation (3fff::/20)"),
	rng("fc00::/7", "unique local (fc00::/7)"),
	rng("fe80::/10", "link-local (fe80::/10)"),
	rng("fec0::/10", "deprecated site-local (fec0::/10)"),
	rng("ff00::/8", "multicast (ff00::/8)"),
}

var (
	prefixNAT64  = netip.MustParsePrefix("64:ff9b::/96")
	prefix6to4   = netip.MustParsePrefix("2002::/16")
	prefixTeredo = netip.MustParsePrefix("2001::/32")
	// SIIT (RFC 2765) translated addresses, written ::ffff:0:a.b.c.d.
	prefixSIIT = netip.MustParsePrefix("::ffff:0:0:0/96")
)

// classify reports why addr must not be a connection target. The boolean is
// true when the address is blocked. IPv4-mapped addresses are judged as IPv4.
// Addresses that embed an IPv4 address (NAT64, 6to4, Teredo, SIIT) are judged
// by the embedded IPv4 address as well.
//
// The net.IP helpers are a supplement to the explicit tables above and are
// never the only check.
func classify(addr netip.Addr) (string, bool) {
	if !addr.IsValid() {
		return "invalid address", true
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return classifyIPv4(addr)
	}
	return classifyIPv6(addr)
}

func classifyIPv4(addr netip.Addr) (string, bool) {
	for _, r := range blockedIPv4 {
		if r.prefix.Contains(addr) {
			return r.reason, true
		}
	}
	return supplementary(addr)
}

func classifyIPv6(addr netip.Addr) (string, bool) {
	for _, r := range blockedIPv6 {
		if r.prefix.Contains(addr) {
			return r.reason, true
		}
	}

	raw := addr.As16()
	var embedded netip.Addr
	var label string
	switch {
	case prefixNAT64.Contains(addr):
		label = "NAT64 (64:ff9b::/96)"
		embedded = ipv4From(raw[12], raw[13], raw[14], raw[15])
	case prefix6to4.Contains(addr):
		label = "6to4 (2002::/16)"
		embedded = ipv4From(raw[2], raw[3], raw[4], raw[5])
	case prefixTeredo.Contains(addr):
		// Teredo: the server address is in bytes 4-7, the obfuscated client
		// address (bitwise NOT) in bytes 12-15. Both must be public.
		server := ipv4From(raw[4], raw[5], raw[6], raw[7])
		if reason, blocked := classifyIPv4(server); blocked {
			return fmt.Sprintf("Teredo server %s is blocked: %s", server, reason), true
		}
		embedded = ipv4From(raw[12]^0xff, raw[13]^0xff, raw[14]^0xff, raw[15]^0xff)
		label = "Teredo (2001::/32) client"
	case prefixSIIT.Contains(addr):
		label = "IPv4-translated (::ffff:0:0/96)"
		embedded = ipv4From(raw[12], raw[13], raw[14], raw[15])
	default:
		return supplementary(addr)
	}

	if reason, blocked := classifyIPv4(embedded); blocked {
		return fmt.Sprintf("%s embeds blocked address %s: %s", label, embedded, reason), true
	}
	return supplementary(addr)
}

func ipv4From(a, b, c, d byte) netip.Addr {
	return netip.AddrFrom4([4]byte{a, b, c, d})
}

// supplementary applies the net.IP classification as an additional check.
func supplementary(addr netip.Addr) (string, bool) {
	ip := net.IP(addr.AsSlice())
	switch {
	case ip.IsUnspecified():
		return "unspecified address", true
	case ip.IsLoopback():
		return "loopback address", true
	case ip.IsPrivate():
		return "private address", true
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast():
		return "link-local address", true
	case ip.IsMulticast():
		return "multicast address", true
	}
	return "", false
}
