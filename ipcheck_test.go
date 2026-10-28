package ssrf

import (
	"net/netip"
	"testing"
)

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		addr    string
		blocked bool
	}{
		// IPv4 boundaries of every blocked range.
		{"public 1.0.0.0", "1.0.0.0", false},
		{"public 8.8.8.8", "8.8.8.8", false},
		{"9.255.255.255 just below 10/8", "9.255.255.255", false},
		{"0/8 start", "0.0.0.0", true},
		{"0/8 end", "0.255.255.255", true},
		{"10/8 start", "10.0.0.0", true},
		{"10/8 end", "10.255.255.255", true},
		{"11.0.0.0 just above 10/8", "11.0.0.0", false},
		{"100.63.255.255 below 100.64/10", "100.63.255.255", false},
		{"100.64/10 start", "100.64.0.0", true},
		{"100.64/10 end", "100.127.255.255", true},
		{"100.128.0.0 above 100.64/10", "100.128.0.0", false},
		{"126.255.255.255 below 127/8", "126.255.255.255", false},
		{"127/8 loopback", "127.0.0.1", true},
		{"127/8 end", "127.255.255.255", true},
		{"128.0.0.0 above 127/8", "128.0.0.0", false},
		{"169.253.255.255 below 169.254/16", "169.253.255.255", false},
		{"169.254/16 start", "169.254.0.0", true},
		{"169.254.169.254 cloud metadata", "169.254.169.254", true},
		{"169.254/16 end", "169.254.255.255", true},
		{"169.255.0.0 above 169.254/16", "169.255.0.0", false},
		{"172.15.255.255 below 172.16/12", "172.15.255.255", false},
		{"172.16/12 start", "172.16.0.0", true},
		{"172.31.255.255 end of 172.16/12", "172.31.255.255", true},
		{"172.32.0.0 above 172.16/12", "172.32.0.0", false},
		{"192.0.0.0/24 start", "192.0.0.0", true},
		{"192.0.0.255 end of 192.0.0/24", "192.0.0.255", true},
		{"192.0.1.0 above 192.0.0/24", "192.0.1.0", false},
		{"192.0.2.0/24 TEST-NET-1", "192.0.2.1", true},
		{"192.0.3.0 above TEST-NET-1", "192.0.3.0", false},
		{"192.167.255.255 below 192.168/16", "192.167.255.255", false},
		{"192.168/16 start", "192.168.0.0", true},
		{"192.168/16 end", "192.168.255.255", true},
		{"192.169.0.0 above 192.168/16", "192.169.0.0", false},
		{"198.17.255.255 below 198.18/15", "198.17.255.255", false},
		{"198.18.0.0 start of 198.18/15", "198.18.0.0", true},
		{"198.19.255.255 end of 198.18/15", "198.19.255.255", true},
		{"198.20.0.0 above 198.18/15", "198.20.0.0", false},
		{"198.51.100/24 TEST-NET-2", "198.51.100.1", true},
		{"198.51.101.0 above TEST-NET-2", "198.51.101.0", false},
		{"203.0.113/24 TEST-NET-3", "203.0.113.1", true},
		{"203.0.114.0 above TEST-NET-3", "203.0.114.0", false},
		{"223.255.255.255 below 224/4", "223.255.255.255", false},
		{"224/4 multicast", "224.0.0.1", true},
		{"239.255.255.255 end of 224/4", "239.255.255.255", true},
		{"240/4 reserved", "240.0.0.0", true},
		{"255.255.255.255 broadcast", "255.255.255.255", true},
		{"public 93.184.216.34", "93.184.216.34", false},

		// Native IPv6.
		{"public 2606:4700:4700::1111", "2606:4700:4700::1111", false},
		{"public 2001:4860:4860::8888", "2001:4860:4860::8888", false},
		{"2001:db9::1 just outside 2001:db8::/32", "2001:db9::1", false},
		{"unspecified ::", "::", true},
		{"loopback ::1", "::1", true},
		{"::2 inside deprecated ::/96", "::2", true},
		{"IPv4-compatible ::8.8.8.8 is deprecated", "::8.8.8.8", true},
		{"discard 100::1", "100::1", true},
		{"100:0:0:1::1 outside 100::/64", "100:0:0:1::1", false},
		{"local-use NAT64 64:ff9b:1::1", "64:ff9b:1::1", true},
		{"documentation 2001:db8::1", "2001:db8::1", true},
		{"documentation 3fff::1", "3fff::1", true},
		{"unique local fc00::1", "fc00::1", true},
		{"unique local fd12:3456::1", "fd12:3456::1", true},
		{"link-local fe80::1", "fe80::1", true},
		{"link-local end febf::1", "febf:ffff:ffff:ffff::1", true},
		{"site-local fec0::1", "fec0::1", true},
		{"multicast ff02::1", "ff02::1", true},

		// IPv4-mapped: judged by the embedded IPv4 address.
		{"mapped public ::ffff:8.8.8.8", "::ffff:8.8.8.8", false},
		{"mapped loopback ::ffff:127.0.0.1", "::ffff:127.0.0.1", true},
		{"mapped private ::ffff:10.0.0.1", "::ffff:10.0.0.1", true},
		{"mapped metadata ::ffff:a9fe:a9fe", "::ffff:a9fe:a9fe", true},

		// IPv4-translated (SIIT) ::ffff:0:a.b.c.d.
		{"SIIT public ::ffff:0:8.8.8.8", "::ffff:0:808:808", false},
		{"SIIT loopback ::ffff:0:127.0.0.1", "::ffff:0:7f00:1", true},

		// NAT64 64:ff9b::/96 with embedded IPv4.
		{"NAT64 public 64:ff9b::8.8.8.8", "64:ff9b::808:808", false},
		{"NAT64 loopback 64:ff9b::127.0.0.1", "64:ff9b::7f00:1", true},
		{"NAT64 metadata 64:ff9b::169.254.169.254", "64:ff9b::a9fe:a9fe", true},
		{"NAT64 private 64:ff9b::192.168.1.1", "64:ff9b::c0a8:101", true},

		// 6to4 2002::/16 with embedded IPv4 in bytes 2-5.
		{"6to4 public 2002:0808:0808::", "2002:808:808::", false},
		{"6to4 loopback 2002:7f00:1::", "2002:7f00:1::", true},
		{"6to4 private 2002:c0a8:101::", "2002:c0a8:101::", true},
		{"6to4 private 2002:0a00:1::", "2002:a00:1::", true},

		// Teredo 2001::/32: server in bytes 4-7, client (bitwise NOT) in bytes 12-15.
		{"Teredo public server and client", "2001:0:4136:e378:8000:63bf:f7f7:f7f7", false},
		{"Teredo client 192.0.2.45 documentation", "2001:0:4136:e378:8000:63bf:3fff:fdd2", true},
		{"Teredo loopback server", "2001:0:7f00:1::", true},

		// Invalid address.
		{"invalid zero value", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var addr netip.Addr
			if tt.addr != "" {
				parsed, err := netip.ParseAddr(tt.addr)
				if err != nil {
					t.Fatalf("test fixture: ParseAddr(%q): %v", tt.addr, err)
				}
				addr = parsed
			}
			reason, blocked := classify(addr)
			if blocked != tt.blocked {
				t.Fatalf("classify(%q) blocked = %v (reason %q), want %v", tt.addr, blocked, reason, tt.blocked)
			}
			if blocked && reason == "" {
				t.Fatalf("classify(%q) blocked without a reason", tt.addr)
			}
		})
	}
}

func TestBlockedRangesParse(t *testing.T) {
	t.Parallel()

	// Every range in the tables must be a valid prefix whose network address
	// is canonical. This catches typos that MustParsePrefix would only panic on
	// at package init.
	for _, r := range append(append([]blockedRange{}, blockedIPv4...), blockedIPv6...) {
		if r.prefix.Masked() != r.prefix {
			t.Errorf("range %s is not canonical, network bits are set", r.prefix)
		}
		if r.reason == "" {
			t.Errorf("range %s has no reason", r.prefix)
		}
	}
}
