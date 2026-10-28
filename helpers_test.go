package ssrf

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
)

// fakeResolver answers from a fixed table and counts lookups per host. Hosts
// missing from the table fail with a not-found DNS error. No network is used.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]net.IPAddr
	calls   map[string]int
}

func newFakeResolver(t *testing.T, answers map[string][]string) *fakeResolver {
	t.Helper()
	r := &fakeResolver{answers: make(map[string][]net.IPAddr), calls: make(map[string]int)}
	for host, ips := range answers {
		r.answers[host] = ipAddrs(t, ips...)
	}
	return r
}

// LookupIPAddr implements Resolver.
func (r *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[host]++
	ips, ok := r.answers[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return ips, nil
}

func (r *fakeResolver) callCount(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[host]
}

// sequenceResolver returns one answer per lookup. It repeats the last answer
// after the list is exhausted. It is used to simulate DNS rebinding.
type sequenceResolver struct {
	mu    sync.Mutex
	steps [][]net.IPAddr
	calls int
}

// LookupIPAddr implements Resolver.
func (r *sequenceResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.calls
	if idx >= len(r.steps) {
		idx = len(r.steps) - 1
	}
	r.calls++
	return r.steps[idx], nil
}

func (r *sequenceResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func ipAddrs(t *testing.T, ips ...string) []net.IPAddr {
	t.Helper()
	out := make([]net.IPAddr, 0, len(ips))
	for _, s := range ips {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("test fixture: invalid IP %q: %v", s, err)
		}
		out = append(out, net.IPAddr{IP: net.IP(addr.AsSlice())})
	}
	return out
}

// noDial fails the test if any connection is attempted.
func noDial(t *testing.T) dialFunc {
	t.Helper()
	return func(_ context.Context, _, address string) (net.Conn, error) {
		t.Errorf("unexpected connection attempt to %s", address)
		return nil, errors.New("connection attempt not expected")
	}
}

// recordingDial records every requested address and connects to backend
// instead. Connections to public test addresses therefore reach a local server.
type recordingDial struct {
	mu      sync.Mutex
	backend string
	targets []string
}

func newRecordingDial(backend string) *recordingDial {
	return &recordingDial{backend: backend}
}

// dial implements dialFunc.
func (d *recordingDial) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.targets = append(d.targets, address)
	d.mu.Unlock()
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, d.backend)
}

func (d *recordingDial) dialedTargets() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.targets...)
}

// mustClient builds a client and fails the test on configuration errors.
func mustClient(t *testing.T, opts ...Option) *http.Client {
	t.Helper()
	client, err := NewClient(opts...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}
