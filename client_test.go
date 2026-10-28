package ssrf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestNewClientOptionValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{"defaults", nil, false},
		{"nil option is ignored", []Option{nil}, false},
		{"https only", []Option{WithAllowedSchemes("https")}, false},
		{"uppercase scheme", []Option{WithAllowedSchemes("HTTPS")}, false},
		{"ftp scheme rejected", []Option{WithAllowedSchemes("ftp")}, true},
		{"empty scheme list", []Option{WithAllowedSchemes()}, true},
		{"empty port list", []Option{WithAllowedPorts()}, true},
		{"port zero", []Option{WithAllowedPorts(0)}, true},
		{"port too large", []Option{WithAllowedPorts(70000)}, true},
		{"negative redirects", []Option{WithMaxRedirects(-1)}, true},
		{"zero redirects allowed", []Option{WithMaxRedirects(0)}, false},
		{"zero timeout", []Option{WithTimeout(0)}, true},
		{"negative timeout", []Option{WithTimeout(-time.Second)}, true},
		{"nil resolver", []Option{WithResolver(nil)}, true},
		{"blocked entry is an IP", []Option{WithBlockedHostnames("10.0.0.1")}, true},
		{"blocked entry is empty", []Option{WithBlockedHostnames("")}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client, err := NewClient(tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewClient error = %v, want error %v", err, tt.wantErr)
			}
			if err == nil && client == nil {
				t.Fatal("NewClient returned nil client without error")
			}
		})
	}
}

func TestRequestsRejectedBeforeDial(t *testing.T) {
	t.Parallel()

	resolver := newFakeResolver(t, map[string][]string{
		"private.test": {"10.0.0.1"},
		"empty.test":   {},
	})

	tests := []struct {
		name   string
		rawURL string
		want   ErrCode
	}{
		{"ftp scheme", "ftp://public.test/", ErrProtocolNotAllowed},
		{"credentials", "http://user:s3cretpw@public.test/", ErrInvalidURL},
		{"port not allowed", "http://public.test:8080/?token=s3cret", ErrPortNotAllowed},
		{"localhost", "http://localhost/?token=s3cret", ErrBlockedHostname},
		{"nested internal name", "http://a.b.internal/", ErrBlockedHostname},
		{"IPv4 loopback literal", "http://127.0.0.1/", ErrBlockedAddress},
		{"metadata literal", "http://169.254.169.254/latest/meta-data/", ErrBlockedAddress},
		{"IPv4-mapped metadata", "http://[::ffff:169.254.169.254]/", ErrBlockedAddress},
		{"NAT64 loopback", "http://[64:ff9b::7f00:1]/", ErrBlockedAddress},
		{"hex IPv4 form", "http://0x7f000001/", ErrInvalidURL},
		{"private address behind a name", "http://private.test/", ErrBlockedAddress},
		{"unknown name", "http://missing.test/", ErrDNSFailure},
		{"name without addresses", "http://empty.test/", ErrDNSFailure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := mustClient(t, WithResolver(resolver), withDialFunc(noDial(t)))
			resp, err := fetch(t, client, tt.rawURL)
			if resp != nil {
				closeBody(t, resp)
			}
			requireErrCode(t, err, tt.want)
			assertNoSecrets(t, err, []string{"s3cretpw", "token=", "s3cret"})
		})
	}
}

func TestConnectsToValidatedAddressAndKeepsHostHeader(t *testing.T) {
	t.Parallel()

	backend := newEchoServer(t)
	dialer := newRecordingDial(backend.Listener.Addr().String())
	resolver := newFakeResolver(t, map[string][]string{"public.test": {"8.8.8.8"}})
	client := mustClient(t, WithResolver(resolver), withDialFunc(dialer.dial))

	body := fetchBody(t, client, "http://public.test/hello")
	if want := "host=public.test;path=/hello"; body != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
	if got := dialer.dialedTargets(); !equalStrings(got, []string{"8.8.8.8:80"}) {
		t.Fatalf("connected to %v, want only the validated address [8.8.8.8:80]", got)
	}
	if n := resolver.callCount("public.test"); n != 1 {
		t.Fatalf("resolver called %d times for one request, want 1", n)
	}
}

func TestEachRequestDialsAndResolvesAgain(t *testing.T) {
	t.Parallel()

	backend := newEchoServer(t)
	dialer := newRecordingDial(backend.Listener.Addr().String())
	resolver := newFakeResolver(t, map[string][]string{"again.test": {"8.8.8.8"}})
	client := mustClient(t, WithResolver(resolver), withDialFunc(dialer.dial))

	for i := 0; i < 3; i++ {
		_ = fetchBody(t, client, "http://again.test/")
	}
	if got := len(dialer.dialedTargets()); got != 3 {
		t.Fatalf("dialed %d times for 3 requests, want 3 (no connection reuse)", got)
	}
	if n := resolver.callCount("again.test"); n != 3 {
		t.Fatalf("resolver called %d times for 3 requests, want 3", n)
	}
}

func TestDNSRebindingIsRevalidatedPerConnection(t *testing.T) {
	t.Parallel()

	backend := newEchoServer(t)
	dialer := newRecordingDial(backend.Listener.Addr().String())
	resolver := &sequenceResolver{steps: [][]net.IPAddr{
		ipAddrs(t, "8.8.8.8"),
		ipAddrs(t, "10.0.0.1"),
	}}
	client := mustClient(t, WithResolver(resolver), withDialFunc(dialer.dial))

	_ = fetchBody(t, client, "http://rebind.test/first")

	resp, err := fetch(t, client, "http://rebind.test/second")
	if resp != nil {
		closeBody(t, resp)
	}
	requireErrCode(t, err, ErrBlockedAddress)

	if n := resolver.callCount(); n != 2 {
		t.Fatalf("resolver called %d times, want 2 (one per connection)", n)
	}
	if got := dialer.dialedTargets(); !equalStrings(got, []string{"8.8.8.8:80"}) {
		t.Fatalf("connected to %v, want only [8.8.8.8:80]; private address must not be dialed", got)
	}
}

func TestMixedResolutionIsRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ips  []string
	}{
		{"public then private", []string{"8.8.8.8", "10.0.0.1"}},
		{"private then public", []string{"10.0.0.1", "8.8.8.8"}},
		{"public IPv6 and loopback", []string{"2606:4700::1111", "::1"}},
		{"public and metadata", []string{"93.184.216.34", "169.254.169.254"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resolver := newFakeResolver(t, map[string][]string{"mixed.test": tt.ips})
			client := mustClient(t, WithResolver(resolver), withDialFunc(noDial(t)))
			resp, err := fetch(t, client, "http://mixed.test/")
			if resp != nil {
				closeBody(t, resp)
			}
			requireErrCode(t, err, ErrBlockedAddress)
		})
	}
}

func TestPrivateNetworksOnlyWhenAllowed(t *testing.T) {
	t.Parallel()

	backend := newEchoServer(t)
	port := backend.Listener.Addr().(*net.TCPAddr).Port
	rawURL := fmt.Sprintf("http://127.0.0.1:%d/x", port)

	tests := []struct {
		name     string
		allow    bool
		wantCode ErrCode
		wantBody string
	}{
		{name: "blocked by default", allow: false, wantCode: ErrBlockedAddress},
		{name: "reachable with WithAllowPrivateNetworks", allow: true, wantBody: fmt.Sprintf("host=127.0.0.1:%d;path=/x", port)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := mustClient(t,
				WithAllowPrivateNetworks(tt.allow),
				WithAllowedPorts(port),
			)
			if tt.wantCode != "" {
				resp, err := fetch(t, client, rawURL)
				if resp != nil {
					closeBody(t, resp)
				}
				requireErrCode(t, err, tt.wantCode)
				return
			}
			if body := fetchBody(t, client, rawURL); body != tt.wantBody {
				t.Fatalf("body = %q, want %q", body, tt.wantBody)
			}
		})
	}
}

func TestTimeoutCoversConnectionAndHeaders(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	client := mustClient(t,
		WithAllowPrivateNetworks(true),
		WithAllowedPorts(port),
		WithTimeout(100*time.Millisecond),
	)

	start := time.Now()
	resp, err := fetch(t, client, fmt.Sprintf("http://127.0.0.1:%d/slow", port))
	if resp != nil {
		closeBody(t, resp)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("request took %v, timeout of 100ms was not enforced", elapsed)
	}
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if !IsTimeout(err) {
		t.Fatalf("IsTimeout(%v) = false, want true", err)
	}
}

func TestTimeoutCoversBody(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	client := mustClient(t,
		WithAllowPrivateNetworks(true),
		WithAllowedPorts(port),
		WithTimeout(150*time.Millisecond),
	)

	// Headers arrive in time. The deadline must still apply to the body.
	resp, err := fetch(t, client, fmt.Sprintf("http://127.0.0.1:%d/body", port))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer closeBody(t, resp)
	_, readErr := io.ReadAll(resp.Body)
	if readErr == nil {
		t.Fatal("expected a timeout while reading the body, got nil")
	}
	if !IsTimeout(readErr) {
		t.Fatalf("IsTimeout(%v) = false, want true", readErr)
	}
}

func TestTLSServerNameIsRequestHostname(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var serverNames []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "tls-ok")
	}))
	srv.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			serverNames = append(serverNames, hello.ServerName)
			mu.Unlock()
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	dialer := newRecordingDial(srv.Listener.Addr().String())
	resolver := newFakeResolver(t, map[string][]string{"example.com": {"8.8.8.8"}})
	client := mustClient(t,
		WithResolver(resolver),
		withDialFunc(dialer.dial),
		withRootCAs(pool),
	)

	// The certificate must verify for example.com while the TCP connection
	// goes to 8.8.8.8, so SNI and verification use the hostname.
	if body := fetchBody(t, client, "https://example.com/"); body != "tls-ok" {
		t.Fatalf("body = %q, want %q", body, "tls-ok")
	}

	mu.Lock()
	defer mu.Unlock()
	if !equalStrings(serverNames, []string{"example.com"}) {
		t.Fatalf("server saw SNI %v, want [example.com]", serverNames)
	}
	if got := dialer.dialedTargets(); !equalStrings(got, []string{"8.8.8.8:443"}) {
		t.Fatalf("connected to %v, want [8.8.8.8:443]", got)
	}
}

func TestClientIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	backend := newEchoServer(t)
	dialer := newRecordingDial(backend.Listener.Addr().String())
	resolver := newFakeResolver(t, map[string][]string{"public.test": {"8.8.8.8"}})
	client := mustClient(t, WithResolver(resolver), withDialFunc(dialer.dial))

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://public.test/c", nil)
			if err != nil {
				errs <- err
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				errs <- err
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			errs <- resp.Body.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent request failed: %v", err)
		}
	}
}

// newEchoServer starts a plain HTTP server on 127.0.0.1 that returns the Host
// header and the path. It is the only network endpoint used by these tests.
func newEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "host=%s;path=%s", r.Host, r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// fetch performs a GET through client. The caller closes the response body.
func fetch(t *testing.T, client *http.Client, rawURL string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("test fixture: NewRequest(%q): %v", rawURL, err)
	}
	return client.Do(req)
}

// fetchBody performs a GET that must succeed and returns the body as a string.
func fetchBody(t *testing.T, client *http.Client, rawURL string) string {
	t.Helper()
	resp, err := fetch(t, client, rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer closeBody(t, resp)
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body of %s: %v", rawURL, err)
	}
	return string(data)
}

func closeBody(t *testing.T, resp *http.Response) {
	t.Helper()
	if err := resp.Body.Close(); err != nil {
		t.Errorf("close response body: %v", err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
