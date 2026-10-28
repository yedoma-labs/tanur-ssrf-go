package ssrf

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestRedirectChecker(t *testing.T) {
	t.Parallel()

	p, err := newPolicy(defaultConfig())
	if err != nil {
		t.Fatalf("newPolicy: %v", err)
	}
	check := newRedirectChecker(p, 5)

	tests := []struct {
		name   string
		rawURL string
		// viaLen is len(via): the number of requests before the redirect.
		viaLen int
		want   ErrCode
	}{
		{name: "public https", rawURL: "https://public.test/next", viaLen: 1},
		{name: "metadata literal", rawURL: "http://169.254.169.254/latest", viaLen: 1, want: ErrBlockedAddress},
		{name: "IPv4 loopback literal", rawURL: "http://127.0.0.1/", viaLen: 2, want: ErrBlockedAddress},
		{name: "IPv6 loopback literal", rawURL: "http://[::1]/", viaLen: 1, want: ErrBlockedAddress},
		{name: "private literal", rawURL: "http://10.20.30.40/", viaLen: 1, want: ErrBlockedAddress},
		{name: "localhost name", rawURL: "http://localhost/", viaLen: 1, want: ErrBlockedHostname},
		{name: "internal name", rawURL: "http://db.internal/", viaLen: 1, want: ErrBlockedHostname},
		{name: "port outside allowlist", rawURL: "http://public.test:8080/", viaLen: 1, want: ErrPortNotAllowed},
		{name: "ftp scheme", rawURL: "ftp://public.test/", viaLen: 1, want: ErrProtocolNotAllowed},
		//nolint:gosec // G101: intentional credentials fixture
		{name: "credentials in hop", rawURL: "https://user:pw@public.test/", viaLen: 1, want: ErrInvalidURL},
		{name: "fifth redirect allowed", rawURL: "https://public.test/", viaLen: 5},
		{name: "sixth redirect refused", rawURL: "https://public.test/", viaLen: 6, want: ErrRedirectLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("test fixture: %v", err)
			}
			req := &http.Request{URL: u}
			via := make([]*http.Request, tt.viaLen)
			err = check(req, via)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("redirect to %s refused: %v", tt.rawURL, err)
				}
				return
			}
			requireErrCode(t, err, tt.want)
		})
	}
}

func TestRedirectLimitIsZeroWhenConfiguredZero(t *testing.T) {
	t.Parallel()

	p, err := newPolicy(defaultConfig())
	if err != nil {
		t.Fatalf("newPolicy: %v", err)
	}
	u, err := url.Parse("https://public.test/")
	if err != nil {
		t.Fatalf("test fixture: %v", err)
	}
	check := newRedirectChecker(p, 0)
	requireErrCode(t, check(&http.Request{URL: u}, make([]*http.Request, 1)), ErrRedirectLimit)
}

func TestRedirectLimitStopsLoop(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		maxRedirects int
		// wantHits is the number of requests that reach the server: the
		// original request plus every followed redirect.
		wantHits int32
	}{
		{name: "default of five", maxRedirects: 5, wantHits: 6},
		{name: "three", maxRedirects: 3, wantHits: 4},
		{name: "zero redirects", maxRedirects: 0, wantHits: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.Header().Set("Location", "/loop")
				w.WriteHeader(http.StatusFound)
			}))
			t.Cleanup(srv.Close)

			resolver := newFakeResolver(t, map[string][]string{"loop.test": {"8.8.8.8"}})
			dialer := newRecordingDial(srv.Listener.Addr().String())
			client := mustClient(t,
				WithResolver(resolver),
				withDialFunc(dialer.dial),
				WithMaxRedirects(tt.maxRedirects),
			)

			resp, err := fetch(t, client, "http://loop.test/loop")
			if resp != nil {
				closeBody(t, resp)
			}
			requireErrCode(t, err, ErrRedirectLimit)
			if got := hits.Load(); got != tt.wantHits {
				t.Fatalf("server received %d requests, want %d", got, tt.wantHits)
			}
		})
	}
}

func TestRedirectHopsAreValidated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		location string
		wantCode ErrCode
		wantBody string
	}{
		{name: "to metadata literal", location: "http://169.254.169.254/latest/meta-data/", wantCode: ErrBlockedAddress},
		{name: "to loopback literal", location: "http://127.0.0.1:80/", wantCode: ErrBlockedAddress},
		{name: "to localhost name", location: "http://localhost/", wantCode: ErrBlockedHostname},
		{name: "to name resolving to private address", location: "http://private.test/", wantCode: ErrBlockedAddress},
		{name: "to port outside allowlist", location: "http://public.test:8080/", wantCode: ErrPortNotAllowed},
		{name: "to disallowed scheme", location: "ftp://public.test/", wantCode: ErrProtocolNotAllowed},
		{name: "relative location is resolved", location: "/next", wantBody: "host=public.test;path=/next"},
		{name: "absolute public location", location: "http://public.test/done", wantBody: "host=public.test;path=/done"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					w.Header().Set("Location", tt.location)
					w.WriteHeader(http.StatusFound)
					return
				}
				_, _ = fmt.Fprintf(w, "host=%s;path=%s", r.Host, r.URL.Path)
			}))
			t.Cleanup(backend.Close)

			resolver := newFakeResolver(t, map[string][]string{
				"public.test":  {"8.8.8.8"},
				"private.test": {"10.0.0.1"},
			})
			dialer := newRecordingDial(backend.Listener.Addr().String())
			client := mustClient(t, WithResolver(resolver), withDialFunc(dialer.dial))

			resp, err := fetch(t, client, "http://public.test/start")
			if tt.wantCode == "" {
				if err != nil {
					t.Fatalf("GET: %v", err)
				}
				body := readAllAndClose(t, resp)
				if body != tt.wantBody {
					t.Fatalf("body = %q, want %q", body, tt.wantBody)
				}
			} else {
				if resp != nil {
					closeBody(t, resp)
				}
				requireErrCode(t, err, tt.wantCode)
			}

			// Every connection must target the validated public address. A
			// connection to any other address means a hop was not validated.
			for _, target := range dialer.dialedTargets() {
				if target != "8.8.8.8:80" {
					t.Fatalf("connection attempted to %s, want only 8.8.8.8:80", target)
				}
			}
		})
	}
}

func readAllAndClose(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer closeBody(t, resp)
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(data)
}
