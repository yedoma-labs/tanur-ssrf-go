package ssrf

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
)

// dialFunc opens a raw connection. It is net.Dialer.DialContext in production.
// Tests replace it to observe the address that is actually connected.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// pinnedDialer resolves a hostname once per connection, validates every
// returned address and connects to one of the validated addresses. It does not
// resolve the name a second time, so a DNS answer that changes between the
// check and the connect (DNS rebinding) has no effect.
type pinnedDialer struct {
	policy   *policy
	resolver Resolver
	dial     dialFunc
}

// DialContext is used as http.Transport.DialContext. The address has the form
// host:port, taken from the request URL. The network is always "tcp".
func (d *pinnedDialer) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	host, rawPort, err := net.SplitHostPort(address)
	if err != nil {
		return nil, newError(ErrInvalidURL, "invalid dial address")
	}
	port, ok := parsePort(rawPort)
	if !ok {
		return nil, newError(ErrInvalidURL, "invalid port")
	}
	if !d.policy.ports[port] {
		return nil, newError(ErrPortNotAllowed, "port "+strconv.Itoa(port)+" is not allowed")
	}

	name, literal, isLiteral, err := parseHost(host)
	if err != nil {
		return nil, err
	}
	if !isLiteral && d.policy.hostnameBlocked(name) {
		return nil, newError(ErrBlockedHostname, "hostname "+strconv.Quote(name)+" is blocked")
	}

	addrs, err := d.resolveChecked(ctx, name, literal, isLiteral)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, addr := range addrs {
		target := net.JoinHostPort(addr.Unmap().String(), strconv.Itoa(port))
		conn, dialErr := d.dial(ctx, "tcp", target)
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
		if ctx.Err() != nil {
			break
		}
	}
	return nil, mapFailure(ctx, ErrNetwork, "connection failed", lastErr)
}

// resolveChecked returns the addresses for a host. If any one of them is
// blocked, the whole result is rejected, so the connection cannot land on a
// blocked address by chance.
func (d *pinnedDialer) resolveChecked(ctx context.Context, name string, literal netip.Addr, isLiteral bool) ([]netip.Addr, error) {
	if isLiteral {
		if err := d.policy.checkAddr(literal); err != nil {
			return nil, err
		}
		return []netip.Addr{literal}, nil
	}

	found, err := d.resolver.LookupIPAddr(ctx, name)
	if err != nil {
		return nil, mapFailure(ctx, ErrDNSFailure, "DNS lookup failed", err)
	}
	if len(found) == 0 {
		return nil, newError(ErrDNSFailure, "DNS lookup returned no addresses")
	}

	addrs := make([]netip.Addr, 0, len(found))
	for _, ip := range found {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			return nil, newError(ErrBlockedAddress, "resolver returned a value that is not an IP address")
		}
		addr = addr.WithZone(ip.Zone)
		if err := d.policy.checkAddr(addr); err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

// guardedTransport checks each request URL before it reaches the transport.
// Redirect hops pass through it as well, so every hop is checked.
type guardedTransport struct {
	policy *policy
	base   http.RoundTripper
}

// RoundTrip validates the URL, then delegates to the base transport. Errors
// are mapped to SafeError where the failure is a policy or timeout failure.
func (t *guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, _, err := t.policy.checkURL(req.URL); err != nil {
		closeRequestBody(req)
		return nil, err
	}

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		var safeErr *SafeError
		if errors.As(err, &safeErr) || errors.Is(req.Context().Err(), context.Canceled) {
			return nil, err
		}
		return nil, mapFailure(req.Context(), ErrNetwork, "request failed", err)
	}
	return resp, nil
}

// mapFailure converts a failure into ErrTimeout when a deadline caused it, and
// into code otherwise.
func mapFailure(ctx context.Context, code ErrCode, msg string, cause error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(cause, context.DeadlineExceeded) || isTimeout(cause) {
		return wrapError(ErrTimeout, "deadline exceeded", cause)
	}
	return wrapError(code, msg, cause)
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}
