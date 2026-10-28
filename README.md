# tanur-ssrf-go

An SSRF-safe `*http.Client` for Go. It is for servers that fetch URLs a user controls, such as webhooks, image URLs, link previews or import-by-URL. Standard library only, no dependencies.

## The problem

Blocklists, hostname regexes and "check the URL, then call `http.Get`" do not stop server-side request forgery (SSRF):

- **DNS rebinding.** A hostname resolves to a public address for the check and to `127.0.0.1` or `10.x` for the connection.
- **Redirect chains.** A public URL redirects to `http://127.0.0.1:6379` or `http://169.254.169.254/` (cloud metadata).
- **IP encodings.** `::ffff:127.0.0.1`, `64:ff9b::7f00:1`, `2002:7f00:1::` and other embedded forms reach internal hosts. Non-canonical IPv4 forms like `0x7f000001` or `2130706433` are rejected.
- **Hostname tricks.** Trailing dots, mixed case, `*.localhost`, `*.internal`.

`NewClient` closes these gaps. It resolves a hostname once per connection, checks every returned address, connects to exactly a validated address, and validates every redirect hop from scratch.

## Quickstart

```go
import ssrf "github.com/yedoma-labs/tanur-ssrf-go"

client, err := ssrf.NewClient(
	ssrf.WithAllowedPorts(80, 443),
	ssrf.WithMaxRedirects(3),
	ssrf.WithTimeout(5*time.Second),
)
if err != nil {
	return err
}

resp, err := client.Get(userURL)
if err != nil {
	if ssrf.IsTimeout(err) {
		return errors.New("upstream too slow")
	}
	var safeErr *ssrf.SafeError
	if errors.As(err, &safeErr) {
		log.Printf("blocked: %s", safeErr.Code)
	}
	return err
}
defer resp.Body.Close()
```

`NewClient` returns a standard `*http.Client`. Use it like any other client. Requests are checked before they leave the process.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `WithAllowedSchemes(...string)` | `http`, `https` | Accepted schemes. Only `http` and `https` are valid values. |
| `WithAllowedPorts(...int)` | `80`, `443` | Ports that may be contacted. |
| `WithAllowPrivateNetworks(bool)` | `false` | Disables the IP range checks. See the warning below. |
| `WithMaxRedirects(int)` | `5` | Redirects followed. The next one fails with `ErrRedirectLimit`. |
| `WithTimeout(time.Duration)` | `10s` | Deadline for the whole call: DNS, connect, TLS, all redirect hops and the body. |
| `WithResolver(ssrf.Resolver)` | `net.DefaultResolver` | Any type with `LookupIPAddr(ctx, host) ([]net.IPAddr, error)`. |
| `WithBlockedHostnames(...string)` | `localhost`, `metadata.google.internal`, `.localhost`, `.internal` | Hostnames rejected before DNS. **Replaces** the default list, so repeat the defaults if you add entries. An entry with a leading `.` matches the suffix and the bare name. |

Invalid options make `NewClient` return an error.

## Errors

Every policy failure is a `*ssrf.SafeError` with a `Code`. Use `errors.Is(err, ssrf.ErrBlockedAddress)` or `errors.As(err, &safeErr)`.

| Code | When |
| --- | --- |
| `ErrProtocolNotAllowed` (`PROTOCOL_NOT_ALLOWED`) | Scheme is not in the allowlist. |
| `ErrInvalidURL` (`INVALID_URL`) | Unparsable URL, no host, credentials in the URL, invalid port, non-canonical hostname. |
| `ErrBlockedHostname` (`BLOCKED_HOSTNAME`) | Hostname is on the blocklist. Checked before DNS. |
| `ErrBlockedAddress` (`BLOCKED_ADDRESS`) | A literal or resolved address is in a blocked range. |
| `ErrPortNotAllowed` (`PORT_NOT_ALLOWED`) | Port is not in the allowlist. |
| `ErrDNSFailure` (`DNS_FAILURE`) | The resolver failed or returned no addresses. |
| `ErrRedirectLimit` (`REDIRECT_LIMIT`) | More redirects than allowed. |
| `ErrTimeout` (`TIMEOUT`) | The deadline elapsed inside the policy layers. For timeouts in general, use `IsTimeout`. |
| `ErrNetwork` (`NETWORK_ERROR`) | Connection or protocol failure. |

`SafeError.Unwrap` returns the underlying cause. Messages never contain credentials or the query string. They name the blocked hostname or address only.

**Timeouts.** `http.Client` enforces `WithTimeout` and wraps its own timeout error. That error does not match `ErrTimeout`. Use `ssrf.IsTimeout(err)`, which is true for `ErrTimeout`, for `context.DeadlineExceeded`, and for any `net.Error` with `Timeout() == true`. This also covers timeouts while reading the body.

## Guarantees

- **One resolution per connection, and every answer is checked.** The hostname is resolved once. If any returned address is blocked, the whole hop is rejected, even if the other addresses are public.
- **Connect to the validated address only.** The dialer connects to a validated IP and never resolves the name a second time, so a change of DNS answer between check and connect (DNS rebinding) cannot redirect the connection.
- **Host and TLS stay the hostname.** The `Host` header is the requested hostname, including a non-default port. TLS SNI and certificate verification use the hostname, never the IP. This is tested against a TLS server.
- **Every redirect is validated.** `Location` is resolved against the current URL by `net/http` (`URL.ResolveReference` semantics). Scheme, credentials, port, hostname and literal addresses are checked again for each hop. Each hop that reaches the network is checked by its resolved addresses.
- **Redirect limit.** More than `WithMaxRedirects` redirects fail with `ErrRedirectLimit`.
- **Overall deadline.** `WithTimeout` covers the whole call, all hops and the body.
- **Credentials are not forwarded across origins.** `net/http` drops `Authorization`, `Cookie` and similar headers on redirects to another domain.
- **IP classification.** IPv4 `0/8`, `10/8`, `100.64/10`, `127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`, `192.0.2/24`, `192.168/16`, `198.18/15`, `198.51.100/24`, `203.0.113/24`, `224/4`, `240/4`, `255.255.255.255`. IPv6 `::/128`, `::1`, `::/96`, `fc00::/7`, `fe80::/10`, `fec0::/10`, `ff00::/8`, `2001:db8::/32`, `100::/64` and the documentation range `3fff::/20`. IPv4-mapped (`::ffff:a.b.c.d`) is judged as IPv4. NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`), Teredo (`2001::/32`) and translated (`::ffff:0:a.b.c.d`) addresses are judged by the embedded IPv4 address. `net.IP` helpers are a supplementary check only.

## Design decisions

- **Proxies are ignored.** `Transport.Proxy` is `nil`, so `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` have no effect. A proxy would receive the request without this policy applied.
- **HTTP/1.1 only.** A custom dialer disables HTTP/2 in `net/http` by default. HTTP/2 would pool connections across requests.
- **No connection reuse.** `DisableKeepAlives` is set. Each request dials, resolves and validates again. This costs a handshake per request and avoids reusing a connection that was validated under an earlier DNS state. All hops share one policy, so reuse would be safe. It was not worth the extra state.
- **No static `TLSClientConfig.ServerName`.** A fixed name would be wrong for every other host on the shared transport. `net/http` derives SNI from the request URL per connection.

## Limits

- **The resolver must be trustworthy.** Its answers decide which addresses are checked. A hostile resolver can only pick addresses that pass the checks, so use the system resolver or a resolver you control.
- **Proxies are not supported** (see above).
- **Pinning covers the connection.** Rebinding between check and connect is excluded by pinning. The response content is not validated. Use `io.LimitReader` or similar to bound the body.
- **Network-level egress filtering is still recommended** for high-risk workloads. This library does not replace a firewall or a separate network namespace.
- **Lists age.** Reserved ranges are hard-coded. Review them when IANA changes allocations.
- **`http.Client` error text.** `net/http` wraps errors in `*url.Error`, which includes the full URL with its query string. Do not log that error text unredacted. `SafeError` messages do not contain the URL.
- **Go version.** The module requires Go 1.23 or later. The suite was run locally with Go 1.27.3. CI runs the Go version from `go.mod`.

### Do not use `WithAllowPrivateNetworks(true)` for untrusted input

It disables the private, loopback, link-local and reserved address checks. Any URL can then reach internal services, including cloud metadata endpoints. The hostname blocklist, the scheme and port allowlists and the credential check still apply. Use this option only in tests, or for destinations you know and trust.

## Development

```sh
gofmt -l .
go vet ./...
go test -race ./...
go build ./...
```

The test suite makes no network connections. DNS is replaced by an in-memory resolver. Connections are redirected to loopback test servers through a recording dialer. The only real socket is a loopback `httptest` server.

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.

## License

MIT. See [LICENSE](LICENSE).
