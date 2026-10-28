package ssrf

import (
	"context"
	"errors"
	"fmt"
)

// ErrCode classifies a failure returned by this package. Every code is also an
// error value, so errors.Is(err, ErrBlockedAddress) works in addition to
// errors.As(err, &safeErr) with safeErr.Code.
type ErrCode string

// Failure codes. The values match the codes of the TypeScript package
// @yedoma-labs/tanur-ssrf.
const (
	// ErrProtocolNotAllowed is returned when the URL scheme is not in the allowlist.
	ErrProtocolNotAllowed ErrCode = "PROTOCOL_NOT_ALLOWED"
	// ErrInvalidURL is returned for unparsable URLs, missing hosts, credentials
	// in the URL, invalid ports and non-canonical hostnames.
	ErrInvalidURL ErrCode = "INVALID_URL"
	// ErrBlockedHostname is returned when the hostname is on the blocklist.
	ErrBlockedHostname ErrCode = "BLOCKED_HOSTNAME"
	// ErrBlockedAddress is returned when a literal or resolved IP address is in a
	// blocked range.
	ErrBlockedAddress ErrCode = "BLOCKED_ADDRESS"
	// ErrPortNotAllowed is returned when the port is not in the allowlist.
	ErrPortNotAllowed ErrCode = "PORT_NOT_ALLOWED"
	// ErrDNSFailure is returned when the resolver fails or returns no addresses.
	ErrDNSFailure ErrCode = "DNS_FAILURE"
	// ErrRedirectLimit is returned when more redirects than allowed are followed.
	ErrRedirectLimit ErrCode = "REDIRECT_LIMIT"
	// ErrTimeout is returned when the overall deadline elapsed inside the
	// policy layers. The http.Client timeout wraps its own errors, so use
	// IsTimeout to detect timeouts reliably.
	ErrTimeout ErrCode = "TIMEOUT"
	// ErrNetwork is returned for connection and protocol failures.
	ErrNetwork ErrCode = "NETWORK_ERROR"
)

// Error returns the code string. It makes ErrCode usable as an error value.
func (c ErrCode) Error() string {
	return string(c)
}

// SafeError is the error type for every policy and transport failure caused by
// this package. Messages never contain credentials or the query string of the
// URL. They name the blocked hostname or address only.
type SafeError struct {
	// Code classifies the failure.
	Code ErrCode
	msg  string
	// cause is the underlying error, if any. It is available through Unwrap.
	cause error
}

// Error returns the message including the code.
func (e *SafeError) Error() string {
	return fmt.Sprintf("ssrf: %s: %s", e.Code, e.msg)
}

// Unwrap returns the underlying cause, if any.
func (e *SafeError) Unwrap() error {
	return e.cause
}

// Is reports whether target is the ErrCode of this error.
func (e *SafeError) Is(target error) bool {
	code, ok := target.(ErrCode)
	return ok && code == e.Code
}

// IsTimeout reports whether err was caused by a deadline. It is the reliable
// check for timeouts. The http.Client wraps timeouts in its own error type, and
// that type does not match ErrTimeout. The wrapped error still matches
// context.DeadlineExceeded and reports Timeout() == true as a net.Error.
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return isTimeout(err)
}

func newError(code ErrCode, msg string) *SafeError {
	return &SafeError{Code: code, msg: msg}
}

func wrapError(code ErrCode, msg string, cause error) *SafeError {
	return &SafeError{Code: code, msg: msg, cause: cause}
}
