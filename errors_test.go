package ssrf

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestErrCodeValues(t *testing.T) {
	t.Parallel()

	// The values must match the codes of @yedoma-labs/tanur-ssrf.
	tests := []struct {
		code ErrCode
		want string
	}{
		{ErrProtocolNotAllowed, "PROTOCOL_NOT_ALLOWED"},
		{ErrInvalidURL, "INVALID_URL"},
		{ErrBlockedHostname, "BLOCKED_HOSTNAME"},
		{ErrBlockedAddress, "BLOCKED_ADDRESS"},
		{ErrPortNotAllowed, "PORT_NOT_ALLOWED"},
		{ErrDNSFailure, "DNS_FAILURE"},
		{ErrRedirectLimit, "REDIRECT_LIMIT"},
		{ErrTimeout, "TIMEOUT"},
		{ErrNetwork, "NETWORK_ERROR"},
	}
	for _, tt := range tests {
		if string(tt.code) != tt.want {
			t.Errorf("code = %q, want %q", tt.code, tt.want)
		}
		if tt.code.Error() != tt.want {
			t.Errorf("Error() = %q, want %q", tt.code.Error(), tt.want)
		}
	}
}

func TestSafeErrorMatching(t *testing.T) {
	t.Parallel()

	cause := context.DeadlineExceeded
	err := wrapError(ErrTimeout, "deadline exceeded", cause)
	outer := fmt.Errorf("request failed: %w", err)

	tests := []struct {
		name   string
		err    error
		target error
		want   bool
	}{
		{"direct code match", err, ErrTimeout, true},
		{"other code does not match", err, ErrBlockedAddress, false},
		{"wrapped code match", outer, ErrTimeout, true},
		{"cause is reachable through Unwrap", err, context.DeadlineExceeded, true},
		{"unrelated error", errors.New("plain"), ErrTimeout, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := errors.Is(tt.err, tt.target); got != tt.want {
				t.Fatalf("errors.Is = %v, want %v", got, tt.want)
			}
		})
	}

	var safeErr *SafeError
	if !errors.As(outer, &safeErr) {
		t.Fatal("errors.As did not find *SafeError through a wrapper")
	}
	if safeErr.Code != ErrTimeout {
		t.Fatalf("Code = %s, want %s", safeErr.Code, ErrTimeout)
	}
	if !strings.Contains(safeErr.Error(), "TIMEOUT") {
		t.Fatalf("Error() = %q, want the code in the message", safeErr.Error())
	}
}

func TestIsTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"ErrTimeout", newError(ErrTimeout, "x"), true},
		{"context deadline", context.DeadlineExceeded, true},
		{"wrapped deadline", fmt.Errorf("x: %w", context.DeadlineExceeded), true},
		{"blocked address", newError(ErrBlockedAddress, "x"), false},
		{"canceled is not a timeout", context.Canceled, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsTimeout(tt.err); got != tt.want {
				t.Fatalf("IsTimeout(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
