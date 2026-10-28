package ssrf_test

import (
	"fmt"
	"io"
	"time"

	ssrf "github.com/yedoma-labs/tanur-ssrf-go"
)

// ExampleNewClient shows how to fetch a user-supplied URL. The example is
// compiled by go test but not executed, because it needs a network.
func ExampleNewClient() {
	client, err := ssrf.NewClient(
		ssrf.WithAllowedPorts(80, 443),
		ssrf.WithMaxRedirects(3),
		ssrf.WithTimeout(5*time.Second),
	)
	if err != nil {
		panic(err)
	}

	resp, err := client.Get("https://example.com/image.png")
	if err != nil {
		if ssrf.IsTimeout(err) {
			fmt.Println("timed out")
			return
		}
		fmt.Println("blocked or failed:", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	const maxBytes = 5 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		fmt.Println("read failed:", err)
		return
	}
	fmt.Println("received", len(body), "bytes")
}
