package ssrf

import (
	"fmt"
	"net/http"
)

// newRedirectChecker returns the http.Client.CheckRedirect function. It runs
// before every redirect hop is requested. The Location header is resolved
// against the current URL by net/http (URL.ResolveReference semantics), so req.URL
// is absolute here.
//
// via holds the requests made so far, starting with the original request.
// Therefore len(via) is the number of the redirect about to be followed. The
// redirect is refused when that number exceeds maxRedirects.
//
// The URL policy (scheme, credentials, port, hostname, literal address) is
// checked here. Hostnames are checked against the address ranges when the
// connection is made, on the resolved addresses.
func newRedirectChecker(p *policy, maxRedirects int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return newError(ErrRedirectLimit, fmt.Sprintf("more than %d redirects", maxRedirects))
		}
		if _, _, err := p.checkURL(req.URL); err != nil {
			return err
		}
		return nil
	}
}
