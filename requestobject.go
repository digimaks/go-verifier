// SPDX-License-Identifier: EUPL-1.2

package verifier

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// extractRequestURI pulls the request_uri query parameter out of an
// "eudi-openid4vp://?client_id=...&request_uri=..." deep link. Parsing (rather
// than substring-matching "request_uri=") matters: request_uri_method is a real
// OpenID4VP parameter and would otherwise match first if ordered ahead of it.
func extractRequestURI(link string) (string, error) {
	parsed, err := url.Parse(link)
	if err != nil {
		return "", err
	}

	requestURI := parsed.Query().Get("request_uri")
	if requestURI == "" {
		return "", errors.New("verifier: offer link has no request_uri")
	}

	return requestURI, nil
}

// requestObjectClient bounds the server-side request-object fetch - the default
// http client has no timeout, so a hung verifier backend would pin the wallet-facing
// request with nothing to cancel it.
var requestObjectClient = &http.Client{Timeout: 10 * time.Second}

// requestObjectContentType is the OpenID4VP media type for a signed request
// object, used when the backend's response omits Content-Type (fasthttp would
// otherwise fall back to text/plain).
const requestObjectContentType = "application/oauth-authz-req+jwt"

// FetchRequestObject pulls request_uri out of offer.Link and fetches it,
// returning the raw body and Content-Type so a caller can proxy the
// verifier backend's signed request object back to the wallet unchanged -
// under OpenID4VP's x509_san_dns client_id scheme, the wallet validates the
// SAN of the request object's signing certificate against client_id, not the
// host that served it, so proxying through the caller's own domain is safe.
func (i *Inst) FetchRequestObject(offer *Offer) ([]byte, string, error) {
	requestURI, err := extractRequestURI(offer.Link)
	if err != nil {
		return nil, "", err
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, requestURI, nil)
	if err != nil {
		return nil, "", err
	}

	resp, err := requestObjectClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("verifier: request_uri returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = requestObjectContentType
	}

	return body, contentType, nil
}
