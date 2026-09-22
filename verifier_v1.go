// SPDX-License-Identifier: EUPL-1.2

package verifier

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"azugo.io/azugo"
	"azugo.io/core/cache"
	"azugo.io/core/http"
)

// v1Attestation is one decoded mso_mdoc document from a v1 presentation response.
type v1Attestation struct {
	DocType    string                 `json:"docType"`
	Attributes map[string]interface{} `json:"attributes"`
}

// v1Events holds the v1 verifier's presentation events payload.
type v1Events struct {
	TransactionID string        `json:"transaction_id"`
	LastUpdated   int64         `json:"last_updated"`
	Events        []v1EventItem `json:"events"`
}

// v1EventItem describes a single verifier or wallet event in the v1 transaction lifecycle.
type v1EventItem struct {
	Timestamp int64  `json:"timestamp"`
	Event     string `json:"event"`
	Actor     string `json:"actor"`
	Cause     string `json:"cause,omitempty"`
}

type v1EventActorStatus struct {
	Verifier         v1EventItem `json:"verifier"`
	Wallet           v1EventItem `json:"wallet"`
	VerifierEndPoint v1EventItem `json:"verifierEndPoint"`
}

// v1IdentificationData is one credential's request shape for the v1 backend.
type v1IdentificationData struct {
	ID         string                  `json:"id"`
	Name       string                  `json:"name"`
	Purpose    string                  `json:"purpose"`
	Algorithms []string                `json:"algorithms"`
	Fields     []v1IdentificationField `json:"fields"`
}

type v1IdentificationField struct {
	Key            string `json:"key"`
	IntentToRetain bool   `json:"intentToRetain"`
}

// v1PrepareRequest is the /ui/presentations/v2 request body.
type v1PrepareRequest struct {
	Nonce                      string       `json:"nonce"`
	DcqlQuery                  *v1DcqlQuery `json:"dcql_query,omitempty"`
	Profile                    string       `json:"profile,omitempty"`                      // "openid4vp" | "haip"
	AuthorizationRequestScheme string       `json:"authorization_request_scheme,omitempty"` // e.g. "eudi-openid4vp://"
}

// v1DcqlQuery is the Digital Credentials Query Language query sent in the presentation request.
type v1DcqlQuery struct {
	Credentials []v1DcqlCredential `json:"credentials"`
}

type v1DcqlCredential struct {
	ID     string        `json:"id"`
	Format string        `json:"format"`
	Meta   *v1DcqlMeta   `json:"meta,omitempty"`
	Claims []v1DcqlClaim `json:"claims,omitempty"`
}

type v1DcqlMeta struct {
	DoctypeValue string `json:"doctype_value,omitempty"`
}

type v1DcqlClaim struct {
	Path           []string `json:"path"`
	IntentToRetain *bool    `json:"intent_to_retain,omitempty"`
}

type v1PrepareResponse struct {
	ClientID                string `json:"client_id"`
	RequestURI              string `json:"request_uri"`
	TransactionID           string `json:"transaction_id"`
	AuthorizationRequestURI string `json:"authorization_request_uri"` // populated by /ui/presentations/v2
}

// v1Presentation holds the v1 verifier response for a completed presentation.
// VpToken is keyed by DCQL credential query ID; each value is an array of
// base64url-encoded CBOR DeviceResponse VP values.
type v1Presentation struct {
	VpToken map[string][]string `json:"vp_token"`
}

// CacheProvider is what New needs to hand the v1 backend a cache store (e.g.
// the Azugo *azugo.App itself satisfies it). Ignored when VerifierEngine is "v2".
type CacheProvider interface {
	Cache() *cache.Cache
}

const v1StoreCache = "edim-verify"

// verifierV1Client talks to the reference EUDI verifier backend's
// /ui/presentations endpoints.
type verifierV1Client struct {
	config *V1Configuration
	ch     cache.Instance[[]v1IdentificationData]
	mu     sync.Mutex
}

func newVerifierV1Client(app CacheProvider, config *V1Configuration) (*verifierV1Client, error) {
	ch, err := cache.Create[[]v1IdentificationData](app.Cache(), v1StoreCache, cache.DefaultTTL(config.PresentTTL))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize verifier: %w", err)
	}

	return &verifierV1Client{
		config: config,
		ch:     ch,
	}, nil
}

func (c *verifierV1Client) generateCredentialOffer(ctx *azugo.Context, identificationData []v1IdentificationData) (*v1PrepareResponse, error) {
	client := ctx.HTTPClient().WithBaseURL(strings.TrimSuffix(c.config.URL, "/"))

	res := &v1PrepareResponse{}

	request := v1PrepareData(identificationData)

	if c.config.Profile != "" {
		request.Profile = c.config.Profile
	}

	if c.config.AuthorizationRequestScheme != "" {
		request.AuthorizationRequestScheme = c.config.AuthorizationRequestScheme
	}

	err := client.PostJSON("/ui/presentations/v2", request, res)
	if err != nil {
		return nil, fmt.Errorf("failed to call generate credential: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	err = c.ch.Set(ctx, res.TransactionID, identificationData)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *verifierV1Client) present(ctx *azugo.Context, presentID string) ([]v1Attestation, error) {
	respPresent, err := c.presentRaw(ctx, presentID)
	if err != nil {
		return nil, err
	}

	output, err := decodeV1Presentation(respPresent)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	origReq, err := c.ch.Get(ctx, presentID)
	if err != nil {
		return nil, err
	}

	err = v1CheckRequiredFields(origReq, output)
	if err != nil {
		return nil, err
	}

	return output, nil
}

func (c *verifierV1Client) presentStatus(ctx *azugo.Context, presentID string) (*v1EventActorStatus, error) {
	respEvents, err := c.presentEvents(ctx, presentID)
	if err != nil {
		return nil, err
	}

	return v1LatestEventPerActor(respEvents), nil
}

func (c *verifierV1Client) presentEvents(ctx *azugo.Context, presentID string) (*v1Events, error) {
	client := ctx.HTTPClient().WithBaseURL(strings.TrimSuffix(c.config.URL, "/"))

	res := &v1Events{}

	err := client.GetJSON("/ui/presentations/"+presentID+"/events", res)
	if err != nil {
		return nil, fmt.Errorf("failed to call present: %w", err)
	}

	return res, nil
}

func (c *verifierV1Client) presentRaw(ctx *azugo.Context, presentID string) (*v1Presentation, error) {
	client := ctx.HTTPClient().WithBaseURL(strings.TrimSuffix(c.config.URL, "/"))

	res := &v1Presentation{}

	err := client.GetJSON("/ui/presentations/"+presentID, res)
	if err != nil {
		return nil, fmt.Errorf("failed to call present: %w", err)
	}

	return res, nil
}

// v1LatestEventPerActor keeps, per actor, only the most recent event - shared
// by the request-scoped presentStatus and the background poller, which fetch
// the same events shape but can't share an *azugo.Context.
func v1LatestEventPerActor(events *v1Events) *v1EventActorStatus {
	res := &v1EventActorStatus{}

	for _, item := range events.Events {
		switch item.Actor {
		case "Verifier":
			if res.Verifier.Timestamp == 0 || res.Verifier.Timestamp < item.Timestamp {
				res.Verifier = item
			}
		case "Wallet":
			if res.Wallet.Timestamp == 0 || res.Wallet.Timestamp < item.Timestamp {
				res.Wallet = item
			}
		case "VerifierEndPoint":
			if res.VerifierEndPoint.Timestamp == 0 || res.VerifierEndPoint.Timestamp < item.Timestamp {
				res.VerifierEndPoint = item
			}
		}
	}

	return res
}

// multiError collects every field-check failure across a presentation's
// credentials rather than stopping at the first one.
type multiError struct {
	errors []error
}

func (m *multiError) Error() string {
	msgs := make([]string, 0, len(m.errors))
	for _, err := range m.errors {
		msgs = append(msgs, err.Error())
	}

	return strings.Join(msgs, "; ")
}

func (m *multiError) add(err error) {
	m.errors = append(m.errors, err)
}

func v1CheckRequiredFields(request []v1IdentificationData, response []v1Attestation) error {
	multiErr := &multiError{}

	for _, req := range request {
		attributes, err := v1FindAttributes(response, req.ID)
		if err != nil {
			multiErr.add(err)

			continue
		}

		if err := v1CompareFields(req.Fields, attributes); err != nil {
			multiErr.add(err)
		}
	}

	if len(multiErr.errors) > 0 {
		return multiErr
	}

	return nil
}

func v1CompareFields(request []v1IdentificationField, response map[string]interface{}) error {
	for _, req := range request {
		if !req.IntentToRetain {
			continue
		}

		if value, ok := response[req.Key]; !ok || value == nil {
			return fmt.Errorf("%q not found", req.Key)
		}
	}

	return nil
}

func v1FindAttributes(attestations []v1Attestation, key string) (map[string]interface{}, error) {
	if attrMap, ok := findAttestationAttributes(attestations, key); ok {
		return attrMap, nil
	}

	return nil, fmt.Errorf("%q not found", key)
}

// v1BackgroundEvents fetches presentID's events without an *azugo.Context -
// for use once the request that started the transaction has already finished.
func v1BackgroundEvents(baseURL, presentID string) (*v1EventActorStatus, error) {
	client := http.NewClient().WithBaseURL(strings.TrimSuffix(baseURL, "/"))

	events := &v1Events{}
	if err := client.GetJSON("/ui/presentations/"+presentID+"/events", events); err != nil {
		return nil, err
	}

	return v1LatestEventPerActor(events), nil
}

// v1BackgroundPresentation fetches and decodes presentID's presentation
// without an *azugo.Context.
func v1BackgroundPresentation(baseURL, presentID string) ([]v1Attestation, error) {
	client := http.NewClient().WithBaseURL(strings.TrimSuffix(baseURL, "/"))

	presentation := &v1Presentation{}
	if err := client.GetJSON("/ui/presentations/"+presentID, presentation); err != nil {
		return nil, err
	}

	return decodeV1Presentation(presentation)
}

var errV1DocTypeMissing = errors.New("verifier: v1 document has no docType")
