// SPDX-License-Identifier: EUPL-1.2

package verifier

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"go.uber.org/zap"
)

type v2SessionResponse struct {
	SessionID string `json:"sessionId"`
	State     string `json:"state"`
	WalletURL string `json:"walletUrl"`
	QRPayload string `json:"qrPayload"`
}

// v2ResultCredential is one credential's result, shared between the polling
// response (v2StatusResponse) and the webhook payload (webhook.go) - both
// carry the identical shape.
type v2ResultCredential struct {
	QueryID      string                            `json:"queryId"`
	DoctypeOrVct string                            `json:"doctypeOrVct"`
	Claims       map[string]map[string]interface{} `json:"claims"`
}

type v2StatusResponse struct {
	SessionID string `json:"sessionId"`
	State     string `json:"state"`
	Failure   *struct {
		Code string `json:"code"`
	} `json:"failure,omitempty"`
	Result *struct {
		Credentials []v2ResultCredential `json:"credentials"`
	} `json:"result,omitempty"`
}

// attributesFromCredentials extracts, for every credential in the template, the
// claims it asked for from whichever matching result credential carries them -
// shared by attributesWith (polling) and VerifyWebhook (webhook.go), since both
// receive the same doctypeOrVct-keyed claims shape.
func attributesFromCredentials(tpl *Template, credentials []v2ResultCredential) []Attribute {
	var out []Attribute

	for _, cred := range tpl.Credentials {
		for _, resCred := range credentials {
			claims, ok := resCred.Claims[cred.DoctypeOrVct]
			if !ok {
				continue
			}

			for _, claim := range cred.Claims {
				value, ok := claims[claim.Key]
				if !ok {
					continue
				}

				out = append(out, Attribute{Namespace: cred.DoctypeOrVct, Key: claim.Key, Value: value})
			}
		}
	}

	return out
}

// verifierV2Client talks to the mgmt/api/v1/sessions verifier backend.
type verifierV2Client struct {
	config *V2Configuration
}

func newVerifierV2Client(config *V2Configuration) *verifierV2Client {
	return &verifierV2Client{config: config}
}

func (c *verifierV2Client) client(ctx *azugo.Context) http.Client {
	return ctx.HTTPClient().WithBaseURL(strings.TrimSuffix(c.config.URL, "/"))
}

// backgroundClient is for use once the request that started a transaction has already
// finished (see Inst.PollUntilComplete) - ctx.HTTPClient() isn't available at that point.
func (c *verifierV2Client) backgroundClient() http.Client {
	return http.NewClient().WithBaseURL(strings.TrimSuffix(c.config.URL, "/"))
}

// dcqlQuery builds a DCQL query from the template: one DCQL credential per
// template credential, one claim path per requested claim.
func dcqlQuery(tpl *Template) map[string]interface{} {
	credentials := make([]map[string]interface{}, 0, len(tpl.Credentials))

	for _, cred := range tpl.Credentials {
		claims := make([]map[string]interface{}, 0, len(cred.Claims))
		for _, claim := range cred.Claims {
			claims = append(claims, map[string]interface{}{"path": []string{cred.DoctypeOrVct, claim.Key}})
		}

		credentials = append(credentials, map[string]interface{}{
			"id":     cred.ID,
			"format": cred.Format,
			"meta":   map[string]string{"doctype_value": cred.DoctypeOrVct},
			"claims": claims,
		})
	}

	return map[string]interface{}{"credentials": credentials}
}

func (c *verifierV2Client) generateOffer(ctx *azugo.Context, tpl *Template, offerReq OfferRequest) (string, string, error) {
	flow := offerReq.Flow
	if flow == "" {
		flow = "cross_device"
	}

	ttlSeconds := int(offerReq.TTL / time.Second)
	if ttlSeconds == 0 {
		ttlSeconds = 300
	}

	req := map[string]interface{}{
		"presentation": map[string]interface{}{
			"dcqlQuery": dcqlQuery(tpl),
		},
		"flow":       flow,
		"ttlSeconds": ttlSeconds,
	}

	if offerReq.RedirectURL != "" {
		req["redirectUri"] = offerReq.RedirectURL
	}

	ctx.Log().Debug("creating verifier session", zap.Any("request", req))

	res := &v2SessionResponse{}

	err := c.client(ctx).PostJSON("/api/v1/sessions", req, res, http.WithHeader("X-API-Key", c.config.APIKey))
	if err != nil {
		return "", "", fmt.Errorf("failed to create verifier session: %w", err)
	}

	return res.QRPayload, res.SessionID, nil
}

// status maps a v2 session state to the same status strings the v1 client returns.
func (c *verifierV2Client) status(ctx *azugo.Context, sessionID string) (string, error) {
	return c.statusWith(c.client(ctx), sessionID)
}

func (c *verifierV2Client) backgroundStatus(sessionID string) (string, error) {
	return c.statusWith(c.backgroundClient(), sessionID)
}

func (c *verifierV2Client) statusWith(client http.Client, sessionID string) (string, error) {
	res := &v2StatusResponse{}

	err := client.GetJSON("/api/v1/sessions/"+sessionID, res, http.WithHeader("X-API-Key", c.config.APIKey))
	if err != nil {
		return "error", fmt.Errorf("failed to get verifier session: %w", err)
	}

	switch res.State {
	case "verified":
		return "success_wallet", nil
	case "failed", "expired":
		code := "unknown"
		if res.Failure != nil {
			code = res.Failure.Code
		}

		return "failed_attestation", errors.New(code)
	case "wallet_engaged":
		return "wallet_scanned", nil
	default:
		return "initialized", nil
	}
}

func (c *verifierV2Client) attributes(ctx *azugo.Context, tpl *Template, sessionID string) ([]Attribute, error) {
	return c.attributesWith(c.client(ctx), tpl, sessionID, "")
}

func (c *verifierV2Client) backgroundAttributes(tpl *Template, sessionID string) ([]Attribute, error) {
	return c.attributesWith(c.backgroundClient(), tpl, sessionID, "")
}

func (c *verifierV2Client) attributesWithCode(ctx *azugo.Context, tpl *Template, sessionID, responseCode string) ([]Attribute, error) {
	return c.attributesWith(c.client(ctx), tpl, sessionID, responseCode)
}

// attributesWith fetches a session's result. A same-device session only releases its
// claims to a request carrying the correct responseCode; without one, state is
// reported but result is withheld.
func (c *verifierV2Client) attributesWith(client http.Client, tpl *Template, sessionID, responseCode string) ([]Attribute, error) {
	res := &v2StatusResponse{}

	opts := []http.RequestOption{http.WithHeader("X-API-Key", c.config.APIKey)}
	if responseCode != "" {
		// WithQueryArg, not a hand-built "?..." suffix: the client joins the path via
		// url.JoinPath, which percent-encodes "?"/"&" as literal path characters rather
		// than treating them as a query string.
		opts = append(opts, http.WithQueryArg("responseCode", responseCode))
	}

	err := client.GetJSON("/api/v1/sessions/"+sessionID, res, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to get verifier session: %w", err)
	}

	if res.State != "verified" || res.Result == nil || len(res.Result.Credentials) == 0 {
		return nil, fmt.Errorf("verifier session %q has no verified credentials (state: %s)", sessionID, res.State)
	}

	out := attributesFromCredentials(tpl, res.Result.Credentials)

	if len(out) == 0 {
		return nil, fmt.Errorf("verifier session %q: no attribute from the configured template was present in the result", sessionID)
	}

	return out, nil
}
