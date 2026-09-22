// SPDX-License-Identifier: EUPL-1.2
package verifier

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"azugo.io/azugo"
	"go.uber.org/zap"
)

// newTestSameDeviceInst returns an Inst wired against a fake mgmt-api server:
// POST /api/v1/sessions captures the redirectUri it was given (so the test can
// recover the tx GenerateSameDeviceOffer generated, exactly as a real wallet
// redirect would carry it back) and always succeeds; any GET reports a
// verified session with one credential.
func newTestSameDeviceInst(t *testing.T) (i *Inst, capturedRedirectURI *string) {
	t.Helper()

	var redirectURI string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			redirectURI, _ = req["redirectUri"].(string)

			_ = json.NewEncoder(w).Encode(v2SessionResponse{SessionID: "sess1", QRPayload: "openid4vp://?client_id=x"})

			return
		}

		res := v2StatusResponse{
			SessionID: "sess1",
			State:     "verified",
			Result: &struct {
				Credentials []v2ResultCredential `json:"credentials"`
			}{
				Credentials: []v2ResultCredential{
					{
						DoctypeOrVct: "org.iso.18013.5.1.mDL",
						Claims: map[string]map[string]interface{}{
							"org.iso.18013.5.1.mDL": {"document_number": "DL123456"},
						},
					},
				},
			},
		}

		_ = json.NewEncoder(w).Encode(res)
	}))
	t.Cleanup(srv.Close)

	i = &Inst{
		config:           &Configuration{VerifierEngine: EngineV2},
		template:         nonPIDTemplate(),
		logger:           zap.NewNop(),
		verifierV2Client: newVerifierV2Client(&V2Configuration{URL: srv.URL, APIKey: "key"}),
	}

	return i, &redirectURI
}

// txFromRedirectURI extracts the tx GenerateSameDeviceOffer embedded in the
// redirectUri it sent to mgmt-api - standing in for the wallet's own redirect
// carrying it back to the return page.
func txFromRedirectURI(t *testing.T, redirectURI string) string {
	t.Helper()

	u, err := url.Parse(redirectURI)
	if err != nil {
		t.Fatalf("parse redirectUri %q: %v", redirectURI, err)
	}

	tx := u.Query().Get("tx")
	if tx == "" {
		t.Fatalf("redirectUri %q has no tx", redirectURI)
	}

	return tx
}

func TestSameDevice_GenerateOfferThenHandleWalletReturn(t *testing.T) {
	i, redirectURI := newTestSameDeviceInst(t)

	app := azugo.NewTestApp()
	app.Start(t)
	t.Cleanup(app.Stop)

	var (
		offer    *Offer
		offerErr error
	)

	app.Get("/generate", func(ctx *azugo.Context) {
		offer, offerErr = i.GenerateSameDeviceOffer(ctx, "https://caller/return", "my-correlation-id")
		ctx.StatusCode(200)
	})

	var (
		sessionID string
		data      any
		attrs     []Attribute
		returnErr error
	)

	app.Get("/return", func(ctx *azugo.Context) {
		tx, _ := ctx.Query.String("tx")
		sessionID, data, attrs, returnErr = i.HandleWalletReturn(ctx, tx, "code123")
		ctx.StatusCode(200)
	})

	if _, err := app.TestClient().Get("/generate"); err != nil {
		t.Fatalf("GET /generate: %v", err)
	}

	if offerErr != nil {
		t.Fatalf("GenerateSameDeviceOffer: %v", offerErr)
	}

	if offer.TransactionID != "sess1" {
		t.Fatalf("offer.TransactionID = %q, want sess1", offer.TransactionID)
	}

	tx := txFromRedirectURI(t, *redirectURI)

	if _, err := app.TestClient().Get("/return?tx=" + tx + "&response_code=code123"); err != nil {
		t.Fatalf("GET /return: %v", err)
	}

	if returnErr != nil {
		t.Fatalf("HandleWalletReturn: %v", returnErr)
	}

	if sessionID != "sess1" {
		t.Fatalf("sessionID = %q, want sess1", sessionID)
	}

	if data != "my-correlation-id" {
		t.Fatalf("data = %v, want my-correlation-id", data)
	}

	if len(attrs) != 1 || attrs[0].Key != "document_number" || attrs[0].Value != "DL123456" {
		t.Fatalf("attrs = %+v, want one document_number=DL123456 attribute", attrs)
	}
}

func TestSameDevice_HandleWalletReturn_UnknownTx(t *testing.T) {
	i, _ := newTestSameDeviceInst(t)

	app := azugo.NewTestApp()
	app.Start(t)
	t.Cleanup(app.Stop)

	var returnErr error

	app.Get("/return", func(ctx *azugo.Context) {
		_, _, _, returnErr = i.HandleWalletReturn(ctx, "never-issued", "code123")
		ctx.StatusCode(200)
	})

	if _, err := app.TestClient().Get("/return"); err != nil {
		t.Fatalf("GET /return: %v", err)
	}

	if returnErr != ErrUnknownTx {
		t.Fatalf("HandleWalletReturn error = %v, want ErrUnknownTx", returnErr)
	}
}

func TestSameDevice_HandleWalletReturn_TxSingleUse(t *testing.T) {
	i, redirectURI := newTestSameDeviceInst(t)

	app := azugo.NewTestApp()
	app.Start(t)
	t.Cleanup(app.Stop)

	app.Get("/generate", func(ctx *azugo.Context) {
		_, _ = i.GenerateSameDeviceOffer(ctx, "https://caller/return", nil)
		ctx.StatusCode(200)
	})

	var returnErr error

	app.Get("/return", func(ctx *azugo.Context) {
		tx, _ := ctx.Query.String("tx")
		_, _, _, returnErr = i.HandleWalletReturn(ctx, tx, "code123")
		ctx.StatusCode(200)
	})

	if _, err := app.TestClient().Get("/generate"); err != nil {
		t.Fatalf("GET /generate: %v", err)
	}

	tx := txFromRedirectURI(t, *redirectURI)

	if _, err := app.TestClient().Get("/return?tx=" + tx); err != nil {
		t.Fatalf("GET /return (first): %v", err)
	}

	if returnErr != nil {
		t.Fatalf("first HandleWalletReturn: %v", returnErr)
	}

	if _, err := app.TestClient().Get("/return?tx=" + tx); err != nil {
		t.Fatalf("GET /return (second): %v", err)
	}

	if returnErr != ErrUnknownTx {
		t.Fatalf("second HandleWalletReturn error = %v, want ErrUnknownTx (tx must be single-use)", returnErr)
	}
}

func TestSameDevice_V1NotSupported(t *testing.T) {
	i := &Inst{config: &Configuration{VerifierEngine: EngineV1}}

	app := azugo.NewTestApp()
	app.Start(t)
	t.Cleanup(app.Stop)

	var genErr, returnErr error

	app.Get("/test", func(ctx *azugo.Context) {
		_, genErr = i.GenerateSameDeviceOffer(ctx, "https://caller/return", nil)
		_, _, _, returnErr = i.HandleWalletReturn(ctx, "any", "any")
		ctx.StatusCode(200)
	})

	if _, err := app.TestClient().Get("/test"); err != nil {
		t.Fatalf("GET /test: %v", err)
	}

	if genErr != ErrNotSupported {
		t.Fatalf("GenerateSameDeviceOffer error = %v, want ErrNotSupported", genErr)
	}

	if returnErr != ErrNotSupported {
		t.Fatalf("HandleWalletReturn error = %v, want ErrNotSupported", returnErr)
	}
}
