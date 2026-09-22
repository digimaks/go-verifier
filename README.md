# go-verifier

Go client for the EUDI/EDIM OpenID4VP verifier stack. Wraps two different
verifier backends behind one interface (`Inst`), so a calling service never
has to know which one is live:

- **v1** — the reference EUDI verifier backend's `/ui/presentations`
  endpoints (mso_mdoc, cross-device only). Formerly a separate `go-edim`
  client library; that logic now lives in this package directly.
- **v2** — the `mgmt/api/v1/sessions` REST API (management-api), which adds
  same-device flow, `redirectUri`/`response_code`, and signed webhooks.

What credential(s)/claims to request is driven entirely by a JSON
**template** file, not hardcoded — this package has no fixed idea of what a
credential "means". A calling service gets back generic `[]Attribute`
(`Namespace`/`Key`/`Value`) from every completion path and decides what to
do with them itself.

## Install

```sh
go get github.com/digimaks/go-verifier
```

## Quick start

```go
import (
    "azugo.io/azugo"
    verifierpkg "github.com/digimaks/go-verifier"
)

verifier, err := verifierpkg.New(azApp, cfg.Verifier, azApp.Log())
if err != nil {
    return err
}

// Cross-device (QR code) offer:
offer, err := verifier.GenerateOffer(ctx, verifierpkg.OfferRequest{Flow: "cross_device"})
// offer.Link is what you render as a QR code / deep link.
// offer.TransactionID is what you poll or redeem with later.

// Poll for completion (from the same request, browser-driven):
status, err := verifier.Status(ctx, offer.TransactionID)
attrs, err := verifier.Attributes(ctx, offer.TransactionID) // once status == "success_wallet"

// Or let the package poll in the background (e.g. while a wallet app has the
// browser tab backgrounded and nothing guarantees the tab ever resumes):
verifier.StartAsync(offer.TransactionID, 24, 5*time.Second, "", func(attrs []verifierpkg.Attribute, correlationID string, err error) {
    // called exactly once, from a goroutine, once the presentation settles or times out
})
```

`verifierpkg` above is just an import alias (this doc's convention for
distinguishing the package from the `verifier` instance variable) - nothing
requires it; `verifier "github.com/digimaks/go-verifier"` or the plain
default `verifier` import all work equally well as long as the instance
variable is named something else.

## Setting up `verifierpkg.New`

```go
func New(cache CacheProvider, cfg *Configuration, logger *zap.Logger) (*Inst, error)
```

- `cache` — a `CacheProvider` (v1 only; e.g. the Azugo `*azugo.App`
  itself satisfies it). Ignored when `VerifierEngine` is `"v2"`.
- `cfg` — see [Configuration](#configuration) below.
- `logger` — used for the package's own internal logging (background poll
  failures, etc).

`New` loads and validates `cfg.TemplatePath` up front, so a bad template
file fails fast at startup rather than on the first offer.

## Configuration

```go
type Configuration struct {
    VerifierEngine string           // "v1" (default) or "v2"
    V1             *V1Configuration // v1 engine settings
    V2             *V2Configuration // v2 engine settings
    TemplatePath   string           // required: path to the credential template JSON
    DeepLinkScheme string           // v1 only; default "eudi-openid4vp"
}
```

| Field | Env var | Required | Notes |
|---|---|---|---|
| `VerifierEngine` | `VERIFIER_ENGINE` | no | `v1` or `v2`, default `v1` |
| `TemplatePath` | `EDIM_TEMPLATE_PATH` | **yes** | see [Template](#template) |
| `DeepLinkScheme` | `EDIM_DEEP_LINK_SCHEME` | no | default `eudi-openid4vp`; v1 only, used when the backend's response has no ready-made deep link |

### `V1Configuration` (v1 only)

| Field | Env var | Required | Notes |
|---|---|---|---|
| `URL` | `VERIFIER_BACKEND_URL` | **yes** | |
| `PresentRetries` | `VERIFIER_BACKEND_PRESENT_RETRIES` | no | default 24 |
| `PresentWaitInSeconds` | `VERIFIER_BACKEND_VERIFY_WAIT_IN_SECONDS` | no | default 5 |
| `PresentTTL` | `VERIFIER_CACHE_TTL` | **yes** | e.g. `10m` |
| `Profile` | `VERIFIER_PROFILE` | no | `openid4vp` \| `haip` |
| `AuthorizationRequestScheme` | `VERIFIER_AUTHORIZATION_REQUEST_SCHEME` | no | e.g. `eudi-openid4vp://` |

### `V2Configuration` (v2 only)

| Field | Env var | Required | Notes |
|---|---|---|---|
| `URL` | `VERIFIER_V2_URL` | **yes** | management-api's mgmt base URL (internal, not the wallet-facing host) |
| `APIKey` | `VERIFIER_V2_API_KEY` (or `VERIFIER_V2_API_KEY_FILE`) | **yes** | client API key |
| `WebhookJWKSURL` | `VERIFIER_V2_WEBHOOK_JWKS_URL` | no | see [Webhooks](#webhooks) |
| `SameDeviceTxTTL` | `VERIFIER_V2_SAME_DEVICE_TX_TTL` | no | default `5m`; how long an unredeemed `GenerateSameDeviceOffer` tx is kept in memory before being dropped |

### Template

`TemplatePath` points to a JSON file describing what to request:

```json
{
  "credentials": [
    {
      "id": "pid_mdoc",
      "doctype_or_vct": "eu.europa.ec.eudi.pid.1",
      "format": "mso_mdoc",
      "name": "Person Identification Data (PID)",
      "algorithms": ["ES256", "ES384", "ES512", "EdDSA"],
      "claims": [
        { "key": "given_name", "intent_to_retain": true },
        { "key": "family_name", "intent_to_retain": true }
      ]
    }
  ]
}
```

Every claim retained from a successful presentation comes back as a
`verifierpkg.Attribute{Namespace: doctype_or_vct, Key: claim key, Value: any}` —
add more credentials/claims here to request more, no code changes needed.

## Completion flows

There are three ways to learn a presentation's outcome, matching the three
places a wallet's response can reach you:

### 1. Cross-device polling (`Status` / `Attributes`)

The default flow: render `offer.Link` as a QR code, poll
`Status(ctx, transactionID)` from the browser until it's `"success_wallet"`,
then call `Attributes(ctx, transactionID)`. `StartAsync`/`PollUntilComplete`
do the same polling server-side (useful when nothing guarantees the browser
tab keeps polling, e.g. a wallet app that backgrounds it).

### 2. Same-device redirect (`GenerateSameDeviceOffer` / `HandleWalletReturn`)

v2 only. For a same-device flow (the wallet is opened directly on the
presenting device), the verifier can redirect the wallet's browser back to
you with a one-time `response_code` once the presentation completes — no
polling needed, and it's the only way to learn a same-device session's
result at all (a plain poll reports `state` but withholds `result`).

```go
// Before opening the wallet:
offer, err := verifier.GenerateSameDeviceOffer(ctx, "https://your-service/wallet/return", myCorrelationData)
// offer.Link opens the wallet directly (not rendered as a QR).
// The package generates a one-time tx, embeds it in the redirect URL it
// hands the verifier, and remembers tx -> (session id, myCorrelationData) for you.

// Later, on your own /wallet/return?tx=...&response_code=... handler:
sessionID, data, attrs, err := verifier.HandleWalletReturn(ctx, tx, responseCode)
if errors.Is(err, verifierpkg.ErrUnknownTx) {
    // tx unknown, expired, or already redeemed - not a transient failure
}
// data is myCorrelationData, unchanged - e.g. an authorization request id, a
// PKCE verifier, whatever this flow needs to resume. Pass nil if unneeded.
```

`data` travels out-of-band, in the package's own in-memory bookkeeping - not
in the URL - so it can be anything (not just a string) and, importantly,
never collides with the "tx" query parameter `GenerateSameDeviceOffer` itself
appends to `returnURL`. If you separately need your own query parameters on
the return URL (e.g. a return page shared across multiple flows), use any
name other than `tx` for them.

### 3. Webhook (`VerifyWebhook`)

v2 only, requires `V2Configuration.WebhookJWKSURL`. management-api can push
a signed HTTP callback the moment a session reaches a terminal state
(`verified`/`failed`/`expired`), independent of whether the wallet's own
redirect ever arrives or the flow is same_device/cross_device. This is the
only way to observe a same-device session that doesn't have a browser
attached at all (e.g. no redirect target configured).

```go
func serveVerifierWebhook(ctx *azugo.Context, verifier *verifierpkg.Inst, store attendance.Store) {
    result, err := verifier.VerifyWebhook(ctx.Body.Bytes(), ctx.Header.Get(verifierpkg.WebhookSignatureHeader))
    if err != nil {
        // bad/missing signature, or webhook not configured (ErrNotSupported)
        ctx.StatusCode(fasthttp.StatusForbidden)
        return
    }
    if result.State != "verified" {
        ctx.StatusCode(fasthttp.StatusOK) // ack failed/expired, nothing to do
        return
    }
    // result.Attributes is populated - do whatever you do with attributes.
    ctx.StatusCode(fasthttp.StatusOK)
}
```

`VerifyWebhook` verifies the detached-JWS `X-Payload-Signature` header
against the verifier's public JWKS (fetched from `WebhookJWKSURL` and
cached, refreshed on a 10-minute TTL or immediately on an unknown `kid`),
then parses the payload and extracts this `Inst`'s template attributes.

**Operator setup required** — a webhook has to be registered against your
client before any of this fires:

```http
PUT /api/clients/{clientId}/webhook
X-API-Key: <registration-api admin key>
Content-Type: application/json

{"webhookUrl": "https://your-service/webhook/verifier"}
```

```http
PUT /api/clients/{clientId}/allowed-origins
X-API-Key: <registration-api admin key>
Content-Type: application/json

{"allowedOrigins": ["https://your-service"]}
```

(The same allowed-origins list also gates `GenerateSameDeviceOffer`'s
`redirectUri`.)

## API reference (selected)

| Method | Engine | Purpose |
|---|---|---|
| `New(cache, cfg, logger) (*Inst, error)` | both | construct |
| `GenerateOffer(ctx, OfferRequest) (*Offer, error)` | both | low-level offer creation; `OfferRequest{Flow, TTL, RedirectURL}` |
| `GenerateSameDeviceOffer(ctx, returnURL, data any) (*Offer, error)` | v2 | same_device offer + tx bookkeeping; `data` is optional caller correlation state returned unchanged by `HandleWalletReturn` |
| `Status(ctx, presentID) (string, error)` | both | `initialized`/`wallet_scanned`/`success_wallet`/`failed_attestation`/`failed_wallet` |
| `Attributes(ctx, presentID) ([]Attribute, error)` | both | fetch claims once verified |
| `AttributesWithCode(ctx, presentID, responseCode) ([]Attribute, error)` | both (v1 ignores code) | redeem a same-device session |
| `HandleWalletReturn(ctx, tx, responseCode) (sessionID string, data any, attrs []Attribute, err error)` | v2 | resolve a `GenerateSameDeviceOffer` tx and redeem in one call |
| `VerifyWebhook(body, signatureHeader) (*WebhookResult, error)` | v2 | verify + parse a webhook call |
| `FetchRequestObject(offer) (body []byte, contentType string, err error)` | both | proxy the wallet's request-object fetch through your own domain |
| `PollUntilComplete(ctx, presentID, retries, wait) ([]Attribute, error)` | both | blocking poll |
| `StartAsync(presentID, retries, wait, correlationID, onComplete)` | both | background poll, calls back once |
| `DebugRedeemURL(presentID, responseCode) string` | v2 | the URL `AttributesWithCode` would call, API key excluded — for manual `curl`-ing while debugging |

Sentinel errors: `ErrNotSupported` (v1, or v2 without `WebhookJWKSURL`),
`ErrUnknownTx` (unknown/already-redeemed `tx`).

## Before committing

```sh
gofumpt -w ./..
golangci-lint run
go test ./...
```
