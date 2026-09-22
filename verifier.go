// SPDX-License-Identifier: EUPL-1.2

package verifier

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"azugo.io/azugo"
	"go.uber.org/zap"
)

// Offer is a QR-encodable OpenID4VP request plus the transaction ID used to poll/fetch its result.
type Offer struct {
	Link          string
	TransactionID string
}

// OfferRequest carries the per-call knobs GenerateOffer needs from its caller.
type OfferRequest struct {
	// Flow is "cross_device" (QR, default) or "same_device" (wallet opened
	// directly on the presenting device). v2 only - v1's backend doesn't
	// vary behavior by flow.
	Flow string

	// TTL bounds how long the created session accepts a wallet response.
	// v2 only; zero uses the backend's own default.
	TTL time.Duration

	// RedirectURL is where the wallet redirects after presentation. v2 only;
	// omitted from the request entirely if empty.
	RedirectURL string
}

type Inst struct {
	config           *Configuration
	template         *Template
	logger           *zap.Logger
	verifierClient   *verifierV1Client
	verifierV2Client *verifierV2Client

	// txSessions backs GenerateSameDeviceOffer/HandleWalletReturn (samedevice.go).
	txSessions sync.Map

	// webhookJWKS backs VerifyWebhook (webhook.go); nil when V2.WebhookJWKSURL
	// is unset, in which case VerifyWebhook refuses every call.
	webhookJWKS *jwksCache
}

// New builds the verifier client for the configured engine, loading and
// validating Configuration.TemplatePath up front so a bad template fails
// fast at startup rather than on the first offer.
func New(cache CacheProvider, cfg *Configuration, logger *zap.Logger) (*Inst, error) {
	tpl, err := LoadTemplate(cfg.TemplatePath)
	if err != nil {
		return nil, err
	}

	var verifierClient *verifierV1Client
	if cfg.VerifierEngine != EngineV2 {
		verifierClient, err = newVerifierV1Client(cache, cfg.V1)
		if err != nil {
			return nil, err
		}
	}

	var webhookJWKS *jwksCache
	if cfg.V2 != nil && cfg.V2.WebhookJWKSURL != "" {
		webhookJWKS = newJWKSCache(cfg.V2.WebhookJWKSURL)
	}

	return &Inst{
		config:           cfg,
		template:         tpl,
		logger:           logger,
		verifierClient:   verifierClient,
		verifierV2Client: newVerifierV2Client(cfg.V2),
		webhookJWKS:      webhookJWKS,
	}, nil
}

// GenerateOffer starts a new presentation transaction and returns its QR deep link.
func (i *Inst) GenerateOffer(ctx *azugo.Context, req OfferRequest) (*Offer, error) {
	if i.config.VerifierEngine == EngineV2 {
		link, transactionID, err := i.verifierV2Client.generateOffer(ctx, i.template, req)
		if err != nil {
			ctx.Log().Error("failed to generate credential offer from verifier v2 backend", zap.Error(err))

			return nil, err
		}

		return &Offer{Link: normalizeVPScheme(link), TransactionID: transactionID}, nil
	}

	identificationData := i.template.identificationData()
	ctx.Log().Debug("creating verifier session", zap.Any("request", identificationData))

	resp, err := i.verifierClient.generateCredentialOffer(ctx, identificationData)
	if err != nil {
		ctx.Log().Error("failed to generate credential offer from verifier backend", zap.Error(err))

		return nil, err
	}

	link := resp.AuthorizationRequestURI
	if link == "" {
		link = i.config.DeepLinkScheme + "://?client_id=" + resp.ClientID + "&request_uri=" + resp.RequestURI
	}

	return &Offer{Link: normalizeVPScheme(link), TransactionID: resp.TransactionID}, nil
}

// normalizeVPScheme rewrites the verifier's "openid4vp://" deep link scheme to
// "openid-vp://" (the newer OpenID4VP draft's scheme name some wallets expect),
// leaving any other scheme (e.g. a configured "eudi-openid4vp://") untouched.
func normalizeVPScheme(link string) string {
	const oldScheme = "openid4vp://"

	if strings.HasPrefix(link, oldScheme) {
		return "openid-vp://" + strings.TrimPrefix(link, oldScheme)
	}

	return link
}

// Status maps the transaction's current state to one of:
// "initialized", "wallet_scanned", "success_wallet", "failed_attestation", "failed_wallet".
func (i *Inst) Status(ctx *azugo.Context, presentID string) (string, error) {
	if i.config.VerifierEngine == EngineV2 {
		return i.verifierV2Client.status(ctx, presentID)
	}

	status, err := i.verifierClient.presentStatus(ctx, presentID)
	if err != nil {
		return "error", err
	}

	return statusFromEvents(status), nil
}

// statusFromEvents applies the same actor-status decision rules as Status, so both the
// request-scoped path and the background poller (which can't reuse an *azugo.Context
// once the originating request has finished) agree on what each state means.
func statusFromEvents(status *v1EventActorStatus) string {
	if status.VerifierEndPoint.Timestamp != 0 && status.VerifierEndPoint.Event == "Attestation status check failed" {
		return "failed_attestation"
	}

	if status.Wallet.Timestamp != 0 {
		switch status.Wallet.Event {
		case "Wallet failed to post response":
			return "failed_wallet"
		case "Wallet response posted":
			return "success_wallet"
		case "Request object retrieved":
			return "wallet_scanned"
		}
	}

	if status.VerifierEndPoint.Timestamp != 0 && status.VerifierEndPoint.Event == "Verifier got wallet response" {
		return "success_wallet"
	}

	return "initialized"
}

// Attributes fetches and extracts the template's claims from a completed presentation.
func (i *Inst) Attributes(ctx *azugo.Context, presentID string) ([]Attribute, error) {
	if i.config.VerifierEngine == EngineV2 {
		return i.verifierV2Client.attributes(ctx, i.template, presentID)
	}

	attestations, err := i.verifierClient.present(ctx, presentID)
	if err != nil {
		return nil, err
	}

	return convertToAttributes(i.template, attestations)
}

// AttributesWithCode redeems a same-device session's one-time response_code,
// releasing its claims. v1 has no response_code concept - it falls back to
// Attributes and ignores responseCode.
func (i *Inst) AttributesWithCode(ctx *azugo.Context, presentID, responseCode string) ([]Attribute, error) {
	if i.config.VerifierEngine == EngineV2 {
		return i.verifierV2Client.attributesWithCode(ctx, i.template, presentID, responseCode)
	}

	return i.Attributes(ctx, presentID)
}

// DebugRedeemURL returns the URL AttributesWithCode would call for presentID/responseCode,
// without the API key - for logging/manual curl-ing while debugging. Empty for v1, which
// has no equivalent endpoint.
func (i *Inst) DebugRedeemURL(presentID, responseCode string) string {
	if i.config.VerifierEngine != EngineV2 {
		return ""
	}

	url := strings.TrimSuffix(i.config.V2.URL, "/") + "/api/v1/sessions/" + presentID
	if responseCode != "" {
		url += "?responseCode=" + responseCode
	}

	return url
}

var (
	errPresentationFailed   = errors.New("presentation failed")
	errPresentationTimedOut = errors.New("presentation timed out")
)

// PollUntilComplete polls the verifier backend directly - bypassing azugo.Context, since
// none is available once the request that started this transaction has already finished
// (the /open same-device flow backgrounds the browser tab for as long as the wallet app
// is open, so nothing keeps client-side polling alive). Blocks until the presentation
// succeeds, fails, or retries*wait elapses.
func (i *Inst) PollUntilComplete(ctx context.Context, presentID string, retries int, wait time.Duration) ([]Attribute, error) {
	for range retries {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		status, err := i.backgroundStatus(presentID)
		if err == nil {
			switch status {
			case "success_wallet":
				if attrs, aerr := i.backgroundAttributes(presentID); aerr == nil {
					return attrs, nil
				}
				// state is "verified" but the backend hasn't populated the result yet -
				// retry rather than failing the whole poll on one race.
			case "failed_attestation", "failed_wallet":
				return nil, errPresentationFailed
			}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}

	return nil, errPresentationTimedOut
}

// CompletionFunc is called once a presentation started via StartAsync settles
// (success, failure, or timeout). correlationID is whatever opaque value the
// caller passed to StartAsync, echoed back for the caller's own logging - edim
// never interprets it.
type CompletionFunc func(attrs []Attribute, correlationID string, err error)

// StartAsync spawns a goroutine that polls presentID to completion and calls
// onComplete exactly once with the result. It owns the whole background
// lifecycle (goroutine, timeout, polling) so callers don't need their own -
// they just react to the outcome. correlationID is optional (pass "" if
// unneeded) and is only used to enrich this package's own log line on
// poll failure/timeout; it is never parsed.
func (i *Inst) StartAsync(presentID string, retries int, wait time.Duration, correlationID string, onComplete CompletionFunc) {
	timeout := time.Duration(retries) * wait

	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		attrs, err := i.PollUntilComplete(bgCtx, presentID, retries, wait)
		if err != nil {
			i.logger.Info("presentation poll did not complete",
				zap.String("presentID", presentID), zap.String("correlationID", correlationID), zap.Error(err))
		}

		onComplete(attrs, correlationID, err)
	}()
}

func (i *Inst) backgroundStatus(presentID string) (string, error) {
	if i.config.VerifierEngine == EngineV2 {
		return i.verifierV2Client.backgroundStatus(presentID)
	}

	status, err := v1BackgroundEvents(i.config.V1.URL, presentID)
	if err != nil {
		return "", err
	}

	return statusFromEvents(status), nil
}

func (i *Inst) backgroundAttributes(presentID string) ([]Attribute, error) {
	if i.config.VerifierEngine == EngineV2 {
		return i.verifierV2Client.backgroundAttributes(i.template, presentID)
	}

	attestations, err := v1BackgroundPresentation(i.config.V1.URL, presentID)
	if err != nil {
		return nil, err
	}

	return convertToAttributes(i.template, attestations)
}
