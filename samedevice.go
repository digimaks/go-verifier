// SPDX-License-Identifier: EUPL-1.2

package verifier

import (
	"errors"
	"strings"
	"time"

	"azugo.io/azugo"
	"github.com/google/uuid"
)

// defaultSameDeviceTxTTL is used when V2Configuration.SameDeviceTxTTL is zero
// - either left unset (config.Bind's own default already fills it in for any
// caller that goes through Bind) or when an Inst is built directly without
// Bind (e.g. in tests). Matches generateOffer's own default ttlSeconds
// (verifier_v2.go), so a tx never outlives the session it points to by much.
const defaultSameDeviceTxTTL = 5 * time.Minute

// sameDeviceTxTTL returns the configured TTL, falling back to
// defaultSameDeviceTxTTL when unset.
func (i *Inst) sameDeviceTxTTL() time.Duration {
	if i.config.V2 != nil && i.config.V2.SameDeviceTxTTL > 0 {
		return i.config.V2.SameDeviceTxTTL
	}

	return defaultSameDeviceTxTTL
}

// ErrNotSupported is returned by same-device/webhook operations against a v1
// backend - v1 has no redirect_uri/response_code or webhook concept.
var ErrNotSupported = errors.New("verifier: not supported by this verifier engine")

// ErrUnknownTx is returned by HandleWalletReturn when tx doesn't match a tx
// GenerateSameDeviceOffer generated (never issued, already redeemed, or the
// process that issued it has since restarted).
var ErrUnknownTx = errors.New("verifier: unknown or already-used tx")

// sameDeviceSession is what txSessions stores per tx: the verifier session it
// resolves to, plus whatever correlation data the caller attached in
// GenerateSameDeviceOffer.
type sameDeviceSession struct {
	sessionID string
	data      any
}

// GenerateSameDeviceOffer is GenerateOffer for the "same_device" flow: it
// generates a one-time tx, embeds it as a "tx" query parameter on returnURL to
// build the session's redirectUri, and remembers tx -> the resulting session
// id so a later HandleWalletReturn(ctx, tx, responseCode) can resolve it - the
// caller never needs its own tx bookkeeping.
//
// data is optional caller-defined correlation state (e.g. an authorization
// request id, a PKCE verifier, a state/nonce pair - whatever the implementing
// service needs to bind this return to the flow that started it) stored
// alongside the session and handed back unchanged by HandleWalletReturn. Pass
// nil if unneeded. Since it travels out-of-band from the redirect URL, it
// never collides with the "tx" query parameter this method itself owns - the
// caller's own returnURL is free to carry its own query parameters (under any
// other name) if it separately needs them to survive the wallet's redirect
// (e.g. for a return page shared with other flows).
//
// v1 returns ErrNotSupported.
func (i *Inst) GenerateSameDeviceOffer(ctx *azugo.Context, returnURL string, data any) (*Offer, error) {
	if i.config.VerifierEngine != EngineV2 {
		return nil, ErrNotSupported
	}

	tx := uuid.NewString()

	sep := "?"
	if strings.Contains(returnURL, "?") {
		sep = "&"
	}

	offer, err := i.GenerateOffer(ctx, OfferRequest{Flow: "same_device", RedirectURL: returnURL + sep + "tx=" + tx})
	if err != nil {
		return nil, err
	}

	i.txSessions.Store(tx, sameDeviceSession{sessionID: offer.TransactionID, data: data})
	time.AfterFunc(i.sameDeviceTxTTL(), func() { i.txSessions.Delete(tx) })

	return offer, nil
}

// HandleWalletReturn resolves tx - single-use, like the response_code itself,
// so a reload of the return page after success correctly falls through to
// ErrUnknownTx rather than re-redeeming - to the verifier session
// GenerateSameDeviceOffer created it for, and redeems responseCode against it.
// Returns the resolved session id and the data passed to GenerateSameDeviceOffer
// alongside the attributes/error, so the caller can key its own dedup/logging
// on the session id and resume whatever flow data it stashed. v1 returns
// ErrNotSupported.
func (i *Inst) HandleWalletReturn(ctx *azugo.Context, tx, responseCode string) (string, any, []Attribute, error) {
	if i.config.VerifierEngine != EngineV2 {
		return "", nil, nil, ErrNotSupported
	}

	v, ok := i.txSessions.LoadAndDelete(tx)
	if !ok {
		return "", nil, nil, ErrUnknownTx
	}

	session, _ := v.(sameDeviceSession)

	attrs, err := i.AttributesWithCode(ctx, session.sessionID, responseCode)

	return session.sessionID, session.data, attrs, err
}
