// SPDX-License-Identifier: EUPL-1.2

package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WebhookSignatureHeader is the HTTP header management-api sends the detached
// JWS in, alongside a webhook call's JSON body.
const WebhookSignatureHeader = "X-Payload-Signature"

// jwksRefreshInterval bounds how long a cached key is trusted before a routine
// refresh; a kid miss triggers an out-of-band refresh regardless (see Key).
const jwksRefreshInterval = 10 * time.Minute

// jwksCache fetches and caches the verifier's ES256 signing keys from its public
// JWKS endpoint, keyed by kid.
type jwksCache struct {
	url string

	mu        sync.Mutex
	keys      map[string]*ecdsa.PublicKey
	fetchedAt time.Time
}

func newJWKSCache(url string) *jwksCache {
	return &jwksCache{url: url}
}

// Key returns the public key for kid, refreshing the cache if it's stale or
// doesn't (yet) contain kid - covers key rotation without waiting out the TTL.
func (c *jwksCache) Key(kid string) (*ecdsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if key, ok := c.keys[kid]; ok && time.Since(c.fetchedAt) < jwksRefreshInterval {
		return key, nil
	}

	keys, err := fetchJWKS(c.url)
	if err != nil {
		// A miss on a stale-but-present cache still gets to try the old key -
		// a transient JWKS fetch failure shouldn't break already-known keys.
		if key, ok := c.keys[kid]; ok {
			return key, nil
		}

		return nil, err
	}

	c.keys = keys
	c.fetchedAt = time.Now()

	key, ok := c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}

	return key, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// p256CoordSize is the byte length of a P-256 field element - JWK x/y are
// base64url-encoded big-endian integers that may come in shorter than this
// (a leading zero byte dropped), so they're left-padded before use.
const p256CoordSize = 32

func fetchJWKS(url string) (map[string]*ecdsa.PublicKey, error) {
	resp, err := http.Get(url) //nolint:gosec,noctx // operator-configured, fixed URL; no per-request context available here
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks: unexpected status %d", resp.StatusCode)
	}

	var doc jwks
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}

	keys := make(map[string]*ecdsa.PublicKey, len(doc.Keys))

	for _, k := range doc.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.Kid == "" {
			continue
		}

		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) > p256CoordSize {
			continue
		}

		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil || len(y) > p256CoordSize {
			continue
		}

		// SEC 1 uncompressed point: 0x04 || X || Y, each coordinate left-padded
		// to p256CoordSize - the format ecdsa.ParseUncompressedPublicKey wants,
		// rather than constructing ecdsa.PublicKey's X/Y fields directly (deprecated).
		point := make([]byte, 1+2*p256CoordSize)
		point[0] = 0x04
		copy(point[1+p256CoordSize-len(x):1+p256CoordSize], x)
		copy(point[1+2*p256CoordSize-len(y):], y)

		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			continue
		}

		keys[k.Kid] = key
	}

	return keys, nil
}

// jwsProtectedHeader is the subset of a JWS protected header this verifier cares
// about - the signing key is operator-controlled and always ES256, so alg is
// checked defensively rather than dispatched on.
type jwsProtectedHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// verifyDetachedJWS checks sigHeader - a compact detached JWS
// ("<protectedB64>..<sigB64>", RFC 7515 Appendix F) - against body, the exact
// raw bytes management-api signed.
func verifyDetachedJWS(sigHeader string, body []byte, cache *jwksCache) error {
	parts := strings.Split(sigHeader, "..")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return errors.New("malformed signature header")
	}

	protectedB64, sigB64 := parts[0], parts[1]

	protectedJSON, err := base64.RawURLEncoding.DecodeString(protectedB64)
	if err != nil {
		return fmt.Errorf("decode protected header: %w", err)
	}

	var header jwsProtectedHeader
	if err := json.Unmarshal(protectedJSON, &header); err != nil {
		return fmt.Errorf("parse protected header: %w", err)
	}

	if header.Alg != "ES256" {
		return fmt.Errorf("unsupported alg %q", header.Alg)
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	if len(sig) != 64 {
		return fmt.Errorf("unexpected signature length %d", len(sig))
	}

	key, err := cache.Key(header.Kid)
	if err != nil {
		return fmt.Errorf("resolve signing key: %w", err)
	}

	signingInput := protectedB64 + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signingInput))

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	if !ecdsa.Verify(key, digest[:], r, s) {
		return errors.New("signature verification failed")
	}

	return nil
}

// WebhookResult is the outcome of a verified incoming webhook call. Attributes
// is populated only when State is "verified".
type WebhookResult struct {
	SessionID  string
	State      string
	Attributes []Attribute
}

// webhookPayload mirrors management-api's WebhookPayload.
type webhookPayload struct {
	SessionID string `json:"sessionId"`
	State     string `json:"state"`
	Result    *struct {
		Credentials []v2ResultCredential `json:"credentials"`
	} `json:"result,omitempty"`
}

// VerifyWebhook checks a management-api webhook call's signature against the
// verifier's public JWKS (Configuration.V2.WebhookJWKSURL) and, when the
// session's state is "verified", extracts this Inst's Template attributes from
// the payload. Callers decide what a "verified"/"failed"/"expired" state means
// for their own bookkeeping - this only verifies and parses. v1 (no webhook
// concept) and an unconfigured WebhookJWKSURL both return ErrNotSupported.
func (i *Inst) VerifyWebhook(body []byte, signatureHeader string) (*WebhookResult, error) {
	if i.config.VerifierEngine != EngineV2 || i.webhookJWKS == nil {
		return nil, ErrNotSupported
	}

	if err := verifyDetachedJWS(signatureHeader, body, i.webhookJWKS); err != nil {
		return nil, fmt.Errorf("verifier: webhook signature check failed: %w", err)
	}

	var payload webhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("verifier: parse webhook payload: %w", err)
	}

	result := &WebhookResult{SessionID: payload.SessionID, State: payload.State}

	if payload.State == "verified" && payload.Result != nil {
		result.Attributes = attributesFromCredentials(i.template, payload.Result.Credentials)
	}

	return result, nil
}
