// SPDX-License-Identifier: EUPL-1.2
package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func signDetached(t *testing.T, key *ecdsa.PrivateKey, kid string, body []byte) string {
	t.Helper()

	header, err := json.Marshal(jwsProtectedHeader{Alg: "ES256", Kid: kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}

	protectedB64 := base64.RawURLEncoding.EncodeToString(header)
	signingInput := protectedB64 + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	return protectedB64 + ".." + base64.RawURLEncoding.EncodeToString(sig)
}

func testCache(t *testing.T, key *ecdsa.PrivateKey, kid string) *jwksCache {
	t.Helper()

	return &jwksCache{
		keys: map[string]*ecdsa.PublicKey{kid: &key.PublicKey},
	}
}

func TestVerifyDetachedJWS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	body := []byte(`{"sessionId":"abc","state":"verified"}`)
	sig := signDetached(t, key, "kid-1", body)
	cache := testCache(t, key, "kid-1")

	if err := verifyDetachedJWS(sig, body, cache); err != nil {
		t.Fatalf("expected valid signature to verify, got: %v", err)
	}
}

func TestVerifyDetachedJWS_TamperedBody(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	body := []byte(`{"sessionId":"abc","state":"verified"}`)
	sig := signDetached(t, key, "kid-1", body)
	cache := testCache(t, key, "kid-1")

	tampered := []byte(`{"sessionId":"abc","state":"failed"}`)
	if err := verifyDetachedJWS(sig, tampered, cache); err == nil {
		t.Fatal("expected tampered body to fail verification")
	}
}

func TestVerifyDetachedJWS_UnknownKid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	body := []byte(`{"sessionId":"abc","state":"verified"}`)
	sig := signDetached(t, key, "other-kid", body)
	cache := testCache(t, key, "kid-1")

	if err := verifyDetachedJWS(sig, body, cache); err == nil {
		t.Fatal("expected unknown kid to fail verification")
	}
}

func TestVerifyDetachedJWS_Malformed(t *testing.T) {
	cache := &jwksCache{}

	if err := verifyDetachedJWS("not-a-jws", []byte("{}"), cache); err == nil {
		t.Fatal("expected malformed signature header to fail")
	}
}

func TestVerifyWebhook(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tpl := nonPIDTemplate()

	body := []byte(`{"sessionId":"sess1","state":"verified","result":{"credentials":[` +
		`{"queryId":"mdl_mdoc","doctypeOrVct":"org.iso.18013.5.1.mDL","claims":{"org.iso.18013.5.1.mDL":` +
		`{"document_number":"DL123456","issuing_authority":"Road Traffic Safety Directorate"}}}]}}`)
	sig := signDetached(t, key, "kid-1", body)

	i := &Inst{
		config:      &Configuration{VerifierEngine: EngineV2, V2: &V2Configuration{WebhookJWKSURL: "unused"}},
		template:    tpl,
		webhookJWKS: testCache(t, key, "kid-1"),
	}

	result, err := i.VerifyWebhook(body, sig)
	if err != nil {
		t.Fatalf("VerifyWebhook: %v", err)
	}

	if result.SessionID != "sess1" || result.State != "verified" {
		t.Fatalf("unexpected result: %+v", result)
	}

	if len(result.Attributes) != 2 {
		t.Fatalf("expected 2 attributes, got %+v", result.Attributes)
	}
}

func TestVerifyWebhook_BadSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	i := &Inst{
		config:      &Configuration{VerifierEngine: EngineV2, V2: &V2Configuration{WebhookJWKSURL: "unused"}},
		template:    nonPIDTemplate(),
		webhookJWKS: testCache(t, key, "kid-1"),
	}

	body := []byte(`{"sessionId":"sess1","state":"verified"}`)

	if _, err := i.VerifyWebhook(body, signDetached(t, key, "wrong-kid", body)); err == nil {
		t.Fatal("expected signature check to fail")
	}
}
