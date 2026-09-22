// SPDX-License-Identifier: EUPL-1.2
package verifier

import "testing"

func TestExtractRequestURI(t *testing.T) {
	link := "eudi-openid4vp://?client_id=x509_san_dns%3Averifier.example.com&request_uri=https%3A%2F%2Fverifier.example.com%2Fwallet%2Fabc%2Frequest.jwt"

	got, err := extractRequestURI(link)
	if err != nil {
		t.Fatalf("extractRequestURI: %v", err)
	}

	want := "https://verifier.example.com/wallet/abc/request.jwt"
	if got != want {
		t.Fatalf("extractRequestURI = %q, want %q", got, want)
	}
}

func TestExtractRequestURI_Missing(t *testing.T) {
	if _, err := extractRequestURI("eudi-openid4vp://?client_id=x"); err == nil {
		t.Fatal("expected error when request_uri is absent")
	}
}
