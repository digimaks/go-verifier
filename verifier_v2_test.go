// SPDX-License-Identifier: EUPL-1.2
package verifier

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	azhttp "azugo.io/core/http"
)

func TestVerifierV2_AttributesWith_NonPID(t *testing.T) {
	tpl := nonPIDTemplate()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := v2StatusResponse{
			SessionID: "sess1",
			State:     "verified",
			Result: &struct {
				Credentials []v2ResultCredential `json:"credentials"`
			}{
				Credentials: []v2ResultCredential{
					{
						QueryID:      "mdl_mdoc",
						DoctypeOrVct: "org.iso.18013.5.1.mDL",
						Claims: map[string]interface{}{
							"org.iso.18013.5.1.mDL": map[string]interface{}{
								"document_number":   "DL123456",
								"issuing_authority": "Road Traffic Safety Directorate",
							},
						},
					},
				},
			},
		}

		_ = json.NewEncoder(w).Encode(res)
	}))
	defer srv.Close()

	c := &verifierV2Client{config: &V2Configuration{URL: srv.URL, APIKey: "key"}}

	got, err := c.attributesWith(azhttp.NewClient().WithBaseURL(srv.URL), tpl, "sess1", "")
	if err != nil {
		t.Fatalf("attributesWith: %v", err)
	}

	sort.Slice(got, func(i, j int) bool { return got[i].Key < got[j].Key })

	want := []Attribute{
		{Namespace: "org.iso.18013.5.1.mDL", Key: "document_number", Value: "DL123456"},
		{Namespace: "org.iso.18013.5.1.mDL", Key: "issuing_authority", Value: "Road Traffic Safety Directorate"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("attributesWith = %+v, want %+v", got, want)
	}
}

func TestAttributesFromCredentialsSDJWTFlat(t *testing.T) {
	tpl := &Template{Credentials: []CredentialRequest{{
		DoctypeOrVct: "lv.dativa.employee_vc_sd_jwt",
		Format:       "dc+sd-jwt",
		Claims:       []ClaimRequest{{Key: "employee_id"}, {Key: "employer"}},
	}}}
	var res v2ResultCredential
	raw := `{"doctypeOrVct":"lv.dativa.employee_vc_sd_jwt","claims":{"employee_id":"E1","employer":{"registration_number":"42"}}}`
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		t.Fatal(err)
	}
	if got := attributesFromCredentials(tpl, []v2ResultCredential{res}); len(got) != 2 {
		t.Fatalf("want 2 attributes, got %v", got)
	}
}

func TestVerifierV2_Status(t *testing.T) {
	for state, want := range map[string]string{
		"verified": "success_wallet", "expired": "expired", "failed": "failed_attestation",
		"wallet_engaged": "wallet_scanned", "created": "initialized",
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"sessionId":"s","state":"` + state + `"}`))
		}))

		c := &verifierV2Client{config: &V2Configuration{URL: srv.URL, APIKey: "key"}}

		got, err := c.backgroundStatus("s")
		srv.Close()

		if err != nil || got != want {
			t.Errorf("state %q: got (%q, %v), want (%q, nil)", state, got, err, want)
		}
	}
}
