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
						Claims: map[string]map[string]interface{}{
							"org.iso.18013.5.1.mDL": {
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
