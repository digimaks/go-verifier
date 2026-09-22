// SPDX-License-Identifier: EUPL-1.2
package verifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestPollUntilComplete_RetriesWhenResultNotYetPopulated is a regression test
// for the race where a mgmt-api session flips state to "verified" before its
// result.credentials are populated: the first backgroundAttributes call after
// success_wallet errors, and PollUntilComplete used to treat that as terminal
// instead of retrying.
func TestPollUntilComplete_RetriesWhenResultNotYetPopulated(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)

		res := v2StatusResponse{SessionID: "sess1", State: "verified"}

		// Result only shows up from the 3rd request onward - simulates the
		// backend's own eventual consistency between "state" and "result".
		if n >= 3 {
			res.Result = &struct {
				Credentials []v2ResultCredential `json:"credentials"`
			}{
				Credentials: []v2ResultCredential{
					{
						QueryID:      "mdl_mdoc",
						DoctypeOrVct: "org.iso.18013.5.1.mDL",
						Claims: map[string]map[string]interface{}{
							"org.iso.18013.5.1.mDL": {"document_number": "DL123456"},
						},
					},
				},
			}
		}

		_ = json.NewEncoder(w).Encode(res)
	}))
	defer srv.Close()

	i := &Inst{
		config:           &Configuration{VerifierEngine: EngineV2},
		template:         nonPIDTemplate(),
		logger:           zap.NewNop(),
		verifierV2Client: newVerifierV2Client(&V2Configuration{URL: srv.URL, APIKey: "key"}),
	}

	attrs, err := i.PollUntilComplete(context.Background(), "sess1", 5, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("PollUntilComplete: %v", err)
	}

	if len(attrs) != 1 || attrs[0].Key != "document_number" || attrs[0].Value != "DL123456" {
		t.Fatalf("attrs = %+v, want one document_number=DL123456 attribute", attrs)
	}

	if got := calls.Load(); got < 4 {
		t.Fatalf("expected at least 4 requests (2 failed attempts before success), got %d", got)
	}
}
