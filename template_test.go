// SPDX-License-Identifier: EUPL-1.2
package verifier

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// nonPIDTemplate is a fake credential type unrelated to PID/given_name/
// family_name - exercising it through convertToAttributes/dcqlQuery proves
// this package has no residual PID-specific assumption anywhere internally.
func nonPIDTemplate() *Template {
	return &Template{
		Credentials: []CredentialRequest{
			{
				ID:           "mdl_mdoc",
				DoctypeOrVct: "org.iso.18013.5.1.mDL",
				Format:       "mso_mdoc",
				Name:         "Mobile Driving License",
				Claims: []ClaimRequest{
					{Key: "document_number", IntentToRetain: true},
					{Key: "issuing_authority"},
				},
			},
		},
	}
}

func TestLoadTemplate_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mdl.json")

	const data = `{
		"credentials": [
			{
				"id": "mdl_mdoc",
				"doctype_or_vct": "org.iso.18013.5.1.mDL",
				"format": "mso_mdoc",
				"name": "Mobile Driving License",
				"claims": [
					{"key": "document_number", "intent_to_retain": true},
					{"key": "issuing_authority"}
				]
			}
		]
	}`

	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tpl, err := LoadTemplate(path)
	if err != nil {
		t.Fatalf("LoadTemplate: %v", err)
	}

	if !reflect.DeepEqual(tpl, nonPIDTemplate()) {
		t.Fatalf("LoadTemplate = %+v, want %+v", tpl, nonPIDTemplate())
	}
}

func TestLoadTemplate_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")

	if err := os.WriteFile(path, []byte(`{"credentials": []}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := LoadTemplate(path); err == nil {
		t.Fatal("LoadTemplate accepted a template with no credentials")
	}
}

func TestIdentificationData_NonPID(t *testing.T) {
	tpl := nonPIDTemplate()

	got := tpl.identificationData()
	if len(got) != 1 {
		t.Fatalf("identificationData returned %d entries, want 1", len(got))
	}

	want := v1IdentificationData{
		ID:         "org.iso.18013.5.1.mDL",
		Name:       "Mobile Driving License",
		Algorithms: nil,
		Fields: []v1IdentificationField{
			{Key: "document_number", IntentToRetain: true},
			{Key: "issuing_authority", IntentToRetain: false},
		},
	}

	if !reflect.DeepEqual(got[0], want) {
		t.Fatalf("identificationData = %+v, want %+v", got[0], want)
	}
}

func TestConvertToAttributes_NonPID(t *testing.T) {
	tpl := nonPIDTemplate()

	attestations := []v1Attestation{
		{
			DocType: "org.iso.18013.5.1.mDL",
			Attributes: map[string]interface{}{
				"org.iso.18013.5.1.mDL": map[string]interface{}{
					"document_number":   "DL123456",
					"issuing_authority": "Road Traffic Safety Directorate",
				},
			},
		},
	}

	got, err := convertToAttributes(tpl, attestations)
	if err != nil {
		t.Fatalf("convertToAttributes: %v", err)
	}

	sort.Slice(got, func(i, j int) bool { return got[i].Key < got[j].Key })

	want := []Attribute{
		{Namespace: "org.iso.18013.5.1.mDL", Key: "document_number", Value: "DL123456"},
		{Namespace: "org.iso.18013.5.1.mDL", Key: "issuing_authority", Value: "Road Traffic Safety Directorate"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("convertToAttributes = %+v, want %+v", got, want)
	}
}

func TestConvertToAttributes_NoMatch(t *testing.T) {
	tpl := nonPIDTemplate()

	attestations := []v1Attestation{
		{
			DocType: "eu.europa.ec.eudi.pid.1",
			Attributes: map[string]interface{}{
				"eu.europa.ec.eudi.pid.1": map[string]interface{}{"given_name": "Jane"},
			},
		},
	}

	if _, err := convertToAttributes(tpl, attestations); err == nil {
		t.Fatal("convertToAttributes accepted a presentation matching no template credential")
	}
}

func TestDcqlQuery_NonPID(t *testing.T) {
	tpl := nonPIDTemplate()

	got := dcqlQuery(tpl)

	credentials, ok := got["credentials"].([]map[string]interface{})
	if !ok || len(credentials) != 1 {
		t.Fatalf("dcqlQuery credentials = %+v, want 1 entry", got["credentials"])
	}

	cred := credentials[0]
	if cred["id"] != "mdl_mdoc" || cred["format"] != "mso_mdoc" {
		t.Fatalf("dcqlQuery credential = %+v", cred)
	}

	meta, ok := cred["meta"].(map[string]string)
	if !ok || meta["doctype_value"] != "org.iso.18013.5.1.mDL" {
		t.Fatalf("dcqlQuery meta = %+v", cred["meta"])
	}

	claims, ok := cred["claims"].([]map[string]interface{})
	if !ok || len(claims) != 2 {
		t.Fatalf("dcqlQuery claims = %+v, want 2 entries", cred["claims"])
	}
}
