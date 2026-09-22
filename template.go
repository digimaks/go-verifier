// SPDX-License-Identifier: EUPL-1.2

package verifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Attribute is one claim retained from a successful presentation. Namespace
// is the credential's doctype/vct (e.g. "eu.europa.ec.eudi.pid.1"); Key is
// the claim name within it (e.g. "given_name"). Callers parse the []Attribute
// a presentation returns into whatever data model they need - this package
// has no fixed idea of what a credential "means".
type Attribute struct {
	Namespace string
	Key       string
	Value     any
}

// ClaimRequest is one claim to request from a credential.
type ClaimRequest struct {
	Key            string `json:"key"`
	IntentToRetain bool   `json:"intent_to_retain,omitempty"`
}

// CredentialRequest describes one credential type to request and which of
// its claims to retain.
type CredentialRequest struct {
	ID           string         `json:"id"`
	DoctypeOrVct string         `json:"doctype_or_vct"`
	Format       string         `json:"format,omitempty"`
	Name         string         `json:"name,omitempty"`
	Algorithms   []string       `json:"algorithms,omitempty"`
	Claims       []ClaimRequest `json:"claims"`
}

// Template describes what an offer should request: one or more credential
// types, each with the claims to retain from it. Loaded from a JSON file via
// LoadTemplate - see Configuration.TemplatePath.
type Template struct {
	Credentials []CredentialRequest `json:"credentials"`
}

// LoadTemplate reads and parses a Template from path.
func LoadTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("verifier: read template %q: %w", path, err)
	}

	var tpl Template
	if err := json.Unmarshal(data, &tpl); err != nil {
		return nil, fmt.Errorf("verifier: parse template %q: %w", path, err)
	}

	if len(tpl.Credentials) == 0 {
		return nil, fmt.Errorf("verifier: template %q has no credentials", path)
	}

	return &tpl, nil
}

// identificationData builds the v1 backend's request shape from the template.
func (t *Template) identificationData() []v1IdentificationData {
	out := make([]v1IdentificationData, 0, len(t.Credentials))

	for _, cred := range t.Credentials {
		fields := make([]v1IdentificationField, 0, len(cred.Claims))
		for _, claim := range cred.Claims {
			fields = append(fields, v1IdentificationField(claim))
		}

		out = append(out, v1IdentificationData{
			ID:         cred.DoctypeOrVct,
			Name:       cred.Name,
			Algorithms: cred.Algorithms,
			Fields:     fields,
		})
	}

	return out
}

var errNoAttestationMatched = errors.New("verifier: no attestation in the presentation matched the configured template")

// convertToAttributes extracts, for every credential in the template, the
// claims it asked for from whichever matching attestation is present -
// generic across whatever credential type(s) the template names.
func convertToAttributes(tpl *Template, attestations []v1Attestation) ([]Attribute, error) {
	var out []Attribute

	for _, cred := range tpl.Credentials {
		attributes, ok := findAttestationAttributes(attestations, cred.DoctypeOrVct)
		if !ok {
			continue
		}

		for _, claim := range cred.Claims {
			value, ok := attributes[claim.Key]
			if !ok {
				continue
			}

			out = append(out, Attribute{Namespace: cred.DoctypeOrVct, Key: claim.Key, Value: value})
		}
	}

	if len(out) == 0 {
		return nil, errNoAttestationMatched
	}

	return out, nil
}

func findAttestationAttributes(attestations []v1Attestation, doctypeOrVct string) (map[string]interface{}, bool) {
	for _, attestation := range attestations {
		if attributes, ok := attestation.Attributes[doctypeOrVct].(map[string]interface{}); ok {
			return attributes, true
		}
	}

	return nil, false
}
