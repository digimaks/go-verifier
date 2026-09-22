// SPDX-License-Identifier: EUPL-1.2

package verifier

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

// decodeV1Presentation decodes a v1 presentation's mso_mdoc VP tokens into attestations.
func decodeV1Presentation(presentationData *v1Presentation) ([]v1Attestation, error) {
	attestations := make([]v1Attestation, 0)

	for _, vpList := range presentationData.VpToken {
		for _, vpBase64 := range vpList {
			decodedBytes, err := base64.RawURLEncoding.DecodeString(vpBase64)
			if err != nil {
				return nil, err
			}

			decodedData, err := decodeV1CborData(decodedBytes)
			if err != nil {
				return nil, err
			}

			documents, ok := decodedData["documents"].([]interface{})
			if !ok {
				return nil, errors.New("verifier: type assertion for documents failed")
			}

			for _, doc := range documents {
				attestation, err := extractV1AttestationSingle(v1ConvertInterfaceToMapString(doc))
				if err != nil {
					return nil, err
				}

				attestations = append(attestations, attestation)
			}
		}
	}

	return attestations, nil
}

func v1ElementAsString(value interface{}) string {
	return fmt.Sprintf("%v", value)
}

func extractV1AttestationSingle(document map[string]interface{}) (v1Attestation, error) {
	issuerSigned := v1ConvertInterfaceToMapString(document["issuerSigned"])
	namespaces := v1ConvertInterfaceToMapString(issuerSigned["nameSpaces"])

	docAttributes := make(map[string]interface{})

	for _, namespace := range namespaces {
		namespaceList, ok := namespace.([]interface{})
		if !ok {
			continue
		}

		for _, element := range namespaceList {
			item, ok := element.(cbor.Tag)
			if !ok {
				continue
			}

			contentBytes, ok := item.Content.([]byte)
			if !ok {
				continue
			}

			decodedElement, err := decodeV1CborData(contentBytes)
			if err != nil {
				return v1Attestation{}, err
			}

			attrName, ok := decodedElement["elementIdentifier"].(string)
			if !ok {
				continue
			}

			attrValue := v1ElementAsString(decodedElement["elementValue"])

			if strings.Contains(attrName, "_date") {
				docAttributes[attrName] = v1ParseDate(attrValue)
			} else {
				docAttributes[attrName] = attrValue
			}
		}
	}

	docType, ok := document["docType"].(string)
	if !ok {
		return v1Attestation{}, errV1DocTypeMissing
	}

	return v1Attestation{
		DocType:    docType,
		Attributes: map[string]interface{}{docType: docAttributes},
	}, nil
}

func decodeV1CborData(data []byte) (map[string]interface{}, error) {
	var decodedData map[string]interface{}

	if err := cbor.Unmarshal(data, &decodedData); err != nil {
		return nil, fmt.Errorf("verifier: decode CBOR data: %w", err)
	}

	return decodedData, nil
}

func v1ConvertInterfaceToMapString(data interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	dataMap, ok := data.(map[interface{}]interface{})
	if !ok {
		return nil
	}

	for key, value := range dataMap {
		strKey, ok := key.(string)
		if !ok {
			continue
		}

		result[strKey] = value
	}

	return result
}

func v1ParseDate(dateStr string) int64 {
	const layout = "2006-01-02"

	dateStr = strings.Trim(dateStr, "{}")

	parts := strings.Split(dateStr, " ")
	if len(parts) == 2 {
		date, err := time.Parse(layout, parts[1])
		if err == nil {
			return date.Unix() * 1000
		}
	}

	return 0
}

// v1SanitizeQueryID replaces characters that are not alphanumeric, underscore or hyphen
// to satisfy the DCQL QueryId constraint (^[a-zA-Z0-9_-]+$).
func v1SanitizeQueryID(id string) string {
	return strings.NewReplacer(".", "_").Replace(id)
}

func v1PrepareData(identifications []v1IdentificationData) *v1PrepareRequest {
	credentials := make([]v1DcqlCredential, 0, len(identifications))

	for _, identification := range identifications {
		claims := make([]v1DcqlClaim, 0, len(identification.Fields))

		for _, field := range identification.Fields {
			claim := v1DcqlClaim{
				// mso_mdoc path is [namespace, element_identifier]
				Path: []string{identification.ID, field.Key},
			}

			if field.IntentToRetain {
				v := true
				claim.IntentToRetain = &v
			}

			claims = append(claims, claim)
		}

		credentials = append(credentials, v1DcqlCredential{
			// QueryId must be alphanumeric/_/- only
			ID:     v1SanitizeQueryID(identification.ID),
			Format: "mso_mdoc",
			Meta: &v1DcqlMeta{
				DoctypeValue: identification.ID,
			},
			Claims: claims,
		})
	}

	return &v1PrepareRequest{
		Nonce: uuid.NewString(),
		DcqlQuery: &v1DcqlQuery{
			Credentials: credentials,
		},
	}
}
