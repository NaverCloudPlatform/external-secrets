// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// NcloudSecretValueResponse represents the success response for getting a secret value.
type NcloudSecretValueResponse struct {
	Code string                `json:"code"`
	Data NcloudSecretValueData `json:"data"`
}

// code returns the top-level status code shared by every Ncloud API envelope,
// letting doGet validate any response type through the apiResponse interface.
func (r *NcloudSecretValueResponse) code() string { return r.Code }

// NcloudSecretValueData represents the data section of a secret value response.
type NcloudSecretValueData struct {
	DecryptedSecretChain NcloudDecryptedSecretChain `json:"decryptedSecretChain"`
	RotationTargets      []string                   `json:"rotationTargets"`
}

// NcloudDecryptedSecretChain holds the decrypted secret across rotation phases.
type NcloudDecryptedSecretChain struct {
	Previous string `json:"previous"`
	Active   string `json:"active"`
	Pending  string `json:"pending"`
}

// NcloudListSecretsResponse represents the success response for listing secrets.
type NcloudListSecretsResponse struct {
	Code string                `json:"code"`
	Data NcloudListSecretsData `json:"data"`
}

// code returns the top-level status code (see NcloudSecretValueResponse.code).
func (r *NcloudListSecretsResponse) code() string { return r.Code }

// NcloudListSecretsData represents the data section of list secrets response.
type NcloudListSecretsData struct {
	TotalPageNo   int        `json:"totalPageNo"`
	CurrentPageNo int        `json:"currentPageNo"`
	TotalCount    int        `json:"totalCount"`
	SecretList    secretRows `json:"secretList"`
}

// maxListRowsPerPage is the most rows one listing page may carry. The
// service pages in tens; a page past this is not a listing.
const maxListRowsPerPage = 1_000

// secretRows is a listing page's rows, decoded one row at a time by
// decodeRows. A row whose secretId is not in the form the API issues is
// refused: listing IDs become request paths and process-wide lock keys, and
// an endpoint a store author controls would otherwise choose both. The
// refusal fails the sweep, which then concludes nothing about any name,
// rather than skipping the row, which would read as absence.
type secretRows []NcloudSecretListItem

func (rows *secretRows) UnmarshalJSON(data []byte) error {
	out, err := decodeRows(data, "secretList", func(i int, item NcloudSecretListItem) error {
		if !isSecretIDFormat(item.SecretID) {
			return fmt.Errorf("%w: listing row %d", ErrSecretIDMalformed, i)
		}
		return nil
	})
	*rows = out
	return err
}

// protectionKeyRows is the protection key listing's rows, decoded like
// secretRows; a few keys exist per account.
type protectionKeyRows []NcloudProtectionKeyEntry

func (rows *protectionKeyRows) UnmarshalJSON(data []byte) error {
	out, err := decodeRows(data, "keyList", func(int, NcloudProtectionKeyEntry) error { return nil })
	*rows = out
	return err
}

// decodeRows decodes a JSON array of rows one row at a time, refusing the
// array past maxListRowsPerPage and refusing any row check rejects. The
// response body is already capped at maxResponseBytes, but encoding/json
// materializes an array in full before handing it over, and 2.8 million
// empty objects fit in 8 MiB while costing some 850 MiB of heap; counting
// rows as they are decoded is what bounds memory. A JSON null decodes to no
// rows.
func decodeRows[T any](data []byte, field string, check func(i int, row T) error) ([]T, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, nil
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return nil, fmt.Errorf("%s is not an array", field)
	}
	out := make([]T, 0, 32)
	for dec.More() {
		if len(out) >= maxListRowsPerPage {
			return nil, fmt.Errorf(msgTooManyRowsOnPage, maxListRowsPerPage)
		}
		var row T
		if err := dec.Decode(&row); err != nil {
			return nil, err
		}
		if err := check(len(out)+1, row); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return out, nil
}

// NcloudSecretListItem represents a single secret item in the list response.
type NcloudSecretListItem struct {
	SecretID     string `json:"secretId"`
	SecretName   string `json:"secretName"`
	SecretStatus string `json:"secretStatus"`
	SecretType   string `json:"secretType"`
	Region       string `json:"region"`
	RegisterDate int64  `json:"registerDate"`
}

// NcloudSecretDetailResponse represents the success response for reading a
// secret's metadata (Get Secret Detail). It never carries the secret value.
type NcloudSecretDetailResponse struct {
	Code string                 `json:"code"`
	Data NcloudSecretDetailData `json:"data"`
}

// code returns the top-level status code (see NcloudSecretValueResponse.code).
func (r *NcloudSecretDetailResponse) code() string { return r.Code }

// NcloudSecretDetailData is the metadata section of a secret detail response.
// Timestamps are Unix milliseconds. This struct doubles as the JSON shape
// served for metadataPolicy=Fetch, so the json tags mirror the API's field
// names exactly; omitempty is kept ONLY on fields the API itself displays
// conditionally (expectedDestroyDate, rotation timing, trigger, protection
// key), so always-present fields stay addressable as Fetch properties even
// when empty.
type NcloudSecretDetailData struct {
	SecretID            string                     `json:"secretId"`
	SecretName          string                     `json:"secretName"`
	SecretStatus        string                     `json:"secretStatus"`
	SecretType          string                     `json:"secretType"`
	Memo                string                     `json:"memo"`
	Region              string                     `json:"region"`
	ExpectedDestroyDate int64                      `json:"expectedDestroyDate,omitempty"`
	UpdateDate          int64                      `json:"updateDate"`
	RegisterDate        int64                      `json:"registerDate"`
	AutoRotationYN      string                     `json:"autoRotationYN"`
	AutoRotationPeriod  int                        `json:"autoRotationPeriod,omitempty"`
	NextRotationDate    int64                      `json:"nextRotationDate,omitempty"`
	RotationPhase       string                     `json:"rotationPhase"`
	Trigger             *NcloudSecretTrigger       `json:"trigger,omitempty"`
	ProtectionKey       *NcloudSecretProtectionKey `json:"protectionKey,omitempty"`
}

// NcloudSecretTrigger describes the rotation trigger attached to a secret.
type NcloudSecretTrigger struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// NcloudSecretProtectionKey describes the KMS key protecting a secret.
type NcloudSecretProtectionKey struct {
	Type            string `json:"type"`
	KmsKeyTag       string `json:"kmsKeyTag"`
	KmsKeyName      string `json:"kmsKeyName"`
	KmsBoundaryType string `json:"kmsBoundaryType"`
}

// NcloudCreateSecretRequest is the request body for creating a secret.
// The rotation and user-managed-key fields are omitted: PushSecret always
// creates plain secrets (BASIC type, rotation off, default protection key).
//
// KmsBoundaryType declares the KMS region-isolation boundary of the protection
// key. A region-isolated account requires it on create, also with
// protectionKeyType DEFAULT. The value comes from
// Client.defaultKeyBoundaryType; omitempty drops the field for an account
// whose keys report no boundary.
type NcloudCreateSecretRequest struct {
	SecretName        string                   `json:"secretName"`
	Memo              string                   `json:"memo,omitempty"`
	SecretValue       NcloudSecretValuePayload `json:"secretValue"`
	SecretType        string                   `json:"secretType"`
	AutoRotationYN    string                   `json:"autoRotationYN"`
	ProtectionKeyType string                   `json:"protectionKeyType"`
	KmsBoundaryType   string                   `json:"kmsBoundaryType,omitempty"`
}

// NcloudProtectionKeyListResponse is the success response for listing the
// account's protection keys (GET /api/v1/keys).
type NcloudProtectionKeyListResponse struct {
	Code string                      `json:"code"`
	Data NcloudProtectionKeyListData `json:"data"`
}

// code returns the top-level status code (see NcloudSecretValueResponse.code).
func (r *NcloudProtectionKeyListResponse) code() string { return r.Code }

// NcloudProtectionKeyListData holds the protection keys available to the caller.
type NcloudProtectionKeyListData struct {
	KeyList protectionKeyRows `json:"keyList"`
}

// NcloudProtectionKeyEntry is one protection key. The account's default key is
// the entry with an empty KeyTag: protectionKeyType DEFAULT selects it, and a
// user-managed key is addressed by tag instead.
type NcloudProtectionKeyEntry struct {
	KeyTag          string `json:"keyTag"`
	KeyName         string `json:"keyName"`
	KeyStatus       string `json:"keyStatus"`
	KeyType         string `json:"keyType"`
	KmsBoundaryType string `json:"kmsBoundaryType"`
}

// NcloudSecretValuePayload carries the value part of a create request.
// RotationTargets is required by the API even when rotation is off.
type NcloudSecretValuePayload struct {
	Value           string   `json:"value"`
	RotationTargets []string `json:"rotationTargets"`
}

// NcloudUpdateStageValueRequest is the request body for updating one stage's
// value (PUT /api/v1/secrets/{id}/values/{stage}).
type NcloudUpdateStageValueRequest struct {
	Value string `json:"value"`
}

// NcloudUpdateStageValueResponse represents the success response for updating
// one stage's value. The returned value is the KMS ciphertext, not plaintext.
type NcloudUpdateStageValueResponse struct {
	Code string                     `json:"code"`
	Data NcloudUpdateStageValueData `json:"data"`
}

// code returns the top-level status code (see NcloudSecretValueResponse.code).
func (r *NcloudUpdateStageValueResponse) code() string { return r.Code }

// NcloudUpdateStageValueData wraps the encrypted value envelope of a stage
// update response.
type NcloudUpdateStageValueData struct {
	EncryptedSecretValue NcloudEncryptedValue `json:"encryptedSecretValue"`
}

// NcloudEncryptedValue is one encrypted stage value.
type NcloudEncryptedValue struct {
	Value      string `json:"value"`
	ValueStage string `json:"valueStage"`
}

// NcloudSecretStatusResponse represents responses that report a secret's
// status transition (e.g. Request Secret Deletion).
type NcloudSecretStatusResponse struct {
	Code string                 `json:"code"`
	Data NcloudSecretStatusData `json:"data"`
}

// code returns the top-level status code (see NcloudSecretValueResponse.code).
func (r *NcloudSecretStatusResponse) code() string { return r.Code }

// NcloudSecretStatusData is the payload of a status-transition response.
type NcloudSecretStatusData struct {
	SecretID     string `json:"secretId"`
	SecretStatus string `json:"secretStatus"`
	UpdateDate   int64  `json:"updateDate"`
}

// NcloudDeleteSecretResponse represents the success response for deleting a
// secret ("data" is null on success).
type NcloudDeleteSecretResponse struct {
	Code string          `json:"code"`
	Data json.RawMessage `json:"data"`
}

// code returns the top-level status code (see NcloudSecretValueResponse.code).
func (r *NcloudDeleteSecretResponse) code() string { return r.Code }
