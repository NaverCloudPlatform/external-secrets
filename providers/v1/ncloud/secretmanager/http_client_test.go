// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testAccessKey = "test-access-key"
	testSecretKey = "test-secret-key"
)

func newSecretManagerHTTPTestClient(endpoint string, httpClient *http.Client) *secretManagerClient {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &secretManagerClient{
		config: &Config{
			AccessKeyID: testAccessKey,
			SecretKey:   testSecretKey,
			Endpoint:    endpoint,
		},
		credentials:  StaticCredentials(testAccessKey, testSecretKey),
		httpClient:   httpClient,
		retryBackoff: func(int) time.Duration { return 0 },
	}
}

func assertNcloudAuthHeaders(t *testing.T, req *http.Request) {
	t.Helper()

	if got := req.Header.Get(headerContentType); got != "application/json" {
		t.Errorf("%s = %q, want application/json", headerContentType, got)
	}
	timestamp := req.Header.Get(headerTimestamp)
	if _, err := strconv.ParseInt(timestamp, 10, 64); err != nil {
		t.Errorf("%s = %q, want Unix-millisecond integer: %v", headerTimestamp, timestamp, err)
	}
	if got := req.Header.Get(headerAccessKey); got != testAccessKey {
		t.Errorf("%s = %q, want %q", headerAccessKey, got, testAccessKey)
	}

	message := fmt.Sprintf("%s %s\n%s\n%s", req.Method, req.URL.RequestURI(), timestamp, testAccessKey)
	mac := hmac.New(sha256.New, []byte(testSecretKey))
	_, _ = mac.Write([]byte(message))
	wantSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if got := req.Header.Get(headerSignature); got != wantSignature {
		t.Errorf("%s = %q, want %q", headerSignature, got, wantSignature)
	}
}

func TestAPINewClient(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr error
	}{
		{
			name: "valid config",
			config: &Config{
				AccessKeyID: "test-access-key",
				SecretKey:   "test-secret-key",
				Endpoint:    secretManagerKRGlobalEndpoint,
			},
			wantErr: nil,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: ErrMissingCredentials,
		},
		{
			name: "missing access key",
			config: &Config{
				SecretKey: "test-secret-key",
				Endpoint:  secretManagerKRGlobalEndpoint,
			},
			wantErr: ErrMissingCredentials,
		},
		{
			name: "missing secret key",
			config: &Config{
				AccessKeyID: "test-access-key",
				Endpoint:    secretManagerKRGlobalEndpoint,
			},
			wantErr: ErrMissingCredentials,
		},
		{
			name: "missing endpoint",
			config: &Config{
				AccessKeyID: "test-access-key",
				SecretKey:   "test-secret-key",
			},
			wantErr: ErrMissingEndpoint,
		},
		{
			name: "plain http endpoint",
			config: &Config{
				AccessKeyID: "test-access-key",
				SecretKey:   "test-secret-key",
				Endpoint:    "http://ocapi-kr.ncloud.com/secretmanager",
			},
			wantErr: ErrEndpointScheme,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := newClient(tt.config)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("newClient() error = %v, want %v", err, tt.wantErr)
				}
				if client != nil {
					t.Error("newClient() should return nil client on error")
				}
			} else {
				if err != nil {
					t.Errorf("newClient() unexpected error = %v", err)
				}
				if client == nil {
					t.Error("newClient() should return non-nil client")
				}
			}
		})
	}
}

func TestGenerateSignature(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		method      string
		path        string
		timestamp   string
		wantSig     string // Expected signature for deterministic input
		description string
	}{
		{
			name: "GET request with standard path",
			config: &Config{
				AccessKeyID: "test-access-key",
				SecretKey:   "test-secret-key",
				Endpoint:    secretManagerKRGlobalEndpoint,
			},
			method:      "GET",
			path:        "/api/v1/secrets",
			timestamp:   "1234567890000",
			wantSig:     "U5GHFbkuRzzmLv4c5NjA7lspMo2rzFqL7celFSrqV7k=",
			description: "Standard GET request signature",
		},
		{
			name: "Different timestamp produces different signature",
			config: &Config{
				AccessKeyID: "test-access-key",
				SecretKey:   "test-secret-key",
				Endpoint:    secretManagerKRGlobalEndpoint,
			},
			method:      "GET",
			path:        "/api/v1/secrets",
			timestamp:   "9999999999999",
			wantSig:     "a/XLf1UiLKgzNqT7TCx1PJBv/dNRKcycnMGl6LEecbU=",
			description: "Different timestamp should produce different signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newClient(tt.config); err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			headers := http.Header{}
			headers.Set(headerTimestamp, tt.timestamp)

			pair := Credentials{AccessKeyID: tt.config.AccessKeyID, SecretKey: tt.config.SecretKey}
			signature := signRequest(tt.method, tt.path, headers.Get(headerTimestamp), pair)

			// Verify signature is not empty
			if signature == "" {
				t.Error("generateSignature() returned empty signature")
			}

			// Verify it's a valid base64 string
			decoded, err := base64.StdEncoding.DecodeString(signature)
			if err != nil {
				t.Errorf("generateSignature() returned invalid base64: %v", err)
			}

			// HMAC-SHA256 produces 32 bytes
			if len(decoded) != 32 {
				t.Errorf("generateSignature() decoded length = %d, want 32 (HMAC-SHA256)", len(decoded))
			}

			// Verify signature matches expected value (deterministic)
			if signature != tt.wantSig {
				t.Errorf("generateSignature() = %v, want %v (%s)", signature, tt.wantSig, tt.description)
			}

			// Verify signature is consistent (calling again with same params produces same result)
			signature2 := signRequest(tt.method, tt.path, headers.Get(headerTimestamp), pair)
			if signature != signature2 {
				t.Error("generateSignature() is not deterministic")
			}
		})
	}
}

func TestGetSecretValue(t *testing.T) {
	tests := []struct {
		name       string
		secretID   string
		statusCode int
		response   string
		wantErr    bool
		checkError func(error) bool
	}{
		{
			name:       "successful response",
			secretID:   testSecretID("test-secret"),
			statusCode: http.StatusOK,
			response: `{
				"code": "SUCCESS",
				"data": {
					"decryptedSecretChain": {
						"previous": "",
						"active": "{\"key\":\"value\"}",
						"pending": ""
					},
					"rotationTargets": []
				}
			}`,
			wantErr: false,
		},
		{
			name:       "secret not found",
			secretID:   testSecretID("non-existent"),
			statusCode: http.StatusNotFound,
			response:   `{"error": {"errorCode": "501001", "message": "RESOURCE_NOT_FOUND", "details": "Secret not found"}}`,
			wantErr:    true,
			checkError: func(err error) bool {
				return errors.Is(err, ErrSecretNotFound)
			},
		},
		{
			name:       "authentication error (401 UNAUTHORIZED)",
			secretID:   testSecretID("test-secret"),
			statusCode: http.StatusUnauthorized,
			response: `{
				"error": {
					"errorCode": "UNAUTHORIZED",
					"message": "Unauthorized",
					"details": "Authentication Failed"
				}
			}`,
			wantErr: true,
			checkError: func(err error) bool {
				return errors.Is(err, ErrUnauthorized)
			},
		},
		{
			name:       "forbidden error (403 FORBIDDEN)",
			secretID:   testSecretID("test-secret"),
			statusCode: http.StatusForbidden,
			response: `{
				"error": {
					"errorCode": "FORBIDDEN",
					"message": "Forbidden",
					"details": "Insufficient permissions"
				}
			}`,
			wantErr: true,
			checkError: func(err error) bool {
				return errors.Is(err, ErrForbidden)
			},
		},
		{
			name:       "invalid request (400 INVALID_REQUEST)",
			secretID:   testSecretID("test-secret"),
			statusCode: http.StatusBadRequest,
			response: `{
				"error": {
					"errorCode": "INVALID_REQUEST",
					"message": "Invalid request",
					"details": "Request parameter is invalid"
				}
			}`,
			wantErr: true,
			checkError: func(err error) bool {
				return errors.Is(err, ErrInvalidRequest)
			},
		},
		{
			name:       "invalid status (409 INVALID_STATUS)",
			secretID:   testSecretID("test-secret"),
			statusCode: http.StatusConflict,
			response: `{
				"error": {
					"errorCode": "INVALID_STATUS",
					"message": "Invalid status",
					"details": "Secret is in invalid state"
				}
			}`,
			wantErr: true,
			checkError: func(err error) bool {
				return errors.Is(err, ErrInvalidStatus)
			},
		},
		{
			name:       "unprocessable entity (422 UNPROCESSABLE_ENTITY)",
			secretID:   testSecretID("test-secret"),
			statusCode: http.StatusUnprocessableEntity,
			response: `{
				"error": {
					"errorCode": "UNPROCESSABLE_ENTITY",
					"message": "Invalid status",
					"details": "Request is valid but violates business rules"
				}
			}`,
			wantErr: true,
			checkError: func(err error) bool {
				return errors.Is(err, ErrUnprocessableEntity)
			},
		},
		{
			name:       "internal server error (500 INTERNAL_SERVER_ERROR)",
			secretID:   testSecretID("test-secret"),
			statusCode: http.StatusInternalServerError,
			response: `{
				"error": {
					"errorCode": "INTERNAL_SERVER_ERROR",
					"message": "Server internal error",
					"details": "An unexpected error occurred"
				}
			}`,
			wantErr: true,
			checkError: func(err error) bool {
				return errors.Is(err, ErrInternalServerError)
			},
		},
		{
			name:       "non-success code",
			secretID:   testSecretID("test-secret"),
			statusCode: http.StatusOK,
			response: `{
				"code": "FAILURE",
				"data": {}
			}`,
			wantErr: true,
			checkError: func(err error) bool {
				return strings.Contains(err.Error(), "non-success code")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request path
				expectedPath := fmt.Sprintf("/api/v1/secrets/%s/values", tt.secretID)
				if r.URL.Path != expectedPath {
					t.Errorf("Request path = %v, want %v", r.URL.Path, expectedPath)
				}

				assertNcloudAuthHeaders(t, r)

				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client := newSecretManagerHTTPTestClient(server.URL, server.Client())

			resp, err := client.GetSecretValue(context.Background(), tt.secretID)

			if tt.wantErr {
				if err == nil {
					t.Error("GetSecretValue() expected error, got nil")
				} else if tt.checkError != nil && !tt.checkError(err) {
					t.Errorf("GetSecretValue() error = %v, does not match expected error condition", err)
				}
			} else {
				if err != nil {
					t.Errorf("GetSecretValue() unexpected error = %v", err)
				}
				if resp == nil {
					t.Error("GetSecretValue() returned nil response")
				} else if resp.Code != successCode {
					t.Errorf("Response Code = %v, want SUCCESS", resp.Code)
				}
			}
		})
	}
}

func TestListSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/secrets" {
			t.Errorf("Request path = %v, want /api/v1/secrets", r.URL.Path)
		}

		pageNo := r.URL.Query().Get("pageNo")
		if pageNo != "1" {
			t.Errorf("Request pageNo = %v, want 1", pageNo)
		}

		response := NcloudListSecretsResponse{
			Code: successCode,
			Data: NcloudListSecretsData{
				TotalPageNo:   1,
				CurrentPageNo: 1,
				TotalCount:    2,
				SecretList: []NcloudSecretListItem{
					{
						SecretID:     testSecretID("id1"),
						SecretName:   "secret1",
						SecretStatus: "ENABLE",
						SecretType:   "BASIC",
						Region:       "KR",
						RegisterDate: 1753065580243,
					},
					{
						SecretID:     testSecretID("id2"),
						SecretName:   "secret2",
						SecretStatus: "ENABLE",
						SecretType:   "BASIC",
						Region:       "KR",
						RegisterDate: 1753065580244,
					},
				},
			},
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := newSecretManagerHTTPTestClient(server.URL, server.Client())

	resp, err := client.ListSecrets(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListSecrets() error = %v", err)
	}

	if resp.Code != successCode {
		t.Errorf("Code = %v, want SUCCESS", resp.Code)
	}
	if resp.Data.TotalCount != 2 {
		t.Errorf("TotalCount = %v, want 2", resp.Data.TotalCount)
	}
	if len(resp.Data.SecretList) != 2 {
		t.Errorf("SecretList length = %v, want 2", len(resp.Data.SecretList))
	}
}

// TestListProtectionKeys covers the endpoint that supplies kmsBoundaryType. The
// path is /api/v1/keys.
func TestListProtectionKeys(t *testing.T) {
	t.Run("returns the account's keys", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/keys" {
				t.Errorf("Request path = %v, want /api/v1/keys", r.URL.Path)
			}
			if r.Method != http.MethodGet {
				t.Errorf("Request method = %v, want GET", r.Method)
			}
			assertNcloudAuthHeaders(t, r)
			_, _ = w.Write([]byte(`{"code":"SUCCESS","data":{"keyList":[
				{"keyId":0,"keyTag":"","keyName":"Secret Manager Default Key","kmsBoundaryType":"ISOLATED"},
				{"keyId":1,"keyTag":"kr-tag","keyName":"user","keyStatus":"ENABLE","keyType":"AES256","kmsBoundaryType":"ISOLATED"}
			]}}`))
		}))
		defer server.Close()

		client := newSecretManagerHTTPTestClient(server.URL, server.Client())
		resp, err := client.ListProtectionKeys(context.Background())
		if err != nil {
			t.Fatalf("ListProtectionKeys() error = %v", err)
		}
		if len(resp.Data.KeyList) != 2 {
			t.Fatalf("KeyList length = %d, want 2", len(resp.Data.KeyList))
		}
		// The default key is the untagged entry; protectionKeyType DEFAULT selects it.
		if got := resp.Data.KeyList[0]; got.KeyTag != "" || got.KmsBoundaryType != "ISOLATED" {
			t.Errorf("default key = %#v, want empty tag and ISOLATED boundary", got)
		}
	})

	t.Run("surfaces a failure instead of empty keys", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"errorCode":"400403","message":"FORBIDDEN","details":"denied"}}`))
		}))
		defer server.Close()

		client := newSecretManagerHTTPTestClient(server.URL, server.Client())
		if _, err := client.ListProtectionKeys(context.Background()); !errors.Is(err, ErrForbidden) {
			t.Errorf("ListProtectionKeys() error = %v, want ErrForbidden", err)
		}
	})
}

// TestListSecretsNotFoundReportsListingUnavailable pins the sentinel split at
// the transport boundary. The listing endpoint answers about the collection, so
// a 404 cannot mean "that one secret is missing" - a reachable store with no
// secrets returns 200 and an empty list. Classifying it as ErrSecretNotFound
// made every name resolution report absence, which callers act on destructively.
func TestListSecretsNotFoundReportsListingUnavailable(t *testing.T) {
	// The answer for an account whose Secretstore is not provisioned.
	const body = `{"error":{"errorCode":"501001","message":"RESOURCE_NOT_FOUND","details":"unavailable Secretstore"}}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	client := newSecretManagerHTTPTestClient(server.URL, server.Client())

	resp, err := client.ListSecrets(context.Background(), 1)
	if err == nil {
		t.Fatalf("ListSecrets() error = nil, want a failure (resp = %#v)", resp)
	}
	if !errors.Is(err, ErrListingUnavailable) {
		t.Errorf("ListSecrets() error = %v, want ErrListingUnavailable", err)
	}
	if errors.Is(err, ErrSecretNotFound) {
		t.Errorf("ListSecrets() error must not report ErrSecretNotFound: %v", err)
	}
	// The re-classification keeps the diagnostic detail the status carried.
	if got := err.Error(); !strings.Contains(got, "status 404") || !strings.Contains(got, "501001") {
		t.Errorf("ListSecrets() error = %q, want it to retain the status and numeric code", got)
	}
}

// TestListingUnavailableNamesAnUnknownAccessKey covers the gateway's own 404 on
// the listing. A key that is not accepted can be answered that way, so the
// message must name the key as a cause; naming only the Secretstore sends an
// operator with a mistyped key to check the account's provisioning instead.
func TestListingUnavailableNamesAnUnknownAccessKey(t *testing.T) {
	const body = `{"error": {"errorCode": "300", "message": "Not Found Exception", "details": "null"}}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	client := newSecretManagerHTTPTestClient(server.URL, server.Client())

	_, err := client.ListSecrets(context.Background(), 1)
	if !errors.Is(err, ErrListingUnavailable) {
		t.Fatalf("ListSecrets() error = %v, want ErrListingUnavailable", err)
	}
	if got := err.Error(); !strings.Contains(got, "access key ID") || !strings.Contains(got, "code 300") {
		t.Errorf("ListSecrets() error = %q, want it to name the access key ID and keep code 300", got)
	}
}

// TestGetSecretNotFoundStillReportsSecretNotFound guards the other direction:
// only the listing endpoint is re-classified. Per-secret endpoints must keep
// answering ErrSecretNotFound, which the delete/create idempotency paths rely on.
func TestGetSecretNotFoundStillReportsSecretNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"errorCode":"501001","message":"RESOURCE_NOT_FOUND","details":"no such secret"}}`))
	}))
	defer server.Close()

	client := newSecretManagerHTTPTestClient(server.URL, server.Client())

	for name, call := range map[string]func() error{
		"GetSecretValue": func() error {
			_, err := client.GetSecretValue(context.Background(), transportTestID)
			return err
		},
		"GetSecretDetail": func() error {
			_, err := client.GetSecretDetail(context.Background(), transportTestID)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := call()
			if !errors.Is(err, ErrSecretNotFound) {
				t.Errorf("%s() error = %v, want ErrSecretNotFound", name, err)
			}
			if errors.Is(err, ErrListingUnavailable) {
				t.Errorf("%s() must not report ErrListingUnavailable: %v", name, err)
			}
		})
	}
}

// TestHTTPMutationContracts pins the wire format of each mutation: verb, escaped
// path, and serialized body.
//
// It deliberately hand-builds its request rather than driving the client, so it
// verifies encoding only. Whether the client populates every field the API
// requires is a separate question, checked by
// TestPushSecretCreateRequestSatisfiesDocumentedContract against the documented
// schema - keep new required fields covered there, not just here.
func TestHTTPMutationContracts(t *testing.T) {
	createRequest := &NcloudCreateSecretRequest{
		SecretName: "contract-secret",
		Memo:       "contract memo",
		SecretValue: NcloudSecretValuePayload{
			Value:           "value-for-contract",
			RotationTargets: []string{},
		},
		SecretType:        "BASIC",
		AutoRotationYN:    "N",
		ProtectionKeyType: "DEFAULT",
		KmsBoundaryType:   "ISOLATED",
	}

	tests := []struct {
		name        string
		method      string
		escapedPath string
		body        string
		response    string
		invoke      func(*testing.T, *secretManagerClient) error
	}{
		{
			name:        "CreateSecret",
			method:      http.MethodPost,
			escapedPath: "/api/v1/secrets",
			body:        `{"secretName":"contract-secret","memo":"contract memo","secretValue":{"value":"value-for-contract","rotationTargets":[]},"secretType":"BASIC","autoRotationYN":"N","protectionKeyType":"DEFAULT","kmsBoundaryType":"ISOLATED"}`,
			response:    `{"code":"SUCCESS","data":{"secretId":"created-id","secretName":"contract-secret"}}`,
			invoke: func(t *testing.T, client *secretManagerClient) error {
				t.Helper()
				got, err := client.CreateSecret(context.Background(), createRequest)
				if err == nil && (got == nil || got.Data.SecretID != "created-id") {
					t.Errorf("CreateSecret() response = %#v, want secret ID created-id", got)
				}
				return err
			},
		},
		{
			name:        "UpdateSecretStageValue",
			method:      http.MethodPut,
			escapedPath: "/api/v1/secrets/" + transportTestID + "/values/pending%2Fvalue",
			body:        `{"value":"updated-value"}`,
			response:    `{"code":"SUCCESS","data":{"encryptedSecretValue":{"value":"ciphertext","valueStage":"pending/value"}}}`,
			invoke: func(t *testing.T, client *secretManagerClient) error {
				t.Helper()
				return client.UpdateSecretStageValue(
					context.Background(),
					transportTestID,
					"pending/value",
					"updated-value",
				)
			},
		},
		{
			name:        "RequestSecretDeletion",
			method:      http.MethodPost,
			escapedPath: "/api/v1/secrets/" + transportTestID + "/request-deletion",
			response:    `{"code":"SUCCESS","data":{"secretId":"` + transportTestID + `","secretStatus":"REVOKE","updateDate":1234}}`,
			invoke: func(t *testing.T, client *secretManagerClient) error {
				t.Helper()
				return client.RequestSecretDeletion(context.Background(), transportTestID)
			},
		},
		{
			name:        "DestroySecret",
			method:      http.MethodDelete,
			escapedPath: "/api/v1/secrets/" + transportTestID,
			response:    `{"code":"SUCCESS","data":null}`,
			invoke: func(t *testing.T, client *secretManagerClient) error {
				t.Helper()
				return client.DestroySecret(context.Background(), transportTestID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls++
				if req.Method != tt.method {
					t.Errorf("method = %s, want %s", req.Method, tt.method)
				}
				if got := req.URL.EscapedPath(); got != tt.escapedPath {
					t.Errorf("escaped path = %q, want %q", got, tt.escapedPath)
				}
				if req.URL.RawQuery != "" {
					t.Errorf("query = %q, want empty", req.URL.RawQuery)
				}
				assertNcloudAuthHeaders(t, req)

				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Errorf("read request body: %v", err)
				} else if got := string(body); got != tt.body {
					t.Errorf("body = %q, want %q", got, tt.body)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, tt.response)
			}))
			defer server.Close()

			client := newSecretManagerHTTPTestClient(server.URL, server.Client())
			if err := tt.invoke(t, client); err != nil {
				t.Fatalf("%s() error = %v", tt.name, err)
			}
			if calls != 1 {
				t.Errorf("request count = %d, want 1", calls)
			}
		})
	}
}

func TestDoSendErrorPaths(t *testing.T) {
	t.Run("non-200 is sentinel preserving, secret safe, and not retried", func(t *testing.T) {
		const secretMarker = "DO-NOT-LEAK-THIS-DETAIL"
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(
				w,
				`{"error":{"errorCode":"INTERNAL_SERVER_ERROR","message":"server error","details":"`+secretMarker+`"}}`,
			)
		}))
		defer server.Close()

		client := newSecretManagerHTTPTestClient(server.URL, server.Client())
		var response NcloudUpdateStageValueResponse
		err := client.doSend(
			context.Background(),
			http.MethodPut,
			"/api/v1/secrets/"+transportTestID+"/values/active",
			&NcloudUpdateStageValueRequest{Value: "request-value"},
			&response,
		)
		if !errors.Is(err, ErrInternalServerError) {
			t.Fatalf("doSend() error = %v, want ErrInternalServerError", err)
		}
		if strings.Contains(err.Error(), secretMarker) {
			t.Errorf("doSend() error leaked server details: %q", err)
		}
		if calls != 1 {
			t.Errorf("request count = %d, want 1 because mutations are never retried", calls)
		}
	})

	t.Run("serialization error prevents request", func(t *testing.T) {
		transport := &scriptedRoundTripper{
			roundTrip: func(int, *http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, `{"code":"SUCCESS","data":null}`), nil
			},
		}
		client := newSecretManagerHTTPTestClient(
			"https://example.invalid",
			&http.Client{Transport: transport},
		)
		var response NcloudDeleteSecretResponse
		err := client.doSend(
			context.Background(),
			http.MethodPost,
			"/api/v1/secrets",
			make(chan string),
			&response,
		)
		if _, ok := errors.AsType[*json.UnsupportedTypeError](err); !ok {
			t.Fatalf("doSend() error = %v, want wrapped json.UnsupportedTypeError", err)
		}
		if got := transport.callCount(); got != 0 {
			t.Errorf("transport calls = %d, want 0 after serialization failure", got)
		}
	})

	t.Run("HTTP 200 with non-success envelope fails", func(t *testing.T) {
		const secretCode = "DATABASE_PASSWORD_123"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"code":"`+secretCode+`","data":null}`)
		}))
		defer server.Close()

		client := newSecretManagerHTTPTestClient(server.URL, server.Client())
		var response NcloudDeleteSecretResponse
		err := client.doSend(
			context.Background(),
			http.MethodDelete,
			"/api/v1/secrets/"+transportTestID,
			nil,
			&response,
		)
		if err == nil || !strings.Contains(err.Error(), "non-success code") {
			t.Errorf("doSend() error = %v, want non-success-code error", err)
		}
		if strings.Contains(err.Error(), secretCode) {
			t.Errorf("doSend() error leaked server-controlled code: %v", err)
		}
	})

	t.Run("invalid internal endpoint preserves parse error", func(t *testing.T) {
		client := newSecretManagerHTTPTestClient("://bad-endpoint", &http.Client{})
		var response NcloudDeleteSecretResponse
		err := client.doSend(
			context.Background(),
			http.MethodDelete,
			"/api/v1/secrets/"+transportTestID,
			nil,
			&response,
		)
		if err == nil || !strings.Contains(err.Error(), "invalid endpoint") {
			t.Errorf("doSend() error = %v, want invalid endpoint", err)
		}
	})
}

type scriptedRoundTripper struct {
	mu        sync.Mutex
	calls     int
	roundTrip func(call int, req *http.Request) (*http.Response, error)
}

func (s *scriptedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()
	return s.roundTrip(call, req)
}

func (s *scriptedRoundTripper) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func jsonResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestDoGetRetryPolicy(t *testing.T) {
	successBody := `{"code":"SUCCESS","data":{"decryptedSecretChain":{"active":"ok"}}}`

	t.Run("retries HTTP 500 then succeeds", func(t *testing.T) {
		transport := &scriptedRoundTripper{
			roundTrip: func(call int, _ *http.Request) (*http.Response, error) {
				if call == 1 {
					return jsonResponse(
						http.StatusInternalServerError,
						`{"error":{"errorCode":"INTERNAL_SERVER_ERROR","message":"temporary","details":"ignored"}}`,
					), nil
				}
				return jsonResponse(http.StatusOK, successBody), nil
			},
		}
		client := newSecretManagerHTTPTestClient(
			"https://example.invalid",
			&http.Client{Transport: transport},
		)

		response, err := client.GetSecretValue(context.Background(), transportTestID)
		if err != nil {
			t.Fatalf("GetSecretValue() error = %v", err)
		}
		if response.Data.DecryptedSecretChain.Active != "ok" {
			t.Errorf("active value = %q, want ok", response.Data.DecryptedSecretChain.Active)
		}
		if got := transport.callCount(); got != 2 {
			t.Errorf("transport calls = %d, want 2", got)
		}
	})

	t.Run("retries HTTP 408 then succeeds", func(t *testing.T) {
		transport := &scriptedRoundTripper{
			roundTrip: func(call int, _ *http.Request) (*http.Response, error) {
				if call == 1 {
					return jsonResponse(http.StatusRequestTimeout, `{"error":{"errorCode":"REQUEST_TIMEOUT"}}`), nil
				}
				return jsonResponse(http.StatusOK, successBody), nil
			},
		}
		client := newSecretManagerHTTPTestClient(
			"https://example.invalid",
			&http.Client{Transport: transport},
		)

		if _, err := client.GetSecretValue(context.Background(), transportTestID); err != nil {
			t.Fatalf("GetSecretValue() error = %v, want success after a 408 retry", err)
		}
		if got := transport.callCount(); got != 2 {
			t.Errorf("transport calls = %d, want 2", got)
		}
	})

	// The Secure Token Service, the Pod Identity exchange and the metadata
	// endpoint read every 5xx as transient; the Secret Manager must too, for
	// a status such as 507 or the 520 a proxy in front of it answers.
	for _, status := range []int{http.StatusNotImplemented, http.StatusInsufficientStorage, 520} {
		t.Run(fmt.Sprintf("retries HTTP %d then succeeds", status), func(t *testing.T) {
			transport := &scriptedRoundTripper{
				roundTrip: func(call int, _ *http.Request) (*http.Response, error) {
					if call == 1 {
						return jsonResponse(status, `{"error":{"errorCode":"SERVER_ERROR"}}`), nil
					}
					return jsonResponse(http.StatusOK, successBody), nil
				},
			}
			client := newSecretManagerHTTPTestClient(
				"https://example.invalid",
				&http.Client{Transport: transport},
			)

			if _, err := client.GetSecretValue(context.Background(), transportTestID); err != nil {
				t.Fatalf("GetSecretValue() error = %v, want success after a %d retry", err, status)
			}
			if got := transport.callCount(); got != 2 {
				t.Errorf("transport calls = %d, want 2", got)
			}
		})
	}

	t.Run("retries transport EOF then succeeds", func(t *testing.T) {
		transport := &scriptedRoundTripper{
			roundTrip: func(call int, _ *http.Request) (*http.Response, error) {
				if call == 1 {
					return nil, io.EOF
				}
				return jsonResponse(http.StatusOK, successBody), nil
			},
		}
		client := newSecretManagerHTTPTestClient(
			"https://example.invalid",
			&http.Client{Transport: transport},
		)

		if _, err := client.GetSecretValue(context.Background(), transportTestID); err != nil {
			t.Fatalf("GetSecretValue() error = %v, want success after EOF retry", err)
		}
		if got := transport.callCount(); got != 2 {
			t.Errorf("transport calls = %d, want 2", got)
		}
	})

	t.Run("stops at retry cap and preserves sentinel", func(t *testing.T) {
		transport := &scriptedRoundTripper{
			roundTrip: func(int, *http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusInternalServerError, "unstructured"), nil
			},
		}
		client := newSecretManagerHTTPTestClient(
			"https://example.invalid",
			&http.Client{Transport: transport},
		)

		_, err := client.GetSecretValue(context.Background(), transportTestID)
		if !errors.Is(err, ErrInternalServerError) {
			t.Fatalf("GetSecretValue() error = %v, want ErrInternalServerError", err)
		}
		if got, want := transport.callCount(), maxGetRetries+1; got != want {
			t.Errorf("transport calls = %d, want %d", got, want)
		}
	})

	t.Run("context cancellation is never retried", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		transport := &scriptedRoundTripper{
			roundTrip: func(int, *http.Request) (*http.Response, error) {
				cancel()
				return nil, context.Canceled
			},
		}
		client := newSecretManagerHTTPTestClient(
			"https://example.invalid",
			&http.Client{Transport: transport},
		)

		_, err := client.GetSecretValue(ctx, transportTestID)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("GetSecretValue() error = %v, want context.Canceled", err)
		}
		if got := transport.callCount(); got != 1 {
			t.Errorf("transport calls = %d, want 1", got)
		}
	})

	t.Run("expired deadline is never retried", func(t *testing.T) {
		transport := &scriptedRoundTripper{
			roundTrip: func(int, *http.Request) (*http.Response, error) {
				return nil, context.DeadlineExceeded
			},
		}
		client := newSecretManagerHTTPTestClient(
			"https://example.invalid",
			&http.Client{Transport: transport},
		)
		ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
		defer cancel()

		_, err := client.GetSecretValue(ctx, transportTestID)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("GetSecretValue() error = %v, want context.DeadlineExceeded", err)
		}
		if got := transport.callCount(); got > 1 {
			t.Errorf("transport calls = %d, want at most 1", got)
		}
	})

	t.Run("client timeout retries while caller context remains active", func(t *testing.T) {
		transport := &scriptedRoundTripper{
			roundTrip: func(call int, _ *http.Request) (*http.Response, error) {
				if call == 1 {
					return nil, context.DeadlineExceeded
				}
				return jsonResponse(http.StatusOK, successBody), nil
			},
		}
		client := newSecretManagerHTTPTestClient(
			"https://example.invalid",
			&http.Client{Transport: transport},
		)

		if _, err := client.GetSecretValue(context.Background(), transportTestID); err != nil {
			t.Fatalf("GetSecretValue() error = %v, want success after client-timeout retry", err)
		}
		if got := transport.callCount(); got != 2 {
			t.Errorf("transport calls = %d, want 2", got)
		}
	})

	t.Run("authentication failure is never retried", func(t *testing.T) {
		transport := &scriptedRoundTripper{
			roundTrip: func(int, *http.Request) (*http.Response, error) {
				return jsonResponse(
					http.StatusUnauthorized,
					`{"error":{"errorCode":"UNAUTHORIZED","message":"unauthorized","details":"ignored"}}`,
				), nil
			},
		}
		client := newSecretManagerHTTPTestClient(
			"https://example.invalid",
			&http.Client{Transport: transport},
		)

		_, err := client.GetSecretValue(context.Background(), transportTestID)
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("GetSecretValue() error = %v, want ErrUnauthorized", err)
		}
		if got := transport.callCount(); got != 1 {
			t.Errorf("transport calls = %d, want 1", got)
		}
	})
}

func TestDoSendBodyIsStableJSON(t *testing.T) {
	var captured bytes.Buffer
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(&captured, req.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"code":"SUCCESS","data":null}`)
	}))
	defer server.Close()

	client := newSecretManagerHTTPTestClient(server.URL, server.Client())
	var response NcloudDeleteSecretResponse
	body := struct {
		First  string `json:"first"`
		Second int    `json:"second"`
	}{
		First:  "one",
		Second: 2,
	}
	if err := client.doSend(
		context.Background(),
		http.MethodPost,
		"/contract",
		body,
		&response,
	); err != nil {
		t.Fatalf("doSend() error = %v", err)
	}
	if got, want := captured.String(), `{"first":"one","second":2}`; got != want {
		t.Errorf("serialized body = %q, want %q", got, want)
	}
}

// TestParseRetryAfter pins both forms RFC 9110 allows, and the rule that an
// unusable value means "no instruction" rather than "retry immediately":
// reporting zero would shorten the caller's own backoff instead of leaving it
// alone.
func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name  string
		value string
		want  time.Duration
		ok    bool
	}{
		{"delta seconds", "120", 2 * time.Minute, true},
		{"delta seconds with surrounding space", "  30 ", 30 * time.Second, true},
		{"zero seconds", "0", 0, true},
		{"http date in the future", "Fri, 11 Sep 2026 12:05:00 GMT", 5 * time.Minute, true},
		{"http date in the past", "Fri, 11 Sep 2026 11:55:00 GMT", 0, false},
		{"negative seconds", "-5", 0, false},
		{"seconds that would overflow a duration", "9223372036854775807", 24 * time.Hour, true},
		{"absent", "", 0, false},
		{"garbage", "soon", 0, false},
	} {
		got, ok := parseRetryAfter(tc.value, now)
		if ok != tc.ok || got != tc.want {
			t.Errorf("parseRetryAfter(%q) = (%v, %v), want (%v, %v) [%s]",
				tc.value, got, ok, tc.want, tc.ok, tc.name)
		}
	}
}

// TestResetResponseClearsAPriorDecode covers the helper itself: that it zeroes
// a struct and tolerates a nil target. The loop-level contract it serves is
// pinned separately by TestRetryDoesNotInheritTheFirstAttemptsDecode, which is
// the test that fails if doGet stops calling this.
func TestResetResponseClearsAPriorDecode(t *testing.T) {
	resp := &NcloudSecretValueResponse{Code: successCode}
	resp.Data.DecryptedSecretChain.Active = "leftover"

	resetResponse(resp)

	if resp.Code != "" || resp.Data.DecryptedSecretChain.Active != "" {
		t.Errorf("resetResponse left %+v, want the zero value", resp)
	}

	// A nil target must not panic: doGet holds an interface, not a concrete
	// type, so it cannot check this itself.
	resetResponse((*NcloudSecretValueResponse)(nil))
}

// TestResponseSizeCapAppliesAfterDecompression pins a property the code gets
// from Go's transport rather than from its own code, which is exactly the
// kind that regresses unnoticed: the 8 MiB cap counts decompressed bytes, so
// a small gzip body that inflates past it is refused instead of being read
// into memory whole.
func TestResponseSizeCapAppliesAfterDecompression(t *testing.T) {
	// Highly compressible, so the wire body stays tiny.
	huge := bytes.Repeat([]byte("A"), maxResponseBytes+1024)

	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(huge); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if compressed.Len() >= maxResponseBytes {
		t.Fatalf("compressed body is %d bytes, which does not test decompression", compressed.Len())
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set(headerContentType, "application/json")
		_, _ = w.Write(compressed.Bytes())
	}))
	defer server.Close()

	c := newTestHTTPClient(server.URL)
	_, err := c.GetSecretValue(context.Background(), transportTestID)
	if err == nil {
		t.Fatal("GetSecretValue() should refuse a body that inflates past the cap")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %v, want the response-size refusal", err)
	}
}

// TestDecodeErrorDoesNotEchoAnOversizedNumber pins the one case in which
// *json.UnmarshalTypeError repeats input: a numeric literal that does not fit
// its field. The literal is server-controlled and unbounded, so the error
// names the field and the offset instead.
func TestDecodeErrorDoesNotEchoAnOversizedNumber(t *testing.T) {
	const literal = "99999999999999999999999"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"code":"SUCCESS","data":{"secretId":"id","registerDate":%s}}`, literal)
	}))
	defer server.Close()

	_, err := newTestHTTPClient(server.URL).GetSecretDetail(context.Background(), transportTestID)
	if err == nil {
		t.Fatal("GetSecretDetail() error = nil, want a decode error")
	}
	if strings.Contains(err.Error(), literal) {
		t.Errorf("GetSecretDetail() error = %v, echoes the server's literal", err)
	}
	if !strings.Contains(err.Error(), "registerDate") {
		t.Errorf("GetSecretDetail() error = %v, want the field named", err)
	}
}

// TestRetryRefreshesTheSignatureTimestamp pins why doGet rebuilds the request
// on every attempt. Ncloud rejects a stale x-ncp-apigw-timestamp, so replaying
// the first attempt's headers would turn a retryable blip into an auth failure.
func TestRetryRefreshesTheSignatureTimestamp(t *testing.T) {
	var (
		mu         sync.Mutex
		timestamps []string
		signatures []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		timestamps = append(timestamps, r.Header.Get(headerTimestamp))
		signatures = append(signatures, r.Header.Get(headerSignature))
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	c := newTestHTTPClient(server.URL)
	// Longer than the millisecond resolution of the timestamp header, so two
	// attempts cannot legitimately share one.
	c.retryBackoff = func(int) time.Duration { return 5 * time.Millisecond }

	if _, err := c.GetSecretValue(context.Background(), transportTestID); err == nil {
		t.Fatal("GetSecretValue() should fail when every attempt 503s")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(timestamps) < 2 {
		t.Fatalf("captured %d attempts, want at least 2", len(timestamps))
	}
	if timestamps[0] == timestamps[1] {
		t.Errorf("retry reused timestamp %q", timestamps[0])
	}
	if signatures[0] == signatures[1] {
		t.Errorf("retry reused signature %q", signatures[0])
	}
}

// retryingDecodeResponse is an apiResponse whose decoder writes a field and
// then fails retryably. No production response type can do that today: every
// error reachable after json.Unmarshal is permanent, and every error that is
// retryable is raised before the decode. That is exactly why doGet's reset
// cannot be observed through GetSecretValue and needs a decode target of its
// own here. The reset is defense in depth for a future error that lands
// between those two halves; this test is what keeps it from being deleted as
// dead code.
type retryingDecodeResponse struct {
	Code     string
	Leftover string
}

func (r *retryingDecodeResponse) code() string { return r.Code }

func (r *retryingDecodeResponse) UnmarshalJSON(data []byte) error {
	// Pointers so an absent key leaves the field untouched, which is what
	// encoding/json does when it decodes into a struct and is the whole
	// reason a stale field can survive a retry. Assigning unconditionally
	// would make this test pass with the reset removed.
	var body struct {
		Code     *string `json:"code"`
		Leftover *string `json:"leftover"`
		Truncate bool    `json:"truncate"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return err
	}
	if body.Code != nil {
		r.Code = *body.Code
	}
	if body.Leftover != nil {
		r.Leftover = *body.Leftover
	}
	if body.Truncate {
		// Retryable (IsRetryable matches io.ErrUnexpectedEOF), and the fields
		// above are already written when it is returned.
		return io.ErrUnexpectedEOF
	}
	return nil
}

// TestRetryDoesNotInheritTheFirstAttemptsDecode pins the retry loop's
// precondition at the loop, not at the helper: doGet must hand attempt N a
// zeroed target, so a field only the first response carried cannot survive
// into the value the caller receives.
func TestRetryDoesNotInheritTheFirstAttemptsDecode(t *testing.T) {
	var (
		mu    sync.Mutex
		calls int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()

		w.Header().Set(headerContentType, "application/json")
		if n == 1 {
			// Decodes leftover, then fails retryably.
			_, _ = w.Write([]byte(`{"code":"SUCCESS","leftover":"from attempt 1","truncate":true}`))
			return
		}
		// The retry's response omits leftover entirely.
		_, _ = w.Write([]byte(`{"code":"SUCCESS"}`))
	}))
	defer server.Close()

	c := newTestHTTPClient(server.URL)
	c.retryBackoff = func(int) time.Duration { return 0 }

	// Bounded like the other retry tests: a regression that made attempt 2
	// hang would otherwise park on maxGetElapsed instead of failing by name.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var resp retryingDecodeResponse
	if err := c.doGet(ctx, "/api/v1/secrets/"+transportTestID+"/values", &resp); err != nil {
		t.Fatalf("doGet() error = %v, want the retry to succeed", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("server calls = %d, want 2 (the first attempt must be retried)", calls)
	}
	if resp.Leftover != "" {
		t.Errorf("Leftover = %q, want it cleared; the retry inherited the first attempt's decode", resp.Leftover)
	}
}

func TestHTTPClientRequestPathWithNormalizedEndpoint(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(NcloudListSecretsResponse{
			Code: successCode,
			Data: NcloudListSecretsData{TotalPageNo: 1},
		})
	}))
	defer server.Close()

	c := newTestHTTPClient(server.URL + "/")
	if _, err := c.ListSecrets(context.Background(), 1); err != nil {
		t.Fatalf("ListSecrets() error = %v", err)
	}
	if strings.Contains(gotPath, "//") {
		t.Errorf("request path %q contains double slash; trailing-slash endpoint not normalized", gotPath)
	}
	if !strings.HasPrefix(gotPath, "/api/v1/secrets") {
		t.Errorf("request path = %q, want prefix /api/v1/secrets", gotPath)
	}
}

// TestDecodeErrorOmitsResponseBytes pins that a malformed
// HTTP-200 body (which for GetSecretValue contains decrypted plaintext) must
// not have its offending byte echoed into the error; only the offset may be
// reported. json.SyntaxError.Error() would include the raw byte.
func TestDecodeErrorOmitsResponseBytes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Invalid JSON: a control byte inside the (would-be secret) string.
		_, _ = w.Write([]byte("{\"code\":\"SUCCESS\",\"data\":\"SENSITIVE\x01VALUE\"}"))
	}))
	defer server.Close()

	client := newTestClientForServer(t, server)
	_, err := client.client.GetSecretValue(context.Background(), "6666666666666666666666666666666666666666666666666666666666666666")
	if err == nil {
		t.Fatal("GetSecretValue() should fail on malformed JSON")
	}
	msg := err.Error()
	if !strings.Contains(msg, "byte offset") {
		t.Errorf("error %q should report the syntax-error offset", msg)
	}
	for _, leak := range []string{"SENSITIVE", "VALUE", "\x01", "invalid character"} {
		if strings.Contains(msg, leak) {
			t.Errorf("error %q leaked response content %q", msg, leak)
		}
	}
}

func TestHTTPClientBoundsResponseBody(t *testing.T) {
	// A hostile/malfunctioning endpoint returning an oversized body must be
	// rejected, not buffered wholesale into memory. The body is VALID JSON so
	// the only reason to reject it is the size bound - if the cap were removed
	// this response would decode successfully, pinning the mechanism.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"code":"`+successCode+`","data":{"decryptedSecretChain":{"active":"`)
		pad := strings.Repeat("x", 1<<20)
		for i := 0; i < maxResponseBytes/len(pad)+2; i++ {
			_, _ = io.WriteString(w, pad)
		}
		_, _ = io.WriteString(w, `"}}}`)
	}))
	defer server.Close()

	c := newTestHTTPClient(server.URL)
	_, err := c.GetSecretValue(context.Background(), transportTestID)
	if err == nil {
		t.Fatal("GetSecretValue() accepted an oversized response body; the read must be bounded")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("error = %v, want the response-size-limit error (not a decode error)", err)
	}
}

func TestNewClientHardeningPinned(t *testing.T) {
	// Pins the three protections newClient installs, through newClient
	// itself: the tests built on a bare &http.Client{} elsewhere bypass the
	// constructor and stay green when a refactor drops them from it.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("redirect target was hit; newClient's client must not follow redirects")
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer origin.Close()

	cfg := &Config{
		AccessKeyID: "ak",
		SecretKey:   "sk",
		Endpoint:    secretManagerKRIsolatedEndpoint,
	}
	c, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient() error = %v", err)
	}

	// (1) 30s timeout is set on the constructed http.Client.
	if c.httpClient.Timeout != 30*time.Second {
		t.Errorf("httpClient.Timeout = %v, want 30s", c.httpClient.Timeout)
	}

	// (2) The config is a private copy: mutating the caller's Config after
	// construction must not retarget the validated endpoint.
	cfg.Endpoint = "https://attacker.example.com"
	if c.config.Endpoint != secretManagerKRIsolatedEndpoint {
		t.Errorf("config.Endpoint = %q after caller mutation, want the validated %q",
			c.config.Endpoint, secretManagerKRIsolatedEndpoint)
	}

	// (3) Redirects are surfaced, not followed. Retarget the private copy at
	// the redirecting test server (same-package access, as NewClient's own
	// callers never can) and issue a real signed request.
	c.config.Endpoint = origin.URL
	c.retryBackoff = func(int) time.Duration { return 0 }
	if _, err := c.GetSecretValue(context.Background(), transportTestID); err == nil {
		t.Error("GetSecretValue() = nil error, want the 3xx surfaced as an error")
	}
}

func TestHTTPClientRetriesTransientErrors(t *testing.T) {
	t.Run("retries 503 then succeeds", func(t *testing.T) {
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			if calls <= 2 { // two transient failures, then success
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(NcloudSecretValueResponse{Code: successCode})
		}))
		defer server.Close()

		c := newTestHTTPClient(server.URL)
		c.retryBackoff = func(int) time.Duration { return 0 }
		if _, err := c.GetSecretValue(context.Background(), transportTestID); err != nil {
			t.Fatalf("GetSecretValue() error = %v, want success after retries", err)
		}
		if calls != 3 {
			t.Errorf("server calls = %d, want 3 (2 x 503 + 1 success)", calls)
		}
	})

	t.Run("stops retrying once the elapsed budget is spent", func(t *testing.T) {
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		// Long enough for the first attempt to reach the server, far shorter
		// than the backoff, so the budget is what ends the sequence.
		restore := maxGetElapsed
		maxGetElapsed = 100 * time.Millisecond
		defer func() { maxGetElapsed = restore }()

		c := newTestHTTPClient(server.URL)
		c.retryBackoff = func(int) time.Duration { return time.Hour }

		// Bounded so a regression in the fail-fast fails this test by name
		// rather than parking it on the hour-long backoff until the package
		// times out. It cannot mask anything: doGet takes the earlier of this
		// and maxGetElapsed, and 10s is far above the healthy path (a single
		// localhost round trip) and far below the regressed one.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		start := time.Now()
		if _, err := c.GetSecretValue(ctx, transportTestID); err == nil {
			t.Fatal("GetSecretValue() should fail when every attempt 500s")
		}
		// One attempt goes out; the budget must prevent the rest, and must
		// not hold the caller for the hour the backoff asked for.
		if calls != 1 {
			t.Errorf("server calls = %d, want 1 (the budget must stop further attempts)", calls)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("GetSecretValue() held the caller for %v; a backoff longer than the budget "+
				"buys no attempt and must not be waited out", elapsed)
		}
	})

	// The budget covers the attempts themselves, not just the gaps between
	// them. Before this, a deadline checked only between attempts let a late
	// attempt spend a full client timeout past the budget.
	t.Run("the budget bounds the attempts, not only the gaps", func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		restore := maxGetElapsed
		maxGetElapsed = 150 * time.Millisecond
		defer func() { maxGetElapsed = restore }()

		c := newTestHTTPClient(server.URL)
		c.retryBackoff = func(int) time.Duration { return 0 }

		start := time.Now()
		if _, err := c.GetSecretValue(context.Background(), transportTestID); err == nil {
			t.Fatal("GetSecretValue() should fail against a server that never answers")
		}
		// The handler blocks until its request context is canceled, which only
		// the budget can do here: the client timeout is 30s. A generous
		// ceiling keeps this from being a timing test.
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("GetSecretValue() took %v, want the %v budget to cut it off", elapsed, maxGetElapsed)
		}
	})

	t.Run("a 429 Retry-After lengthens the backoff", func(t *testing.T) {
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()

		// Generous enough that sleeping to the end of it would be obvious in
		// the elapsed time below, which is the point: honoring an hour-long
		// Retry-After must free the reconcile now, not park it on the budget.
		restore := maxGetElapsed
		maxGetElapsed = 3 * time.Second
		defer func() { maxGetElapsed = restore }()

		c := newTestHTTPClient(server.URL)
		// Without Retry-After this would retry three times immediately.
		c.retryBackoff = func(int) time.Duration { return 0 }

		// Bounded for the same reason as the budget subtest above: without it
		// a regression in the fail-fast hangs on the hour-long Retry-After
		// instead of failing here. Capping c.retryBackoff would not help, the
		// wait comes from the server's header, not from the ramp.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		start := time.Now()
		if _, err := c.GetSecretValue(ctx, transportTestID); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("error = %v, want ErrRateLimited", err)
		}
		if calls != 1 {
			t.Errorf("server calls = %d, want 1 (the hour-long Retry-After must be honored)", calls)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("GetSecretValue() held the caller for %v; a Retry-After longer than the "+
				"budget must fail fast instead of waiting out the budget", elapsed)
		}
	})

	t.Run("a Retry-After past the in-place limit fails at once inside the budget", func(t *testing.T) {
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.Header().Set("Retry-After", strconv.Itoa(int((maxRetryAfterWait+2*time.Second)/time.Second)))
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()

		c := newTestHTTPClient(server.URL)
		c.retryBackoff = func(int) time.Duration { return 0 }
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		start := time.Now()
		if _, err := c.GetSecretValue(ctx, transportTestID); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("error = %v, want ErrRateLimited", err)
		}
		if calls != 1 {
			t.Errorf("server calls = %d, want 1", calls)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("GetSecretValue() held the caller for %v; a Retry-After over %v must be left to the controller's backoff", elapsed, maxRetryAfterWait)
		}
	})

	t.Run("does not retry a permanent 404", func(t *testing.T) {
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		c := newTestHTTPClient(server.URL)
		c.retryBackoff = func(int) time.Duration { return 0 }
		_, err := c.GetSecretValue(context.Background(), transportTestID)
		// A bodyless 404 carries no service code, so it is not absence.
		if !errors.Is(err, ErrNotFoundUnverified) {
			t.Fatalf("error = %v, want ErrNotFoundUnverified", err)
		}
		if calls != 1 {
			t.Errorf("server calls = %d, want 1 (404 must not be retried)", calls)
		}
	})

	t.Run("gives up after maxGetRetries", func(t *testing.T) {
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()

		c := newTestHTTPClient(server.URL)
		c.retryBackoff = func(int) time.Duration { return 0 }
		if _, err := c.GetSecretValue(context.Background(), transportTestID); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("error = %v, want ErrRateLimited after exhausting retries", err)
		}
		if calls != maxGetRetries+1 {
			t.Errorf("server calls = %d, want %d (initial + %d retries)", calls, maxGetRetries+1, maxGetRetries)
		}
	})

	t.Run("stops retrying when context is canceled during backoff", func(t *testing.T) {
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := newTestHTTPClient(server.URL)
		c.retryBackoff = func(int) time.Duration {
			cancel()
			return time.Hour
		}
		if _, err := c.GetSecretValue(ctx, transportTestID); !errors.Is(err, context.Canceled) {
			t.Errorf("GetSecretValue() error = %v, want context.Canceled", err)
		}
		if calls != 1 {
			t.Errorf("server calls = %d, want 1 (context canceled before retry)", calls)
		}
	})
}

func TestDoGetWaitsOutTheCredentialFailureHold(t *testing.T) {
	// A failed fetch is answered from memory for failureHold. A retry inside
	// the hold would re-read the memo and never reach the issuer, spending
	// the whole retry budget on one failure.
	previous := failureHold
	failureHold = 50 * time.Millisecond
	t.Cleanup(func() { failureHold = previous })

	fetches := 0
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		fetches++
		if fetches == 1 {
			return Credentials{}, newAPIError(ErrServiceUnavailable, http.StatusServiceUnavailable, "")
		}
		return temporaryPair("fresh", time.Now().Add(time.Hour)), nil
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerContentType, "application/json")
		_ = json.NewEncoder(w).Encode(newSecretValueResponse("v"))
	}))
	defer server.Close()
	c := newTestHTTPClient(server.URL)
	c.credentials = identifiedSource{source}
	c.retryBackoff = func(int) time.Duration { return 0 }

	start := time.Now()
	if _, err := c.GetSecretValue(context.Background(), transportTestID); err != nil {
		t.Fatalf("GetSecretValue() error = %v, want the retry to reach the issuer once the hold passed", err)
	}
	if fetches != 2 {
		t.Errorf("issuer fetches = %d, want 2 (the failure, then the retry's fetch)", fetches)
	}
	if elapsed := time.Since(start); elapsed < failureHold {
		t.Errorf("retried after %v, inside the %v hold", elapsed, failureHold)
	}
}

// TestRetryWaitStaysUnderTheInPlaceCap pins the one rule every lengthening of
// the wait obeys: nothing holds the reconcile in place for longer than
// maxRetryAfterWait, which the controller's one-at-a-time default makes a
// hold on every other store too.
func TestRetryWaitStaysUnderTheInPlaceCap(t *testing.T) {
	previous := failureHold
	t.Cleanup(func() { failureHold = previous })
	c := &secretManagerClient{}
	credErr := credentialsError{errors.New("issuer down")}
	rateLimited := func(after time.Duration) error {
		return &retryAfterError{err: newAPIError(ErrRateLimited, http.StatusTooManyRequests, ""), after: after}
	}

	failureHold = maxRetryAfterWait + time.Second
	if wait, retry := c.retryWait(0, credErr); !retry || wait != maxRetryAfterWait {
		t.Errorf("retryWait(credential failure, hold %v) = %v, %v; want the cap %v", failureHold, wait, retry, maxRetryAfterWait)
	}

	failureHold = 50 * time.Millisecond
	if wait, retry := c.retryWait(0, credErr); !retry || wait != retryBackoff(0) {
		t.Errorf("retryWait(credential failure, hold %v) = %v, %v; want the longer backoff %v", failureHold, wait, retry, retryBackoff(0))
	}
	if wait, retry := c.retryWait(0, errors.New("transient")); !retry || wait != retryBackoff(0) {
		t.Errorf("retryWait(plain error) = %v, %v; want the backoff %v", wait, retry, retryBackoff(0))
	}

	tooLong := rateLimited(maxRetryAfterWait + time.Second)
	if _, retry := c.retryWait(0, tooLong); retry {
		t.Errorf("retryWait(Retry-After %v) retried; want the error returned to the controller's backoff", maxRetryAfterWait+time.Second)
	}
	if wait, retry := c.retryWait(0, rateLimited(maxRetryAfterWait)); !retry || wait != maxRetryAfterWait {
		t.Errorf("retryWait(Retry-After %v) = %v, %v; want it waited out", maxRetryAfterWait, wait, retry)
	}
}

// transportTestID is the secret ID the transport tests address; request
// paths accept only an ID in the form the API issues.
var transportTestID = testSecretID("transport")

// identifiedSource gives a bare refreshingSource the Identity a
// CredentialsSource needs.
type identifiedSource struct{ *refreshingSource }

func (identifiedSource) Identity() string { return "test" }

// TestSecretPathRefusesAnIDThatIsNotOne pins the choke point every request
// built from a secret ID passes: an ID not in the form the API issues never
// becomes a signed request, whatever supplied it.
func TestSecretPathRefusesAnIDThatIsNotOne(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("a request reached the server: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	c := newTestHTTPClient(server.URL)
	ctx := context.Background()

	for _, id := range []string{"", ".", "..", "id", "a/b", strings.Repeat("a", 64) + "b", strings.ToUpper(testSecretID("x"))} {
		for name, call := range map[string]func() error{
			"value":   func() error { _, err := c.GetSecretValue(ctx, id); return err },
			"detail":  func() error { _, err := c.GetSecretDetail(ctx, id); return err },
			"update":  func() error { return c.UpdateSecretStageValue(ctx, id, stageActive, `{"k":"v"}`) },
			"revoke":  func() error { return c.RequestSecretDeletion(ctx, id) },
			"destroy": func() error { return c.DestroySecret(ctx, id) },
		} {
			if err := call(); !errors.Is(err, ErrSecretIDMalformed) {
				t.Errorf("%s(%.20q) error = %v, want ErrSecretIDMalformed", name, id, err)
			}
		}
	}
	if got, err := secretPath(testSecretID("x"), "/values"); err != nil || got != "/api/v1/secrets/"+testSecretID("x")+"/values" {
		t.Errorf("secretPath(valid) = %q, %v", got, err)
	}
}

// countingSource counts how often a client asks its source for a pair.
type countingSource struct {
	CredentialsSource
	calls atomic.Int32
}

func (c *countingSource) Credentials(ctx context.Context) (Credentials, error) {
	c.calls.Add(1)
	return c.CredentialsSource.Credentials(ctx)
}

// TestDoGetDoesNotRetryAConfigurationError pins the fail-fast half of the
// retry policy for the credential step. A Server Role source whose metadata
// endpoint is not there reports ErrServerRoleUnavailable, a configuration
// error, with the network error inside; the retry loop must read the
// sentinel, not the wrapped error, or every GET of a store that cannot
// authenticate spends maxGetRetries extra fetches, each a metadataTimeout
// long when the address black-holes, before reporting it.
func TestDoGetDoesNotRetryAConfigurationError(t *testing.T) {
	previous := failureHold
	failureHold = 0
	t.Cleanup(func() { failureHold = previous })

	expectOneAsk := func(t *testing.T, source *countingSource) {
		t.Helper()
		server, log := listingServer(t)
		c := clientWithSource(server, source)
		_, err := c.ListSecrets(context.Background(), 1)
		if !errors.Is(err, ErrServerRoleUnavailable) || !isAuthError(err) {
			t.Fatalf("ListSecrets() error = %v, want the configuration error ErrServerRoleUnavailable", err)
		}
		if n := len(log.seen()); n != 0 {
			t.Errorf("Secret Manager requests = %d, want 0", n)
		}
		if got := source.calls.Load(); got != 1 {
			t.Errorf("the source was asked %d times for a pair, want 1: a configuration error fails fast", got)
		}
	}

	t.Run("metadata endpoint refuses the connection", func(t *testing.T) {
		closed := httptest.NewServer(http.NotFoundHandler())
		endpoint := closed.URL
		closed.Close()
		expectOneAsk(t, &countingSource{CredentialsSource: newServerRoleSource(endpoint, metadataHTTPClient())})
	})

	t.Run("metadata endpoint black-holes", func(t *testing.T) {
		// The endpoint accepts the connection and never answers; the client
		// timeout stands in for metadataTimeout.
		hang := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer hang.Close()
		slow := metadataHTTPClient()
		slow.Timeout = 50 * time.Millisecond
		expectOneAsk(t, &countingSource{CredentialsSource: newServerRoleSource(hang.URL, slow)})
	})

	t.Run("a refused pair whose refresh fails on a transient error", func(t *testing.T) {
		// The refusal is the configuration error; the transient refresh
		// failure next to it does not make the pair any more acceptable, so
		// the controller's backoff carries the retry, not this loop.
		server, log := listingServer(t, staleKeyID)
		source := &fakeSource{
			pairs:        []Credentials{temporaryPair(staleKeyID, time.Now().Add(time.Hour))},
			errAfterDrop: newAPIError(ErrServiceUnavailable, http.StatusServiceUnavailable, ""),
		}
		c := clientWithSource(server, source)
		_, err := c.ListSecrets(context.Background(), 1)
		if !errors.Is(err, ErrUnauthorized) || !errors.Is(err, ErrServiceUnavailable) {
			t.Fatalf("ListSecrets() error = %v, want the refusal and the refresh failure", err)
		}
		if n := len(log.seen()); n != 1 {
			t.Errorf("Secret Manager requests = %d, want 1", n)
		}
		if source.calls != 2 {
			t.Errorf("the source was asked %d times for a pair, want 2 (the refused pair, then the one failed refresh)", source.calls)
		}
	})
}
