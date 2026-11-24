// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

const testSecretObjectJSON = `{"value":"ok"}`

// testGoneSecretID names a listed secret that no longer resolves, shared by the
// several tests that assert vanished-secret handling.
const testGoneSecretID = "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"

// Mock implementations for testing.
type mockPushSecretRemoteRef struct {
	remoteKey string
	property  string
}

func (m mockPushSecretRemoteRef) GetRemoteKey() string {
	return m.remoteKey
}

func (m mockPushSecretRemoteRef) GetProperty() string {
	return m.property
}

type mockPushSecretData struct {
	secretKey string
	remoteKey string
	property  string
	metadata  *apiextensionsv1.JSON
}

func (m mockPushSecretData) GetMetadata() *apiextensionsv1.JSON {
	return m.metadata
}

func (m mockPushSecretData) GetSecretKey() string {
	return m.secretKey
}

func (m mockPushSecretData) GetRemoteKey() string {
	return m.remoteKey
}

func (m mockPushSecretData) GetProperty() string {
	return m.property
}

func setupTestServer(t *testing.T) (*httptest.Server, *Client) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets/" + testSecretID("test-secret") + "/values":
			response := NcloudSecretValueResponse{
				Code: successCode,
			}
			response.Data.DecryptedSecretChain.Previous = `{"username":"olduser","password":"old123"}`
			response.Data.DecryptedSecretChain.Active = `{"username":"admin","password":"secret123"}`
			response.Data.DecryptedSecretChain.Pending = `{"username":"newuser","password":"new123"}`
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)

		case "/api/v1/secrets/" + testSecretID("empty-secret") + "/values":
			response := NcloudSecretValueResponse{
				Code: successCode,
			}
			response.Data.DecryptedSecretChain.Active = ""
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)

		case "/api/v1/secrets/" + testSecretID("test-secret"):
			response := NcloudSecretDetailResponse{
				Code: successCode,
				Data: NcloudSecretDetailData{
					SecretID:     testSecretID("test-secret"),
					SecretName:   "test-secret",
					SecretStatus: secretStatusEnable,
					SecretType:   "BASIC",
					Memo:         "unit-test secret",
					Region:       "KR",
					UpdateDate:   1753159021411,
					RegisterDate: 1753065580243,
					ProtectionKey: &NcloudSecretProtectionKey{
						Type: "DEFAULT",
					},
				},
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)

		case "/api/v1/secrets":
			response := NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo:   1,
					CurrentPageNo: 1,
					TotalCount:    5,
					SecretList: []NcloudSecretListItem{
						{SecretID: testSecretID("test-secret"), SecretName: "test-secret"},
						{SecretID: testSecretID("empty-secret"), SecretName: "empty-secret"},
						{SecretID: testSecretID("1"), SecretName: "secret1"},
						{SecretID: testSecretID("2"), SecretName: "prod/secret2"},
						{SecretID: testSecretID("nested"), SecretName: "nested-secret"},
					},
				},
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)

		case "/api/v1/secrets/" + testSecretID("nested") + "/values":
			response := NcloudSecretValueResponse{
				Code: successCode,
			}
			response.Data.DecryptedSecretChain.Active = `{"db":{"user":"u1","pass":"p1"},"plain":"x","jsonstr":"{\"a\":\"1\"}"}`
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)

		case "/api/v1/secrets/" + testSecretID("1") + "/values":
			response := NcloudSecretValueResponse{
				Code: successCode,
			}
			response.Data.DecryptedSecretChain.Active = `{"key":"value1"}`
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)

		case "/api/v1/secrets/" + testSecretID("2") + "/values":
			response := NcloudSecretValueResponse{
				Code: successCode,
			}
			response.Data.DecryptedSecretChain.Active = `{"key":"value2"}`
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)

		default:
			// Model the service's own not-found answer, not a bare status:
			// an unattributed 404 is ErrNotFoundUnverified by design.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"errorCode":"501001","message":"RESOURCE_NOT_FOUND"}}`))
		}
	}))

	return server, newTestClientForServer(t, server)
}

// newTestHTTPClient builds the internal HTTP implementation for an httptest
// endpoint. Production construction accepts https:// URLs only, and an
// httptest server speaks plain http, so unit tests inject their loopback
// transport directly rather than loosen that check for testability.
func newTestHTTPClient(endpoint string) *secretManagerClient {
	return &secretManagerClient{
		config: &Config{
			AccessKeyID: "test-access-key",
			SecretKey:   "test-secret-key",
			Endpoint:    strings.TrimRight(endpoint, "/"),
		},
		credentials: StaticCredentials("test-access-key", "test-secret-key"),
		// The production transport, not a copy of it: a test that builds its
		// own client cannot notice a change to the real one.
		httpClient: newHTTPTransport(),
	}
}

// newTestClientForServer builds a *Client pointed at the given test server.
func newTestClientForServer(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	return &Client{
		client: newTestHTTPClient(server.URL),
		cache:  newSecretIDCache(DefaultCacheTTL, DefaultCacheNegativeTTL),
	}
}

func TestClientNewClient(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				AccessKeyID: "test-key",
				SecretKey:   "test-secret",
				Endpoint:    secretManagerKRGlobalEndpoint,
			},
			wantErr: false,
		},
		{
			name: "missing credentials",
			config: &Config{
				Endpoint: secretManagerKRGlobalEndpoint,
			},
			wantErr: true,
		},
		{
			name: "missing endpoint",
			config: &Config{
				AccessKeyID: "test-key",
				SecretKey:   "test-secret",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && client == nil {
				t.Error("NewClient() returned nil client")
			}
		})
	}
}

// newMockedClient wires a countingMockClient into a Client with a fresh,
// isolated cache (bypassing the shared registry).
func newMockedClient(mock *countingMockClient) *Client {
	return &Client{
		client: mock,
		cache:  newSecretIDCache(DefaultCacheTTL, DefaultCacheNegativeTTL),
	}
}

// newForceMockedClient is newMockedClient with ForceDeleteWithoutRecovery
// semantics: DeleteSecret destroys immediately instead of stopping at REVOKE.
func newForceMockedClient(mock *countingMockClient) *Client {
	c := newMockedClient(mock)
	c.forceDelete = true
	return c
}

// listingWith returns a listFn serving one single-page listing.
func listingWith(items ...NcloudSecretListItem) func(ctx context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
	return func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
		return &NcloudListSecretsResponse{
			Code: successCode,
			Data: NcloudListSecretsData{TotalPageNo: 1, CurrentPageNo: 1, TotalCount: len(items), SecretList: items},
		}, nil
	}
}

// detailWithStatus models an ESO-managed secret, so it carries the managed-by
// memo marker; ownership-guard tests build unmanaged details explicitly.
func detailWithStatus(status string) func(ctx context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
	return func(_ context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
		return &NcloudSecretDetailResponse{
			Code: successCode,
			Data: NcloudSecretDetailData{SecretID: secretID, SecretStatus: status, Memo: managedByMemo},
		}, nil
	}
}

func detailWithRotation(status, autoRotationYN string) func(
	ctx context.Context,
	secretID string,
) (*NcloudSecretDetailResponse, error) {
	return func(_ context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
		return &NcloudSecretDetailResponse{
			Code: successCode,
			Data: NcloudSecretDetailData{
				SecretID:       secretID,
				Memo:           managedByMemo,
				SecretStatus:   status,
				AutoRotationYN: autoRotationYN,
			},
		}, nil
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// shiftingListing serves a two-page listing whose reported totalCount changes
// after the first page of each sweep, simulating a concurrent deletion. It
// settles into a stable listing once settleAfter sweeps have started, so a
// test can exercise both the retry and the give-up path.
func shiftingListing(page1, page2 []NcloudSecretListItem, settleAfter int) func(ctx context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
	sweeps := 0
	return func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
		if pageNo == 1 {
			sweeps++
		}
		items, total := page1, len(page1)+len(page2)
		if pageNo == 2 {
			items = page2
			if sweeps <= settleAfter {
				total-- // something left the collection mid-sweep
			}
		}
		return &NcloudListSecretsResponse{
			Code: successCode,
			Data: NcloudListSecretsData{
				TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: total, SecretList: items,
			},
		}, nil
	}
}

// shortListing serves a two-page listing that consistently declares
// TotalPageNo 2 and the full totalCount, but answers page 2 empty until
// settleAfter sweeps have started: the total holds still (no shift), yet the
// sweep under-delivers. Simulates a glitching server or gateway dropping one
// page's entries.
func shortListing(page1, page2 []NcloudSecretListItem, settleAfter int) func(ctx context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
	sweeps := 0
	return func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
		if pageNo == 1 {
			sweeps++
		}
		items := page1
		if pageNo == 2 {
			items = page2
			if sweeps <= settleAfter {
				items = nil // glitch: the page exists but answers empty
			}
		}
		return &NcloudListSecretsResponse{
			Code: successCode,
			Data: NcloudListSecretsData{
				TotalPageNo: 2, CurrentPageNo: pageNo,
				TotalCount: len(page1) + len(page2), SecretList: items,
			},
		}, nil
	}
}

// unmanagedDetail models a secret created outside external-secrets: live, but
// its memo lacks the managed-by marker (a human description instead).
func unmanagedDetail(status string) func(ctx context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
	return func(_ context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
		return &NcloudSecretDetailResponse{
			Code: successCode,
			Data: NcloudSecretDetailData{SecretID: secretID, SecretStatus: status, Memo: "made in the console"},
		}, nil
	}
}

// twoPageListing serves a fixed two-page listing, for index-sharing tests.
func twoPageListing(page1, page2 []NcloudSecretListItem) func(ctx context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
	return func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
		items := page1
		if pageNo == 2 {
			items = page2
		}
		return &NcloudListSecretsResponse{
			Code: successCode,
			Data: NcloudListSecretsData{TotalPageNo: 2, CurrentPageNo: pageNo, SecretList: items},
		}, nil
	}
}

func TestClose(t *testing.T) {
	server, client := setupTestServer(t)
	defer server.Close()

	err := client.Close(context.Background())
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestValidate(t *testing.T) {
	t.Run("uninitialized client", func(t *testing.T) {
		client := &Client{}
		result, err := client.Validate()
		if !errors.Is(err, ErrUninitializedClient) {
			t.Errorf("Validate() error = %v, want %v", err, ErrUninitializedClient)
		}
		if result != esv1.ValidationResultError {
			t.Errorf("Validate() result = %v, want %v", result, esv1.ValidationResultError)
		}
	})

	t.Run("successful validation", func(t *testing.T) {
		server, client := setupTestServer(t)
		defer server.Close()

		result, err := client.Validate()
		if err != nil {
			t.Errorf("Validate() unexpected error = %v", err)
		}
		if result != esv1.ValidationResultReady {
			t.Errorf("Validate() result = %v, want %v", result, esv1.ValidationResultReady)
		}
	})

	t.Run("authentication error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			// Return error response with "Authentication Failed" message
			w.Write([]byte(`{"error": {"errorCode": "UNAUTHORIZED", "message": "Authentication Failed", "details": "Invalid credentials"}}`))
		}))
		defer server.Close()

		client := &Client{client: newTestHTTPClient(server.URL)}
		result, err := client.Validate()

		if err == nil {
			t.Error("Validate() expected error for auth failure")
		}
		if result != esv1.ValidationResultError {
			t.Errorf("Validate() result = %v, want %v", result, esv1.ValidationResultError)
		}
	})

	t.Run("unknown error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": {"errorCode": "500", "message": "Internal Server Error"}}`))
		}))
		defer server.Close()

		client := &Client{client: newTestHTTPClient(server.URL)}
		result, err := client.Validate()

		if err == nil {
			t.Error("Validate() expected error")
		}
		if result != esv1.ValidationResultUnknown {
			t.Errorf("Validate() result = %v, want %v", result, esv1.ValidationResultUnknown)
		}
	})

	// An unprovisioned Secretstore (listing 404) must be Error, not Unknown:
	// the store controller maps Unknown to Ready=True, so without this branch
	// a store no operation can use reports as healthy.
	t.Run("unprovisioned store is a validation error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error": {"errorCode": "501001", "message": "RESOURCE_NOT_FOUND", "details": "unavailable Secretstore"}}`))
		}))
		defer server.Close()

		client := &Client{client: newTestHTTPClient(server.URL)}
		result, err := client.Validate()

		if !errors.Is(err, ErrListingUnavailable) {
			t.Errorf("Validate() error = %v, want ErrListingUnavailable", err)
		}
		if result != esv1.ValidationResultError {
			t.Errorf("Validate() result = %v, want %v", result, esv1.ValidationResultError)
		}
	})
}

func TestNewClientInitializesCacheWithDefaults(t *testing.T) {
	c, err := NewClient(&Config{AccessKeyID: "ak", SecretKey: "sk", Endpoint: secretManagerKRGlobalEndpoint})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	cache := c.(*Client).cache
	if cache == nil {
		t.Fatal("NewClient() did not initialize the cache")
	}
	if cache.ttl != DefaultCacheTTL || cache.negTTL != DefaultCacheNegativeTTL {
		t.Errorf("cache TTLs = (%v, %v), want defaults (%v, %v)", cache.ttl, cache.negTTL, DefaultCacheTTL, DefaultCacheNegativeTTL)
	}
}

func TestValidateAppliesTimeout(t *testing.T) {
	var deadline time.Time
	var hasDeadline bool
	mock := &countingMockClient{
		listFn: func(ctx context.Context, _ int) (*NcloudListSecretsResponse, error) {
			deadline, hasDeadline = ctx.Deadline()
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{TotalPageNo: 1, SecretList: nil},
			}, nil
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	result, err := client.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result != esv1.ValidationResultReady {
		t.Errorf("Validate() = %v, want %v", result, esv1.ValidationResultReady)
	}
	if !hasDeadline {
		t.Fatal("Validate() must pass a context with a deadline to ListSecrets")
	}
	if remaining := time.Until(deadline); remaining > validateTimeout {
		t.Errorf("deadline %v from now exceeds validateTimeout %v", remaining, validateTimeout)
	}
}

func TestIsAuthError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "wrapped unauthorized sentinel",
			err:  fmt.Errorf("ncloud api: %w", ErrUnauthorized),
			want: true,
		},
		{
			name: "wrapped forbidden sentinel",
			err:  fmt.Errorf("ncloud api: %w", ErrForbidden),
			want: true,
		},
		{
			// Regression guard: detection must not rely on message text.
			name: "plain message containing Authentication Failed",
			err:  errors.New("Authentication Failed - Invalid credentials"),
			want: false,
		},
		{
			name: "other wrapped sentinel",
			err:  fmt.Errorf("ncloud api: %w", ErrInternalServerError),
			want: false,
		},
		{
			name: "unrelated error",
			err:  errors.New("network timeout"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAuthError(tt.err); got != tt.want {
				t.Errorf("isAuthError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// countingMockClient tracks invocation counts for cache-related tests.
// It implements SecretManagerInterface and dispatches to per-test fn fields.
type countingMockClient struct {
	listCalls            int
	getSecretValueCalls  int
	getSecretDetailCalls int
	listFn               func(ctx context.Context, pageNo int) (*NcloudListSecretsResponse, error)
	getSecretValueFn     func(ctx context.Context, secretID string) (*NcloudSecretValueResponse, error)
	getSecretDetailFn    func(ctx context.Context, secretID string) (*NcloudSecretDetailResponse, error)
	createCalls          int
	createFn             func(ctx context.Context, req *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error)
	updateStageCalls     int
	updateStageFn        func(ctx context.Context, secretID, stage, value string) error
	requestDeletionCalls int
	requestDeletionFn    func(ctx context.Context, secretID string) error
	destroyCalls         int
	destroyFn            func(ctx context.Context, secretID string) error
	protectionKeyCalls   int
	protectionKeyFn      func(ctx context.Context) (*NcloudProtectionKeyListResponse, error)
}

func (m *countingMockClient) ListSecrets(ctx context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
	m.listCalls++
	return m.listFn(ctx, pageNo)
}

// ListProtectionKeys reports no keys unless a test supplies them, so existing
// create expectations keep omitting kmsBoundaryType.
func (m *countingMockClient) ListProtectionKeys(ctx context.Context) (*NcloudProtectionKeyListResponse, error) {
	m.protectionKeyCalls++
	if m.protectionKeyFn != nil {
		return m.protectionKeyFn(ctx)
	}
	return &NcloudProtectionKeyListResponse{}, nil
}

func (m *countingMockClient) GetSecretValue(ctx context.Context, secretID string) (*NcloudSecretValueResponse, error) {
	m.getSecretValueCalls++
	return m.getSecretValueFn(ctx, secretID)
}

func (m *countingMockClient) GetSecretDetail(ctx context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
	m.getSecretDetailCalls++
	if m.getSecretDetailFn == nil {
		// Neutral default: an ordinary ESO-managed live secret, so tests that
		// exercise other behavior do not each have to restate the ownership
		// marker the guard now reads on every mutation.
		return detailWithStatus(secretStatusEnable)(ctx, secretID)
	}
	return m.getSecretDetailFn(ctx, secretID)
}

func (m *countingMockClient) CreateSecret(ctx context.Context, req *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
	m.createCalls++
	if m.createFn == nil {
		return nil, errors.New("unexpected CreateSecret call")
	}
	return m.createFn(ctx, req)
}

func (m *countingMockClient) UpdateSecretStageValue(ctx context.Context, secretID, stage, value string) error {
	m.updateStageCalls++
	if m.updateStageFn == nil {
		return errors.New("unexpected UpdateSecretStageValue call")
	}
	return m.updateStageFn(ctx, secretID, stage, value)
}

func (m *countingMockClient) RequestSecretDeletion(ctx context.Context, secretID string) error {
	m.requestDeletionCalls++
	if m.requestDeletionFn == nil {
		return errors.New("unexpected RequestSecretDeletion call")
	}
	return m.requestDeletionFn(ctx, secretID)
}

func (m *countingMockClient) DestroySecret(ctx context.Context, secretID string) error {
	m.destroyCalls++
	if m.destroyFn == nil {
		return errors.New("unexpected DestroySecret call")
	}
	return m.destroyFn(ctx, secretID)
}

func (m *countingMockClient) Close() error { return nil }

func newSecretValueResponse(active string) *NcloudSecretValueResponse {
	resp := &NcloudSecretValueResponse{Code: successCode}
	resp.Data.DecryptedSecretChain.Active = active
	return resp
}
