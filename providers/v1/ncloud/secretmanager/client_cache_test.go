// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0
package secretmanager

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

func TestClientGetSecretDirectIDBypassesList(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	mock := &countingMockClient{
		listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
			t.Fatal("ListSecrets must not be called when key is a direct secret ID")
			return nil, nil
		},
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			if secretID != id {
				t.Errorf("GetSecretValue secretID = %q, want %q", secretID, id)
			}
			return newSecretValueResponse("direct-id-value"), nil
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	got, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: id})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if string(got) != "direct-id-value" {
		t.Errorf("GetSecret() = %q, want direct-id-value", got)
	}
	if mock.getSecretValueCalls != 1 {
		t.Errorf("GetSecretValue calls = %d, want 1", mock.getSecretValueCalls)
	}
}

func TestClientGetSecretCacheReducesListCalls(t *testing.T) {
	listResponse := &NcloudListSecretsResponse{
		Code: successCode,
		Data: NcloudListSecretsData{
			TotalPageNo: 1,
			SecretList: []NcloudSecretListItem{
				{SecretID: testSecretID("abc"), SecretName: "my-secret"},
			},
		},
	}
	mock := &countingMockClient{
		listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
			return listResponse, nil
		},
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return newSecretValueResponse("v"), nil
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	const iterations = 5
	for i := range iterations {
		if _, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "my-secret"}); err != nil {
			t.Fatalf("GetSecret iteration %d error = %v", i, err)
		}
	}
	if mock.listCalls != 1 {
		t.Errorf("ListSecrets calls = %d, want 1 (subsequent calls should hit cache)", mock.listCalls)
	}
	if mock.getSecretValueCalls != iterations {
		t.Errorf("GetSecretValue calls = %d, want %d (every read fetches fresh value)", mock.getSecretValueCalls, iterations)
	}
}

func TestClientGetSecretNegativeCachePreventsResweep(t *testing.T) {
	mock := &countingMockClient{
		listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{TotalPageNo: 1, SecretList: nil},
			}, nil
		},
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			t.Fatal("GetSecretValue must not be called when name is not found")
			return nil, nil
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	for i := range 3 {
		_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "ghost"})
		if !errors.Is(err, ErrSecretNotFound) {
			t.Fatalf("iteration %d: GetSecret error = %v, want ErrSecretNotFound", i, err)
		}
	}
	if mock.listCalls != 1 {
		t.Errorf("ListSecrets calls = %d, want 1 (negative cache should prevent re-sweep)", mock.listCalls)
	}
}

func TestClientGetSecretStaleIDInvalidationAndRetry(t *testing.T) {
	mock := &countingMockClient{
		listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 1,
					SecretList:  []NcloudSecretListItem{{SecretID: testSecretID("fresh"), SecretName: "rotated"}},
				},
			}, nil
		},
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			if secretID == testSecretID("stale") {
				return nil, fmt.Errorf("%w: simulated 404", ErrSecretNotFound)
			}
			return newSecretValueResponse("fresh-value"), nil
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	// Pre-warm cache with a stale ID to simulate prior state
	client.cache.Set("rotated", testSecretID("stale"))

	got, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "rotated"})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if string(got) != "fresh-value" {
		t.Errorf("GetSecret() = %q, want fresh-value", got)
	}
	if mock.listCalls != 1 {
		t.Errorf("ListSecrets calls = %d, want 1 (one re-sweep after invalidation)", mock.listCalls)
	}
	if mock.getSecretValueCalls != 2 {
		t.Errorf("GetSecretValue calls = %d, want 2 (initial stale + retry)", mock.getSecretValueCalls)
	}
	id, found, negative := client.cache.Get("rotated")
	if !found || negative || id != testSecretID("fresh") {
		t.Errorf("cache after retry: id=%q found=%v negative=%v; want fresh-id,true,false", id, found, negative)
	}
}

// TestClientGetSecretDirectIDSkipsListingFallback pins the read-path ID
// shortcut: secret names are 3-15 characters, so a 64-char hex key can only be
// a direct ID and the listing fallback could never resolve it. Its NotFound is
// authoritative and must cost zero list calls - the same invariant the write
// paths (SecretExists/PushSecret/DeleteSecret) already rely on. Before this
// pin, every read of a deleted ID paid a guaranteed-miss full listing sweep per
// reconcile, and an unstable listing could even turn the clean NoSecretErr
// into ErrListingUnstable.
func TestClientGetSecretDirectIDSkipsListingFallback(t *testing.T) {
	const id = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	mock := &countingMockClient{
		listFn: listingWith(),
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return nil, fmt.Errorf("%w: simulated 404", ErrSecretNotFound)
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: id})
	if !errors.Is(err, ErrSecretNotFound) || !errors.Is(err, esv1.NoSecretErr) {
		t.Fatalf("GetSecret() error = %v, want ErrSecretNotFound wrapped as NoSecretErr", err)
	}
	if mock.listCalls != 0 {
		t.Errorf("ListSecrets calls = %d, want 0 (an ID-shaped key's NotFound is authoritative)", mock.listCalls)
	}
	if mock.getSecretValueCalls != 1 {
		t.Errorf("GetSecretValue calls = %d, want 1 (only the direct-ID call)", mock.getSecretValueCalls)
	}
}

func TestClientGetSecretDirectIDMissIsNotNegativeCached(t *testing.T) {
	// A transient 404 on a direct-ID read must not leave a negative cache
	// entry for the ID: the very next GetSecret(id) has to reach the API
	// again instead of being pinned to NotFound for the negative TTL.
	const id = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	unavailable := true
	mock := &countingMockClient{
		listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{TotalPageNo: 1, SecretList: nil},
			}, nil
		},
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			if unavailable {
				return nil, fmt.Errorf("%w: transient 404", ErrSecretNotFound)
			}
			return newSecretValueResponse("recovered"), nil
		},
	}
	cache := newSecretIDCache(time.Hour, time.Minute)
	client := &Client{client: mock, cache: cache}

	if _, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: id}); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("first GetSecret() error = %v, want ErrSecretNotFound", err)
	}
	if _, found, negative := cache.Get(id); found && negative {
		t.Fatal("transient direct-ID miss must not record a negative cache entry")
	}

	// The secret becomes readable; the next read must succeed immediately.
	unavailable = false
	getsBefore := mock.getSecretValueCalls
	got, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: id})
	if err != nil {
		t.Fatalf("second GetSecret() error = %v (negative cache poisoned the ID shortcut)", err)
	}
	if string(got) != "recovered" {
		t.Errorf("second GetSecret() = %q, want recovered", got)
	}
	if mock.getSecretValueCalls == getsBefore {
		t.Error("second GetSecret() never reached the API - short-circuited by a poisoned cache entry")
	}
}

func TestClientGetAllSecretsWarmsCache(t *testing.T) {
	mock := &countingMockClient{
		listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 1,
					SecretList: []NcloudSecretListItem{
						{SecretID: testSecretID("a"), SecretName: "all-a"},
						{SecretID: testSecretID("b"), SecretName: "all-b"},
					},
				},
			}, nil
		},
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return newSecretValueResponse(`{"k":"v"}`), nil
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	if _, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{}); err != nil {
		t.Fatalf("GetAllSecrets() error = %v", err)
	}

	listsBefore := mock.listCalls
	if _, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "all-b"}); err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if mock.listCalls != listsBefore {
		t.Errorf("ListSecrets calls grew from %d to %d (cache should have been warmed by GetAllSecrets)", listsBefore, mock.listCalls)
	}
}

func TestClientSecretExistsBypassesStaleCache(t *testing.T) {
	mock := &countingMockClient{
		listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{TotalPageNo: 1, SecretList: nil},
			}, nil
		},
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			t.Fatal("GetSecretValue must not be called by SecretExists")
			return nil, nil
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	// Pre-populate cache as if a previous lookup found the secret.
	client.cache.Set("ghost", testSecretID("stale"))

	exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "ghost"})
	if err != nil {
		t.Fatalf("SecretExists() error = %v", err)
	}
	if exists {
		t.Errorf("SecretExists() = true; want false (cache should be bypassed)")
	}
	if mock.listCalls != 1 {
		t.Errorf("ListSecrets calls = %d, want 1 (forced fresh sweep)", mock.listCalls)
	}
}

func TestClientSecretExistsDirectIDUsesDetailProbe(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	probeMock := func(status string) *countingMockClient {
		return &countingMockClient{
			listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
				t.Fatal("ListSecrets must not be called when key is a direct secret ID")
				return nil, nil
			},
			getSecretDetailFn: func(_ context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
				if secretID != id {
					t.Errorf("GetSecretDetail secretID = %q, want %q", secretID, id)
				}
				return &NcloudSecretDetailResponse{
					Code: successCode,
					Data: NcloudSecretDetailData{SecretID: id, SecretStatus: status},
				}, nil
			},
		}
	}

	t.Run("live secret is reported present from metadata alone", func(t *testing.T) {
		mock := probeMock(secretStatusEnable)
		client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

		exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: id})
		if err != nil {
			t.Fatalf("SecretExists() error = %v", err)
		}
		if !exists {
			t.Error("SecretExists() = false; want true")
		}
		if mock.getSecretDetailCalls != 1 {
			t.Errorf("GetSecretDetail calls = %d, want 1", mock.getSecretDetailCalls)
		}
		if mock.getSecretValueCalls != 0 {
			t.Errorf("GetSecretValue calls = %d, want 0 (metadata probe only)", mock.getSecretValueCalls)
		}
	})

	// A REVOKE secret holds no readable value and the read paths report
	// it as not found. Reporting it present here would let IfNotExists skip
	// the push and mark the PushSecret Synced with the data nowhere readable.
	t.Run("REVOKE secret is reported absent", func(t *testing.T) {
		mock := probeMock(secretStatusRevoke)
		client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

		exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: id})
		if err != nil {
			t.Fatalf("SecretExists() error = %v", err)
		}
		if exists {
			t.Error("SecretExists() = true; want false for a deletion-requested secret")
		}
		if mock.getSecretValueCalls != 0 {
			t.Errorf("GetSecretValue calls = %d, want 0 (metadata probe only)", mock.getSecretValueCalls)
		}
	})
}

func TestClientSecretExistsDirectIDNotFound(t *testing.T) {
	const id = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	mock := &countingMockClient{
		getSecretDetailFn: func(_ context.Context, _ string) (*NcloudSecretDetailResponse, error) {
			return nil, fmt.Errorf("%w: simulated 404", ErrSecretNotFound)
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: id})
	if err != nil {
		t.Fatalf("SecretExists() error = %v", err)
	}
	if exists {
		t.Errorf("SecretExists() = true; want false")
	}
	// No listing fallback: secret names are 3-15 chars, so a 64-hex key can
	// never be a name; a detail 404 is authoritative.
	if mock.listCalls != 0 {
		t.Errorf("ListSecrets calls = %d, want 0", mock.listCalls)
	}
}

func TestClientSecretExistsDirectIDMissDoesNotPoisonCache(t *testing.T) {
	const id = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	mock := &countingMockClient{
		getSecretDetailFn: func(_ context.Context, _ string) (*NcloudSecretDetailResponse, error) {
			return nil, fmt.Errorf("%w", ErrSecretNotFound)
		},
	}
	cache := newSecretIDCache(time.Hour, time.Minute)
	client := &Client{client: mock, cache: cache}

	exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: id})
	if err != nil {
		t.Fatalf("SecretExists() error = %v", err)
	}
	if exists {
		t.Errorf("SecretExists() = true; want false")
	}
	// A direct-ID existence miss must NOT leave a negative cache entry for the ID:
	// resolveSecretID consults the negative cache before the ID shortcut, so a
	// poisoned entry would force later GetSecret(id) to ErrSecretNotFound until TTL.
	if _, found, negative := cache.Get(id); found && negative {
		t.Errorf("cache poisoned: Get(%q) returned a negative entry; want none", id)
	}
	// The ID shortcut must still work after the existence check.
	if got, err := client.resolveSecretID(context.Background(), id); err != nil || got != id {
		t.Errorf("resolveSecretID(%q) = (%q, %v); want (%q, nil)", id, got, err, id)
	}
}

func TestClientResolveSecretIDCacheWarming(t *testing.T) {
	mock := &countingMockClient{
		listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 1,
					SecretList: []NcloudSecretListItem{
						{SecretID: testSecretID("a"), SecretName: "secret-a"},
						{SecretID: testSecretID("b"), SecretName: "secret-b"},
						{SecretID: testSecretID("c"), SecretName: "secret-c"},
					},
				},
			}, nil
		},
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return newSecretValueResponse("v"), nil
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	if _, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "secret-a"}); err != nil {
		t.Fatalf("first lookup error = %v", err)
	}
	if _, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "secret-c"}); err != nil {
		t.Fatalf("second lookup error = %v", err)
	}
	if mock.listCalls != 1 {
		t.Errorf("ListSecrets calls = %d, want 1 (cache warming should serve secret-c)", mock.listCalls)
	}
}
