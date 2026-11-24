// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

func TestNewClientCredentialsConfiguration(t *testing.T) {
	source := &fakeSource{pairs: []Credentials{temporaryPair("k", time.Now().Add(time.Hour))}}

	t.Run("a source and a static pair together are refused", func(t *testing.T) {
		_, err := newClient(&Config{AccessKeyID: "ak", SecretKey: "sk", Credentials: source, Endpoint: secretManagerKRIsolatedEndpoint})
		if !errors.Is(err, ErrAmbiguousCredentials) {
			t.Errorf("newClient() error = %v, want ErrAmbiguousCredentials", err)
		}
	})

	t.Run("a source alone is used as given", func(t *testing.T) {
		client, err := newClient(&Config{Credentials: source, Endpoint: secretManagerKRIsolatedEndpoint})
		if err != nil {
			t.Fatalf("newClient() error = %v", err)
		}
		if client.credentials != source {
			t.Error("newClient() did not keep the configured source")
		}
	})

	t.Run("a role wraps the pair in a switch and keys the cache by it", func(t *testing.T) {
		cfg := &Config{AccessKeyID: "ak", SecretKey: "sk", Role: testRole, STSEndpoint: "https://sts.example", Endpoint: secretManagerKRIsolatedEndpoint}
		client, err := newClient(cfg)
		if err != nil {
			t.Fatalf("newClient() error = %v", err)
		}
		if got := client.credentials.Identity(); got != "role:"+testRole+"@"+StaticCredentials("ak", "sk").Identity() {
			t.Errorf("credentials identity = %q, want the switched role over the static key", got)
		}

		// Two clients for the same store share the name -> ID cache through
		// the identity, exactly as two static clients do; the temporary key,
		// which rotates, must not be what keys it.
		c1, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}
		c2, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}
		if c1.(*Client).cache != c2.(*Client).cache {
			t.Error("clients for the same switched role do not share one cross-reconcile cache")
		}

		// The same static key switched to another role is another principal
		// with its own view of the account; keying by the static key alone
		// would let the two share name -> ID verdicts.
		other := *cfg
		other.Role = testRole + "2"
		c3, err := NewClient(&other)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}
		if c1.(*Client).cache == c3.(*Client).cache {
			t.Error("clients switched to different roles from the same key share one cache")
		}
	})

	t.Run("a role over an invalid STS endpoint is refused at construction", func(t *testing.T) {
		_, err := newClient(&Config{AccessKeyID: "ak", SecretKey: "sk", Role: testRole, STSEndpoint: "http://sts.example", Endpoint: secretManagerKRIsolatedEndpoint})
		if !errors.Is(err, ErrEndpointScheme) {
			t.Errorf("newClient() error = %v, want ErrEndpointScheme", err)
		}
	})
}

// keyLog records the access keys a fake Secret Manager saw.
type keyLog struct {
	mu   sync.Mutex
	keys []string
}

func (l *keyLog) add(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = append(l.keys, key)
}

func (l *keyLog) seen() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.keys...)
}

// listingServer answers every request with 401 for the access keys in refused
// and with a successful empty listing otherwise, recording the keys it saw.
func listingServer(t *testing.T, refused ...string) (*httptest.Server, *keyLog) {
	t.Helper()
	return refusingServer(t, http.StatusUnauthorized, `{"error":{"errorCode":"200","message":"Authentication Failed"}}`, refused...)
}

// refusingServer is listingServer with the refusal's status and body chosen
// by the caller.
func refusingServer(t *testing.T, status int, body string, refused ...string) (*httptest.Server, *keyLog) {
	t.Helper()
	log := &keyLog{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get(headerAccessKey)
		log.add(key)
		if slices.Contains(refused, key) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte(`{"code":"SUCCESS","data":{"totalPageNo":1,"currentPageNo":1,"totalCount":0,"secretList":[]}}`))
	}))
	t.Cleanup(server.Close)
	return server, log
}

func clientWithSource(server *httptest.Server, source CredentialsSource) *secretManagerClient {
	return &secretManagerClient{
		config:       &Config{Endpoint: server.URL},
		credentials:  source,
		httpClient:   newHTTPTransport(),
		retryBackoff: func(int) time.Duration { return 0 },
	}
}

func TestRefusedTemporaryPairIsRefreshedOnce(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	const secretID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	t.Run("a refreshed pair that differs is re-sent, once", func(t *testing.T) {
		server, log := listingServer(t, staleKeyID)
		source := &fakeSource{pairs: []Credentials{temporaryPair(staleKeyID, expiry), temporaryPair(freshKeyID, expiry)}}
		client := clientWithSource(server, source)

		if _, err := client.ListSecrets(context.Background(), 1); err != nil {
			t.Fatalf("ListSecrets() error = %v, want the retry with the fresh pair to succeed", err)
		}
		if seen := log.seen(); len(seen) != 2 || seen[0] != staleKeyID || seen[1] != freshKeyID {
			t.Errorf("keys seen by the server = %v, want [stale fresh]", seen)
		}
		if source.invalidations != 1 {
			t.Errorf("source invalidations = %d, want 1", source.invalidations)
		}
	})

	t.Run("a refreshed pair that is the same is not re-sent", func(t *testing.T) {
		server, log := listingServer(t, staleKeyID)
		source := &fakeSource{pairs: []Credentials{temporaryPair(staleKeyID, expiry)}}
		client := clientWithSource(server, source)

		_, err := client.ListSecrets(context.Background(), 1)
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("ListSecrets() error = %v, want ErrUnauthorized", err)
		}
		if seen := log.seen(); len(seen) != 1 {
			t.Errorf("requests = %d, want 1: the same pair would be refused again", len(seen))
		}
		if source.invalidations != 1 {
			t.Errorf("source invalidations = %d, want 1", source.invalidations)
		}
	})

	t.Run("a refused permanent pair is neither refreshed nor re-sent", func(t *testing.T) {
		server, log := listingServer(t, "ak")
		source := &fakeSource{pairs: []Credentials{{AccessKeyID: "ak", SecretKey: "sk"}}}
		client := clientWithSource(server, source)

		if _, err := client.ListSecrets(context.Background(), 1); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("ListSecrets() error = %v, want ErrUnauthorized", err)
		}
		if seen := log.seen(); len(seen) != 1 || source.invalidations != 0 {
			t.Errorf("requests=%d invalidations=%d, want 1 and 0", len(seen), source.invalidations)
		}
	})

	t.Run("a mutation is re-sent too: 401 means it never ran", func(t *testing.T) {
		server, log := listingServer(t, staleKeyID)
		source := &fakeSource{pairs: []Credentials{temporaryPair(staleKeyID, expiry), temporaryPair(freshKeyID, expiry)}}
		client := clientWithSource(server, source)

		if err := client.UpdateSecretStageValue(context.Background(), secretID, "active", "v"); err != nil {
			t.Fatalf("UpdateSecretStageValue() error = %v", err)
		}
		if seen := log.seen(); len(seen) != 2 {
			t.Errorf("requests = %d, want 2", len(seen))
		}
	})

	t.Run("a failed refresh is reported next to the refusal", func(t *testing.T) {
		server, log := listingServer(t, staleKeyID)
		boom := errors.New("sts down")
		source := &fakeSource{pairs: []Credentials{temporaryPair(staleKeyID, expiry)}, errAfterDrop: boom}
		client := clientWithSource(server, source)

		_, err := client.ListSecrets(context.Background(), 1)
		if !errors.Is(err, ErrUnauthorized) || !errors.Is(err, boom) {
			t.Fatalf("ListSecrets() error = %v, want both the refusal and the refresh failure", err)
		}
		if seen := log.seen(); len(seen) != 1 {
			t.Errorf("requests = %d, want 1", len(seen))
		}
	})

	t.Run("a source that cannot produce a pair fails the request without sending it", func(t *testing.T) {
		server, log := listingServer(t)
		boom := errors.New("no metadata")
		client := clientWithSource(server, &fakeSource{err: boom})

		if _, err := client.ListSecrets(context.Background(), 1); !errors.Is(err, boom) {
			t.Fatalf("ListSecrets() error = %v, want the source error", err)
		}
		if seen := log.seen(); len(seen) != 0 {
			t.Errorf("requests = %d, want 0", len(seen))
		}
	})
}

// TestTemporaryPairRefusedWithGatewayNotFoundIsRefreshedOnce covers the other
// way a temporary pair is refused: with the API gateway's 404 and code 300
// rather than a 401. Such a refusal earns the same one refresh and one re-send
// as a 401. A 404 without that code is not about the key and must not cost a
// refresh.
func TestTemporaryPairRefusedWithGatewayNotFoundIsRefreshedOnce(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	const secretID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const gatewayNotFound = `{"error": {"errorCode": "300", "message": "Not Found Exception", "details": "null"}}`

	t.Run("a listing is re-sent, once, with a refreshed pair that differs", func(t *testing.T) {
		server, log := refusingServer(t, http.StatusNotFound, gatewayNotFound, staleKeyID)
		source := &fakeSource{pairs: []Credentials{temporaryPair(staleKeyID, expiry), temporaryPair(freshKeyID, expiry)}}
		client := clientWithSource(server, source)

		if _, err := client.ListSecrets(context.Background(), 1); err != nil {
			t.Fatalf("ListSecrets() error = %v, want the retry with the fresh pair to succeed", err)
		}
		if seen := log.seen(); len(seen) != 2 || seen[0] != staleKeyID || seen[1] != freshKeyID {
			t.Errorf("keys seen by the server = %v, want [stale fresh]", seen)
		}
		if source.invalidations != 1 {
			t.Errorf("source invalidations = %d, want 1", source.invalidations)
		}
	})

	t.Run("a single-secret read is re-sent, once, with a refreshed pair that differs", func(t *testing.T) {
		server, log := refusingServer(t, http.StatusNotFound, gatewayNotFound, staleKeyID)
		source := &fakeSource{pairs: []Credentials{temporaryPair(staleKeyID, expiry), temporaryPair(freshKeyID, expiry)}}
		client := clientWithSource(server, source)

		if _, err := client.GetSecretValue(context.Background(), secretID); err != nil {
			t.Fatalf("GetSecretValue() error = %v, want the retry with the fresh pair to succeed", err)
		}
		if seen := log.seen(); len(seen) != 2 || seen[0] != staleKeyID || seen[1] != freshKeyID {
			t.Errorf("keys seen by the server = %v, want [stale fresh]", seen)
		}
	})

	t.Run("a refreshed pair that is the same is not re-sent and the listing error is kept", func(t *testing.T) {
		server, log := refusingServer(t, http.StatusNotFound, gatewayNotFound, staleKeyID)
		source := &fakeSource{pairs: []Credentials{temporaryPair(staleKeyID, expiry)}}
		client := clientWithSource(server, source)

		_, err := client.ListSecrets(context.Background(), 1)
		if !errors.Is(err, ErrListingUnavailable) {
			t.Fatalf("ListSecrets() error = %v, want ErrListingUnavailable", err)
		}
		if seen := log.seen(); len(seen) != 1 {
			t.Errorf("requests = %d, want 1: the same pair would be refused again", len(seen))
		}
		if source.invalidations != 1 {
			t.Errorf("source invalidations = %d, want 1", source.invalidations)
		}
	})

	for _, tc := range []struct {
		name string
		call func(*secretManagerClient) error
		want error
	}{
		{
			name: "a listing whose refreshed pair is refused too stops after the one re-send",
			call: func(c *secretManagerClient) error {
				_, err := c.ListSecrets(context.Background(), 1)
				return err
			},
			want: ErrListingUnavailable,
		},
		{
			name: "a single-secret read whose refreshed pair is refused too stops after the one re-send",
			call: func(c *secretManagerClient) error {
				_, err := c.GetSecretValue(context.Background(), secretID)
				return err
			},
			want: ErrNotFoundUnverified,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, log := refusingServer(t, http.StatusNotFound, gatewayNotFound, staleKeyID, freshKeyID)
			source := &fakeSource{pairs: []Credentials{temporaryPair(staleKeyID, expiry), temporaryPair(freshKeyID, expiry)}}

			if err := tc.call(clientWithSource(server, source)); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if seen := log.seen(); len(seen) != 2 || seen[0] != staleKeyID || seen[1] != freshKeyID {
				t.Errorf("keys seen by the server = %v, want [stale fresh] and nothing after", seen)
			}
			if source.invalidations != 1 {
				t.Errorf("source invalidations = %d, want 1", source.invalidations)
			}
		})
	}

	t.Run("a failed refresh is reported next to the refusal", func(t *testing.T) {
		server, log := refusingServer(t, http.StatusNotFound, gatewayNotFound, staleKeyID)
		boom := errors.New("metadata endpoint unreachable")
		source := &fakeSource{pairs: []Credentials{temporaryPair(staleKeyID, expiry)}, errAfterDrop: boom}
		client := clientWithSource(server, source)

		_, err := client.ListSecrets(context.Background(), 1)
		if !errors.Is(err, ErrListingUnavailable) || !errors.Is(err, boom) {
			t.Fatalf("ListSecrets() error = %v, want both the listing's 404 and the refresh failure", err)
		}
		if seen := log.seen(); len(seen) != 1 {
			t.Errorf("requests = %d, want 1", len(seen))
		}
	})

	t.Run("a permanent pair is neither refreshed nor re-sent", func(t *testing.T) {
		server, log := refusingServer(t, http.StatusNotFound, gatewayNotFound, "ak")
		source := &fakeSource{pairs: []Credentials{{AccessKeyID: "ak", SecretKey: "sk"}}}
		client := clientWithSource(server, source)

		if _, err := client.ListSecrets(context.Background(), 1); !errors.Is(err, ErrListingUnavailable) {
			t.Fatalf("ListSecrets() error = %v, want ErrListingUnavailable", err)
		}
		if seen := log.seen(); len(seen) != 1 || source.invalidations != 0 {
			t.Errorf("requests=%d invalidations=%d, want 1 and 0", len(seen), source.invalidations)
		}
	})

	t.Run("a mutation is re-sent too: the gateway refused it before the service saw it", func(t *testing.T) {
		server, log := refusingServer(t, http.StatusNotFound, gatewayNotFound, staleKeyID)
		source := &fakeSource{pairs: []Credentials{temporaryPair(staleKeyID, expiry), temporaryPair(freshKeyID, expiry)}}
		client := clientWithSource(server, source)

		if err := client.UpdateSecretStageValue(context.Background(), secretID, "active", "v"); err != nil {
			t.Fatalf("UpdateSecretStageValue() error = %v", err)
		}
		if seen := log.seen(); len(seen) != 2 {
			t.Errorf("requests = %d, want 2", len(seen))
		}
	})

	for _, tc := range []struct {
		name string
		body string
		want error
	}{
		{
			name: "the service's own resource-not-found is absence, not a refused key",
			body: `{"error":{"errorCode":"501001","message":"RESOURCE_NOT_FOUND"}}`,
			want: ErrSecretNotFound,
		},
		{
			name: "a 404 with no envelope is not about the key",
			body: `<html><body>404 Not Found</body></html>`,
			want: ErrNotFoundUnverified,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, log := refusingServer(t, http.StatusNotFound, tc.body, staleKeyID)
			source := &fakeSource{pairs: []Credentials{temporaryPair(staleKeyID, expiry), temporaryPair(freshKeyID, expiry)}}
			client := clientWithSource(server, source)

			if _, err := client.GetSecretValue(context.Background(), secretID); !errors.Is(err, tc.want) {
				t.Fatalf("GetSecretValue() error = %v, want %v", err, tc.want)
			}
			if seen := log.seen(); len(seen) != 1 || source.invalidations != 0 {
				t.Errorf("requests=%d invalidations=%d, want 1 and 0", len(seen), source.invalidations)
			}
		})
	}
}

// TestListingRefusalThatCannotRefreshReportsTheCredentials pins the verdict an
// operator reads when a temporary pair is refused with the gateway's 404 and
// the refresh then fails for a reason outside the cluster, such as the node
// losing its Server Role. The listing's 404 stays in the error, but Validate
// reads the credential failure first: a store whose credentials cannot be
// obtained is Error (Ready=False), and calling it an unaddressable listing
// would send the operator after the endpoint instead.
func TestListingRefusalThatCannotRefreshReportsTheCredentials(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	const gatewayNotFound = `{"error": {"errorCode": "300", "message": "Not Found Exception", "details": "null"}}`

	server, _ := refusingServer(t, http.StatusNotFound, gatewayNotFound, staleKeyID)
	source := &fakeSource{
		pairs:        []Credentials{temporaryPair(staleKeyID, expiry)},
		errAfterDrop: ErrServerRoleUnavailable,
	}
	_, refusal := clientWithSource(server, source).ListSecrets(context.Background(), 1)
	if !errors.Is(refusal, ErrListingUnavailable) || !errors.Is(refusal, ErrServerRoleUnavailable) {
		t.Fatalf("ListSecrets() error = %v, want both the listing's 404 and the missing Server Role", refusal)
	}

	c := newMockedClient(&countingMockClient{
		listFn: func(context.Context, int) (*NcloudListSecretsResponse, error) { return nil, refusal },
	})
	got, err := c.Validate()
	if got != esv1.ValidationResultError {
		t.Errorf("Validate() = %v, want Error", got)
	}
	if !strings.HasPrefix(err.Error(), "the credentials could not be used: ") {
		t.Errorf("Validate() error = %q, want the credentials prefix", err)
	}
}

// TestListingRefusalWithTransientRefreshFailureIsNotRetried pins that the
// 404/300 refusal is answered once even when the refresh failed on something
// transient. Retrying would meet the memoized credential failure before
// sending, so no attempt would re-send, and the last error would carry no
// refusal, which Validate reads as Unknown (Ready=True) while every call
// fails.
func TestListingRefusalWithTransientRefreshFailureIsNotRetried(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	const gatewayNotFound = `{"error": {"errorCode": "300", "message": "Not Found Exception", "details": "null"}}`

	server, log := refusingServer(t, http.StatusNotFound, gatewayNotFound, staleKeyID)
	source := &fakeSource{
		pairs:        []Credentials{temporaryPair(staleKeyID, expiry)},
		errAfterDrop: ErrServiceUnavailable,
	}
	_, refusal := clientWithSource(server, source).ListSecrets(context.Background(), 1)
	if source.calls != 2 {
		t.Errorf("source calls = %d, want 2 (the first pair and the one refresh): a retry asks the source again", source.calls)
	}
	if !errors.Is(refusal, ErrListingUnavailable) || !errors.Is(refusal, ErrServiceUnavailable) {
		t.Fatalf("ListSecrets() error = %v, want both the listing's 404 and the failed refresh", refusal)
	}
	if seen := log.seen(); len(seen) != 1 {
		t.Errorf("requests = %d, want 1", len(seen))
	}

	c := newMockedClient(&countingMockClient{
		listFn: func(context.Context, int) (*NcloudListSecretsResponse, error) { return nil, refusal },
	})
	if got, _ := c.Validate(); got != esv1.ValidationResultError {
		t.Errorf("Validate() = %v, want Error", got)
	}
}

func TestEveryRequestIsSignedWithTheCurrentPair(t *testing.T) {
	// The source rotates between calls without any refusal; the client must
	// pick the new pair up on the next request rather than pin the first.
	server, log := listingServer(t)
	expiry := time.Now().Add(time.Hour)
	source := &fakeSource{pairs: []Credentials{temporaryPair("first", expiry), temporaryPair("second", expiry)}}
	client := clientWithSource(server, source)

	if _, err := client.ListSecrets(context.Background(), 1); err != nil {
		t.Fatalf("ListSecrets() error = %v", err)
	}
	source.Invalidate(context.Background(), Credentials{}) // the source rotated on its own schedule
	if _, err := client.ListSecrets(context.Background(), 1); err != nil {
		t.Fatalf("second ListSecrets() error = %v", err)
	}
	if seen := log.seen(); len(seen) != 2 || seen[0] != "first" || seen[1] != "second" {
		t.Errorf("keys seen = %v, want [first second]", seen)
	}
}

func TestSTSRejectionKeepsItsClassificationThroughListSecrets(t *testing.T) {
	// The Secure Token Service answers a refused caller key with 404, the
	// same status the listing endpoint uses for an unprovisioned store.
	// ListSecrets must not read the one as the other.
	source, _ := newSwitchRoleFixture(t, StaticCredentials(testAccessKeyID, "s"), func(string) (int, string) {
		return http.StatusNotFound, `{"code":404,"message":"invalid or expired credentials"}`
	})
	server, log := listingServer(t)
	client := clientWithSource(server, source)

	_, err := client.ListSecrets(context.Background(), 1)
	if !errors.Is(err, ErrSwitchRoleRejected) {
		t.Fatalf("ListSecrets() error = %v, want ErrSwitchRoleRejected", err)
	}
	if errors.Is(err, ErrListingUnavailable) {
		t.Errorf("ListSecrets() error = %v; an STS refusal was read as an unprovisioned store", err)
	}
	if seen := log.seen(); len(seen) != 0 {
		t.Errorf("Secret Manager requests = %d, want 0", len(seen))
	}

	// And through Validate, which is where an operator reads it.
	c := &Client{client: client, cache: newSecretIDCache(DefaultCacheTTL, DefaultCacheNegativeTTL)}
	got, verr := c.Validate()
	if got != esv1.ValidationResultError || !errors.Is(verr, ErrSwitchRoleRejected) {
		t.Errorf("Validate() = %v, %v; want Error carrying ErrSwitchRoleRejected", got, verr)
	}
}
