// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0
package secretmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

func TestClientGetSecret(t *testing.T) {
	server, client := setupTestServer(t)
	defer server.Close()

	tests := []struct {
		name      string
		ref       esv1.ExternalSecretDataRemoteRef
		want      string
		wantErr   bool
		wantErrIs error
	}{
		{
			name: "get full secret",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key: "test-secret",
			},
			want:    `{"username":"admin","password":"secret123"}`,
			wantErr: false,
		},
		{
			name: "get secret property",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:      "test-secret",
				Property: "username",
			},
			want:    "admin",
			wantErr: false,
		},
		{
			name: "property not found",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:      "test-secret",
				Property: "nonexistent",
			},
			wantErr: true,
		},
		{
			name: "empty secret data",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key: "empty-secret",
			},
			wantErr:   true,
			wantErrIs: ErrEmptySecretData,
		},
		{
			name: "secret not found",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key: "not-found",
			},
			wantErr: true,
		},
		{
			name: "version previous",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:     "test-secret",
				Version: "previous",
			},
			want:    `{"username":"olduser","password":"old123"}`,
			wantErr: false,
		},
		{
			name: "version pending",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:     "test-secret",
				Version: "pending",
			},
			want:    `{"username":"newuser","password":"new123"}`,
			wantErr: false,
		},
		{
			name: "version active matches default",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:     "test-secret",
				Version: "active",
			},
			want:    `{"username":"admin","password":"secret123"}`,
			wantErr: false,
		},
		{
			name: "version is case-insensitive",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:     "test-secret",
				Version: "Previous",
			},
			want:    `{"username":"olduser","password":"old123"}`,
			wantErr: false,
		},
		{
			name: "version combines with property",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:      "test-secret",
				Version:  "pending",
				Property: "username",
			},
			want:    "newuser",
			wantErr: false,
		},
		{
			name: "unknown version is rejected",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:     "test-secret",
				Version: "v3",
			},
			wantErr: true,
		},
		{
			name: "empty stage value",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:     "empty-secret",
				Version: "pending",
			},
			wantErr:   true,
			wantErrIs: ErrEmptySecretData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.GetSecret(context.Background(), tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Errorf("GetSecret() error = %v, want errors.Is(%v)", err, tt.wantErrIs)
			}
			if !tt.wantErr && string(got) != tt.want {
				t.Errorf("GetSecret() = %v, want %v", string(got), tt.want)
			}
		})
	}
}

// TestGetSecretInvalidVersionFailsFast proves version validation happens
// before any API traffic: a bad version must not trigger name resolution or a
// value fetch.
func TestGetSecretInvalidVersionFailsFast(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTestClientForServer(t, server)
	_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{
		Key:     "test-secret",
		Version: "nope",
	})
	if err == nil {
		t.Fatal("GetSecret() with invalid version should fail")
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("invalid version reached the API: %d call(s), want 0", got)
	}

	_, err = client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{
		Key:     "test-secret",
		Version: strings.Repeat("v", 4096),
	})
	if err == nil {
		t.Fatal("GetSecret() with a 4096-character version should fail")
	}
	if got := len(err.Error()); got > 300 {
		t.Errorf("GetSecret() error is %d bytes; the manifest's version must be cut short", got)
	}
}

func TestGetSecretMap(t *testing.T) {
	server, client := setupTestServer(t)
	defer server.Close()

	tests := []struct {
		name     string
		ref      esv1.ExternalSecretDataRemoteRef
		wantLen  int
		wantUser string
		wantErr  bool
	}{
		{
			name: "get secret map",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key: "test-secret",
			},
			wantLen: 2,
			wantErr: false,
		},
		{
			name: "empty secret data",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key: "empty-secret",
			},
			wantErr: true,
		},
		{
			name: "map from pending stage",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:     "test-secret",
				Version: "pending",
			},
			wantLen:  2,
			wantUser: "newuser",
			wantErr:  false,
		},
		{
			name: "unknown version is rejected",
			ref: esv1.ExternalSecretDataRemoteRef{
				Key:     "test-secret",
				Version: "v2",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.GetSecretMap(context.Background(), tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSecretMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != tt.wantLen {
					t.Errorf("GetSecretMap() returned %d items, want %d", len(got), tt.wantLen)
				}
				wantUser := tt.wantUser
				if wantUser == "" {
					wantUser = "admin"
				}
				if string(got["username"]) != wantUser {
					t.Errorf("GetSecretMap()[username] = %v, want %v", string(got["username"]), wantUser)
				}
			}
		})
	}
}

// TestGetSecretMapProperty pins the AWS/GCP-style contract that
// GetSecretMap(ref) == parseSecretMap(GetSecret(ref)): ref.Property narrows
// the document first and must resolve to a JSON object.
func TestGetSecretMapProperty(t *testing.T) {
	server, client := setupTestServer(t)
	defer server.Close()

	ctx := context.Background()

	t.Run("object property yields its sub-map", func(t *testing.T) {
		got, err := client.GetSecretMap(ctx, esv1.ExternalSecretDataRemoteRef{
			Key:      "nested-secret",
			Property: "db",
		})
		if err != nil {
			t.Fatalf("GetSecretMap(property=db) error = %v", err)
		}
		if len(got) != 2 || string(got["user"]) != "u1" || string(got["pass"]) != "p1" {
			t.Errorf("GetSecretMap(property=db) = %v, want user/pass sub-map", got)
		}
	})

	t.Run("quoted JSON object string is parsed like GetSecret would return it", func(t *testing.T) {
		got, err := client.GetSecretMap(ctx, esv1.ExternalSecretDataRemoteRef{
			Key:      "nested-secret",
			Property: "jsonstr",
		})
		if err != nil {
			t.Fatalf("GetSecretMap(property=jsonstr) error = %v", err)
		}
		if string(got["a"]) != "1" {
			t.Errorf("GetSecretMap(property=jsonstr)[a] = %q, want 1", got["a"])
		}
	})

	t.Run("scalar property cannot become a map", func(t *testing.T) {
		_, err := client.GetSecretMap(ctx, esv1.ExternalSecretDataRemoteRef{
			Key:      "nested-secret",
			Property: "plain",
		})
		if err == nil || !strings.Contains(err.Error(), `property "plain" of secret "nested-secret" is not a JSON object`) {
			t.Fatalf("GetSecretMap(property=plain) error = %v, want the property named as not an object", err)
		}
	})

	t.Run("missing property is rejected", func(t *testing.T) {
		_, err := client.GetSecretMap(ctx, esv1.ExternalSecretDataRemoteRef{
			Key:      "nested-secret",
			Property: "nope",
		})
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("GetSecretMap(property=nope) error = %v, want property-not-found", err)
		}
	})
}

// TestGetSecretMapPropertyNotObjectNamesTheProperty pins the diagnosis when a
// property selects something other than a JSON object: the error names the
// property, on the value path and on the metadataPolicy=Fetch path alike. A
// string that merely starts with a brace, such as a template, is the case a
// first-byte check lets through to parseSecretMap, which then blames the
// secret itself.
func TestGetSecretMapPropertyNotObjectNamesTheProperty(t *testing.T) {
	wantNamed := func(t *testing.T, err error, property string) {
		t.Helper()
		if err == nil {
			t.Fatalf("GetSecretMap(property=%s) = nil error, want the property refused as not an object", property)
		}
		if !strings.Contains(err.Error(), property) || !strings.Contains(err.Error(), "is not a JSON object") {
			t.Errorf("GetSecretMap(property=%s) error = %q, want the property named as not an object", property, err)
		}
	}

	t.Run("value whose text starts with a brace", func(t *testing.T) {
		client := newClientWithValue(`{"tmpl":"{{ .Values.host }}","k":"v"}`)

		_, err := client.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{
			Key: "db-cred", Property: "tmpl",
		})
		wantNamed(t, err, "tmpl")
	})

	t.Run("metadata scalar", func(t *testing.T) {
		client := newMockedClient(&countingMockClient{getSecretDetailFn: detailWithStatus(secretStatusEnable)})
		client.cache.Set("db-cred", testSecretID("db-cred"))

		_, err := client.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{
			Key: "db-cred", Property: "secretStatus", MetadataPolicy: esv1.ExternalSecretMetadataPolicyFetch,
		})
		wantNamed(t, err, "secretStatus")
	})

	t.Run("metadata object still yields its sub-map", func(t *testing.T) {
		server, client := setupTestServer(t)
		defer server.Close()

		got, err := client.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{
			Key: "test-secret", Property: "protectionKey", MetadataPolicy: esv1.ExternalSecretMetadataPolicyFetch,
		})
		if err != nil {
			t.Fatalf("GetSecretMap(Fetch, property=protectionKey) error = %v", err)
		}
		if len(got["type"]) == 0 {
			t.Errorf("GetSecretMap(Fetch, property=protectionKey) = %v, want the protection key's fields", got)
		}
	})
}

// TestPropertyErrorsAreBoundedAndQuoted pins that a property is echoed the
// way a key or a version is: quoted and cut to 40 characters. It is manifest
// text of any length, and the error reaches the controller log.
func TestPropertyErrorsAreBoundedAndQuoted(t *testing.T) {
	client := newClientWithValue(`{"k":"v"}`)
	long := strings.Repeat("p", 4096)

	for name, read := range map[string]func(property string) error{
		"GetSecret": func(property string) error {
			_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred", Property: property})
			return err
		},
		"GetSecretMap": func(property string) error {
			_, err := client.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred", Property: property})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := read(long)
			if err == nil {
				t.Fatal("an absent property should fail")
			}
			if n := len(err.Error()); n > 300 {
				t.Errorf("error is %d bytes for a 4096-character property; want it cut short", n)
			}
			if !strings.Contains(err.Error(), `"pppp`) || !strings.Contains(err.Error(), `secret "db-cred"`) {
				t.Errorf("error = %q, want the property and the key quoted", err)
			}

			err = read("a\nb")
			if err == nil {
				t.Fatal("an absent property should fail")
			}
			if strings.Contains(err.Error(), "\n") || !strings.Contains(err.Error(), `"a\nb"`) {
				t.Errorf("error = %q, want the newline escaped by quoting", err)
			}
		})
	}

	// The same holds when the property exists but is not an object.
	_, err := client.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred", Property: "k"})
	if err == nil || !strings.Contains(err.Error(), `property "k" of secret "db-cred"`) {
		t.Errorf("GetSecretMap(property=k) error = %v, want the property and the key quoted", err)
	}
}

func TestGetSecretMetadataFetch(t *testing.T) {
	server, client := setupTestServer(t)
	defer server.Close()

	ctx := context.Background()

	t.Run("whole metadata document", func(t *testing.T) {
		got, err := client.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
			Key:            "test-secret",
			MetadataPolicy: esv1.ExternalSecretMetadataPolicyFetch,
		})
		if err != nil {
			t.Fatalf("GetSecret(Fetch) error = %v", err)
		}
		var meta map[string]any
		if err := json.Unmarshal(got, &meta); err != nil {
			t.Fatalf("metadata is not valid JSON: %v", err)
		}
		if meta["secretName"] != "test-secret" || meta["secretStatus"] != secretStatusEnable {
			t.Errorf("metadata = %s, want secretName/secretStatus fields", got)
		}
		// The metadata document must never leak the secret value.
		if strings.Contains(string(got), "secret123") {
			t.Errorf("metadata leaked the secret value: %s", got)
		}
	})

	t.Run("property extraction", func(t *testing.T) {
		got, err := client.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
			Key:            "test-secret",
			MetadataPolicy: esv1.ExternalSecretMetadataPolicyFetch,
			Property:       "secretStatus",
		})
		if err != nil {
			t.Fatalf("GetSecret(Fetch, property) error = %v", err)
		}
		if string(got) != secretStatusEnable {
			t.Errorf("GetSecret(Fetch, secretStatus) = %q, want ENABLE", got)
		}
	})

	t.Run("nested property extraction", func(t *testing.T) {
		got, err := client.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
			Key:            "test-secret",
			MetadataPolicy: esv1.ExternalSecretMetadataPolicyFetch,
			Property:       "protectionKey.type",
		})
		if err != nil {
			t.Fatalf("GetSecret(Fetch, nested property) error = %v", err)
		}
		if string(got) != "DEFAULT" {
			t.Errorf("GetSecret(Fetch, protectionKey.type) = %q, want DEFAULT", got)
		}
	})

	t.Run("missing property fails", func(t *testing.T) {
		_, err := client.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
			Key:            "test-secret",
			MetadataPolicy: esv1.ExternalSecretMetadataPolicyFetch,
			Property:       "nonexistent",
		})
		if err == nil {
			t.Fatal("GetSecret(Fetch, missing property) should fail")
		}
	})

	t.Run("even an invalid version is ignored for metadata", func(t *testing.T) {
		// Docs promise version is ignored with metadataPolicy: Fetch - that
		// must hold for values stageForVersion would reject, too.
		got, err := client.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
			Key:            "test-secret",
			MetadataPolicy: esv1.ExternalSecretMetadataPolicyFetch,
			Version:        "garbage",
		})
		if err != nil {
			t.Fatalf("GetSecret(Fetch, invalid version) error = %v", err)
		}
		if !strings.Contains(string(got), `"secretName":"test-secret"`) {
			t.Errorf("expected metadata document, got %s", got)
		}
	})

	t.Run("version is ignored for metadata", func(t *testing.T) {
		got, err := client.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
			Key:            "test-secret",
			MetadataPolicy: esv1.ExternalSecretMetadataPolicyFetch,
			Version:        "pending",
		})
		if err != nil {
			t.Fatalf("GetSecret(Fetch, version) error = %v", err)
		}
		if !strings.Contains(string(got), `"secretName":"test-secret"`) {
			t.Errorf("expected metadata document, got %s", got)
		}
	})

	t.Run("GetSecretMap returns metadata fields", func(t *testing.T) {
		got, err := client.GetSecretMap(ctx, esv1.ExternalSecretDataRemoteRef{
			Key:            "test-secret",
			MetadataPolicy: esv1.ExternalSecretMetadataPolicyFetch,
		})
		if err != nil {
			t.Fatalf("GetSecretMap(Fetch) error = %v", err)
		}
		if string(got["secretName"]) != "test-secret" {
			t.Errorf("GetSecretMap(Fetch)[secretName] = %q, want test-secret", got["secretName"])
		}
		if string(got["secretStatus"]) != secretStatusEnable {
			t.Errorf("GetSecretMap(Fetch)[secretStatus] = %q, want ENABLE", got["secretStatus"])
		}
	})

	t.Run("unresolvable name wraps NoSecretErr", func(t *testing.T) {
		_, err := client.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
			Key:            "missing-secret",
			MetadataPolicy: esv1.ExternalSecretMetadataPolicyFetch,
		})
		if !errors.Is(err, esv1.NoSecretErr) {
			t.Errorf("GetSecret(Fetch, missing) error = %v, want esv1.NoSecretErr", err)
		}
	})

	t.Run("detail 404 wraps NoSecretErr after fallback", func(t *testing.T) {
		// "secret1" resolves via the listing to id1, but the fixture serves no
		// detail route for id1, so GetSecretDetail 404s; the stale-ID fallback
		// re-resolves and 404s again. The error must still carry NoSecretErr.
		_, err := client.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
			Key:            "secret1",
			MetadataPolicy: esv1.ExternalSecretMetadataPolicyFetch,
		})
		if !errors.Is(err, esv1.NoSecretErr) {
			t.Errorf("GetSecret(Fetch, no detail route) error = %v, want esv1.NoSecretErr", err)
		}
	})
}

// TestGetSecretMetadataOnARevokedSecretIsCacheIndependent pins the REVOKE
// contract for metadataPolicy: Fetch. Ncloud answers Get Secret Detail for a
// REVOKE secret, and observing the state is the point of a metadata read, so
// the document comes back rather than NoSecretErr. AWS draws the same line
// between GetSecretValue and DescribeSecret. Above all the answer must not
// depend on whether a value read tombstoned the name first, which is what
// made the same manifest report two different things inside and outside the
// negative TTL.
func TestGetSecretMetadataOnARevokedSecretIsCacheIndependent(t *testing.T) {
	const id = "7777777777777777777777777777777777777777777777777777777777777777"

	newRevoked := func() (*countingMockClient, *Client) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{
				SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusRevoke,
			}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return nil, ErrInvalidStatus
			},
			getSecretDetailFn: detailWithStatus(secretStatusRevoke),
		}
		client := newMockedClient(mock)
		client.cache.Set("db-cred", id)
		return mock, client
	}

	statusRef := esv1.ExternalSecretDataRemoteRef{
		Key:            "db-cred",
		MetadataPolicy: esv1.ExternalSecretMetadataPolicyFetch,
		Property:       "secretStatus",
	}

	t.Run("without a preceding value read", func(t *testing.T) {
		mock, client := newRevoked()
		// Genuinely cold. The fixture seeds the cache so the other subtests
		// can start from a resolved name; leaving it seeded here would let a
		// cache hit answer and the listing path, which is what a freshly
		// restarted controller pod takes, would go unexercised.
		client.cache.Invalidate("db-cred")

		got, err := client.GetSecret(context.Background(), statusRef)
		if err != nil {
			t.Fatalf("GetSecret(Fetch) error = %v, want the REVOKE document", err)
		}
		if string(got) != secretStatusRevoke {
			t.Errorf("secretStatus = %q, want %q", got, secretStatusRevoke)
		}
		// The listing is what has to answer here: it must hand back the
		// REVOKE entry's ID rather than filtering it out the way it filters
		// DESTROYED.
		if mock.listCalls == 0 {
			t.Error("the metadata read answered without consulting the listing, so this is not the cold path")
		}
	})

	t.Run("after a value read tombstoned the name", func(t *testing.T) {
		mock, client := newRevoked()

		if _, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{
			Key: "db-cred",
		}); !errors.Is(err, esv1.NoSecretErr) {
			t.Fatalf("value read error = %v, want esv1.NoSecretErr", err)
		}
		if _, _, negative := client.cache.Get("db-cred"); !negative {
			t.Fatal("the value read did not tombstone the name")
		}

		listCalls := mock.listCalls
		got, err := client.GetSecret(context.Background(), statusRef)
		if err != nil {
			t.Fatalf("GetSecret(Fetch) after a value read error = %v, want the REVOKE document", err)
		}
		if string(got) != secretStatusRevoke {
			t.Errorf("secretStatus = %q, want %q", got, secretStatusRevoke)
		}
		// The tombstone keeps the ID precisely so this costs no listing sweep.
		if mock.listCalls != listCalls {
			t.Errorf("the metadata read re-scanned the listing (%d -> %d)", listCalls, mock.listCalls)
		}
	})

	// A name that resolves to nothing is still absent for a metadata read:
	// only a tombstone entry carries an ID, so a plain negative falls through
	// to the ordinary resolution and stays NoSecretErr.
	t.Run("a plain absence stays absent", func(t *testing.T) {
		client := newMockedClient(&countingMockClient{listFn: listingWith()})

		if _, err := client.GetSecret(context.Background(), statusRef); !errors.Is(err, esv1.NoSecretErr) {
			t.Errorf("GetSecret(Fetch, missing) error = %v, want esv1.NoSecretErr", err)
		}
	})

	t.Run("GetSecretMap agrees", func(t *testing.T) {
		_, client := newRevoked()

		got, err := client.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{
			Key:            "db-cred",
			MetadataPolicy: esv1.ExternalSecretMetadataPolicyFetch,
		})
		if err != nil {
			t.Fatalf("GetSecretMap(Fetch) error = %v", err)
		}
		if string(got["secretStatus"]) != secretStatusRevoke {
			t.Errorf("GetSecretMap(Fetch)[secretStatus] = %q, want %q", got["secretStatus"], secretStatusRevoke)
		}
	})
}

func TestGetSecretDestroyedListingIsNotFound(t *testing.T) {
	const tombstoneID = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
	mock := &countingMockClient{
		listFn: listingWith(NcloudSecretListItem{
			SecretID: tombstoneID, SecretName: "db-cred", SecretStatus: secretStatusDestroyed,
		}),
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			t.Fatalf("GetSecretValue(%q) called for a destroyed tombstone", secretID)
			return nil, nil
		},
	}
	client := newMockedClient(mock)

	_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
	if !errors.Is(err, esv1.NoSecretErr) || !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("GetSecret() error = %v, want NoSecretErr wrapping ErrSecretNotFound", err)
	}
	if id, found, negative := client.cache.Get("db-cred"); found && !negative {
		t.Errorf("destroyed mapping cached as live: id=%q", id)
	}
}

func TestGetSecretDestroyedDuplicatePrefersLive(t *testing.T) {
	const (
		tombstoneID = "5656565656565656565656565656565656565656565656565656565656565656"
		liveID      = "7878787878787878787878787878787878787878787878787878787878787878"
	)
	mock := &countingMockClient{
		listFn: listingWith(
			NcloudSecretListItem{
				SecretID: tombstoneID, SecretName: "db-cred", SecretStatus: secretStatusDestroyed,
			},
			NcloudSecretListItem{
				SecretID: liveID, SecretName: "db-cred", SecretStatus: secretStatusEnable,
			},
		),
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			if secretID != liveID {
				t.Fatalf("GetSecretValue() ID = %q, want live duplicate %q", secretID, liveID)
			}
			return newSecretValueResponse(`{"value":"live"}`), nil
		},
	}
	client := newMockedClient(mock)

	got, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if string(got) != `{"value":"live"}` {
		t.Errorf("GetSecret() = %q, want live duplicate value", got)
	}
	if id, found, negative := client.cache.Get("db-cred"); !found || negative || id != liveID {
		t.Errorf("cache = (%q, %v, %v), want live ID", id, found, negative)
	}
}

// TestListingSweepShiftIsNotAbsence pins a hazard of reading a listing page by
// page: a deletion during a multi-page sweep can shift a live secret into
// pages already read. Concluding "not found" from such a sweep negative-caches
// the name and makes deletionPolicy: Delete drop the target Secret, and
// returning a short GetAllSecrets map deletes keys the same way. Both must
// retry and then fail rather than report the missing entry as gone.
func TestListingSweepShiftIsNotAbsence(t *testing.T) {
	const (
		idA = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
		idB = "1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b"
	)
	page1 := []NcloudSecretListItem{{SecretID: idA, SecretName: "key-a"}}
	page2 := []NcloudSecretListItem{{SecretID: idB, SecretName: "key-b"}}

	t.Run("read resolution retries and then fails instead of reporting absence", func(t *testing.T) {
		mock := &countingMockClient{listFn: shiftingListing(page1, page2, 99)}
		client := newMockedClient(mock)

		_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "missing"})
		if !errors.Is(err, ErrListingUnstable) {
			t.Fatalf("GetSecret() error = %v, want ErrListingUnstable", err)
		}
		if errors.Is(err, esv1.NoSecretErr) {
			t.Error("an unstable listing must not surface as NoSecretErr; it deletes the target Secret")
		}
		if _, found, _ := client.cache.Get("missing"); found {
			t.Error("an unstable sweep must not negative-cache the name")
		}
	})

	t.Run("a settling listing resolves without an error", func(t *testing.T) {
		mock := &countingMockClient{listFn: shiftingListing(page1, page2, 1)}
		client := newMockedClient(mock)

		item, err := client.listingRowFor(context.Background(), "key-b")
		if err != nil {
			t.Fatalf("listingRowFor() error = %v", err)
		}
		if item.SecretID != idB {
			t.Errorf("resolved ID = %s, want %s", item.SecretID, idB)
		}
	})

	t.Run("a found entry is returned even from an unstable sweep", func(t *testing.T) {
		mock := &countingMockClient{listFn: shiftingListing(page1, page2, 99)}
		client := newMockedClient(mock)

		item, err := client.listingRowFor(context.Background(), "key-a")
		if err != nil {
			t.Fatalf("listingRowFor() error = %v, want the observed entry", err)
		}
		if item.SecretID != idA {
			t.Errorf("resolved ID = %s, want %s", item.SecretID, idA)
		}
	})

	t.Run("write resolution retries and then fails instead of reporting absence", func(t *testing.T) {
		mock := &countingMockClient{listFn: shiftingListing(page1, page2, 99)}
		client := newMockedClient(mock)

		_, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "missing"})
		if !errors.Is(err, ErrListingUnstable) {
			t.Fatalf("SecretExists() error = %v, want ErrListingUnstable", err)
		}
		if _, found, _ := client.cache.Get("missing"); found {
			t.Error("an unstable sweep must not negative-cache the name")
		}
	})

	t.Run("GetAllSecrets fails rather than returning a short map", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: shiftingListing(page1, page2, 99),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(`{"k":"v"}`), nil
			},
		}
		client := newMockedClient(mock)

		_, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
		if !errors.Is(err, ErrListingUnstable) {
			t.Fatalf("GetAllSecrets() error = %v, want ErrListingUnstable", err)
		}
		if mock.getSecretValueCalls != 0 {
			t.Errorf("getSecretValueCalls = %d, want 0 (values are read only after the listing settles)",
				mock.getSecretValueCalls)
		}
	})

	t.Run("GetAllSecrets returns the full set once the listing settles", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: shiftingListing(page1, page2, 1),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(`{"k":"v"}`), nil
			},
		}
		client := newMockedClient(mock)

		got, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
		if err != nil {
			t.Fatalf("GetAllSecrets() error = %v", err)
		}
		if len(got) != 2 {
			t.Errorf("GetAllSecrets() returned %d entries, want 2", len(got))
		}
	})
}

// TestListingSweepTombstoneDoesNotBypassStabilityChecks pins the one sighting
// that is NOT a license to skip the stability retries. Seeing a live entry
// proves it exists, so a shifting listing cannot invalidate it. Seeing only a
// DESTROYED tombstone proves the opposite of what the caller concludes: the
// name is reported absent, negative-cached, and surfaced as NoSecretErr, which
// a deletionPolicy: Delete ExternalSecret acts on by deleting its target
// Secret. A listing can carry a tombstone beside a live entry of the same name
// (which is why the sweep keeps looking past one), so an unstable sweep that
// saw only the tombstone may simply have missed a live secret of that name.
func TestListingSweepTombstoneDoesNotBypassStabilityChecks(t *testing.T) {
	const tombID = "dededededededededededededededededededededededededededededededede"

	// Page 1 carries a retained tombstone for "db-cred"; the live entry of the
	// same name sits on page 2, which the sweep never gets a stable view of
	// because the server's declared total keeps moving.
	unstableWithTombstone := func() func(context.Context, int) (*NcloudListSecretsResponse, error) {
		sweeps := 0
		return func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			if pageNo == 1 {
				sweeps++
			}
			var items []NcloudSecretListItem
			total := 2
			if pageNo == 1 {
				items = []NcloudSecretListItem{
					{SecretID: tombID, SecretName: "db-cred", SecretStatus: secretStatusDestroyed},
				}
			} else {
				total = 2 + sweeps
			}
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: total, SecretList: items,
				},
			}, nil
		}
	}

	t.Run("an unstable sweep that saw only a tombstone fails instead of reporting absence", func(t *testing.T) {
		mock := &countingMockClient{listFn: unstableWithTombstone()}
		client := newMockedClient(mock)

		_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
		if errors.Is(err, esv1.NoSecretErr) {
			t.Fatalf("GetSecret() error = %v, want ErrListingUnstable: a tombstone must not license an absence conclusion", err)
		}
		if !errors.Is(err, ErrListingUnstable) {
			t.Fatalf("GetSecret() error = %v, want ErrListingUnstable", err)
		}
		if _, found, _ := client.cache.Get("db-cred"); found {
			t.Error("an unstable sweep must not negative-cache the name")
		}
	})

	t.Run("a tombstone from a stable sweep is still reported as absent", func(t *testing.T) {
		mock := &countingMockClient{listFn: listingWith(
			NcloudSecretListItem{SecretID: tombID, SecretName: "db-cred", SecretStatus: secretStatusDestroyed},
		)}
		client := newMockedClient(mock)

		_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
		if !errors.Is(err, esv1.NoSecretErr) {
			t.Fatalf("GetSecret() error = %v, want NoSecretErr for a trustworthy tombstone", err)
		}
		if _, found, negative := client.cache.Get("db-cred"); !found || !negative {
			t.Error("a tombstone seen by a stable sweep should still negative-cache the name")
		}
	})

	t.Run("a live entry is returned even from an unstable sweep", func(t *testing.T) {
		// The live-sighting short-circuit must survive the fix: seeing the
		// entry proves it exists, so no retry is warranted.
		mock := &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				items := []NcloudSecretListItem{
					{SecretID: tombID, SecretName: "other", SecretStatus: secretStatusDestroyed},
				}
				if pageNo == 1 {
					items = append(items, NcloudSecretListItem{
						SecretID:   "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
						SecretName: "db-cred",
					})
				}
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{
						TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: 99, SecretList: items,
					},
				}, nil
			},
		}
		client := newMockedClient(mock)

		item, err := client.listingRowFor(context.Background(), "db-cred")
		if err != nil {
			t.Fatalf("listingRowFor() error = %v, want the live entry", err)
		}
		if item.SecretStatus == secretStatusDestroyed {
			t.Error("resolved a tombstone where a live entry exists")
		}
		if mock.listCalls != 1 {
			t.Errorf("listCalls = %d, want 1 (a live sighting needs no stability retry)", mock.listCalls)
		}
	})
}

// TestListingSweepShortPageIsNotAbsence extends that pin: totalCount
// tracking only catches a total that CHANGED mid-sweep. A page that answers
// empty while the declared total holds still under-delivers without a shift,
// and concluding absence (negative cache -> deletionPolicy: Delete drops the
// target Secret) or returning the short map (ESO deletes the missing keys)
// from such a sweep is the same data-loss class. The sweep must retry and then
// fail loudly instead.
func TestListingSweepShortPageIsNotAbsence(t *testing.T) {
	const (
		idA = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
		idB = "1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b"
	)
	page1 := []NcloudSecretListItem{{SecretID: idA, SecretName: "key-a"}}
	page2 := []NcloudSecretListItem{{SecretID: idB, SecretName: "key-b"}}

	t.Run("read resolution retries and then fails instead of reporting absence", func(t *testing.T) {
		mock := &countingMockClient{listFn: shortListing(page1, page2, 99)}
		client := newMockedClient(mock)

		_, err := client.resolveSecretIDFromListing(context.Background(), "key-b")
		if !errors.Is(err, ErrListingUnstable) {
			t.Fatalf("resolveSecretIDFromListing() error = %v, want ErrListingUnstable", err)
		}
		if _, found, _ := client.cache.Get("key-b"); found {
			t.Error("an under-delivering sweep must not negative-cache the name")
		}
	})

	t.Run("read resolution succeeds once the listing settles", func(t *testing.T) {
		mock := &countingMockClient{listFn: shortListing(page1, page2, 1)}
		client := newMockedClient(mock)

		id, err := client.resolveSecretIDFromListing(context.Background(), "key-b")
		if err != nil {
			t.Fatalf("resolveSecretIDFromListing() error = %v", err)
		}
		if id != idB {
			t.Errorf("resolved ID = %s, want %s", id, idB)
		}
	})

	t.Run("write resolution retries and then fails instead of reporting absence", func(t *testing.T) {
		mock := &countingMockClient{listFn: shortListing(page1, page2, 99)}
		client := newMockedClient(mock)

		_, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "key-b"})
		if !errors.Is(err, ErrListingUnstable) {
			t.Fatalf("SecretExists() error = %v, want ErrListingUnstable", err)
		}
		if _, found, _ := client.cache.Get("key-b"); found {
			t.Error("an under-delivering sweep must not negative-cache the name")
		}
	})

	t.Run("GetAllSecrets fails rather than returning a short map", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: shortListing(page1, page2, 99),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(`{"k":"v"}`), nil
			},
		}
		client := newMockedClient(mock)

		_, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
		if !errors.Is(err, ErrListingUnstable) {
			t.Fatalf("GetAllSecrets() error = %v, want ErrListingUnstable", err)
		}
		if mock.getSecretValueCalls != 0 {
			t.Errorf("getSecretValueCalls = %d, want 0 (values are read only after the listing settles)",
				mock.getSecretValueCalls)
		}
	})

	t.Run("GetAllSecrets returns the full set once the listing settles", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: shortListing(page1, page2, 1),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(`{"k":"v"}`), nil
			},
		}
		client := newMockedClient(mock)

		got, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
		if err != nil {
			t.Fatalf("GetAllSecrets() error = %v", err)
		}
		if len(got) != 2 {
			t.Errorf("GetAllSecrets() returned %d entries, want 2", len(got))
		}
	})
}

// TestListingSweepRequiresTheDeclaredCount pins that a sweep may conclude
// only from rows that match totalCount exactly, with no ID read twice. A REVOKE
// row is listed and counted, so a tombstone counted like any other row passes,
// and every excess, shortfall or repeat fails, including the ones where
// uncounted or repeated rows would make up for a missed live row. Each case
// runs the three sweeps that conclude absence or completeness: the read
// resolver's, the write index's, and a find's.
func TestListingSweepRequiresTheDeclaredCount(t *testing.T) {
	const (
		idA     = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
		idB     = "1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b"
		idC     = "1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c"
		idDead  = "dededededededededededededededededededededededededededededededede"
		idDead2 = "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
	)
	live := func(id, name string) NcloudSecretListItem {
		return NcloudSecretListItem{SecretID: id, SecretName: name, SecretStatus: secretStatusEnable}
	}
	dead := func(status string) NcloudSecretListItem {
		return NcloudSecretListItem{SecretID: idDead, SecretName: "gone", SecretStatus: status}
	}
	dead2 := func(status string) NcloudSecretListItem {
		return NcloudSecretListItem{SecretID: idDead2, SecretName: "gone-too", SecretStatus: status}
	}
	listing := func(total int, pages [][]NcloudSecretListItem) func(context.Context, int) (*NcloudListSecretsResponse, error) {
		return func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			var items []NcloudSecretListItem
			if pageNo >= 1 && pageNo <= len(pages) {
				items = pages[pageNo-1]
			}
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: len(pages), CurrentPageNo: pageNo, TotalCount: total, SecretList: items,
				},
			}, nil
		}
	}

	cases := []struct {
		name   string
		total  int
		pages  [][]NcloudSecretListItem
		stable bool
	}{{
		name:   "a DESTROYED row listed but not counted",
		total:  2,
		pages:  [][]NcloudSecretListItem{{live(idA, "key-a"), dead(secretStatusDestroyed)}, {live(idB, "key-b")}},
		stable: false,
	}, {
		name:   "a REVOKE row listed but not counted",
		total:  2,
		pages:  [][]NcloudSecretListItem{{live(idA, "key-a"), dead(secretStatusRevoke)}, {live(idB, "key-b")}},
		stable: false,
	}, {
		name:   "a tombstone counted like any other row",
		total:  3,
		pages:  [][]NcloudSecretListItem{{live(idA, "key-a"), dead(secretStatusDestroyed)}, {live(idB, "key-b")}},
		stable: true,
	}, {
		// A REVOKE row is listed and counted.
		name:   "a REVOKE row counted like any other row",
		total:  3,
		pages:  [][]NcloudSecretListItem{{live(idA, "key-a"), dead(secretStatusRevoke)}, {live(idB, "key-b")}},
		stable: true,
	}, {
		name:   "a live row past the total",
		total:  2,
		pages:  [][]NcloudSecretListItem{{live(idA, "key-a"), live(idC, "key-c")}, {live(idB, "key-b")}},
		stable: false,
	}, {
		name:  "two rows past the total",
		total: 2,
		pages: [][]NcloudSecretListItem{
			{live(idA, "key-a"), dead(secretStatusDestroyed)},
			{live(idB, "key-b"), live(idC, "key-c")},
		},
		stable: false,
	}, {
		name:   "a shortfall with a tombstone present",
		total:  3,
		pages:  [][]NcloudSecretListItem{{dead(secretStatusDestroyed)}, {live(idB, "key-b")}},
		stable: false,
	}, {
		// key-b is missing; two uncounted DESTROYED rows make an excess of
		// one, which a tolerance for uncounted tombstones would accept.
		name:  "uncounted tombstones beside a missed live row",
		total: 2,
		pages: [][]NcloudSecretListItem{
			{dead(secretStatusDestroyed), dead2(secretStatusDestroyed), live(idA, "key-a")},
		},
		stable: false,
	}, {
		// key-b is missing and one uncounted DESTROYED row comes back twice.
		name:   "a repeated tombstone beside a missed live row",
		total:  2,
		pages:  [][]NcloudSecretListItem{{dead(secretStatusDestroyed), live(idA, "key-a"), dead(secretStatusDestroyed)}},
		stable: false,
	}, {
		// key-b is missing and key-a comes back twice; the count matches,
		// so only the repeated ID gives it away.
		name:   "a repeated live row standing in for a missed one",
		total:  2,
		pages:  [][]NcloudSecretListItem{{live(idA, "key-a")}, {live(idA, "key-a")}},
		stable: false,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantLive := 0
			for _, page := range tc.pages {
				for _, item := range page {
					if !isTombstone(item.SecretStatus) {
						wantLive++
					}
				}
			}

			t.Run("read resolution of an absent name", func(t *testing.T) {
				client := newMockedClient(&countingMockClient{listFn: listing(tc.total, tc.pages)})
				_, err := client.resolveSecretIDFromListing(context.Background(), "key-z")
				switch {
				case tc.stable && !errors.Is(err, ErrSecretNotFound):
					t.Fatalf("error = %v, want ErrSecretNotFound from a stable listing", err)
				case !tc.stable && !errors.Is(err, ErrListingUnstable):
					t.Fatalf("error = %v, want ErrListingUnstable", err)
				}
			})

			t.Run("write index absence", func(t *testing.T) {
				client := newMockedClient(&countingMockClient{listFn: listing(tc.total, tc.pages)})
				exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "key-z"})
				switch {
				case tc.stable && (err != nil || exists):
					t.Fatalf("SecretExists() = (%v, %v), want (false, nil) from a stable listing", exists, err)
				case !tc.stable && !errors.Is(err, ErrListingUnstable):
					t.Fatalf("SecretExists() error = %v, want ErrListingUnstable", err)
				}
			})

			t.Run("find", func(t *testing.T) {
				client := newMockedClient(&countingMockClient{
					listFn: listing(tc.total, tc.pages),
					getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
						return newSecretValueResponse(`{"k":"v"}`), nil
					},
				})
				got, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
				switch {
				case tc.stable && err != nil:
					t.Fatalf("GetAllSecrets() error = %v, want the live rows of a stable listing", err)
				case tc.stable && len(got) != wantLive:
					t.Fatalf("GetAllSecrets() returned %d entries, want %d", len(got), wantLive)
				case !tc.stable && !errors.Is(err, ErrListingUnstable):
					t.Fatalf("GetAllSecrets() error = %v, want ErrListingUnstable", err)
				}
			})
		})
	}
}

// TestResolveSecretIDDuplicateNameIsFirstWins pins first-wins: when a listing carries
// two live entries with the same name, the ID this call returns and the ID left
// in the write index and the shared cache must be the same one. Otherwise two
// operations on one remote key within a reconcile silently touch two different
// secrets.
func TestResolveSecretIDDuplicateNameIsFirstWins(t *testing.T) {
	const (
		dupA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		dupB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	duplicates := listingWith(
		NcloudSecretListItem{SecretID: dupA, SecretName: "db-cred"},
		NcloudSecretListItem{SecretID: dupB, SecretName: "db-cred"},
	)

	t.Run("writeIndex.Resolve agrees with its index and cache", func(t *testing.T) {
		client := newMockedClient(&countingMockClient{listFn: duplicates})

		got, err := client.writes.Resolve(context.Background(), client.client, client.cache, "db-cred")
		if err != nil {
			t.Fatalf("writeIndex.Resolve() error = %v", err)
		}
		if got != dupA {
			t.Errorf("writeIndex.Resolve() = %s, want the first occurrence %s", got, dupA)
		}
		if indexed := client.writes.names["db-cred"]; indexed != got {
			t.Errorf("write index = %s, want the returned ID %s", indexed, got)
		}
		if cached, found, _ := client.cache.Get("db-cred"); !found || cached != got {
			t.Errorf("cache = %s (found=%v), want the returned ID %s", cached, found, got)
		}
	})

	t.Run("listingRowFor agrees with its cache", func(t *testing.T) {
		client := newMockedClient(&countingMockClient{listFn: duplicates})

		item, err := client.listingRowFor(context.Background(), "db-cred")
		if err != nil {
			t.Fatalf("listingRowFor() error = %v", err)
		}
		if item.SecretID != dupA {
			t.Errorf("resolved ID = %s, want the first occurrence %s", item.SecretID, dupA)
		}
		if cached, found, _ := client.cache.Get("db-cred"); !found || cached != item.SecretID {
			t.Errorf("cache = %s (found=%v), want the resolved ID %s", cached, found, item.SecretID)
		}
	})
}

// TestResolveSecretIDDuplicateNameFirstWinsAcrossPages extends first-wins to
// duplicates that straddle a page boundary: first-wins must hold across the
// whole sweep, not just within one page, or the shared cache (and a find's
// result map) ends up pointing at a different secret than every resolution
// returns.
func TestResolveSecretIDDuplicateNameFirstWinsAcrossPages(t *testing.T) {
	const (
		dupA   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		dupB   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		wanted = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	)
	pages := map[int][]NcloudSecretListItem{
		1: {{SecretID: dupA, SecretName: "db-cred"}},
		2: {
			{SecretID: dupB, SecretName: "db-cred"},
			{SecretID: wanted, SecretName: "wanted"},
		},
	}
	pagedListing := func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
		return &NcloudListSecretsResponse{
			Code: successCode,
			Data: NcloudListSecretsData{
				TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: 3, SecretList: pages[pageNo],
			},
		}, nil
	}

	t.Run("read resolution warms the first occurrence", func(t *testing.T) {
		client := newMockedClient(&countingMockClient{listFn: pagedListing})

		// Resolving a page-2 name forces the sweep across both pages.
		item, err := client.listingRowFor(context.Background(), "wanted")
		if err != nil || item.SecretID != wanted {
			t.Fatalf("listingRowFor() = %s, %v; want %s", item.SecretID, err, wanted)
		}
		if cached, found, _ := client.cache.Get("db-cred"); !found || cached != dupA {
			t.Errorf("cache = %s (found=%v), want the page-1 occurrence %s", cached, found, dupA)
		}
	})

	t.Run("write index records the first occurrence", func(t *testing.T) {
		client := newMockedClient(&countingMockClient{listFn: pagedListing})

		if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, "wanted"); err != nil {
			t.Fatalf("writeIndex.Resolve() error = %v", err)
		}
		if indexed := client.writes.names["db-cred"]; indexed != dupA {
			t.Errorf("write index = %s, want the page-1 occurrence %s", indexed, dupA)
		}
		if cached, found, _ := client.cache.Get("db-cred"); !found || cached != dupA {
			t.Errorf("cache = %s (found=%v), want the page-1 occurrence %s", cached, found, dupA)
		}
	})

	t.Run("GetAllSecrets reports the first occurrence's value", func(t *testing.T) {
		client := newMockedClient(&countingMockClient{
			listFn: pagedListing,
			getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(`{"id":"` + secretID + `"}`), nil
			},
		})

		got, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
		if err != nil {
			t.Fatalf("GetAllSecrets() error = %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("GetAllSecrets() returned %d entries, want 2 (db-cred + wanted)", len(got))
		}
		if want := `{"id":"` + dupA + `"}`; string(got["db-cred"]) != want {
			t.Errorf("GetAllSecrets()[db-cred] = %s, want the page-1 occurrence's value %s", got["db-cred"], want)
		}
		if cached, found, _ := client.cache.Get("db-cred"); !found || cached != dupA {
			t.Errorf("cache = %s (found=%v), want the page-1 occurrence %s", cached, found, dupA)
		}
	})
}

// TestResolveSecretIDUnresolvableKeyNeverReachesTheListing pins the read-path
// name gate. A key that is neither a secret ID nor a name the Create Secret API
// would have accepted cannot exist remotely, so paying a full listing sweep for
// it and then caching it under whatever the manifest contained is pure cost:
// the cache bounds the number of entries, not the size of a key. The answer is
// an error, not an absence: a typo in a manifest must not become the
// NoSecretErr that deletionPolicy: Delete removes the target Secret on.
func TestResolveSecretIDUnresolvableKeyNeverReachesTheListing(t *testing.T) {
	for _, key := range []string{
		"ab",                      // shorter than the 3-character minimum
		"0starts-with-a-digit",    // must start with a letter
		"has a space",             // outside the character set
		"prod/db-cred",            // a path, which an Ncloud name cannot be
		"sixteen-char-nam",        // one past the 15-character maximum
		strings.Repeat("x", 4096), // unbounded input reaching a cache key
		strings.Repeat("가", 50),   // multibyte, cut to a whole character
	} {
		mock := &countingMockClient{listFn: listingWith()}
		client := newMockedClient(mock)

		_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: key})
		if !errors.Is(err, ErrKeyNotAddressable) || errors.Is(err, esv1.NoSecretErr) {
			t.Errorf("GetSecret(%.20q) error = %v, want ErrKeyNotAddressable and not NoSecretErr", key, err)
		}
		if err != nil && len(err.Error()) > 300 {
			t.Errorf("GetSecret(%.20q) error is %d bytes; the key must be cut short", key, len(err.Error()))
		}
		if err != nil && strings.Contains(err.Error(), `\x`) {
			t.Errorf("GetSecret(%.20q) error = %v; the key was cut inside a character", key, err)
		}
		if mock.listCalls != 0 {
			t.Errorf("GetSecret(%.20q) scanned the listing %d time(s)", key, mock.listCalls)
		}
		if _, found, _ := client.cache.Get(key); found {
			t.Errorf("GetSecret(%.20q) left a cache entry", key)
		}
	}

	// The write path keeps its idempotent answers: nothing to find, nothing
	// to delete, and a push refuses the name on its own.
	mock := &countingMockClient{listFn: listingWith()}
	client := newMockedClient(mock)
	if exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "prod/db-cred"}); err != nil || exists {
		t.Errorf("SecretExists(prod/db-cred) = %v, %v; want false, nil", exists, err)
	}
	if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "prod/db-cred"}); err != nil {
		t.Errorf("DeleteSecret(prod/db-cred) error = %v, want nil", err)
	}
	if mock.listCalls != 0 {
		t.Errorf("the write path scanned the listing %d time(s) for an unaddressable key", mock.listCalls)
	}
}

// TestUnaddressableKeyMessageNamesTheIDCase pins the message a 64-character
// uppercase hex key gets. Only lowercase is an ID (isSecretIDFormat), as the
// docs say, so the refusal has to say so too: told only that "an ID is 64 hex
// characters", an operator who pasted such a key is refused by a rule they
// appear to satisfy.
func TestUnaddressableKeyMessageNamesTheIDCase(t *testing.T) {
	mock := &countingMockClient{listFn: listingWith()}
	client := newMockedClient(mock)
	key := strings.ToUpper(testSecretID("db-cred"))

	_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: key})
	if !errors.Is(err, ErrKeyNotAddressable) {
		t.Fatalf("GetSecret() error = %v, want ErrKeyNotAddressable", err)
	}
	if !strings.Contains(err.Error(), "64 lowercase hex characters") {
		t.Errorf("GetSecret() error = %q, want the message to say an ID is lowercase", err)
	}
	if mock.listCalls != 0 {
		t.Errorf("GetSecret() scanned the listing %d time(s) for an uppercase ID", mock.listCalls)
	}
}

// TestExtractPropertyFidelity pins the value-fidelity rules of property
// extraction: a JSON null property is not-found rather than
// an empty string, numbers keep their raw text instead of a float64 round
// trip, and a top-level null document is an error rather than an empty map.
// newClientWithValue wires a mock whose value endpoint answers every ID with
// value as the active stage, with "db-cred" already resolved so no listing
// runs.
func newClientWithValue(value string) *Client {
	mock := &countingMockClient{
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return newSecretValueResponse(value), nil
		},
	}
	c := newMockedClient(mock)
	c.cache.Set("db-cred", testSecretID("db-cred"))
	return c
}

func TestExtractPropertyFidelity(t *testing.T) {
	t.Run("null property is not found, not an empty value", func(t *testing.T) {
		client := newClientWithValue(`{"password":null}`)

		_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{
			Key: "db-cred", Property: "password",
		})
		if err == nil {
			t.Fatal("GetSecret(property=password) on a null field should fail, not sync an empty value")
		}
		if !strings.Contains(err.Error(), "password") {
			t.Errorf("error = %v, want a property-not-found error naming the property", err)
		}
	})

	t.Run("high precision and exponent numbers keep their raw text", func(t *testing.T) {
		for _, tc := range []struct{ raw, want string }{
			{`{"pi":3.141592653589793238462643}`, "3.141592653589793238462643"},
			{`{"pi":1e100}`, "1e100"},
			{`{"pi":42}`, "42"},
		} {
			client := newClientWithValue(tc.raw)
			got, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{
				Key: "db-cred", Property: "pi",
			})
			if err != nil {
				t.Fatalf("GetSecret(%s) error = %v", tc.raw, err)
			}
			if string(got) != tc.want {
				t.Errorf("GetSecret(%s) = %q, want %q", tc.raw, got, tc.want)
			}
		}
	})

	t.Run("string property stays unquoted", func(t *testing.T) {
		client := newClientWithValue(`{"password":"p@ss"}`)
		got, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{
			Key: "db-cred", Property: "password",
		})
		if err != nil {
			t.Fatalf("GetSecret() error = %v", err)
		}
		if string(got) != "p@ss" {
			t.Errorf("GetSecret() = %q, want %q", got, "p@ss")
		}
	})

	t.Run("string property is unquoted the way a map entry is", func(t *testing.T) {
		// gjson and encoding/json unescape a lone high surrogate followed by
		// another surrogate escape differently (one replacement character
		// against two); the property read must match the map read, which
		// encoding/json produces.
		for _, doc := range []string{
			`{"k":"\ud800\ud800Atail"}`,
			`{"k":"\ud800Atail"}`,
			`{"k":"line\nbreak \"quoted\" \\ slash é"}`,
		} {
			client := newClientWithValue(doc)
			whole, err := client.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
			if err != nil {
				t.Fatalf("GetSecretMap(%s) error = %v", doc, err)
			}
			one, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred", Property: "k"})
			if err != nil {
				t.Fatalf("GetSecret(%s, property=k) error = %v", doc, err)
			}
			if !bytes.Equal(one, whole["k"]) {
				t.Errorf("GetSecret(property=k) = %q, GetSecretMap()[k] = %q for %s; the two read paths disagree", one, whole["k"], doc)
			}
		}
	})

	t.Run("GetSecretMap equals parseSecretMap of GetSecret for a nested object", func(t *testing.T) {
		const doc = `{"db":{"host":"h","port":5432,"ratio":0.30000000000000004}}`
		client := newClientWithValue(doc)
		ref := esv1.ExternalSecretDataRemoteRef{Key: "db-cred", Property: "db"}

		raw, err := client.GetSecret(context.Background(), ref)
		if err != nil {
			t.Fatalf("GetSecret() error = %v", err)
		}
		want, err := parseSecretMap(raw, "db-cred")
		if err != nil {
			t.Fatalf("parseSecretMap() error = %v", err)
		}
		got, err := client.GetSecretMap(context.Background(), ref)
		if err != nil {
			t.Fatalf("GetSecretMap() error = %v", err)
		}
		if len(got) != len(want) {
			t.Fatalf("GetSecretMap() = %v, want %v", got, want)
		}
		for k, v := range want {
			if !bytes.Equal(got[k], v) {
				t.Errorf("key %s = %q, want %q", k, got[k], v)
			}
		}
		if string(got["ratio"]) != "0.30000000000000004" {
			t.Errorf("ratio = %q, want the raw JSON number", got["ratio"])
		}
	})

	t.Run("top-level null document is an error, not an empty map", func(t *testing.T) {
		client := newClientWithValue("null")

		_, err := client.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
		if err == nil {
			t.Fatal("GetSecretMap() on a null document should fail; an empty map would delete every managed key")
		}
	})

	t.Run("parseSecretMap rejects a top-level null directly", func(t *testing.T) {
		if _, err := parseSecretMap([]byte("null"), "db-cred"); err == nil {
			t.Fatal("parseSecretMap(null) should fail")
		}
	})
}

// TestGetSecretDeletionLifecyclePromotesNotFound pins the grace-period read
// semantics: a secret whose deletion was requested (REVOKE) refuses value reads
// for up to 7 days (see deletionLifecycleCandidate), and GetSecret must report
// it as NoSecretErr so deletionPolicy handling in the core keeps working. The
// promotion must stay fail-closed: DISABLE refuses value reads the same way but
// still holds a value, so it must surface an error instead.
func TestGetSecretDeletionLifecyclePromotesNotFound(t *testing.T) {
	const id = "9999999999999999999999999999999999999999999999999999999999999999"

	t.Run("REVOKE value read becomes NoSecretErr", func(t *testing.T) {
		mock := &countingMockClient{
			// The listing agrees the name still resolves to the revoked secret,
			// which is what licenses the absence verdict.
			listFn: listingWith(NcloudSecretListItem{
				SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusRevoke,
			}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return nil, ErrInvalidStatus
			},
			getSecretDetailFn: detailWithStatus(secretStatusRevoke),
		}
		client := newMockedClient(mock)
		client.cache.Set("db-cred", id)

		_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
		if err == nil {
			t.Fatal("GetSecret() on a REVOKE secret should fail")
		}
		if !errors.Is(err, ErrSecretNotFound) || !errors.Is(err, esv1.NoSecretErr) {
			t.Fatalf("GetSecret() error = %v, want ErrSecretNotFound wrapped in esv1.NoSecretErr", err)
		}
		// The name is negative-cached rather than merely forgotten: a secret
		// spends up to 7 days in REVOKE, and forgetting alone makes every
		// reconcile re-sweep the whole listing to reach the same verdict.
		gotID, found, negative := client.cache.Get("db-cred")
		if !found || !negative {
			t.Errorf("cache.Get() = (%q, found=%v, negative=%v), want a negative entry", gotID, found, negative)
		}
		listCalls := mock.listCalls
		if _, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"}); !errors.Is(err, esv1.NoSecretErr) {
			t.Fatalf("second GetSecret() error = %v, want esv1.NoSecretErr", err)
		}
		if mock.listCalls != listCalls {
			t.Errorf("second call scanned the listing again (%d -> %d)", listCalls, mock.listCalls)
		}
	})

	// A tombstone answers for one secret ID. Another writer sharing the account
	// can destroy that secret and recreate the same name under a new ID, and the
	// cached mapping is then stale. Reporting absence from the stale ID alone
	// would make deletionPolicy: Delete remove a Kubernetes Secret whose remote
	// value is very much alive.
	t.Run("tombstoned cache entry defers to a live listing entry", func(t *testing.T) {
		const liveID = "1111111111111111111111111111111111111111111111111111111111111111"
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{
				SecretID: liveID, SecretName: "db-cred", SecretStatus: secretStatusEnable,
			}),
			getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
				if secretID == id {
					return nil, ErrInvalidStatus // the stale, destroyed ID
				}
				return newSecretValueResponse(`{"password":"live"}`), nil
			},
			getSecretDetailFn: detailWithStatus(secretStatusDestroyed),
		}
		client := newMockedClient(mock)
		client.cache.Set("db-cred", id)

		got, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{
			Key: "db-cred", Property: "password",
		})
		if err != nil {
			t.Fatalf("GetSecret() error = %v, want the value from the recreated secret", err)
		}
		if string(got) != "live" {
			t.Errorf("GetSecret() = %q, want %q", got, "live")
		}
		if _, _, negative := client.cache.Get("db-cred"); negative {
			t.Error("a live name was negative-cached")
		}
	})

	// The listing has the last word on a name, so a listing that could not be
	// read has not spoken. Concluding absence from a transport failure hands
	// deletionPolicy: Delete a false negative, and the negative entry would
	// then repeat that verdict for its whole TTL without retrying the listing.
	t.Run("a re-check listing that failed is not absence", func(t *testing.T) {
		errListing := errors.New("listing endpoint unreachable")
		mock := &countingMockClient{
			listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
				return nil, errListing
			},
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return nil, ErrInvalidStatus
			},
			getSecretDetailFn: detailWithStatus(secretStatusRevoke),
		}
		client := newMockedClient(mock)
		client.cache.Set("db-cred", id)

		_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
		if !errors.Is(err, errListing) {
			t.Fatalf("GetSecret() error = %v, want it to carry the listing failure", err)
		}
		if errors.Is(err, esv1.NoSecretErr) {
			t.Fatal("GetSecret() reported absence from a listing it could not read")
		}
		if _, found, negative := client.cache.Get("db-cred"); found && negative {
			t.Error("a name was negative-cached from a listing that failed")
		}
	})

	// A value read of a REVOKE secret can be refused with 400 and code 501007
	// as well as with 409. The verdict must not depend on which of the two it
	// is: both are lifecycle-shaped, and the detail read is what proves the
	// state.
	t.Run("REVOKE value read answering 400 with code 501007 becomes NoSecretErr", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{
				SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusRevoke,
			}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return nil, newAPIError(ErrInvalidRequest, http.StatusBadRequest, "501007")
			},
			getSecretDetailFn: detailWithStatus(secretStatusRevoke),
		}
		client := newMockedClient(mock)
		client.cache.Set("db-cred", id)

		_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
		if !errors.Is(err, ErrSecretNotFound) || !errors.Is(err, esv1.NoSecretErr) {
			t.Fatalf("GetSecret() error = %v, want ErrSecretNotFound wrapped in esv1.NoSecretErr", err)
		}
		if _, found, negative := client.cache.Get("db-cred"); !found || !negative {
			t.Error("the revoked name was not negative-cached")
		}
	})

	t.Run("DISABLE value read stays an error (fail closed)", func(t *testing.T) {
		for name, readErr := range map[string]error{
			"409":             ErrInvalidStatus,
			"400 code 501007": newAPIError(ErrInvalidRequest, http.StatusBadRequest, "501007"),
		} {
			t.Run(name, func(t *testing.T) {
				mock := &countingMockClient{
					getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
						return nil, readErr
					},
					getSecretDetailFn: detailWithStatus(secretStatusDisable),
				}
				client := newMockedClient(mock)
				client.cache.Set("db-cred", id)

				_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
				if err == nil {
					t.Fatal("GetSecret() on a DISABLE secret should fail")
				}
				if errors.Is(err, esv1.NoSecretErr) || errors.Is(err, ErrSecretNotFound) {
					t.Fatalf("GetSecret() error = %v, must not report a paused secret as deleted", err)
				}
			})
		}
	})
}

// TestListingSweepConfirmationInvariants pins four rules of absence
// corroboration: a confirming sweep that fails confirms nothing; a sweep
// confirmed once is not re-confirmed for every later key; an unstable sweep
// between two stable ones is not a corroborating pair; and a find and a single
// read must resolve a duplicated name to the same secret.
func TestListingSweepConfirmationInvariants(t *testing.T) {
	// A confirming sweep that dies must not leave the Client claiming a pair
	// that never agreed, or every later key of the reconcile gets a one-sweep
	// absence into the shared negative cache.
	t.Run("a failed confirming sweep confirms nothing", func(t *testing.T) {
		sweep := 0
		mock := &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				if pageNo == 1 {
					sweep++
				}
				if sweep == 2 {
					return nil, errors.New("transport died mid-confirmation")
				}
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{
						TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: 2,
						SecretList: []NcloudSecretListItem{{
							SecretID:   "9999999999999999999999999999999999999999999999999999999999999999",
							SecretName: "other", SecretStatus: secretStatusEnable,
						}},
					},
				}, nil
			},
		}
		client := newMockedClient(mock)

		if _, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "first"}); err == nil {
			t.Fatal("SecretExists() should surface the transport error")
		}
		if client.writes.confirmed {
			t.Error("writeConfirmed is set although the confirming sweep never completed")
		}
	})

	// The other side of the same flag: once a pair has agreed, later keys of
	// the same reconcile rest on it instead of each paying for its own.
	t.Run("a confirmed sweep is not re-confirmed per key", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				other := fmt.Sprintf("other-%d", pageNo)
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{
						TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: 2,
						SecretList: []NcloudSecretListItem{{
							SecretID:   testSecretID(other),
							SecretName: other, SecretStatus: secretStatusEnable,
						}},
					},
				}, nil
			},
		}
		client := newMockedClient(mock)

		for _, key := range []string{"first", "second", "third"} {
			if _, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: key}); err != nil {
				t.Fatalf("SecretExists(%s) error = %v", key, err)
			}
		}
		// Two pages, swept twice, once for the whole reconcile.
		if mock.listCalls != 4 {
			t.Errorf("listCalls = %d, want 4 (one confirmed sweep for the reconcile, not one per key)", mock.listCalls)
		}
	})

	// An unstable sweep says nothing, so it cannot sit between two that do and
	// let them corroborate each other.
	t.Run("instability breaks a corroborating pair", func(t *testing.T) {
		sweep := 0
		mock := &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				if pageNo == 1 {
					sweep++
				}
				// Sweep 2 reports a moving totalCount; the rest hold still.
				total := 2
				if sweep == 2 {
					total = 2 + pageNo
				}
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{
						TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: total,
						SecretList: []NcloudSecretListItem{{
							SecretID:   "7777777777777777777777777777777777777777777777777777777777777777",
							SecretName: "other", SecretStatus: secretStatusEnable,
						}},
					},
				}, nil
			},
		}
		client := newMockedClient(mock)

		_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "ghost"})
		// Sweeps 1 and 3 are stable but sweep 2 is not, so they are not a pair
		// and the bound is reached before a verdict is earned.
		if !errors.Is(err, ErrListingUnstable) {
			t.Errorf("GetSecret() error = %v, want ErrListingUnstable; a stable sweep either side of an unstable one is not a pair", err)
		}
		if _, found, _ := client.cache.Get("ghost"); found {
			t.Error("an unconfirmed absence was cached")
		}
	})

	// The same stable/unstable/stable sequence through the other two loops. The
	// three share a rule that has to hold in all three or not be claimed.
	unstableMiddleSweep := func() *countingMockClient {
		sweep := 0
		return &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				if pageNo == 1 {
					sweep++
				}
				total := 2
				if sweep == 2 {
					total = 2 + pageNo
				}
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{
						TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: total,
						SecretList: []NcloudSecretListItem{{
							SecretID:   "8888888888888888888888888888888888888888888888888888888888888888",
							SecretName: "other", SecretStatus: secretStatusEnable,
						}},
					},
				}, nil
			},
			getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(secretID), nil
			},
		}
	}

	t.Run("a find gives up rather than sweeping past the bound", func(t *testing.T) {
		mock := unstableMiddleSweep()
		client := newMockedClient(mock)

		_, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{
			Name: &esv1.FindName{RegExp: ".*"},
		})
		if !errors.Is(err, ErrListingUnstable) {
			t.Fatalf("GetAllSecrets() error = %v, want ErrListingUnstable", err)
		}
		// Three sweeps of two pages. A fourth would mean the confirming branch
		// ran unbounded, or that the unstable sweep in the middle was allowed
		// to stand as half of a corroborating pair.
		if mock.listCalls != 6 {
			t.Errorf("listCalls = %d, want 6 (three two-page sweeps)", mock.listCalls)
		}
	})

	t.Run("a write resolution gives up rather than sweeping past the bound", func(t *testing.T) {
		mock := unstableMiddleSweep()
		client := newMockedClient(mock)

		_, err := client.writes.Resolve(context.Background(), client.client, client.cache, "ghost")
		if !errors.Is(err, ErrListingUnstable) {
			t.Fatalf("writeIndex.Resolve() error = %v, want ErrListingUnstable", err)
		}
		if mock.listCalls != 6 {
			t.Errorf("listCalls = %d, want 6 (three two-page sweeps)", mock.listCalls)
		}
		if _, found, _ := client.cache.Get("ghost"); found {
			t.Error("an unconfirmed absence was cached")
		}
	})

	// Two live secrets sharing a name must resolve the same way through find
	// and through a single-secret read, which is the invariant
	// collectListedSecret documents.
	t.Run("find and a single read agree on a duplicated name", func(t *testing.T) {
		const (
			first  = "1111111111111111111111111111111111111111111111111111111111111111"
			second = "2222222222222222222222222222222222222222222222222222222222222222"
		)
		sweep := 0
		mock := &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				if pageNo == 1 {
					sweep++
				}
				item := func(id string) NcloudSecretListItem {
					return NcloudSecretListItem{SecretID: id, SecretName: "dup", SecretStatus: secretStatusEnable}
				}
				var rows []NcloudSecretListItem
				switch {
				case sweep == 1 && pageNo == 1:
					// The earlier duplicate is the one this sweep misses.
					rows = []NcloudSecretListItem{item(second)}
				case pageNo == 1:
					rows = []NcloudSecretListItem{item(first)}
				default:
					rows = []NcloudSecretListItem{item(second)}
				}
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{
						TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: 2, SecretList: rows,
					},
				}, nil
			},
			getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(secretID), nil
			},
		}
		client := newMockedClient(mock)

		all, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{
			Name: &esv1.FindName{RegExp: "dup"},
		})
		if err != nil {
			t.Fatalf("GetAllSecrets() error = %v", err)
		}
		if got := string(all["dup"]); got != first {
			t.Errorf("find resolved dup to %s, want the first occurrence %s; find and a read would disagree", got, first)
		}
	})
}

// TestSweepListingForPurgesADestroyedMatchEverywhere pins what a read does
// when the only row holding the name is DESTROYED: that ID can no longer be
// addressed, so every mapping to it goes, not just the one for the name being
// read. An alias left in the shared cache would keep routing reads to a secret
// that no longer exists, and an index entry would route a write to it.
func TestSweepListingForPurgesADestroyedMatchEverywhere(t *testing.T) {
	const destroyed = "3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c"
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 1, CurrentPageNo: pageNo, TotalCount: 1,
					SecretList: []NcloudSecretListItem{
						{SecretID: destroyed, SecretName: "gone", SecretStatus: secretStatusDestroyed},
					},
				},
			}, nil
		},
	}
	client := newMockedClient(mock)
	client.cache.Set("alias", destroyed)
	client.writes.names = map[string]string{"alias": destroyed}

	if _, err := client.resolveSecretIDFromListing(context.Background(), "gone"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("resolveSecretIDFromListing(gone) error = %v, want ErrSecretNotFound", err)
	}
	if id, found, _ := client.cache.Get("alias"); found {
		t.Errorf("cache still maps alias to %s after its secret was listed as DESTROYED", id)
	}
	if id, ok := client.writes.names["alias"]; ok {
		t.Errorf("write index still maps alias to %s after its secret was listed as DESTROYED", id)
	}
}

// TestResolveSecretIDLooksPastARevokedNameToTheLiveSecret covers the
// single-secret and write resolvers for the rule
// TestGetAllSecretsSkipsATombstoneInFrontOfTheLiveName covers for the find. A
// REVOKE secret holds its name but has no readable value, so a reader that
// stops at one answers ErrSecretNotFound for a name a live secret is serving -
// and with deletionPolicy Delete that removes the key from the managed Secret.
func TestResolveSecretIDLooksPastARevokedNameToTheLiveSecret(t *testing.T) {
	const (
		revoked = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
		live    = "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	)
	newClient := func() (*Client, *countingMockClient) {
		mock := &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{
						TotalPageNo: 1, CurrentPageNo: pageNo, TotalCount: 2,
						SecretList: []NcloudSecretListItem{
							{SecretID: revoked, SecretName: "dup", SecretStatus: secretStatusRevoke},
							{SecretID: live, SecretName: "dup", SecretStatus: secretStatusEnable},
						},
					},
				}, nil
			},
			getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
				if secretID == revoked {
					// What Ncloud answers for a deletion-requested secret.
					return nil, fmt.Errorf("%w: deletion requested", ErrSecretNotFound)
				}
				return newSecretValueResponse(secretID), nil
			},
		}
		return newMockedClient(mock), mock
	}

	read := func(t *testing.T, client *Client) []byte {
		t.Helper()
		got, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "dup"})
		if err != nil {
			t.Fatalf("GetSecret() error = %v, want the live secret's value", err)
		}
		if string(got) != live {
			t.Fatalf("GetSecret() = %q, want %s", got, live)
		}
		return got
	}

	t.Run("GetSecret resolves the live secret", func(t *testing.T) {
		client, _ := newClient()
		read(t, client)
	})

	t.Run("the resolution is cached, not re-swept every read", func(t *testing.T) {
		client, mock := newClient()
		read(t, client)
		swept := mock.listCalls
		read(t, client)
		// Warming the cache from the tombstone still answers correctly - the
		// 404 sends the read back to the listing - but it pays a value read
		// and a full sweep on every reconcile for the whole 7-day grace
		// period, which is what that fallback exists to stop.
		if mock.listCalls != swept {
			t.Errorf("second read swept the listing again (%d -> %d calls); the cache is pointing at the tombstone",
				swept, mock.listCalls)
		}
	})

	t.Run("a write resolution leaves no read pointing at the tombstone", func(t *testing.T) {
		client, mock := newClient()
		// The write index may hold the REVOKE secret - that is the one
		// DeleteSecret finalizes - but the name -> ID cache it shares with
		// every later read may not.
		if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, "dup"); err != nil {
			t.Fatalf("writeIndex.Resolve() error = %v", err)
		}
		reads := mock.getSecretValueCalls
		read(t, client)
		if got := mock.getSecretValueCalls - reads; got != 1 {
			t.Errorf("the read spent %d value calls, want 1; it was sent to the tombstone first", got)
		}
	})

	t.Run("a tombstone pair answers with the one still holding the name", func(t *testing.T) {
		// No live row at all: the answer is a tombstone either way, and which
		// one decides what createSecretLocked does with the name. A DESTROYED
		// row reads as a free name and lets the create through; the REVOKE row
		// is the one actually holding it, so it has to win.
		client := newMockedClient(&countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{
						TotalPageNo: 1, CurrentPageNo: pageNo, TotalCount: 2,
						SecretList: []NcloudSecretListItem{
							{SecretID: live, SecretName: "dup", SecretStatus: secretStatusDestroyed},
							{SecretID: revoked, SecretName: "dup", SecretStatus: secretStatusRevoke},
						},
					},
				}, nil
			},
		})

		item, err := client.listingRowFor(context.Background(), "dup")
		if err != nil {
			t.Fatalf("listingRowFor() error = %v", err)
		}
		if item.SecretStatus != secretStatusRevoke {
			t.Errorf("listingRowFor() = %s/%s, want the REVOKE row %s",
				item.SecretID, item.SecretStatus, revoked)
		}
	})
}

// TestListingRowForRevokedTombstoneNeedsAStableSweep pins what
// listingRowFor's own comment argues: a tombstone concludes ABSENCE
// of a live entry, and a sweep that shifted may simply have missed a live
// secret sharing the name, so a tombstone answer has to clear the same bar an
// empty answer does. The early return discriminated on DESTROYED alone, so a
// REVOKE row skipped the bar entirely and the wrong verdict was then pinned in
// the negative cache for its whole TTL.
func TestListingRowForRevokedTombstoneNeedsAStableSweep(t *testing.T) {
	const tombstone = "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c"

	for _, dead := range []string{secretStatusRevoke, secretStatusDestroyed} {
		t.Run(dead, func(t *testing.T) {
			mock := &countingMockClient{
				listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
					// The count moves underneath the sweep, which is exactly
					// the shape that can push a live namesake out of view.
					return &NcloudListSecretsResponse{
						Code: successCode,
						Data: NcloudListSecretsData{
							TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: 2 + pageNo,
							SecretList: []NcloudSecretListItem{
								{SecretID: tombstone, SecretName: "dup", SecretStatus: dead},
							},
						},
					}, nil
				},
			}
			client := newMockedClient(mock)

			_, err := client.listingRowFor(context.Background(), "dup")
			if !errors.Is(err, ErrListingUnstable) {
				t.Errorf("listingRowFor() error = %v, want ErrListingUnstable after %d list calls",
					err, mock.listCalls)
			}
			if _, found, _ := client.cache.Get("dup"); found {
				t.Error("a verdict from an unstable sweep was cached")
			}
		})
	}
}

// TestResolveSecretIDMultiPageAbsenceIsConfirmed pins the one instrument this
// provider has for absence. A name that a sweep did not see is an inference,
// and the inference has a hole the stability gates cannot see: a delete and a
// create landing together leave totalCount where it was while shifting a name
// backward into a page the sweep already read.
//
// The verdict feeds deletionPolicy: Delete, so the sweep has to say it twice.
func TestResolveSecretIDMultiPageAbsenceIsConfirmed(t *testing.T) {
	const id = "1212121212121212121212121212121212121212121212121212121212121212"

	// Two pages, four entries. On the first sweep "db-cred" has just been
	// shifted off page 2 into page 1, which the sweep has already read; a
	// create elsewhere keeps totalCount at 4, so neither gate fires. The
	// second sweep sees the settled listing.
	t.Run("a name the first sweep missed is not absent", func(t *testing.T) {
		sweep := 0
		mock := &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				if pageNo == 1 {
					sweep++
				}
				page := func(items ...NcloudSecretListItem) *NcloudListSecretsResponse {
					return &NcloudListSecretsResponse{
						Code: successCode,
						Data: NcloudListSecretsData{
							TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: 4, SecretList: items,
						},
					}
				}
				other := func(n string) NcloudSecretListItem {
					return NcloudSecretListItem{SecretID: testSecretID(n), SecretName: n, SecretStatus: secretStatusEnable}
				}
				target := NcloudSecretListItem{SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusEnable}

				if sweep == 1 {
					// db-cred moved into page 1 after page 1 was served.
					if pageNo == 1 {
						return page(other("aaa"), other("bbb")), nil
					}
					return page(other("ccc"), other("ddd")), nil
				}
				if pageNo == 1 {
					return page(other("aaa"), target), nil
				}
				return page(other("ccc"), other("ddd")), nil
			},
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse("v"), nil
			},
		}
		client := newMockedClient(mock)

		got, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
		if err != nil {
			t.Fatalf("GetSecret() error = %v, want the secret the second sweep saw", err)
		}
		if string(got) != "v" {
			t.Errorf("GetSecret() = %q, want %q", got, "v")
		}
		if _, _, negative := client.cache.Get("db-cred"); negative {
			t.Error("a single sweep that missed the name negative-cached it")
		}
	})

	// The corroboration must not turn a genuine absence into an error or an
	// endless re-sweep, and it must still negative-cache once both agree.
	t.Run("a name neither sweep sees is absent", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				other := fmt.Sprintf("other-%d", pageNo)
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{
						TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: 2,
						SecretList: []NcloudSecretListItem{{
							SecretID: testSecretID(other), SecretName: other, SecretStatus: secretStatusEnable,
						}},
					},
				}, nil
			},
		}
		client := newMockedClient(mock)

		_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
		if !errors.Is(err, esv1.NoSecretErr) {
			t.Fatalf("GetSecret() error = %v, want esv1.NoSecretErr", err)
		}
		if _, found, negative := client.cache.Get("db-cred"); !found || !negative {
			t.Error("an absence both sweeps agree on should still be negative-cached")
		}
	})

	// A listing that fits in one request has no window between pages, so it
	// costs nothing extra.
	t.Run("a single-page sweep is not asked twice", func(t *testing.T) {
		mock := &countingMockClient{listFn: listingWith(NcloudSecretListItem{
			SecretID: testSecretID("other"), SecretName: "other", SecretStatus: secretStatusEnable,
		})}
		client := newMockedClient(mock)

		if _, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"}); !errors.Is(err, esv1.NoSecretErr) {
			t.Fatalf("GetSecret() error = %v, want esv1.NoSecretErr", err)
		}
		if mock.listCalls != 1 {
			t.Errorf("listCalls = %d, want 1 (one request leaves no window to corroborate)", mock.listCalls)
		}
	})
}

// TestGetSecretMetadataEmptyFieldsAddressable pins that fields
// the API always returns (memo, autoRotationYN, rotationPhase) stay in the
// Fetch document even when empty, so property lookups return "" instead of
// PropertyNotFound.
func TestGetSecretMetadataEmptyFieldsAddressable(t *testing.T) {
	mock := &countingMockClient{
		getSecretDetailFn: func(_ context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
			return &NcloudSecretDetailResponse{
				Code: successCode,
				Data: NcloudSecretDetailData{SecretID: secretID, SecretStatus: secretStatusEnable}, // Memo etc. empty
			}, nil
		},
	}
	client := newMockedClient(mock)
	client.cache.Set("db-cred", "6666666666666666666666666666666666666666666666666666666666666666")

	for _, property := range []string{"memo", "autoRotationYN", "rotationPhase"} {
		got, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{
			Key:            "db-cred",
			MetadataPolicy: esv1.ExternalSecretMetadataPolicyFetch,
			Property:       property,
		})
		if err != nil {
			t.Fatalf("GetSecret(Fetch, property=%s) error = %v, want empty string", property, err)
		}
		if len(got) != 0 {
			t.Errorf("GetSecret(Fetch, property=%s) = %q, want empty", property, got)
		}
	}
}

func TestExtractSecretForStage(t *testing.T) {
	full := &NcloudSecretValueResponse{Code: successCode}
	full.Data.DecryptedSecretChain.Previous = "old"
	full.Data.DecryptedSecretChain.Active = "current"
	full.Data.DecryptedSecretChain.Pending = "next"

	tests := []struct {
		name  string
		resp  *NcloudSecretValueResponse
		stage string
		want  string
	}{
		{name: "active stage", resp: full, stage: stageActive, want: "current"},
		{name: "previous stage", resp: full, stage: stagePrevious, want: "old"},
		{name: "pending stage", resp: full, stage: stagePending, want: "next"},
		{name: "empty pending stage", resp: &NcloudSecretValueResponse{Code: successCode}, stage: stagePending, want: ""},
		{name: "nil response", resp: nil, stage: stageActive, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSecretForStage(tt.resp, tt.stage)
			if string(got) != tt.want {
				t.Errorf("extractSecretForStage(%q) = %v, want %v", tt.stage, string(got), tt.want)
			}
		})
	}
}

func TestStageForVersion(t *testing.T) {
	tests := []struct {
		version string
		want    string
		wantErr bool
	}{
		{version: "", want: stageActive},
		{version: "active", want: stageActive},
		{version: "previous", want: stagePrevious},
		{version: "pending", want: stagePending},
		{version: "Pending", want: stagePending}, // case-insensitive
		{version: "ACTIVE", want: stageActive},
		{version: "latest", wantErr: true},
		{version: "AWSCURRENT", wantErr: true},
		{version: "active ", wantErr: true}, // no whitespace trimming
	}

	for _, tt := range tests {
		t.Run("version="+tt.version, func(t *testing.T) {
			got, err := stageForVersion(tt.version)
			if (err != nil) != tt.wantErr {
				t.Fatalf("stageForVersion(%q) error = %v, wantErr %v", tt.version, err, tt.wantErr)
			}
			if tt.wantErr {
				if !strings.Contains(err.Error(), tt.version) {
					t.Errorf("error %q should quote the rejected version %q", err.Error(), tt.version)
				}
				return
			}
			if got != tt.want {
				t.Errorf("stageForVersion(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestMapSecretToGjson(t *testing.T) {
	secretData := []byte(`{"username":"admin","password":"secret"}`)

	result := mapSecretToGjson(secretData, "username")
	if !result.Exists() {
		t.Error("mapSecretToGjson() property should exist")
	}
	if result.String() != "admin" {
		t.Errorf("mapSecretToGjson() = %v, want admin", result.String())
	}
}

func TestMapSecretToGjsonEscapesAllMetacharacters(t *testing.T) {
	// Keys containing gjson wildcards must be matched literally, never as
	// patterns. The wild keys come first in document order so an unescaped
	// wildcard would match them instead of the literal key.
	data := []byte(`{"axb":"wild-star","a*b":"lit-star","ayb":"wild-q","a?b":"lit-q"}`)
	if got := mapSecretToGjson(data, "a*b"); got.String() != "lit-star" {
		t.Errorf(`property "a*b" = %q, want lit-star (literal match, not wildcard)`, got.String())
	}
	if got := mapSecretToGjson(data, "a?b"); got.String() != "lit-q" {
		t.Errorf(`property "a?b" = %q, want lit-q (literal match, not wildcard)`, got.String())
	}

	// Every gjson path operator must be treated literally. The most dangerous
	// case is a key named like a modifier: without escaping, gjson applies the
	// modifier to the whole document and leaks every other key's value.
	doc := []byte(`{"@this":"MOD","@reverse":"REV","@values":"VALS","a|b":"PIPE","[x]":"BRK","{y}":"BRACE","#h":"HASH","secret":"OTHER"}`)
	for _, tc := range []struct{ prop, want string }{
		{"@this", "MOD"},
		{"@reverse", "REV"},
		{"@values", "VALS"},
		{"a|b", "PIPE"},
		{"[x]", "BRK"},
		{"{y}", "BRACE"},
		{"#h", "HASH"},
	} {
		got := mapSecretToGjson(doc, tc.prop)
		if got.String() != tc.want {
			t.Errorf("property %q = %q, want %q (must be a literal key, not a gjson operator)", tc.prop, got.String(), tc.want)
		}
		// Guard against silent over-exposure: the result must never contain a
		// sibling key's value.
		if strings.Contains(got.String(), "OTHER") {
			t.Errorf("property %q leaked sibling value: %q", tc.prop, got.String())
		}
	}

	// Operators that are absent as literal keys must remain absent. In
	// particular, raw gjson("@this") would return the entire document.
	withoutOperators := []byte(`{"secret":"must-not-leak","db":{"host":"nested"}}`)
	for _, property := range []string{
		"@this",
		"@values",
		"secret|@this",
		"*",
		"#",
		"[secret]",
		"{secret}",
		"db.#(host)",
	} {
		if got := mapSecretToGjson(withoutOperators, property); got.Exists() {
			t.Errorf("absent operator property %q unexpectedly resolved to %q", property, got.String())
		}
	}
}

func TestMapSecretToGjsonPropertyLookupOrder(t *testing.T) {
	// Literal dotted key: preserved flat-key behavior.
	flat := []byte(`{"tls.crt":"CERT","tls.key":"KEY"}`)
	if got := mapSecretToGjson(flat, "tls.crt"); !got.Exists() || got.String() != "CERT" {
		t.Errorf(`literal "tls.crt" = %q (exists=%v), want CERT`, got.String(), got.Exists())
	}

	// Nested navigation: falls back to the gjson path like other providers.
	nested := []byte(`{"db":{"host":"pg.internal","port":5432}}`)
	if got := mapSecretToGjson(nested, "db.host"); !got.Exists() || got.String() != "pg.internal" {
		t.Errorf(`nested "db.host" = %q (exists=%v), want pg.internal`, got.String(), got.Exists())
	}

	// Both forms present: the literal key wins (backward compatibility).
	both := []byte(`{"db.host":"literal-wins","db":{"host":"nested"}}`)
	if got := mapSecretToGjson(both, "db.host"); got.String() != "literal-wins" {
		t.Errorf(`ambiguous "db.host" = %q, want literal-wins`, got.String())
	}

	// Still missing in both forms: reports non-existence.
	if got := mapSecretToGjson(flat, "absent.key"); got.Exists() {
		t.Errorf(`"absent.key" should not exist, got %q`, got.String())
	}
}

func TestParseSecretMap(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantLen int
		wantErr bool
	}{
		{
			name:    "valid JSON",
			data:    []byte(`{"key1":"value1","key2":"value2"}`),
			wantLen: 2,
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			data:    []byte(`{invalid json`),
			wantErr: true,
		},
		{
			name:    "empty JSON",
			data:    []byte(`{}`),
			wantLen: 0,
			wantErr: false,
		},
		{
			name:    "mixed value types accepted",
			data:    []byte(`{"str":"v","port":5432,"flag":true,"nested":{"a":"b"},"arr":[1,2],"nul":null}`),
			wantLen: 6,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSecretMap(tt.data, "test-secret")
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSecretMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) != tt.wantLen {
				t.Errorf("parseSecretMap() returned %d items, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestGetSecretMissingWrapsCoreNoSecretErr(t *testing.T) {
	mock := &countingMockClient{
		listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{TotalPageNo: 1, SecretList: nil},
			}, nil
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "ghost"})
	if !errors.Is(err, esv1.NoSecretErr) {
		t.Errorf("GetSecret() missing-secret error = %v, must wrap esv1.NoSecretErr (deletionPolicy=Delete)", err)
	}
	if !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("GetSecret() missing-secret error = %v, must keep ErrSecretNotFound in the chain", err)
	}

	_, err = client.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "ghost"})
	if !errors.Is(err, esv1.NoSecretErr) {
		t.Errorf("GetSecretMap() missing-secret error = %v, must wrap esv1.NoSecretErr", err)
	}

	// Non-NotFound errors must pass through unwrapped.
	mock2 := &countingMockClient{
		listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
			return nil, fmt.Errorf("%w: flake", ErrServiceUnavailable)
		},
	}
	client2 := &Client{client: mock2, cache: newSecretIDCache(time.Hour, time.Minute)}
	_, err = client2.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "any"})
	if errors.Is(err, esv1.NoSecretErr) {
		t.Errorf("transient error must not be classified as NoSecretErr: %v", err)
	}
}

func TestParseSecretMapValueRepresentations(t *testing.T) {
	got, err := parseSecretMap(
		[]byte(`{"str":"plain","port":5432,"flag":true,"nested":{"a":"b"},"arr":[1,2],"nul":null}`),
		"mixed")
	if err != nil {
		t.Fatalf("parseSecretMap() error = %v", err)
	}
	want := map[string]string{
		"str":    "plain", // strings are unquoted
		"port":   "5432",  // scalars keep their JSON text
		"flag":   "true",
		"nested": `{"a":"b"}`, // composites stay raw JSON
		"arr":    "[1,2]",
		"nul":    "null",
	}
	for k, w := range want {
		if g := string(got[k]); g != w {
			t.Errorf("parseSecretMap()[%q] = %q, want %q", k, g, w)
		}
	}
}

// TestGetSecretListingUnavailableIsNotCoreNoSecretErr pins the ESO-core-facing
// side of ErrListingUnavailable, the one that decides whether data survives.
//
// The core keys deletionPolicy: Delete on esv1.NoSecretErr: when a read reports
// it, the target Kubernetes Secret is deleted. asCoreNotFound promotes only
// ErrSecretNotFound, so an unreachable listing must not carry that sentinel - it
// has to surface as a plain error and leave the synced data in place.
func TestGetSecretListingUnavailableIsNotCoreNoSecretErr(t *testing.T) {
	unavailable := func(context.Context, int) (*NcloudListSecretsResponse, error) {
		return nil, newAPIError(ErrListingUnavailable, http.StatusNotFound, "501001")
	}

	for name, read := range map[string]func(*Client) error{
		"GetSecret": func(c *Client) error {
			_, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
			return err
		},
		"GetSecretMap": func(c *Client) error {
			_, err := c.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
			return err
		},
		"GetAllSecrets": func(c *Client) error {
			_, err := c.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			client := newMockedClient(&countingMockClient{listFn: unavailable})

			err := read(client)
			if err == nil {
				t.Fatalf("%s() error = nil, want the listing failure surfaced", name)
			}
			if errors.Is(err, esv1.NoSecretErr) {
				t.Errorf("%s() reports esv1.NoSecretErr; deletionPolicy: Delete would delete the target Secret: %v", name, err)
			}
			if errors.Is(err, ErrSecretNotFound) {
				t.Errorf("%s() still reports ErrSecretNotFound: %v", name, err)
			}
			if !errors.Is(err, ErrListingUnavailable) {
				t.Errorf("%s() error = %v, want ErrListingUnavailable", name, err)
			}
		})
	}
}

func TestParseSecretMapErrorOmitsSecretBytes(t *testing.T) {
	// A non-JSON secret value must not leak into the error. encoding/json's
	// SyntaxError echoes the offending input ("invalid character 'x' ..."),
	// so the returned error must not carry the parser detail.
	const secret = "Zode9uahiedoo0aV"
	_, err := parseSecretMap([]byte(secret), "db-cred")
	if err == nil {
		t.Fatal("parseSecretMap() on non-JSON input should error")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "invalid character") {
		t.Errorf("error message leaks secret content or parser detail: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "db-cred") {
		t.Errorf("error should name the secret: %q", err.Error())
	}
}

func TestPaginationTotalPageNoZeroFetchesUntilEmptyPage(t *testing.T) {
	// A totalPageNo of 0 (an omitted field unmarshals to 0) must mean
	// "unknown, keep paging" - not "stop after the first page".
	pages := map[int][]NcloudSecretListItem{
		1: {{SecretID: testSecretID("1"), SecretName: "page-one"}},
		2: {{SecretID: testSecretID("2"), SecretName: "page-two"}},
		3: nil, // empty page terminates
	}
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{TotalPageNo: 0, SecretList: pages[pageNo]},
			}, nil
		},
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return newSecretValueResponse("v"), nil
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	// resolveSecretIDFromListing must find a secret on page 2. The names
	// have to be ones Ncloud could actually issue, or the read-path syntax
	// gate answers before the listing is ever consulted.
	id, err := client.resolveSecretIDFromListing(context.Background(), "page-two")
	if err != nil {
		t.Fatalf("resolveSecretIDFromListing() error = %v", err)
	}
	if id != testSecretID("2") {
		t.Errorf("resolved id = %q, want id-2", id)
	}

	// GetAllSecrets must include entries from every page.
	mock.listCalls = 0
	all, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
	if err != nil {
		t.Fatalf("GetAllSecrets() error = %v", err)
	}
	if len(all) != 2 {
		t.Errorf("GetAllSecrets() returned %d secrets, want 2 (multi-page)", len(all))
	}
	// Six, not three: a find that spans more than one page is swept twice and
	// unioned, because an earlier delete can push a later entry out of view
	// and ESO rebuilds the Secret from this map.
	if mock.listCalls != 6 {
		t.Errorf("ListSecrets calls = %d, want 6 (two data pages + terminating empty page, swept twice)", mock.listCalls)
	}
}

func TestPaginationEmptyMidPageWithTotalPageNoContinues(t *testing.T) {
	// Regression: a glitching server can return an empty page while
	// totalPageNo still declares more pages. The declared count is
	// authoritative; ending the sweep early would silently truncate
	// GetAllSecrets (partial map, nil error) and misclassify a live secret
	// as NoSecretErr on the remoteRef path.
	pages := map[int][]NcloudSecretListItem{
		1: {{SecretID: testSecretID("other"), SecretName: "other"}},
		2: nil, // inconsistent empty page mid-sweep
		3: {{SecretID: testSecretID("db"), SecretName: "db-cred"}},
	}
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{TotalPageNo: 3, SecretList: pages[pageNo]},
			}, nil
		},
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return newSecretValueResponse("v"), nil
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	// Name resolution must reach page 3.
	id, err := client.resolveSecretIDFromListing(context.Background(), "db-cred")
	if err != nil {
		t.Fatalf("resolveSecretIDFromListing() error = %v, want secret found on page 3", err)
	}
	if id != testSecretID("db") {
		t.Errorf("resolved id = %q, want id-db", id)
	}

	// GetAllSecrets must include entries from every declared page.
	mock.listCalls = 0
	all, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
	if err != nil {
		t.Fatalf("GetAllSecrets() error = %v", err)
	}
	if len(all) != 2 {
		t.Errorf("GetAllSecrets() returned %d secrets, want 2 (empty mid-page must not truncate)", len(all))
	}
	// Twice the declared pages: see the confirmation note on listAllSecretItems.
	if mock.listCalls != 6 {
		t.Errorf("ListSecrets calls = %d, want 6 (all declared pages, swept twice)", mock.listCalls)
	}
}

func TestPaginationTotalPageNoZeroEmptyFirstPageTerminates(t *testing.T) {
	mock := &countingMockClient{
		listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{TotalPageNo: 0, SecretList: nil},
			}, nil
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	if _, err := client.resolveSecretIDFromListing(context.Background(), "ghost"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("error = %v, want ErrSecretNotFound", err)
	}
	// Two, not one, and not a loop. This response declares no page count and
	// carries no rows, so it is the shape absenceConfirmed refuses to accept
	// on its own: nothing in it distinguishes an empty account from a
	// truncated answer. The sweep is repeated once and then stops, which is
	// what this test is really about.
	if mock.listCalls != 2 {
		t.Errorf("ListSecrets calls = %d, want 2 (one sweep, one confirmation, then stop)", mock.listCalls)
	}
}

// TestListingSweepUndeclaredEmptyPageIsNotFirstHand pins the distinction the
// page count alone cannot make. A server that declares its page count has
// spoken, even when the answer is "nothing"; a response carrying neither a page
// count nor a row has not, and a glitched or truncated one looks exactly like
// it.
func TestListingSweepUndeclaredEmptyPageIsNotFirstHand(t *testing.T) {
	for _, tc := range []struct {
		name      string
		totalPage int
		want      int
	}{
		{name: "the server declared one page", totalPage: 1, want: 1},
		{name: "the server declared nothing", totalPage: 0, want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &countingMockClient{
				listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
					return &NcloudListSecretsResponse{
						Code: successCode,
						Data: NcloudListSecretsData{TotalPageNo: tc.totalPage, SecretList: nil},
					}, nil
				},
			}
			client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

			if _, err := client.resolveSecretIDFromListing(context.Background(), "ghost"); !errors.Is(err, ErrSecretNotFound) {
				t.Fatalf("error = %v, want ErrSecretNotFound", err)
			}
			if mock.listCalls != tc.want {
				t.Errorf("ListSecrets calls = %d, want %d", mock.listCalls, tc.want)
			}
		})
	}
}

func TestPaginationCapAbortsUnboundedSweep(t *testing.T) {
	// A server that clamps out-of-range pageNo to the last non-empty page
	// would never send the empty page the TotalPageNo==0 mode waits for; the
	// hard cap must abort with an error instead of looping forever.
	mock := &countingMockClient{
		listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 0,
					SecretList:  []NcloudSecretListItem{{SecretID: testSecretID("x"), SecretName: "same-page"}},
				},
			}, nil
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	_, err := client.resolveSecretIDFromListing(context.Background(), "absent")
	if err == nil || errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("error = %v, want a pagination-cap error distinct from NotFound", err)
	}
	if mock.listCalls != maxListPages {
		t.Errorf("ListSecrets calls = %d, want exactly maxListPages (%d)", mock.listCalls, maxListPages)
	}

	// GetAllSecrets shares the same guard (matcher excludes every item so no
	// per-item value fetches slow the loop down).
	mock.listCalls = 0
	name := "^never-matches$"
	if _, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: name}}); err == nil {
		t.Fatal("GetAllSecrets() must abort at the pagination cap")
	}
}

// TestGetSecretRevokedNameOnACacheMissListsOnce pins that a tombstone reached
// through this call's own listing is final: the second listing exists to
// overrule a stale cache entry, and there is none to overrule.
func TestGetSecretRevokedNameOnACacheMissListsOnce(t *testing.T) {
	const id = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	mock := &countingMockClient{
		listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusRevoke}),
		getSecretValueFn: func(context.Context, string) (*NcloudSecretValueResponse, error) {
			return nil, fmt.Errorf("%w: deletion requested", ErrInvalidStatus)
		},
		getSecretDetailFn: detailWithStatus(secretStatusRevoke),
	}
	client := newMockedClient(mock)

	_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
	if !errors.Is(err, esv1.NoSecretErr) {
		t.Fatalf("GetSecret() error = %v, want NoSecretErr", err)
	}
	if mock.listCalls != 1 {
		t.Errorf("ListSecrets calls = %d, want 1: the ID came from this call's listing, so no second listing can overrule it", mock.listCalls)
	}
	if got, found, negative := client.cache.Get("db-cred"); !found || !negative || got != id {
		t.Errorf("cache = (%q, %v, %v), want a tombstone for %s", got, found, negative, id)
	}
}

// TestGetSecretCachedTombstoneIsOverruledByTheListing pins the other half: a
// tombstone reached through a cached ID may be stale, since another writer
// can have recreated the name, so the listing gets the final word.
func TestGetSecretCachedTombstoneIsOverruledByTheListing(t *testing.T) {
	const (
		staleID = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"
		liveID  = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	)
	mock := &countingMockClient{
		listFn: listingWith(NcloudSecretListItem{SecretID: liveID, SecretName: "db-cred", SecretStatus: secretStatusEnable}),
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			if secretID == staleID {
				return nil, fmt.Errorf("%w: deletion requested", ErrInvalidStatus)
			}
			return newSecretValueResponse("recreated"), nil
		},
		getSecretDetailFn: detailWithStatus(secretStatusRevoke),
	}
	client := newMockedClient(mock)
	client.cache.Set("db-cred", staleID)

	got, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
	if err != nil {
		t.Fatalf("GetSecret() error = %v, want the recreated secret's value", err)
	}
	if string(got) != "recreated" {
		t.Errorf("GetSecret() = %q, want recreated", got)
	}
	if mock.listCalls != 1 {
		t.Errorf("ListSecrets calls = %d, want 1 (the listing that overruled the cache)", mock.listCalls)
	}
}

// TestGetSecretLiveRowGoneBeforeTheReadAsksTheListingAgain pins the third
// case: the listing resolved the name to a LIVE row, and the value read then
// found that secret in deletion. That settles the secret, not the name, since
// a second live row can hold it, so the listing is asked again; a tombstone
// row would have been offered only after no live row was found, and needs no
// second look (TestGetSecretRevokedNameOnACacheMissListsOnce).
func TestGetSecretLiveRowGoneBeforeTheReadAsksTheListingAgain(t *testing.T) {
	const (
		firstID  = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"
		secondID = "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
	)
	newMock := func(afterFirstListing ...NcloudSecretListItem) *countingMockClient {
		mock := &countingMockClient{
			getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
				if secretID == firstID {
					return nil, fmt.Errorf("%w: deletion requested", ErrInvalidStatus)
				}
				return newSecretValueResponse("second"), nil
			},
			getSecretDetailFn: detailWithStatus(secretStatusRevoke),
		}
		mock.listFn = func(ctx context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			if mock.listCalls == 1 {
				return listingWith(NcloudSecretListItem{SecretID: firstID, SecretName: "db-cred", SecretStatus: secretStatusEnable})(ctx, pageNo)
			}
			return listingWith(afterFirstListing...)(ctx, pageNo)
		}
		return mock
	}

	t.Run("a second live row keeps the name", func(t *testing.T) {
		mock := newMock(
			NcloudSecretListItem{SecretID: firstID, SecretName: "db-cred", SecretStatus: secretStatusRevoke},
			NcloudSecretListItem{SecretID: secondID, SecretName: "db-cred", SecretStatus: secretStatusEnable},
		)
		client := newMockedClient(mock)

		got, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
		if err != nil {
			t.Fatalf("GetSecret() error = %v, want the second live secret's value", err)
		}
		if string(got) != "second" {
			t.Errorf("GetSecret() = %q, want second", got)
		}
		if mock.listCalls != 2 {
			t.Errorf("ListSecrets calls = %d, want 2 (the resolution, then the listing asked again)", mock.listCalls)
		}
		if id, found, negative := client.cache.Get("db-cred"); !found || negative || id != secondID {
			t.Errorf("cache = (%q, %v, %v), want the live mapping to %s, not a tombstone", id, found, negative, secondID)
		}
	})

	t.Run("the listing agrees the name is gone", func(t *testing.T) {
		mock := newMock(NcloudSecretListItem{SecretID: firstID, SecretName: "db-cred", SecretStatus: secretStatusRevoke})
		client := newMockedClient(mock)

		_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
		if !errors.Is(err, esv1.NoSecretErr) {
			t.Fatalf("GetSecret() error = %v, want NoSecretErr", err)
		}
		if mock.listCalls != 2 {
			t.Errorf("ListSecrets calls = %d, want 2", mock.listCalls)
		}
		if id, found, negative := client.cache.Get("db-cred"); !found || !negative || id != firstID {
			t.Errorf("cache = (%q, %v, %v), want a tombstone for %s", id, found, negative, firstID)
		}
	})
}

// TestListingAbsenceDoesNotOverruleACreateThatLandedMeanwhile pins the write
// sequence rule of the shared cache: a sweep that began before a create in
// this process cannot have seen the secret, so its absence verdict must not
// replace the create's mapping, which would answer every read as absent for
// the negative TTL.
func TestListingAbsenceDoesNotOverruleACreateThatLandedMeanwhile(t *testing.T) {
	const id = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
	var client *Client
	mock := &countingMockClient{
		getSecretValueFn: func(context.Context, string) (*NcloudSecretValueResponse, error) {
			return newSecretValueResponse("fresh"), nil
		},
	}
	mock.listFn = func(ctx context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
		// The server computed this page before the create; the create's
		// cache write lands while the page is in flight.
		client.cache.Set("db-cred", id)
		return listingWith()(ctx, pageNo)
	}
	client = newMockedClient(mock)

	if _, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"}); !errors.Is(err, esv1.NoSecretErr) {
		t.Fatalf("GetSecret() error = %v, want NoSecretErr from the sweep that found nothing", err)
	}
	if got, found, negative := client.cache.Get("db-cred"); !found || negative || got != id {
		t.Fatalf("cache = (%q, %v, %v), want the create's mapping to %s kept", got, found, negative, id)
	}
	got, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
	if err != nil || string(got) != "fresh" {
		t.Errorf("GetSecret() = %q, %v; want fresh from the kept mapping", got, err)
	}
	if mock.listCalls != 1 {
		t.Errorf("ListSecrets calls = %d, want 1", mock.listCalls)
	}

	// The other direction still holds: a mapping older than the sweep is
	// what a cache-bypassing sweep went to check, and its absence verdict
	// replaces it.
	stale := &countingMockClient{listFn: listingWith()}
	client = newMockedClient(stale)
	client.cache.Set("db-cred", id)
	if _, err := client.resolveSecretIDFromListing(context.Background(), "db-cred"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("resolveSecretIDFromListing() error = %v, want ErrSecretNotFound", err)
	}
	if _, found, negative := client.cache.Get("db-cred"); !found || !negative {
		t.Errorf("cache kept a mapping older than the sweep that found the name absent")
	}
}

// TestGetSecretOnAPausedSecretNamesTheState pins that a read refused because
// the secret is DISABLE says so, as the write path does, instead of handing
// the operator a bare 409.
func TestGetSecretOnAPausedSecretNamesTheState(t *testing.T) {
	const id = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"
	mock := &countingMockClient{
		listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusEnable}),
		getSecretValueFn: func(context.Context, string) (*NcloudSecretValueResponse, error) {
			return nil, newAPIError(ErrInvalidStatus, http.StatusConflict, "501002")
		},
		getSecretDetailFn: detailWithStatus(secretStatusDisable),
	}
	client := newMockedClient(mock)

	_, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
	if !errors.Is(err, ErrInvalidStatus) || errors.Is(err, esv1.NoSecretErr) {
		t.Fatalf("GetSecret() error = %v, want the refusal, not absence", err)
	}
	if !strings.Contains(err.Error(), "paused (DISABLE)") {
		t.Errorf("GetSecret() error = %q, want it to name the paused state", err)
	}
}
