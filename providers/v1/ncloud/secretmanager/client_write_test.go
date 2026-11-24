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
	"slices"
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/runtime/util/locks"
)

func TestSecretExists(t *testing.T) {
	server, client := setupTestServer(t)
	defer server.Close()

	tests := []struct {
		name     string
		ref      esv1.PushSecretRemoteRef
		wantBool bool
		wantErr  bool
	}{
		{
			name:     "secret exists",
			ref:      mockPushSecretRemoteRef{remoteKey: "test-secret"},
			wantBool: true,
			wantErr:  false,
		},
		{
			name:     "secret does not exist",
			ref:      mockPushSecretRemoteRef{remoteKey: "not-found"},
			wantBool: false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exists, err := client.SecretExists(context.Background(), tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("SecretExists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if exists != tt.wantBool {
				t.Errorf("SecretExists() = %v, want %v", exists, tt.wantBool)
			}
		})
	}
}

func TestSecretExistsPropertyUsesExactTopLevelKey(t *testing.T) {
	const id = "abababababababababababababababababababababababababababababababab"
	newClient := func(valueFn func(context.Context, string) (*NcloudSecretValueResponse, error)) *Client {
		return newMockedClient(&countingMockClient{
			listFn:            listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
			getSecretDetailFn: detailWithStatus(secretStatusEnable),
			getSecretValueFn:  valueFn,
		})
	}

	for _, tc := range []struct {
		name     string
		property string
		want     bool
	}{
		{name: "literal top-level property exists", property: "literal", want: true},
		{name: "nested path is not a PushSecret property", property: "db.host", want: false},
		{name: "missing property", property: "absent", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newClient(func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(`{"literal":"v","db":{"host":"nested"}}`), nil
			})
			got, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{
				remoteKey: "db-cred",
				property:  tc.property,
			})
			if err != nil {
				t.Fatalf("SecretExists() error = %v", err)
			}
			if got != tc.want {
				t.Errorf("SecretExists(property=%q) = %v, want %v", tc.property, got, tc.want)
			}
		})
	}

	t.Run("Forbidden fails closed", func(t *testing.T) {
		client := newClient(func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return nil, fmt.Errorf("%w: active value is unreadable", ErrForbidden)
		})
		got, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{
			remoteKey: "db-cred",
			property:  "literal",
		})
		if got || !errors.Is(err, ErrForbidden) {
			t.Fatalf("SecretExists() = (%v, %v), want (false, ErrForbidden)", got, err)
		}
	})

	t.Run("value NotFound is absent", func(t *testing.T) {
		client := newClient(func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return nil, fmt.Errorf("%w: deleted after listing", ErrSecretNotFound)
		})
		got, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{
			remoteKey: "db-cred",
			property:  "literal",
		})
		if err != nil || got {
			t.Fatalf("SecretExists() = (%v, %v), want (false, nil)", got, err)
		}
	})

	t.Run("empty active value fails closed", func(t *testing.T) {
		client := newClient(func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return newSecretValueResponse(""), nil
		})
		got, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{
			remoteKey: "db-cred",
			property:  "literal",
		})
		if got || !errors.Is(err, ErrEmptySecretData) {
			t.Fatalf("SecretExists() = (%v, %v), want (false, ErrEmptySecretData)", got, err)
		}
	})

	t.Run("non-object active value fails closed", func(t *testing.T) {
		client := newClient(func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return newSecretValueResponse(`"scalar"`), nil
		})
		got, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{
			remoteKey: "db-cred",
			property:  "literal",
		})
		if got || !errors.Is(err, errSecretValueNotObject) {
			t.Fatalf("SecretExists() = (%v, %v), want (false, object error)", got, err)
		}
	})
}

func TestSecretExistsNameReportsDestroyedAbsent(t *testing.T) {
	const id = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	mock := &countingMockClient{
		listFn:            listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
		getSecretDetailFn: detailWithStatus(secretStatusDestroyed),
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			t.Fatal("destroyed secret must not have its value fetched")
			return nil, nil
		},
	}
	client := newMockedClient(mock)

	got, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
	if err != nil || got {
		t.Fatalf("SecretExists() = (%v, %v), want (false, nil)", got, err)
	}
}

func TestPushSecretDestroyedTombstoneCreatesReplacement(t *testing.T) {
	const (
		remoteName    = "db-cred"
		tombstoneID   = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
		replacementID = "dededededededededededededededededededededededededededededededede"
	)
	mock := &countingMockClient{
		listFn: listingWith(NcloudSecretListItem{
			SecretID: tombstoneID, SecretName: remoteName, SecretStatus: secretStatusDestroyed,
		}),
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			t.Fatalf("GetSecretValue(%q) called for a destroyed tombstone", secretID)
			return nil, nil
		},
		createFn: func(_ context.Context, req *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
			if req.SecretName != remoteName {
				t.Errorf("CreateSecret name = %q, want %s", req.SecretName, remoteName)
			}
			return &NcloudSecretDetailResponse{
				Code: successCode,
				Data: NcloudSecretDetailData{SecretID: replacementID},
			}, nil
		},
	}
	client := newMockedClient(mock)

	err := client.PushSecret(
		context.Background(),
		&corev1.Secret{Data: map[string][]byte{"password": []byte("v")}},
		mockPushSecretData{remoteKey: remoteName, secretKey: "password"},
	)
	if err != nil {
		t.Fatalf("PushSecret() error = %v", err)
	}
	if mock.createCalls != 1 || mock.getSecretValueCalls != 0 {
		t.Errorf("calls: create=%d getValue=%d; want 1,0", mock.createCalls, mock.getSecretValueCalls)
	}
	if id, found, negative := client.cache.Get(remoteName); !found || negative || id != replacementID {
		t.Errorf("cache = (%q, %v, %v), want replacement ID", id, found, negative)
	}
}

func TestPushSecretDestroyedDuplicatePrefersLive(t *testing.T) {
	const (
		tombstoneID = "abababababababababababababababababababababababababababababababab"
		liveID      = "bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc"
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
			return newSecretValueResponse(`{"password":"v"}`), nil
		},
		createFn: func(_ context.Context, _ *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
			t.Fatal("live duplicate must be updated instead of creating")
			return nil, nil
		},
	}
	client := newMockedClient(mock)

	err := client.PushSecret(
		context.Background(),
		&corev1.Secret{Data: map[string][]byte{"password": []byte("v")}},
		mockPushSecretData{remoteKey: "db-cred", secretKey: "password"},
	)
	if err != nil {
		t.Fatalf("PushSecret() error = %v", err)
	}
	if mock.createCalls != 0 || mock.getSecretValueCalls != 1 {
		t.Errorf("calls: create=%d getValue=%d; want 0,1", mock.createCalls, mock.getSecretValueCalls)
	}
	if id, found, negative := client.cache.Get("db-cred"); !found || negative || id != liveID {
		t.Errorf("cache = (%q, %v, %v), want live ID", id, found, negative)
	}
}

func TestSecretExistsDestroyedThenPushRecovers(t *testing.T) {
	const (
		tombstoneID   = "1212121212121212121212121212121212121212121212121212121212121212"
		replacementID = "3434343434343434343434343434343434343434343434343434343434343434"
	)
	listCalls := 0
	mock := &countingMockClient{
		listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
			listCalls++
			status := ""
			if listCalls > 1 {
				status = secretStatusDestroyed
			}
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 1,
					SecretList: []NcloudSecretListItem{{
						SecretID: tombstoneID, SecretName: "db-cred", SecretStatus: status,
					}},
				},
			}, nil
		},
		getSecretDetailFn: detailWithStatus(secretStatusDestroyed),
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			t.Fatalf("GetSecretValue(%q) called for destroyed secret", secretID)
			return nil, nil
		},
		createFn: func(_ context.Context, _ *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
			return &NcloudSecretDetailResponse{
				Code: successCode,
				Data: NcloudSecretDetailData{SecretID: replacementID},
			}, nil
		},
	}
	client := newMockedClient(mock)

	exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
	if err != nil || exists {
		t.Fatalf("SecretExists() = (%v, %v), want (false, nil)", exists, err)
	}
	if id, found, negative := client.cache.Get("db-cred"); found && !negative {
		t.Fatalf("SecretExists left destroyed mapping cached: %q", id)
	}

	err = client.PushSecret(
		context.Background(),
		&corev1.Secret{Data: map[string][]byte{"password": []byte("v")}},
		mockPushSecretData{remoteKey: "db-cred", secretKey: "password"},
	)
	if err != nil {
		t.Fatalf("PushSecret() after SecretExists error = %v", err)
	}
	if mock.createCalls != 1 || mock.getSecretValueCalls != 0 {
		t.Errorf("calls: create=%d getValue=%d; want 1,0", mock.createCalls, mock.getSecretValueCalls)
	}
}

func TestPushSecret(t *testing.T) {
	const existingID = "1111111111111111111111111111111111111111111111111111111111111111"
	k8sSecret := &corev1.Secret{Data: map[string][]byte{
		"password": []byte("s3cr3t"),
		"username": []byte("admin"),
	}}

	t.Run("creates missing secret with safe defaults", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(),
			createFn: func(_ context.Context, req *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
				if req.SecretName != "db-cred" {
					t.Errorf("CreateSecret name = %q, want db-cred", req.SecretName)
				}
				if req.SecretValue.Value != `{"password":"s3cr3t"}` {
					t.Errorf("CreateSecret value = %q, want selected key wrapped as a JSON object", req.SecretValue.Value)
				}
				if len(req.SecretValue.RotationTargets) != 1 || req.SecretValue.RotationTargets[0] != "password" {
					t.Errorf("RotationTargets = %v, want [password]", req.SecretValue.RotationTargets)
				}
				if req.SecretType != "BASIC" || req.AutoRotationYN != "N" || req.ProtectionKeyType != "DEFAULT" {
					t.Errorf("unexpected defaults: %+v", req)
				}
				return &NcloudSecretDetailResponse{Code: successCode, Data: NcloudSecretDetailData{SecretID: existingID}}, nil
			},
		}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "password"})
		if err != nil {
			t.Fatalf("PushSecret() error = %v", err)
		}
		if mock.createCalls != 1 {
			t.Errorf("createCalls = %d, want 1", mock.createCalls)
		}
		if id, found, negative := client.cache.Get("db-cred"); !found || negative || id != existingID {
			t.Errorf("cache not warmed with new ID: id=%q found=%v negative=%v", id, found, negative)
		}
	})

	// The create path wraps the value under the property itself and makes
	// the property the permanent rotation target; the merge into an existing
	// value is a different path, pinned below.
	t.Run("creates a missing secret under the property", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(),
			createFn: func(_ context.Context, req *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
				if req.SecretValue.Value != `{"user":"admin"}` {
					t.Errorf("CreateSecret value = %q, want the selected key's value under the property", req.SecretValue.Value)
				}
				if len(req.SecretValue.RotationTargets) != 1 || req.SecretValue.RotationTargets[0] != "user" {
					t.Errorf("RotationTargets = %v, want [user]: the property is the field this push manages", req.SecretValue.RotationTargets)
				}
				return &NcloudSecretDetailResponse{Code: successCode, Data: NcloudSecretDetailData{SecretID: existingID}}, nil
			},
		}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "username", property: "user"})
		if err != nil {
			t.Fatalf("PushSecret() error = %v", err)
		}
		if mock.createCalls != 1 {
			t.Errorf("createCalls = %d, want 1", mock.createCalls)
		}
	})

	t.Run("updates existing secret's active stage", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse("old-value"), nil
			},
			updateStageFn: func(_ context.Context, secretID, stage, value string) error {
				if secretID != existingID || stage != stageActive || value != `{"password":"s3cr3t"}` {
					t.Errorf("UpdateSecretStageValue(%q, %q, %q), want (%q, active, selected-key object)", secretID, stage, value, existingID)
				}
				return nil
			},
		}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "password"})
		if err != nil {
			t.Fatalf("PushSecret() error = %v", err)
		}
		if mock.updateStageCalls != 1 || mock.createCalls != 0 {
			t.Errorf("updateStageCalls = %d, createCalls = %d; want 1, 0", mock.updateStageCalls, mock.createCalls)
		}
	})

	t.Run("skips the write when the value is unchanged", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(`{"password":"s3cr3t"}`), nil
			},
		}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "password"})
		if err != nil {
			t.Fatalf("PushSecret() error = %v", err)
		}
		if mock.updateStageCalls != 0 {
			t.Errorf("updateStageCalls = %d, want 0 (no-op push)", mock.updateStageCalls)
		}
	})

	t.Run("whole secret marshals Data as a JSON object", func(t *testing.T) {
		var pushed string
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse("old"), nil
			},
			updateStageFn: func(_ context.Context, _, _, value string) error {
				pushed = value
				return nil
			},
		}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred"})
		if err != nil {
			t.Fatalf("PushSecret() error = %v", err)
		}
		want := `{"password":"s3cr3t","username":"admin"}`
		if pushed != want {
			t.Errorf("pushed = %s, want %s", pushed, want)
		}
	})

	t.Run("merges property into the existing JSON object", func(t *testing.T) {
		var pushed string
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(`{"host":"db.example.com"}`), nil
			},
			updateStageFn: func(_ context.Context, _, _, value string) error {
				pushed = value
				return nil
			},
		}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "username", property: "user"})
		if err != nil {
			t.Fatalf("PushSecret() error = %v", err)
		}
		want := `{"host":"db.example.com","user":"admin"}`
		if pushed != want {
			t.Errorf("pushed = %s, want %s", pushed, want)
		}
	})

	t.Run("property push into a non-object value fails", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse("plain-text"), nil
			},
		}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "username", property: "user"})
		if err == nil || !strings.Contains(err.Error(), "not a JSON object") {
			t.Fatalf("PushSecret() error = %v, want non-object rejection", err)
		}
		if mock.updateStageCalls != 0 {
			t.Errorf("updateStageCalls = %d, want 0", mock.updateStageCalls)
		}
	})

	t.Run("rejects a name the API would refuse", func(t *testing.T) {
		mock := &countingMockClient{}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "no", secretKey: "password"})
		if err == nil || !strings.Contains(err.Error(), "invalid secret name") {
			t.Fatalf("PushSecret() error = %v, want invalid-name rejection", err)
		}
		if mock.createCalls != 0 {
			t.Errorf("createCalls = %d, want 0", mock.createCalls)
		}
		if mock.listCalls != 0 {
			t.Errorf("listCalls = %d, want 0", mock.listCalls)
		}
	})

	t.Run("cuts a long refused name short in the error", func(t *testing.T) {
		client := newMockedClient(&countingMockClient{})

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: strings.Repeat("x", 4096), secretKey: "password"})
		if err == nil || !strings.Contains(err.Error(), "invalid secret name") {
			t.Fatalf("PushSecret() error = %.80v, want invalid-name rejection", err)
		}
		if got := len(err.Error()); got > 300 {
			t.Errorf("PushSecret() error is %d bytes; the manifest's key must be cut short", got)
		}
	})

	t.Run("ID-shaped key updates the secret addressed by ID", func(t *testing.T) {
		mock := &countingMockClient{
			getSecretDetailFn: detailWithStatus(secretStatusEnable),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse("old"), nil
			},
			updateStageFn: func(_ context.Context, secretID, _, _ string) error {
				if secretID != existingID {
					t.Errorf("update addressed %q, want %q", secretID, existingID)
				}
				return nil
			},
		}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: existingID, secretKey: "password"})
		if err != nil {
			t.Fatalf("PushSecret() error = %v", err)
		}
		if mock.updateStageCalls != 1 || mock.createCalls != 0 {
			t.Errorf("updateStageCalls = %d, createCalls = %d; want 1, 0", mock.updateStageCalls, mock.createCalls)
		}
		if mock.getSecretDetailCalls != 1 {
			t.Errorf("getSecretDetailCalls = %d, want 1 (the ownership gate doubles as the direct-ID probe)", mock.getSecretDetailCalls)
		}
		if mock.listCalls != 0 {
			t.Errorf("listCalls = %d, want 0", mock.listCalls)
		}
	})

	// TestWriteOwnershipGuard covers the name path; an ID addresses a secret
	// past the listing, so the guard has to hold on this path on its own.
	t.Run("ID-shaped key refuses a secret it does not manage", func(t *testing.T) {
		mock := &countingMockClient{
			getSecretDetailFn: unmanagedDetail(secretStatusEnable),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse("old"), nil
			},
		}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: existingID, secretKey: "password"})
		if !errors.Is(err, ErrNotManagedByESO) {
			t.Fatalf("PushSecret() error = %v, want ErrNotManagedByESO", err)
		}
		if mock.updateStageCalls != 0 || mock.getSecretValueCalls != 0 || mock.createCalls != 0 {
			t.Errorf("an unmanaged secret was touched: update=%d valueReads=%d create=%d",
				mock.updateStageCalls, mock.getSecretValueCalls, mock.createCalls)
		}
	})

	t.Run("absent ID-shaped key fails without listing or mutation", func(t *testing.T) {
		mock := &countingMockClient{
			getSecretDetailFn: func(_ context.Context, _ string) (*NcloudSecretDetailResponse, error) {
				return nil, fmt.Errorf("%w: absent direct ID", ErrSecretNotFound)
			},
		}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{
			remoteKey: existingID,
			secretKey: "password",
		})
		if err == nil || !strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "invalid secret name") {
			t.Fatalf("PushSecret() error = %v, want an ID-not-found error, not the name rule", err)
		}
		if mock.getSecretDetailCalls != 1 {
			t.Errorf("getSecretDetailCalls = %d, want 1", mock.getSecretDetailCalls)
		}
		if mock.listCalls != 0 || mock.createCalls != 0 || mock.getSecretValueCalls != 0 || mock.updateStageCalls != 0 {
			t.Errorf("unexpected calls after absent ID: list=%d create=%d value=%d update=%d",
				mock.listCalls, mock.createCalls, mock.getSecretValueCalls, mock.updateStageCalls)
		}
		if _, found, _ := client.cache.Get(existingID); found {
			t.Error("absent direct ID was cached")
		}
	})

	t.Run("direct ID update NotFound has no create fallback", func(t *testing.T) {
		mock := &countingMockClient{
			getSecretDetailFn: detailWithStatus(secretStatusEnable),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return nil, fmt.Errorf("%w: destroyed before update", ErrSecretNotFound)
			},
		}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{
			remoteKey: existingID,
			secretKey: "password",
		})
		if !errors.Is(err, ErrSecretNotFound) {
			t.Fatalf("PushSecret() error = %v, want ErrSecretNotFound", err)
		}
		if mock.listCalls != 0 || mock.createCalls != 0 || mock.updateStageCalls != 0 {
			t.Errorf("unexpected fallback after update-time NotFound: list=%d create=%d update=%d",
				mock.listCalls, mock.createCalls, mock.updateStageCalls)
		}
	})

	t.Run("direct ID detail failures fail closed", func(t *testing.T) {
		detailErr := errors.New("detail unavailable")
		tests := []struct {
			name    string
			detail  *NcloudSecretDetailResponse
			err     error
			wantErr error
		}{
			{name: "nil detail", wantErr: errEmptySecretDetail},
			{name: "detail error", err: detailErr, wantErr: detailErr},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				mock := &countingMockClient{
					getSecretDetailFn: func(_ context.Context, _ string) (*NcloudSecretDetailResponse, error) {
						return tt.detail, tt.err
					},
				}
				client := newMockedClient(mock)

				err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{
					remoteKey: existingID,
					secretKey: "password",
				})
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("PushSecret() error = %v, want %v", err, tt.wantErr)
				}
				if mock.getSecretDetailCalls != 1 {
					t.Errorf("getSecretDetailCalls = %d, want 1", mock.getSecretDetailCalls)
				}
				if mock.listCalls != 0 || mock.createCalls != 0 || mock.getSecretValueCalls != 0 || mock.updateStageCalls != 0 {
					t.Errorf("unexpected calls after detail failure: list=%d create=%d value=%d update=%d",
						mock.listCalls, mock.createCalls, mock.getSecretValueCalls, mock.updateStageCalls)
				}
			})
		}
	})

	t.Run("push metadata is rejected loudly", func(t *testing.T) {
		client := newMockedClient(&countingMockClient{})

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{
			remoteKey: "db-cred",
			metadata:  &apiextensionsv1.JSON{Raw: []byte(`{"memo":"x"}`)},
		})
		if !errors.Is(err, ErrPushMetadataNotSupported) {
			t.Fatalf("PushSecret() error = %v, want ErrPushMetadataNotSupported", err)
		}
	})

	t.Run("missing secretKey fails before any API call", func(t *testing.T) {
		mock := &countingMockClient{}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "nope"})
		if err == nil || !strings.Contains(err.Error(), "not found in the Kubernetes secret") {
			t.Fatalf("PushSecret() error = %v, want missing-key rejection", err)
		}
		if mock.listCalls != 0 || mock.createCalls != 0 {
			t.Errorf("API reached despite invalid input: list=%d create=%d", mock.listCalls, mock.createCalls)
		}
	})

	t.Run("whole Data create has sorted nonempty rotation targets", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(),
			createFn: func(_ context.Context, req *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
				if req.SecretValue.Value != `{"password":"s3cr3t","username":"admin"}` {
					t.Errorf("CreateSecret value = %q, want string-valued Data object", req.SecretValue.Value)
				}
				gotTargets := strings.Join(req.SecretValue.RotationTargets, ",")
				if gotTargets != "password,username" {
					t.Errorf("RotationTargets = %v, want sorted [password username]", req.SecretValue.RotationTargets)
				}
				return &NcloudSecretDetailResponse{
					Code: successCode,
					Data: NcloudSecretDetailData{SecretID: existingID},
				}, nil
			},
		}
		client := newMockedClient(mock)

		if err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "all-data"}); err != nil {
			t.Fatalf("PushSecret() error = %v", err)
		}
	})

	// Storing the whole Data map under one property would write a nested
	// object, and Ncloud accepts only values whose leaves are all strings.
	// The request can never succeed, so it is refused locally with an
	// actionable message before any API call.
	t.Run("whole Data under a property is refused before any API call", func(t *testing.T) {
		mock := &countingMockClient{}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{
			remoteKey: "db-cred",
			property:  "bundle",
		})
		if !errors.Is(err, ErrPushWholeDataUnderProperty) {
			t.Fatalf("PushSecret() error = %v, want ErrPushWholeDataUnderProperty", err)
		}
		if mock.listCalls != 0 || mock.createCalls != 0 || mock.updateStageCalls != 0 ||
			mock.getSecretValueCalls != 0 || mock.getSecretDetailCalls != 0 {
			t.Errorf("API reached for an unsatisfiable push: list=%d create=%d update=%d value=%d detail=%d",
				mock.listCalls, mock.createCalls, mock.updateStageCalls,
				mock.getSecretValueCalls, mock.getSecretDetailCalls)
		}
	})

	t.Run("selected JSON-looking bytes stay a JSON string under property", func(t *testing.T) {
		secret := &corev1.Secret{Data: map[string][]byte{"flag": []byte("true")}}
		var pushed string
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(`{"sibling":"keep"}`), nil
			},
			updateStageFn: func(_ context.Context, _, _, value string) error {
				pushed = value
				return nil
			},
		}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), secret, mockPushSecretData{
			remoteKey: "db-cred",
			secretKey: "flag",
			property:  "enabled",
		})
		if err != nil {
			t.Fatalf("PushSecret() error = %v", err)
		}
		if pushed != `{"enabled":"true","sibling":"keep"}` {
			t.Errorf("pushed = %s, want JSON-looking input encoded as a string", pushed)
		}
	})

	t.Run("empty Data fails before any API call", func(t *testing.T) {
		mock := &countingMockClient{}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), &corev1.Secret{}, mockPushSecretData{remoteKey: "db-cred"})
		if !errors.Is(err, errPushEmptyData) {
			t.Fatalf("PushSecret() error = %v, want errPushEmptyData", err)
		}
		if mock.listCalls != 0 || mock.createCalls != 0 || mock.updateStageCalls != 0 {
			t.Errorf("API reached despite empty Data: list=%d create=%d update=%d", mock.listCalls, mock.createCalls, mock.updateStageCalls)
		}
	})

	t.Run("whole Data with an empty key fails before any API call", func(t *testing.T) {
		// Only the no-property form reaches this check: with a property set,
		// the push is refused earlier as unsatisfiable regardless of the data
		// (see the whole-Data-under-a-property case above).
		tests := []struct {
			name     string
			property string
		}{
			{name: "without property"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				secret := &corev1.Secret{Data: map[string][]byte{
					"":      []byte("sensitive"),
					"valid": []byte("value"),
				}}
				mock := &countingMockClient{}
				client := newMockedClient(mock)

				err := client.PushSecret(context.Background(), secret, mockPushSecretData{
					remoteKey: "db-cred",
					property:  tt.property,
				})
				if !errors.Is(err, errPushEmptyDataKey) {
					t.Fatalf("PushSecret() error = %v, want errPushEmptyDataKey", err)
				}

				calls := []struct {
					name string
					got  int
				}{
					{name: "ListSecrets", got: mock.listCalls},
					{name: "GetSecretValue", got: mock.getSecretValueCalls},
					{name: "GetSecretDetail", got: mock.getSecretDetailCalls},
					{name: "CreateSecret", got: mock.createCalls},
					{name: "UpdateSecretStageValue", got: mock.updateStageCalls},
					{name: "RequestSecretDeletion", got: mock.requestDeletionCalls},
					{name: "DestroySecret", got: mock.destroyCalls},
				}
				for _, call := range calls {
					if call.got != 0 {
						t.Errorf("%s calls = %d, want 0", call.name, call.got)
					}
				}
			})
		}
	})

	t.Run("invalid UTF-8 fails before API without leaking bytes", func(t *testing.T) {
		const marker = "SENSITIVE"
		secret := &corev1.Secret{Data: map[string][]byte{
			"selected": append([]byte{0xff}, marker...),
		}}
		mock := &countingMockClient{}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), secret, mockPushSecretData{
			remoteKey: "db-cred",
			secretKey: "selected",
		})
		if !errors.Is(err, errPushInvalidUTF8) {
			t.Fatalf("PushSecret() error = %v, want errPushInvalidUTF8", err)
		}
		if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "\xff") {
			t.Errorf("error leaked invalid secret bytes: %q", err)
		}
		if mock.listCalls != 0 || mock.createCalls != 0 || mock.updateStageCalls != 0 {
			t.Errorf("API reached despite invalid UTF-8: list=%d create=%d update=%d", mock.listCalls, mock.createCalls, mock.updateStageCalls)
		}
	})

	t.Run("selected key ignores invalid bytes in unrelated Data", func(t *testing.T) {
		secret := &corev1.Secret{Data: map[string][]byte{
			"selected": []byte("safe"),
			"unused":   {0xff},
		}}
		mock := &countingMockClient{
			listFn: listingWith(),
			createFn: func(_ context.Context, req *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
				if req.SecretValue.Value != `{"selected":"safe"}` {
					t.Errorf("CreateSecret value = %q, want selected key only", req.SecretValue.Value)
				}
				return &NcloudSecretDetailResponse{
					Code: successCode,
					Data: NcloudSecretDetailData{SecretID: existingID},
				}, nil
			},
		}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), secret, mockPushSecretData{
			remoteKey: "db-cred",
			secretKey: "selected",
		})
		if err != nil {
			t.Fatalf("PushSecret() error = %v", err)
		}
	})

	t.Run("whole Data rejects any invalid UTF-8 entry before API", func(t *testing.T) {
		secret := &corev1.Secret{Data: map[string][]byte{
			"safe":    []byte("value"),
			"invalid": {0xff},
		}}
		mock := &countingMockClient{}
		client := newMockedClient(mock)

		err := client.PushSecret(context.Background(), secret, mockPushSecretData{remoteKey: "db-cred"})
		if !errors.Is(err, errPushInvalidUTF8) {
			t.Fatalf("PushSecret() error = %v, want errPushInvalidUTF8", err)
		}
		if mock.listCalls != 0 {
			t.Errorf("ListSecrets calls = %d, want 0", mock.listCalls)
		}
	})
}

func TestPushSecretPreservesConfiguredRotationTargets(t *testing.T) {
	const id = "4545454545454545454545454545454545454545454545454545454545454545"

	// Ncloud fixes rotation targets when the secret is created and rejects any
	// value that omits one, on the create and the update path alike, with
	// rotation on or off. The provider refuses locally instead of forwarding
	// that request, and decides without a detail read, so the ownership gate
	// accounts for the only one.
	for _, rotation := range []struct{ autoRotationYN, name string }{
		{"N", "disabled"},
		{"Y", "enabled"},
		{"", "unknown"},
	} {
		t.Run("whole Data replacement cannot remove a target when rotation is "+rotation.name, func(t *testing.T) {
			mock := &countingMockClient{
				listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
				getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
					resp := newSecretValueResponse(`{"a":"old-a","b":"old-b"}`)
					resp.Data.RotationTargets = []string{"a", "b"}
					return resp, nil
				},
				getSecretDetailFn: detailWithRotation(secretStatusEnable, rotation.autoRotationYN),
				updateStageFn: func(_ context.Context, _, _, value string) error {
					t.Errorf("UpdateSecretStageValue(%s) called; a target-dropping write must not reach Ncloud", value)
					return nil
				},
			}
			client := newMockedClient(mock)

			source := &corev1.Secret{Data: map[string][]byte{"a": []byte("new-a")}}
			err := client.PushSecret(context.Background(), source, mockPushSecretData{
				remoteKey: "db-cred",
			})
			if !errors.Is(err, errRotationTargetAbsent) {
				t.Fatalf("PushSecret() error = %v, want errRotationTargetAbsent", err)
			}
			if mock.getSecretDetailCalls != 1 || mock.updateStageCalls != 0 {
				t.Errorf("calls detail=%d update=%d, want 1,0 (ownership gate only)", mock.getSecretDetailCalls, mock.updateStageCalls)
			}
		})

		t.Run("selected-key replacement cannot remove a target when rotation is "+rotation.name, func(t *testing.T) {
			mock := &countingMockClient{
				listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
				getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
					resp := newSecretValueResponse(`{"password":"old-password","username":"old-user"}`)
					resp.Data.RotationTargets = []string{"password"}
					return resp, nil
				},
				getSecretDetailFn: detailWithRotation(secretStatusEnable, rotation.autoRotationYN),
				updateStageFn: func(_ context.Context, _, _, value string) error {
					t.Errorf("UpdateSecretStageValue(%s) called; a target-dropping write must not reach Ncloud", value)
					return nil
				},
			}
			client := newMockedClient(mock)

			source := &corev1.Secret{Data: map[string][]byte{"username": []byte("new-user")}}
			err := client.PushSecret(context.Background(), source, mockPushSecretData{
				remoteKey: "db-cred",
				secretKey: "username",
			})
			if !errors.Is(err, errRotationTargetAbsent) {
				t.Fatalf("PushSecret() error = %v, want errRotationTargetAbsent", err)
			}
			if mock.getSecretDetailCalls != 1 || mock.updateStageCalls != 0 {
				t.Errorf("calls detail=%d update=%d, want 1,0 (ownership gate only)", mock.getSecretDetailCalls, mock.updateStageCalls)
			}
		})
	}

	t.Run("preserved targets avoid detail lookup", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				resp := newSecretValueResponse(`{"password":"old-password","username":"old-user"}`)
				resp.Data.RotationTargets = []string{"password"}
				return resp, nil
			},
			updateStageFn: func(_ context.Context, _, _, value string) error {
				if value != `{"password":"old-password","username":"new-user"}` {
					t.Errorf("updated value = %s, want target-preserving object", value)
				}
				return nil
			},
		}
		client := newMockedClient(mock)
		source := &corev1.Secret{Data: map[string][]byte{"username": []byte("new-user")}}

		if err := client.PushSecret(context.Background(), source, mockPushSecretData{
			remoteKey: "db-cred",
			secretKey: "username",
			property:  "username",
		}); err != nil {
			t.Fatalf("PushSecret() error = %v", err)
		}
		if mock.getSecretDetailCalls != 1 || mock.updateStageCalls != 1 {
			t.Errorf("calls detail=%d update=%d, want 1,1 (ownership gate only; no rotation lookup)", mock.getSecretDetailCalls, mock.updateStageCalls)
		}
	})
}

func TestDeleteSecret(t *testing.T) {
	const existingID = "2222222222222222222222222222222222222222222222222222222222222222"

	t.Run("requests deletion and stops at REVOKE for ENABLE", func(t *testing.T) {
		mock := &countingMockClient{
			listFn:            listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretDetailFn: detailWithStatus(secretStatusEnable),
			requestDeletionFn: func(_ context.Context, secretID string) error {
				if secretID != existingID {
					t.Errorf("RequestSecretDeletion(%q), want %q", secretID, existingID)
				}
				return nil
			},
			destroyFn: func(_ context.Context, secretID string) error {
				t.Errorf("DestroySecret(%q) called without ForceDeleteWithoutRecovery", secretID)
				return nil
			},
		}
		client := newMockedClient(mock)
		client.cache.Set("db-cred", existingID)

		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"}); err != nil {
			t.Fatalf("DeleteSecret() error = %v", err)
		}
		if mock.requestDeletionCalls != 1 || mock.destroyCalls != 0 {
			t.Errorf("requestDeletionCalls = %d, destroyCalls = %d; want 1, 0", mock.requestDeletionCalls, mock.destroyCalls)
		}
		// The listing rewarms the cache during resolution, so assert on the
		// post-delete invalidation rather than absence at some earlier point.
		if _, found, _ := client.cache.Get("db-cred"); found {
			t.Error("cache entry should be invalidated after deletion")
		}
	})

	t.Run("force mode requests deletion then destroys for ENABLE", func(t *testing.T) {
		mock := &countingMockClient{
			listFn:            listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretDetailFn: detailWithStatus(secretStatusEnable),
			requestDeletionFn: func(_ context.Context, secretID string) error {
				if secretID != existingID {
					t.Errorf("RequestSecretDeletion(%q), want %q", secretID, existingID)
				}
				return nil
			},
			destroyFn: func(_ context.Context, secretID string) error {
				if secretID != existingID {
					t.Errorf("DestroySecret(%q), want %q", secretID, existingID)
				}
				return nil
			},
		}
		client := newForceMockedClient(mock)
		client.cache.Set("db-cred", existingID)

		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"}); err != nil {
			t.Fatalf("DeleteSecret() error = %v", err)
		}
		if mock.requestDeletionCalls != 1 || mock.destroyCalls != 1 {
			t.Errorf("requestDeletionCalls = %d, destroyCalls = %d; want 1, 1", mock.requestDeletionCalls, mock.destroyCalls)
		}
		if _, found, _ := client.cache.Get("db-cred"); found {
			t.Error("cache entry should be invalidated after deletion")
		}
	})

	t.Run("REVOKE is acknowledged without another mutation", func(t *testing.T) {
		mock := &countingMockClient{
			listFn:            listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretDetailFn: detailWithStatus(secretStatusRevoke),
			destroyFn: func(_ context.Context, secretID string) error {
				t.Errorf("DestroySecret(%q) called without ForceDeleteWithoutRecovery", secretID)
				return nil
			},
		}
		client := newMockedClient(mock)

		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"}); err != nil {
			t.Fatalf("DeleteSecret() error = %v", err)
		}
		if mock.requestDeletionCalls != 0 || mock.destroyCalls != 0 {
			t.Errorf("requestDeletionCalls = %d, destroyCalls = %d; want 0, 0", mock.requestDeletionCalls, mock.destroyCalls)
		}
	})

	t.Run("force mode REVOKE goes straight to finalization", func(t *testing.T) {
		mock := &countingMockClient{
			listFn:            listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretDetailFn: detailWithStatus(secretStatusRevoke),
			destroyFn:         func(_ context.Context, _ string) error { return nil },
		}
		client := newForceMockedClient(mock)

		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"}); err != nil {
			t.Fatalf("DeleteSecret() error = %v", err)
		}
		if mock.requestDeletionCalls != 0 || mock.destroyCalls != 1 {
			t.Errorf("requestDeletionCalls = %d, destroyCalls = %d; want 0, 1", mock.requestDeletionCalls, mock.destroyCalls)
		}
	})

	t.Run("DESTROYED is a no-op", func(t *testing.T) {
		mock := &countingMockClient{
			listFn:            listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretDetailFn: detailWithStatus(secretStatusDestroyed),
		}
		client := newMockedClient(mock)

		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"}); err != nil {
			t.Fatalf("DeleteSecret() error = %v", err)
		}
		if mock.requestDeletionCalls != 0 || mock.destroyCalls != 0 {
			t.Errorf("no mutation expected for DESTROYED: request=%d delete=%d", mock.requestDeletionCalls, mock.destroyCalls)
		}
	})

	t.Run("missing secret deletes idempotently", func(t *testing.T) {
		mock := &countingMockClient{listFn: listingWith()}
		client := newMockedClient(mock)

		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "already-gone"}); err != nil {
			t.Fatalf("DeleteSecret() error = %v, want nil for missing secret", err)
		}
		if mock.destroyCalls != 0 {
			t.Errorf("destroyCalls = %d, want 0", mock.destroyCalls)
		}
	})

	t.Run("ROTATING cannot be deleted", func(t *testing.T) {
		mock := &countingMockClient{
			listFn:            listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretDetailFn: detailWithStatus("ROTATING"),
		}
		client := newMockedClient(mock)

		err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
		if err == nil || !strings.Contains(err.Error(), "ROTATING") {
			t.Fatalf("DeleteSecret() error = %v, want status rejection", err)
		}
		if mock.destroyCalls != 0 {
			t.Errorf("destroyCalls = %d, want 0", mock.destroyCalls)
		}
	})

	t.Run("ID-shaped key is addressed directly without a listing sweep", func(t *testing.T) {
		mock := &countingMockClient{
			listFn:            listingWith(), // must not be consulted at all
			getSecretDetailFn: detailWithStatus(secretStatusEnable),
			requestDeletionFn: func(_ context.Context, _ string) error { return nil },
			destroyFn:         func(_ context.Context, _ string) error { return nil },
		}
		client := newMockedClient(mock)

		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: existingID}); err != nil {
			t.Fatalf("DeleteSecret() error = %v", err)
		}
		if mock.requestDeletionCalls != 1 || mock.destroyCalls != 0 {
			t.Errorf("requestDeletionCalls = %d, destroyCalls = %d; want 1, 0", mock.requestDeletionCalls, mock.destroyCalls)
		}
		// Names are 3-15 chars, so a 64-hex key can never resolve by name:
		// the listing sweep would be guaranteed wasted work.
		if mock.listCalls != 0 {
			t.Errorf("listCalls = %d, want 0 (ID-shaped key must skip resolution)", mock.listCalls)
		}
	})

	t.Run("NotFound on finalization is tolerated", func(t *testing.T) {
		mock := &countingMockClient{
			listFn:            listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretDetailFn: detailWithStatus(secretStatusRevoke),
			destroyFn:         func(_ context.Context, _ string) error { return ErrSecretNotFound },
		}
		client := newForceMockedClient(mock)

		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"}); err != nil {
			t.Fatalf("DeleteSecret() error = %v, want nil when already gone", err)
		}
	})

	t.Run("property delete preserves sibling and unmanaged fields", func(t *testing.T) {
		var pushed string
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(`{"managed":"remove","sibling":"keep","unmanaged":{"nested":true}}`), nil
			},
			updateStageFn: func(_ context.Context, secretID, stage, value string) error {
				if secretID != existingID || stage != stageActive {
					t.Errorf("UpdateSecretStageValue(%q, %q), want (%q, active)", secretID, stage, existingID)
				}
				pushed = value
				return nil
			},
		}
		client := newMockedClient(mock)

		err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{
			remoteKey: "db-cred",
			property:  "managed",
		})
		if err != nil {
			t.Fatalf("DeleteSecret() error = %v", err)
		}
		if pushed != `{"sibling":"keep","unmanaged":{"nested":true}}` {
			t.Errorf("updated value = %s, want siblings preserved", pushed)
		}
		if mock.requestDeletionCalls != 0 || mock.destroyCalls != 0 {
			t.Errorf("property delete destroyed secret with siblings: request=%d destroy=%d", mock.requestDeletionCalls, mock.destroyCalls)
		}
	})

	t.Run("missing property is idempotent and exact top-level only", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(`{"db":{"host":"nested"},"sibling":"keep"}`), nil
			},
		}
		client := newMockedClient(mock)

		err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{
			remoteKey: "db-cred",
			property:  "db.host",
		})
		if err != nil {
			t.Fatalf("DeleteSecret() error = %v", err)
		}
		if mock.updateStageCalls != 0 || mock.requestDeletionCalls != 0 || mock.destroyCalls != 0 {
			t.Errorf("absent literal property mutated remote: update=%d request=%d destroy=%d",
				mock.updateStageCalls, mock.requestDeletionCalls, mock.destroyCalls)
		}
	})

	t.Run("final property follows full two-step deletion", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(`{"managed":"remove"}`), nil
			},
			getSecretDetailFn: detailWithStatus(secretStatusEnable),
			requestDeletionFn: func(_ context.Context, _ string) error {
				return nil
			},
			destroyFn: func(_ context.Context, _ string) error {
				return nil
			},
		}
		client := newMockedClient(mock)

		err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{
			remoteKey: "db-cred",
			property:  "managed",
		})
		if err != nil {
			t.Fatalf("DeleteSecret() error = %v", err)
		}
		if mock.updateStageCalls != 0 || mock.requestDeletionCalls != 1 || mock.destroyCalls != 0 {
			t.Errorf("final property mutation counts: update=%d request=%d destroy=%d; want 0,1,0",
				mock.updateStageCalls, mock.requestDeletionCalls, mock.destroyCalls)
		}
		// The ownership gate already read the detail under the ID lock, and
		// the full-delete fall-through reuses it rather than reading again.
		// Nothing else asserted that, so the reuse could be undone silently.
		if mock.getSecretDetailCalls != 1 {
			t.Errorf("getSecretDetailCalls = %d, want 1 (the fall-through reuses the gate's read)",
				mock.getSecretDetailCalls)
		}
	})

	t.Run("property delete rejects non-object without mutating", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(`"not-an-object"`), nil
			},
		}
		client := newMockedClient(mock)

		err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{
			remoteKey: "db-cred",
			property:  "managed",
		})
		if err == nil || !strings.Contains(err.Error(), "not a JSON object") {
			t.Fatalf("DeleteSecret() error = %v, want non-object rejection", err)
		}
		if mock.updateStageCalls != 0 || mock.requestDeletionCalls != 0 || mock.destroyCalls != 0 {
			t.Errorf("non-object property delete mutated remote: update=%d request=%d destroy=%d",
				mock.updateStageCalls, mock.requestDeletionCalls, mock.destroyCalls)
		}
	})

	t.Run("unreadable property fails closed without full delete", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: existingID, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return nil, fmt.Errorf("%w: cannot read active value", ErrForbidden)
			},
		}
		client := newMockedClient(mock)

		err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{
			remoteKey: "db-cred",
			property:  "managed",
		})
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("DeleteSecret() error = %v, want ErrForbidden", err)
		}
		if mock.updateStageCalls != 0 || mock.requestDeletionCalls != 0 || mock.destroyCalls != 0 {
			t.Errorf("unreadable property delete mutated remote: update=%d request=%d destroy=%d",
				mock.updateStageCalls, mock.requestDeletionCalls, mock.destroyCalls)
		}
	})
}

func TestDeleteSecretRotationTargetsAndResume(t *testing.T) {
	const id = "5656565656565656565656565656565656565656565656565656565656565656"

	// Same server rule as on the push path: the create-time target cannot be
	// dropped, so deleting it is refused locally whatever autoRotationYN says.
	for _, rotation := range []struct{ autoRotationYN, name string }{
		{"N", "disabled"},
		{"Y", "enabled"},
		{"", "unknown"},
	} {
		t.Run("targeted property cannot be removed when rotation is "+rotation.name, func(t *testing.T) {
			mock := &countingMockClient{
				listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
				getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
					resp := newSecretValueResponse(`{"password":"p","username":"u"}`)
					resp.Data.RotationTargets = []string{"password"}
					return resp, nil
				},
				getSecretDetailFn: detailWithRotation(secretStatusEnable, rotation.autoRotationYN),
				updateStageFn: func(_ context.Context, _, _, value string) error {
					t.Errorf("UpdateSecretStageValue(%s) called; a target-dropping write must not reach Ncloud", value)
					return nil
				},
			}
			client := newMockedClient(mock)

			err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{
				remoteKey: "db-cred",
				property:  "password",
			})
			if !errors.Is(err, errRotationTargetAbsent) {
				t.Fatalf("DeleteSecret() error = %v, want errRotationTargetAbsent", err)
			}
			// A refused property delete must not fall through to destroying the
			// secret: the sibling field is still wanted.
			if mock.getSecretDetailCalls != 1 || mock.updateStageCalls != 0 ||
				mock.requestDeletionCalls != 0 || mock.destroyCalls != 0 {
				t.Errorf("calls detail=%d update=%d request=%d destroy=%d; want 1,0,0,0",
					mock.getSecretDetailCalls, mock.updateStageCalls, mock.requestDeletionCalls, mock.destroyCalls)
			}
		})
	}

	t.Run("detail NotFound during target removal is idempotent", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				resp := newSecretValueResponse(`{"password":"p","username":"u"}`)
				resp.Data.RotationTargets = []string{"password"}
				return resp, nil
			},
			getSecretDetailFn: func(_ context.Context, _ string) (*NcloudSecretDetailResponse, error) {
				return nil, ErrSecretNotFound
			},
		}
		client := newMockedClient(mock)

		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{
			remoteKey: "db-cred",
			property:  "password",
		}); err != nil {
			t.Fatalf("DeleteSecret() error = %v, want nil for concurrently missing secret", err)
		}
		if mock.updateStageCalls != 0 || mock.requestDeletionCalls != 0 || mock.destroyCalls != 0 {
			t.Errorf("concurrently missing target delete mutated remote: update=%d request=%d destroy=%d",
				mock.updateStageCalls, mock.requestDeletionCalls, mock.destroyCalls)
		}
	})

	// A paused secret still holds its value, so the read-modify-write is only
	// blocked, not moot. Whole deletion succeeds from DISABLE, so the error has
	// to explain the asymmetry rather than relay a bare 409.
	t.Run("property deletion on a paused secret explains itself", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return nil, ErrInvalidStatus
			},
			getSecretDetailFn: detailWithStatus(secretStatusDisable),
		}
		client := newMockedClient(mock)

		err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{
			remoteKey: "db-cred",
			property:  "password",
		})
		if err == nil {
			t.Fatal("DeleteSecret() on a paused secret should fail")
		}
		if !strings.Contains(err.Error(), "DISABLE") || !strings.Contains(err.Error(), "Enable Secret") {
			t.Errorf("DeleteSecret() error = %v, want it to name the paused state and the way out", err)
		}
		if mock.requestDeletionCalls != 0 || mock.destroyCalls != 0 {
			t.Errorf("a refused property delete touched the secret: request=%d destroy=%d",
				mock.requestDeletionCalls, mock.destroyCalls)
		}
	})

	t.Run("non-target property deletion preserves target", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				resp := newSecretValueResponse(`{"password":"p","username":"u"}`)
				resp.Data.RotationTargets = []string{"password"}
				return resp, nil
			},
			updateStageFn: func(_ context.Context, _, _, value string) error {
				if value != `{"password":"p"}` {
					t.Errorf("updated value = %s, want target-preserving object", value)
				}
				return nil
			},
		}
		client := newMockedClient(mock)

		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{
			remoteKey: "db-cred",
			property:  "username",
		}); err != nil {
			t.Fatalf("DeleteSecret() error = %v", err)
		}
		if mock.updateStageCalls != 1 {
			t.Errorf("updateStageCalls = %d, want 1", mock.updateStageCalls)
		}
		if mock.getSecretDetailCalls != 1 {
			t.Errorf("getSecretDetailCalls = %d, want 1 (ownership gate only)", mock.getSecretDetailCalls)
		}
	})

	// Deleting one managed property must never escalate into destroying
	// the whole secret. When the secret is already in a deletion lifecycle its
	// value is unreadable and the property removal is moot, so the call
	// succeeds without touching the secret; Ncloud finalizes the pending
	// deletion on its own.
	t.Run("property delete on a REVOKE secret does not escalate", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return nil, ErrInvalidStatus
			},
			getSecretDetailFn: detailWithStatus(secretStatusRevoke),
			requestDeletionFn: func(_ context.Context, _ string) error {
				t.Error("RequestSecretDeletion called from a property delete")
				return nil
			},
			destroyFn: func(_ context.Context, _ string) error {
				t.Error("DestroySecret called from a property delete")
				return nil
			},
		}
		for _, client := range []*Client{newMockedClient(mock), newForceMockedClient(mock)} {
			err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{
				remoteKey: "db-cred", property: "password",
			})
			if err != nil {
				t.Fatalf("DeleteSecret(property) on a REVOKE secret error = %v, want nil", err)
			}
		}
		if mock.requestDeletionCalls != 0 || mock.destroyCalls != 0 || mock.updateStageCalls != 0 {
			t.Errorf("mutations: request=%d destroy=%d update=%d; want 0,0,0",
				mock.requestDeletionCalls, mock.destroyCalls, mock.updateStageCalls)
		}
		// REVOKE still holds the name, so no other writer can have created
		// it again and the name is not resolved once more: one sweep per
		// client.
		if mock.listCalls != 2 {
			t.Errorf("listCalls = %d, want 2", mock.listCalls)
		}
	})

	// The whole-secret delete path still resumes an interrupted finalization
	// in force mode, which is where that recovery belongs.
	t.Run("force mode whole-secret retry resumes final destroy from REVOKE", func(t *testing.T) {
		detailCalls := 0
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
			getSecretDetailFn: func(_ context.Context, _ string) (*NcloudSecretDetailResponse, error) {
				detailCalls++
				status := secretStatusEnable
				if detailCalls > 1 {
					status = secretStatusRevoke
				}
				return detailWithStatus(status)(context.Background(), id)
			},
			requestDeletionFn: func(_ context.Context, _ string) error { return nil },
			destroyFn: func(_ context.Context, _ string) error {
				if detailCalls == 1 {
					return errors.New("transient destroy failure")
				}
				return nil
			},
		}
		client := newForceMockedClient(mock)
		ref := mockPushSecretRemoteRef{remoteKey: "db-cred"}

		if err := client.DeleteSecret(context.Background(), ref); err == nil {
			t.Fatal("first DeleteSecret() should report the failed final destroy")
		}
		if err := client.DeleteSecret(context.Background(), ref); err != nil {
			t.Fatalf("second DeleteSecret() error = %v, want resumed destroy success", err)
		}
		if mock.requestDeletionCalls != 1 || mock.destroyCalls != 2 {
			t.Errorf("deletion calls: request=%d destroy=%d; want 1,2",
				mock.requestDeletionCalls, mock.destroyCalls)
		}
	})
}

func TestWriteLocksPreserveConflict(t *testing.T) {
	const id = "1212121212121212121212121212121212121212121212121212121212121212"

	t.Run("direct ID push locks ID before detail probe", func(t *testing.T) {
		unlock, err := locks.TryLock(providerName, id)
		if err != nil {
			t.Fatalf("pre-acquire lock: %v", err)
		}
		defer unlock()

		mock := &countingMockClient{}
		client := newMockedClient(mock)
		secret := &corev1.Secret{Data: map[string][]byte{"password": []byte("v")}}

		err = client.PushSecret(context.Background(), secret, mockPushSecretData{
			remoteKey: id,
			secretKey: "password",
		})
		if !errors.Is(err, locks.ErrConflict) {
			t.Fatalf("PushSecret() error = %v, want locks.ErrConflict", err)
		}
		if mock.getSecretDetailCalls != 0 || mock.listCalls != 0 {
			t.Errorf("API reached despite lock conflict: detail=%d list=%d",
				mock.getSecretDetailCalls, mock.listCalls)
		}
	})

	t.Run("existing push locks resolved ID", func(t *testing.T) {
		unlock, err := locks.TryLock(providerName, id)
		if err != nil {
			t.Fatalf("pre-acquire lock: %v", err)
		}
		defer unlock()

		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				t.Fatal("locked push must stop before reading the remote value")
				return nil, nil
			},
		}
		client := newMockedClient(mock)
		secret := &corev1.Secret{Data: map[string][]byte{"password": []byte("v")}}

		err = client.PushSecret(context.Background(), secret, mockPushSecretData{
			remoteKey: "db-cred",
			secretKey: "password",
		})
		if !errors.Is(err, locks.ErrConflict) {
			t.Fatalf("PushSecret() error = %v, want locks.ErrConflict", err)
		}
	})

	t.Run("delete locks resolved ID", func(t *testing.T) {
		unlock, err := locks.TryLock(providerName, id)
		if err != nil {
			t.Fatalf("pre-acquire lock: %v", err)
		}
		defer unlock()

		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
			getSecretDetailFn: func(_ context.Context, _ string) (*NcloudSecretDetailResponse, error) {
				t.Fatal("locked delete must stop before reading remote detail")
				return nil, nil
			},
		}
		client := newMockedClient(mock)

		err = client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
		if !errors.Is(err, locks.ErrConflict) {
			t.Fatalf("DeleteSecret() error = %v, want locks.ErrConflict", err)
		}
	})

	t.Run("create locks remote name", func(t *testing.T) {
		const name = "db-create"
		unlock, err := locks.TryLock(providerName, name)
		if err != nil {
			t.Fatalf("pre-acquire lock: %v", err)
		}
		defer unlock()

		mock := &countingMockClient{
			listFn: listingWith(),
			createFn: func(_ context.Context, _ *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
				t.Fatal("locked create must stop before the mutation")
				return nil, nil
			},
		}
		client := newMockedClient(mock)
		secret := &corev1.Secret{Data: map[string][]byte{"password": []byte("v")}}

		err = client.PushSecret(context.Background(), secret, mockPushSecretData{
			remoteKey: name,
			secretKey: "password",
		})
		if !errors.Is(err, locks.ErrConflict) {
			t.Fatalf("PushSecret() error = %v, want locks.ErrConflict", err)
		}
	})
}

// TestPushSecretRechecksAbsenceInsideCreateLock pins the locked recheck: a
// name another writer created after this client's pre-lock listing miss is
// neither created again nor updated. Updating would overwrite the other
// writer's secret under updatePolicy IfNotExists, whose SecretExists check
// answered from the same stale listing; the push fails with
// ErrNameTakenMeanwhile and the next reconcile sees the secret.
func TestPushSecretRechecksAbsenceInsideCreateLock(t *testing.T) {
	const (
		name = "db-create"
		id   = "3434343434343434343434343434343434343434343434343434343434343434"
	)

	listingCalls := 0
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			listingCalls++
			items := []NcloudSecretListItem(nil)
			if listingCalls > 1 {
				// Simulate another client creating the secret after this
				// client's pre-lock listing miss but before it acquires the
				// name lock.
				items = []NcloudSecretListItem{{SecretID: id, SecretName: name}}
			}
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					CurrentPageNo: pageNo,
					TotalPageNo:   1,
					SecretList:    items,
				},
			}, nil
		},
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			t.Fatalf("GetSecretValue(%q) called; the other writer's secret must not be read, let alone written", secretID)
			return nil, nil
		},
		createFn: func(_ context.Context, _ *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
			t.Fatal("stale pre-lock absence must not create a duplicate secret")
			return nil, nil
		},
	}
	client := newMockedClient(mock)
	secret := &corev1.Secret{Data: map[string][]byte{"password": []byte("new")}}

	err := client.PushSecret(context.Background(), secret, mockPushSecretData{
		remoteKey: name,
		secretKey: "password",
	})
	if !errors.Is(err, ErrNameTakenMeanwhile) {
		t.Fatalf("PushSecret() error = %v, want ErrNameTakenMeanwhile", err)
	}
	if listingCalls != 2 {
		t.Errorf("ListSecrets calls = %d, want 2 (pre-lock check plus locked recheck)", listingCalls)
	}
	if mock.createCalls != 0 || mock.updateStageCalls != 0 {
		t.Errorf("mutation counts: create=%d update=%d; want 0,0", mock.createCalls, mock.updateStageCalls)
	}
	if _, pinned := client.writes.pinned[name]; pinned {
		t.Error("the other writer's secret was pinned as this reconcile's own")
	}
}

// TestPushSecretRefusesToOverwriteASecretCreatedAfterTheIndexSweep is the
// IfNotExists case end to end, with the other writer a second Client sharing
// the cache. Our reconcile's first entry builds and confirms the write index;
// the other writer then creates the name; our next entry asks SecretExists,
// which answers from the index built before that create, so the controller
// goes on to push. The push must leave the other writer's value alone.
func TestPushSecretRefusesToOverwriteASecretCreatedAfterTheIndexSweep(t *testing.T) {
	const id = "3535353535353535353535353535353535353535353535353535353535353535"
	created, replacing := false, false
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			var items []NcloudSecretListItem
			if created {
				items = []NcloudSecretListItem{{SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusEnable}}
			}
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{TotalPageNo: 1, CurrentPageNo: pageNo, TotalCount: len(items), SecretList: items},
			}, nil
		},
		createFn: func(_ context.Context, req *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
			if created {
				return nil, fmt.Errorf("%w: the name is already in use", ErrInvalidStatus)
			}
			created = true
			return &NcloudSecretDetailResponse{Code: successCode, Data: NcloudSecretDetailData{SecretID: id}}, nil
		},
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return newSecretValueResponse(`{"k":"theirs"}`), nil
		},
		updateStageFn: func(_ context.Context, _, _, value string) error {
			if !replacing {
				t.Errorf("UpdateSecretStageValue(%s) overwrote the other writer's value", value)
			}
			return nil
		},
	}
	ours := newMockedClient(mock)
	theirs := &Client{client: mock, cache: ours.cache}

	if exists, err := ours.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "first"}); err != nil || exists {
		t.Fatalf("SecretExists(first) = (%v, %v), want (false, nil)", exists, err)
	}
	if err := theirs.PushSecret(context.Background(), &corev1.Secret{Data: map[string][]byte{"k": []byte("theirs")}},
		mockPushSecretData{remoteKey: "db-cred", secretKey: "k"}); err != nil {
		t.Fatalf("their PushSecret() error = %v", err)
	}
	if mock.createCalls != 1 {
		t.Fatalf("createCalls = %d after their push, want 1", mock.createCalls)
	}

	exists, err := ours.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
	if err != nil {
		t.Fatalf("SecretExists(db-cred) error = %v", err)
	}
	if exists {
		// A SecretExists that sees past the index would make the controller
		// skip the push, which is also correct; the push below is what the
		// controller does on false.
		t.Log("SecretExists(db-cred) answered true; pushing anyway to cover the Replace policy")
	}
	err = ours.PushSecret(context.Background(), &corev1.Secret{Data: map[string][]byte{"k": []byte("ours")}},
		mockPushSecretData{remoteKey: "db-cred", secretKey: "k"})
	if !errors.Is(err, ErrNameTakenMeanwhile) {
		t.Fatalf("our PushSecret() error = %v, want ErrNameTakenMeanwhile", err)
	}
	if mock.createCalls != 1 || mock.updateStageCalls != 0 {
		t.Errorf("mutation counts after our push: create=%d update=%d; want 1,0", mock.createCalls, mock.updateStageCalls)
	}

	// The next reconcile's fresh index lists the secret: IfNotExists skips
	// it, Replace updates it. The controller calls SecretExists only for
	// IfNotExists, so the Replace push below comes from a client of its own.
	next := &Client{client: mock, cache: ours.cache}
	if exists, err := next.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"}); err != nil || !exists {
		t.Errorf("SecretExists(db-cred) from the next reconcile = (%v, %v), want (true, nil)", exists, err)
	}
	replacing = true
	replace := &Client{client: mock, cache: ours.cache}
	if err := replace.PushSecret(context.Background(), &corev1.Secret{Data: map[string][]byte{"k": []byte("ours")}},
		mockPushSecretData{remoteKey: "db-cred", secretKey: "k"}); err != nil {
		t.Fatalf("Replace PushSecret() from the next reconcile error = %v, want an update of the listed secret", err)
	}
	if mock.createCalls != 1 || mock.updateStageCalls != 1 {
		t.Errorf("mutation counts after the Replace push: create=%d update=%d; want 1,1", mock.createCalls, mock.updateStageCalls)
	}
}

// TestPushSecretCreateClearsNegativeCache pins that the listing
// miss right before a create negative-caches the name; a create must never
// leave that entry alive, even when the response carries no ID or the create
// fails in a way that may have created the secret anyway.
func TestPushSecretCreateClearsNegativeCache(t *testing.T) {
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"password": []byte("v")}}

	for _, tc := range []struct {
		name      string
		secretID  string
		createErr error
		wantErr   string
	}{
		{name: "response with ID overwrites the negative entry", secretID: "3333333333333333333333333333333333333333333333333333333333333333"},
		// The documented Create response always carries the ID; its absence
		// is an API-contract violation surfaced loudly.
		{name: "response without ID fails loudly but still clears the negative entry", secretID: "", wantErr: "no usable secret ID"},
		// A timeout after the request was sent may have created the secret.
		{name: "failed create still clears the negative entry", createErr: context.DeadlineExceeded, wantErr: "deadline exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &countingMockClient{
				listFn: listingWith(),
				createFn: func(_ context.Context, _ *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
					if tc.createErr != nil {
						return nil, tc.createErr
					}
					return &NcloudSecretDetailResponse{Code: successCode, Data: NcloudSecretDetailData{SecretID: tc.secretID}}, nil
				},
			}
			client := newMockedClient(mock)

			err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "password"})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("PushSecret() error = %v, want it to mention %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("PushSecret() error = %v", err)
			}
			if _, found, negative := client.cache.Get("db-cred"); found && negative {
				t.Error("negative cache entry survived the create; GetSecret would report NotFound")
			}
		})
	}
}

// createSecretRequiredFields is the required field set of the documented Create
// Secret request body, per
// https://api.ncloud-docs.com/docs/en/secretmanager-createsecret.
//
// This list comes from the API reference, NOT from what the client currently
// emits. That direction matters: a test that freezes a body built by the client
// itself certifies whatever the client sends and can never reveal a field the
// client never learned to send, such as kmsBoundaryType, whose absence a
// region-isolated account rejects with 400 MISSING_REQUIRED_FIELD.
var createSecretRequiredFields = []string{
	"secretName",
	"secretValue",
	"secretType",
	"autoRotationYN",
	"protectionKeyType",
}

// TestPushSecretCreateRequestSatisfiesDocumentedContract checks the create body
// the client actually builds against the documented required fields, and pins
// kmsBoundaryType to the boundary the account's own default protection key
// reports.
func TestPushSecretCreateRequestSatisfiesDocumentedContract(t *testing.T) {
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"password": []byte("v")}}
	const createdID = "9999999999999999999999999999999999999999999999999999999999999999"

	keyList := func(entries ...NcloudProtectionKeyEntry) func(context.Context) (*NcloudProtectionKeyListResponse, error) {
		return func(context.Context) (*NcloudProtectionKeyListResponse, error) {
			return &NcloudProtectionKeyListResponse{
				Code: successCode,
				Data: NcloudProtectionKeyListData{KeyList: entries},
			}, nil
		}
	}

	for _, tc := range []struct {
		name         string
		keysFn       func(context.Context) (*NcloudProtectionKeyListResponse, error)
		wantBoundary string
	}{
		{
			name: "region-isolated account declares ISOLATED",
			keysFn: keyList(
				NcloudProtectionKeyEntry{KeyName: "Secret Manager Default Key", KmsBoundaryType: "ISOLATED"},
				NcloudProtectionKeyEntry{KeyTag: "kr-tagged", KeyName: "user-key", KmsBoundaryType: "ISOLATED"},
			),
			wantBoundary: "ISOLATED",
		},
		{
			name:         "global account declares GLOBAL",
			keysFn:       keyList(NcloudProtectionKeyEntry{KmsBoundaryType: "GLOBAL"}),
			wantBoundary: "GLOBAL",
		},
		{
			name:         "no default key: field omitted rather than guessed",
			keysFn:       keyList(NcloudProtectionKeyEntry{KeyTag: "kr-tagged", KmsBoundaryType: "ISOLATED"}),
			wantBoundary: "",
		},
		{
			name: "key listing fails: field omitted and the create still proceeds",
			keysFn: func(context.Context) (*NcloudProtectionKeyListResponse, error) {
				return nil, ErrForbidden
			},
			wantBoundary: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got *NcloudCreateSecretRequest
			mock := &countingMockClient{
				listFn:          listingWith(),
				protectionKeyFn: tc.keysFn,
				createFn: func(_ context.Context, req *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
					got = req
					return &NcloudSecretDetailResponse{Code: successCode, Data: NcloudSecretDetailData{SecretID: createdID}}, nil
				},
			}
			client := newMockedClient(mock)

			if err := client.PushSecret(
				context.Background(), k8sSecret,
				mockPushSecretData{remoteKey: "db-cred", secretKey: "password"},
			); err != nil {
				t.Fatalf("PushSecret() error = %v", err)
			}
			if got == nil {
				t.Fatal("CreateSecret was never called")
			}

			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("marshal create request: %v", err)
			}
			var body map[string]any
			if err := json.Unmarshal(encoded, &body); err != nil {
				t.Fatalf("decode create request: %v", err)
			}

			for _, field := range createSecretRequiredFields {
				value, present := body[field]
				if !present {
					t.Errorf("create body omits documented required field %q: %s", field, encoded)
					continue
				}
				if s, isString := value.(string); isString && s == "" {
					t.Errorf("create body sends empty required field %q", field)
				}
			}

			// rotationTargets is required inside secretValue even with rotation off.
			secretValue, _ := body["secretValue"].(map[string]any)
			if secretValue == nil {
				t.Fatalf("create body has no secretValue object: %s", encoded)
			}
			for _, field := range []string{"value", "rotationTargets"} {
				if _, present := secretValue[field]; !present {
					t.Errorf("secretValue omits required field %q: %s", field, encoded)
				}
			}
			if targets, _ := secretValue["rotationTargets"].([]any); len(targets) == 0 {
				t.Errorf("rotationTargets must be nonempty on create: %s", encoded)
			}

			if got.KmsBoundaryType != tc.wantBoundary {
				t.Errorf("kmsBoundaryType = %q, want %q", got.KmsBoundaryType, tc.wantBoundary)
			}
			// Omitted rather than sent empty, so an account that never needed the
			// field keeps the pre-existing request shape byte for byte.
			if _, present := body["kmsBoundaryType"]; present != (tc.wantBoundary != "") {
				t.Errorf("kmsBoundaryType presence = %v, want %v: %s", present, tc.wantBoundary != "", encoded)
			}
		})
	}
}

// TestDefaultKeyBoundaryResolvedOncePerClient keeps the added lookup off the
// steady-state path: it must not repeat per create, and must never run for
// reads or updates.
func TestDefaultKeyBoundaryResolvedOncePerClient(t *testing.T) {
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"password": []byte("v")}}
	ids := []string{
		"1111111111111111111111111111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222222222222222222222222222",
	}
	var created int
	mock := &countingMockClient{
		listFn: listingWith(),
		protectionKeyFn: func(context.Context) (*NcloudProtectionKeyListResponse, error) {
			return &NcloudProtectionKeyListResponse{
				Code: successCode,
				Data: NcloudProtectionKeyListData{
					KeyList: []NcloudProtectionKeyEntry{{KmsBoundaryType: "ISOLATED"}},
				},
			}, nil
		},
		createFn: func(_ context.Context, _ *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
			id := ids[created]
			created++
			return &NcloudSecretDetailResponse{Code: successCode, Data: NcloudSecretDetailData{SecretID: id}}, nil
		},
	}
	client := newMockedClient(mock)

	for _, name := range []string{"cred-one", "cred-two"} {
		if err := client.PushSecret(
			context.Background(), k8sSecret,
			mockPushSecretData{remoteKey: name, secretKey: "password"},
		); err != nil {
			t.Fatalf("PushSecret(%s) error = %v", name, err)
		}
	}

	if mock.protectionKeyCalls != 1 {
		t.Errorf("ListProtectionKeys called %d times, want 1 (cached per Client)", mock.protectionKeyCalls)
	}
}

// TestDefaultKeyBoundaryLookupRetriesAfterFailure pins the latch direction:
// only a successful protection-key listing is remembered. A transient failure
// must not pin every later create of the same client (one reconcile can push
// many entries) to the omitted-field request shape the server rejects on
// region-isolated accounts.
func TestDefaultKeyBoundaryLookupRetriesAfterFailure(t *testing.T) {
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"password": []byte("v")}}
	ids := []string{
		"1111111111111111111111111111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222222222222222222222222222",
		"3333333333333333333333333333333333333333333333333333333333333333",
	}
	var boundaries []string
	keysAvailable := false
	mock := &countingMockClient{
		listFn: listingWith(),
		protectionKeyFn: func(context.Context) (*NcloudProtectionKeyListResponse, error) {
			if !keysAvailable {
				return nil, fmt.Errorf("%w: transient blip", ErrServiceUnavailable)
			}
			return &NcloudProtectionKeyListResponse{
				Code: successCode,
				Data: NcloudProtectionKeyListData{
					KeyList: []NcloudProtectionKeyEntry{{KmsBoundaryType: "ISOLATED"}},
				},
			}, nil
		},
		createFn: func(_ context.Context, req *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
			boundaries = append(boundaries, req.KmsBoundaryType)
			return &NcloudSecretDetailResponse{
				Code: successCode,
				Data: NcloudSecretDetailData{SecretID: ids[len(boundaries)-1]},
			}, nil
		},
	}
	client := newMockedClient(mock)

	push := func(name string) error {
		return client.PushSecret(context.Background(), k8sSecret,
			mockPushSecretData{remoteKey: name, secretKey: "password"})
	}

	if err := push("cred-one"); err != nil {
		t.Fatalf("PushSecret(cred-one) error = %v (the boundary lookup failing must not fail the create)", err)
	}
	keysAvailable = true
	if err := push("cred-two"); err != nil {
		t.Fatalf("PushSecret(cred-two) error = %v", err)
	}
	if err := push("cred-thr"); err != nil {
		t.Fatalf("PushSecret(cred-thr) error = %v", err)
	}

	if want := []string{"", "ISOLATED", "ISOLATED"}; !slicesEqual(boundaries, want) {
		t.Errorf("kmsBoundaryType per create = %q, want %q (retry after the blip, then latched)", boundaries, want)
	}
	if mock.protectionKeyCalls != 2 {
		t.Errorf("ListProtectionKeys called %d times, want 2 (failed lookup retried once, success latched)",
			mock.protectionKeyCalls)
	}
}

// TestWriteListingUnavailableIsNotAbsence pins the data-loss guard: a 404 from
// the listing endpoint means the store could not be addressed, never that a
// secret is absent. Reporting absence makes DeleteSecret answer "already gone"
// and SecretExists answer false, and an ExternalSecret with deletionPolicy:
// Delete acts on that by deleting the Kubernetes Secret.
func TestWriteListingUnavailableIsNotAbsence(t *testing.T) {
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"password": []byte("v")}}
	unavailable := func(context.Context, int) (*NcloudListSecretsResponse, error) {
		return nil, newAPIError(ErrListingUnavailable, http.StatusNotFound, "501001")
	}

	t.Run("SecretExists surfaces the failure instead of false", func(t *testing.T) {
		client := newMockedClient(&countingMockClient{listFn: unavailable})
		exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
		if err == nil {
			t.Fatal("SecretExists() error = nil, want the listing failure surfaced")
		}
		if !errors.Is(err, ErrListingUnavailable) {
			t.Errorf("SecretExists() error = %v, want ErrListingUnavailable", err)
		}
		if errors.Is(err, ErrSecretNotFound) {
			t.Errorf("SecretExists() error still reports ErrSecretNotFound: %v", err)
		}
		if exists {
			t.Error("SecretExists() = true on an unreadable listing")
		}
	})

	t.Run("DeleteSecret refuses to treat it as already gone", func(t *testing.T) {
		client := newMockedClient(&countingMockClient{listFn: unavailable})
		err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
		if err == nil {
			t.Fatal("DeleteSecret() error = nil, want the listing failure surfaced")
		}
		if !errors.Is(err, ErrListingUnavailable) {
			t.Errorf("DeleteSecret() error = %v, want ErrListingUnavailable", err)
		}
	})

	t.Run("PushSecret does not create a duplicate", func(t *testing.T) {
		mock := &countingMockClient{listFn: unavailable}
		client := newMockedClient(mock)
		err := client.PushSecret(
			context.Background(), k8sSecret,
			mockPushSecretData{remoteKey: "db-cred", secretKey: "password"},
		)
		if err == nil {
			t.Fatal("PushSecret() error = nil, want the listing failure surfaced")
		}
		if !errors.Is(err, ErrListingUnavailable) {
			t.Errorf("PushSecret() error = %v, want ErrListingUnavailable", err)
		}
		if mock.createCalls != 0 {
			t.Errorf("CreateSecret called %d times; an unreadable listing must not trigger a create", mock.createCalls)
		}
	})

	t.Run("no negative cache entry is poisoned", func(t *testing.T) {
		client := newMockedClient(&countingMockClient{listFn: unavailable})
		_, _ = client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
		if _, found, negative := client.cache.Get("db-cred"); found && negative {
			t.Error("listing failure negative-cached the name; reads would report NotFound for the TTL")
		}
	})
}

// TestDeleteSecretAlreadyGoneCleansMappings pins that every confirmed-gone
// exit of DeleteSecret must drop the write-index/cache mappings the resolution
// listing just warmed, or a later same-reconcile SecretExists/PushSecret for
// the key silently uses the destroyed ID.
func TestDeleteSecretAlreadyGoneCleansMappings(t *testing.T) {
	const id = "7777777777777777777777777777777777777777777777777777777777777777"
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}

	t.Run("DESTROYED status: subsequent push creates a replacement", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{
				SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusDestroyed,
			}),
			getSecretDetailFn: detailWithStatus(secretStatusDestroyed),
			createFn: func(_ context.Context, _ *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
				return &NcloudSecretDetailResponse{Code: successCode, Data: NcloudSecretDetailData{SecretID: "8888888888888888888888888888888888888888888888888888888888888888"}}, nil
			},
		}
		client := newMockedClient(mock)

		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"}); err != nil {
			t.Fatalf("DeleteSecret() error = %v", err)
		}
		if err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"}); err != nil {
			t.Fatalf("PushSecret() after DESTROYED delete error = %v", err)
		}
		if mock.createCalls != 1 {
			t.Errorf("createCalls = %d, want 1 (index must not point at the destroyed ID)", mock.createCalls)
		}
		if mock.updateStageCalls != 0 {
			t.Errorf("updateStageCalls = %d, want 0", mock.updateStageCalls)
		}
	})

	t.Run("detail NotFound: subsequent SecretExists reports false", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
			getSecretDetailFn: func(_ context.Context, _ string) (*NcloudSecretDetailResponse, error) {
				return nil, fmt.Errorf("%w: tombstoned", ErrSecretNotFound)
			},
		}
		client := newMockedClient(mock)

		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"}); err != nil {
			t.Fatalf("DeleteSecret() error = %v", err)
		}
		// The index entry warmed during delete's resolution must be gone; the
		// shared cache entry too. SecretExists re-resolves and misses.
		if _, ok := client.writes.names["db-cred"]; ok {
			t.Error("write index still maps db-cred after an already-gone delete")
		}
		if _, found, negative := client.cache.Get("db-cred"); found && !negative {
			t.Error("shared cache still maps db-cred at the dead ID")
		}
	})
}

// TestPushSecretUpdateNotFoundFallsBackToCreate pins that a secret destroyed
// between the resolution listing and the update call is recreated instead of
// failing the reconcile (parity with the delete path's tolerance).
func TestPushSecretUpdateNotFoundFallsBackToCreate(t *testing.T) {
	const id = "9999999999999999999999999999999999999999999999999999999999999999"
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}

	mock := &countingMockClient{
		listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return nil, fmt.Errorf("%w: destroyed concurrently", ErrSecretNotFound)
		},
		createFn: func(_ context.Context, req *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
			if req.SecretName != "db-cred" {
				t.Errorf("CreateSecret name = %q, want db-cred", req.SecretName)
			}
			return &NcloudSecretDetailResponse{Code: successCode, Data: NcloudSecretDetailData{SecretID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"}}, nil
		},
	}
	client := newMockedClient(mock)

	if err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"}); err != nil {
		t.Fatalf("PushSecret() error = %v, want create fallback", err)
	}
	if mock.createCalls != 1 {
		t.Errorf("createCalls = %d, want 1", mock.createCalls)
	}
	if _, ok := client.writes.names["db-cred"]; !ok {
		t.Error("write index should map db-cred to the replacement ID")
	}
}

// TestPushSecretUpdateNotFoundRefusesAnotherSecretUnderTheName is the other
// half of that fallback. The listing the create lock reads may still show the
// secret the update just saw gone, and that row is skipped; a live row under
// another ID is a writer that took the name after the 404, and creating over
// it would duplicate the name or overwrite that writer's value.
func TestPushSecretUpdateNotFoundRefusesAnotherSecretUnderTheName(t *testing.T) {
	const (
		goneID  = "9999999999999999999999999999999999999999999999999999999999999999"
		otherID = "8888888888888888888888888888888888888888888888888888888888888888"
	)
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}

	sweeps := 0
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			if pageNo == 1 {
				sweeps++
			}
			row := NcloudSecretListItem{SecretID: goneID, SecretName: "db-cred", SecretStatus: secretStatusEnable}
			if sweeps > 1 {
				row.SecretID = otherID
			}
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{TotalPageNo: 1, CurrentPageNo: pageNo, TotalCount: 1, SecretList: []NcloudSecretListItem{row}},
			}, nil
		},
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			if secretID != goneID {
				t.Errorf("value read addressed %s, want only the resolved %s", secretID, goneID)
			}
			return nil, fmt.Errorf("%w: destroyed concurrently", ErrSecretNotFound)
		},
	}
	client := newMockedClient(mock)

	err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"})
	if !errors.Is(err, ErrNameTakenMeanwhile) {
		t.Fatalf("PushSecret() error = %v, want ErrNameTakenMeanwhile for the live %s", err, otherID)
	}
	if sweeps < 2 {
		t.Fatalf("the listing was swept %d time(s); the test needs the create lock's own read", sweeps)
	}
	if mock.createCalls != 0 || mock.updateStageCalls != 0 {
		t.Errorf("createCalls = %d, updateStageCalls = %d; want 0, 0: the name belongs to another writer",
			mock.createCalls, mock.updateStageCalls)
	}
}

// TestWriteIndexMatchWinsAtPageCap pins parity with resolveSecretIDFromListing:
// a name found on the very page where the pagination cap fires still resolves;
// only an unmatched sweep errors.
func TestWriteIndexMatchWinsAtPageCap(t *testing.T) {
	const targetID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccd"

	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			items := []NcloudSecretListItem{{SecretID: testSecretID("filler"), SecretName: fmt.Sprintf("f-%d", pageNo)}}
			if pageNo == maxListPages {
				items = append(items, NcloudSecretListItem{SecretID: targetID, SecretName: "target"})
			}
			return &NcloudListSecretsResponse{
				Code: successCode,
				// TotalPageNo 0 = unknown: hasMorePages stays true on every
				// non-empty page, so the cap guard governs termination.
				Data: NcloudListSecretsData{TotalPageNo: 0, CurrentPageNo: pageNo, SecretList: items},
			}, nil
		},
	}
	client := newMockedClient(mock)

	id, err := client.writes.Resolve(context.Background(), client.client, client.cache, "target")
	if err != nil {
		t.Fatalf("writeIndex.Resolve(target) error = %v, want match at the cap page", err)
	}
	if id != targetID {
		t.Errorf("writeIndex.Resolve(target) = %q, want %q", id, targetID)
	}

	// An unmatched key at the cap must still error (NOT NotFound: unscanned
	// pages may hold it, and a NotFound would poison the negative cache).
	fresh := newMockedClient(mock)
	if _, err := fresh.writes.Resolve(context.Background(), fresh.client, fresh.cache, "absent-name"); err == nil || errors.Is(err, ErrSecretNotFound) {
		t.Errorf("writeIndex.Resolve(absent) error = %v, want pagination-cap error, not NotFound", err)
	}
}

// TestDeleteSecretByIDSweepsNameEntries pins that deleting by ID also drops
// name-keyed cache entries pointing at that ID (warmed by any other listing),
// even though the ID shortcut itself does not list.
func TestDeleteSecretByIDSweepsNameEntries(t *testing.T) {
	const id = "4444444444444444444444444444444444444444444444444444444444444444"

	mock := &countingMockClient{
		listFn:            listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
		getSecretDetailFn: detailWithStatus(secretStatusEnable),
		requestDeletionFn: func(_ context.Context, _ string) error { return nil },
		destroyFn:         func(_ context.Context, _ string) error { return nil },
	}
	client := newMockedClient(mock)
	client.cache.Set("db-cred", id) // warmed by an earlier operation

	if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: id}); err != nil {
		t.Fatalf("DeleteSecret() error = %v", err)
	}
	if _, found, _ := client.cache.Get("db-cred"); found {
		t.Error("name-keyed cache entry pointing at the destroyed ID survived")
	}
	if mock.listCalls != 0 {
		t.Errorf("listCalls = %d, want 0 (ID-shaped key must skip resolution)", mock.listCalls)
	}
}

// TestDeleteSecretRequestDeletionNotFoundTolerated pins that a
// secret destroyed between the detail read and request-deletion must not
// fail the reconcile (idempotent delete, matching the finalize DELETE).
func TestDeleteSecretRequestDeletionNotFoundTolerated(t *testing.T) {
	const id = "5555555555555555555555555555555555555555555555555555555555555555"

	mock := &countingMockClient{
		listFn:            listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
		getSecretDetailFn: detailWithStatus(secretStatusEnable),
		requestDeletionFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("%w: destroyed concurrently", ErrSecretNotFound)
		},
		destroyFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("%w: destroyed concurrently", ErrSecretNotFound)
		},
	}
	client := newMockedClient(mock)

	if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"}); err != nil {
		t.Fatalf("DeleteSecret() error = %v, want nil when destroyed concurrently", err)
	}
}

// TestPushSecretCreateRecheckTreatsRotatingAsLive pins that a ROTATING
// competitor the locked create recheck surfaces is a live creator, like an
// ENABLE one: the push fails with ErrNameTakenMeanwhile, not with the occupied
// name error that REVOKE and DISABLE get, and nothing is written.
func TestPushSecretCreateRecheckTreatsRotatingAsLive(t *testing.T) {
	const id = "abababababababababababababababababababababababababababababababab"
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"password": []byte("v")}}

	listings := 0
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			// The pre-lock resolution sees an empty store; the locked recheck
			// then finds the freshly created secret already rotating.
			listings++
			items := []NcloudSecretListItem{}
			if listings > 1 {
				items = []NcloudSecretListItem{{SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusRotating}}
			}
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 1, CurrentPageNo: pageNo, TotalCount: len(items), SecretList: items,
				},
			}, nil
		},
		getSecretDetailFn: detailWithStatus(secretStatusRotating),
	}
	client := newMockedClient(mock)

	err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "password"})
	if !errors.Is(err, ErrNameTakenMeanwhile) || errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("PushSecret() error = %v, want ErrNameTakenMeanwhile and not the occupied name error", err)
	}
	if mock.createCalls != 0 || mock.updateStageCalls != 0 {
		t.Errorf("createCalls = %d, updateStageCalls = %d; want 0, 0",
			mock.createCalls, mock.updateStageCalls)
	}
}

// TestPushSecretNoOpSkipsRotationValidation pins that a push that changes
// nothing must be idempotent even when the stored value already lacks one of
// its persisted rotation targets. The byte-equality check therefore runs before
// the rotation-target validation, which would otherwise fail every reconcile
// forever.
func TestPushSecretNoOpSkipsRotationValidation(t *testing.T) {
	const id = "dededededededededededededededededededededededededededededededede"
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}
	stored := `{"k":"v"}` // byte-identical to what preparePushValue produces

	mock := &countingMockClient{
		listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			resp := newSecretValueResponse(stored)
			// The secret still lists "password" as a rotation target even
			// though the active value no longer carries it.
			resp.Data.RotationTargets = []string{"password"}
			return resp, nil
		},
		getSecretDetailFn: func(_ context.Context, _ string) (*NcloudSecretDetailResponse, error) {
			return &NcloudSecretDetailResponse{
				Code: successCode,
				Data: NcloudSecretDetailData{
					SecretID: id, SecretStatus: secretStatusEnable, AutoRotationYN: "Y", Memo: managedByMemo,
				},
			}, nil
		},
	}
	client := newMockedClient(mock)

	if err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"}); err != nil {
		t.Fatalf("no-op PushSecret() error = %v, want nil", err)
	}
	if mock.updateStageCalls != 0 {
		t.Errorf("updateStageCalls = %d, want 0 (nothing changed)", mock.updateStageCalls)
	}
}

// TestSecretExistsRevokedNameReportsAbsent pins the REVOKE rule at the name-resolution
// level: a REVOKE secret reached by name must also report absent, so
// updatePolicy=IfNotExists attempts the push instead of reporting Synced.
func TestSecretExistsRevokedNameReportsAbsent(t *testing.T) {
	const id = "dfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdf"

	mock := &countingMockClient{
		listFn: listingWith(NcloudSecretListItem{
			SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusRevoke,
		}),
		getSecretDetailFn: detailWithStatus(secretStatusRevoke),
	}
	client := newMockedClient(mock)

	exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
	if err != nil {
		t.Fatalf("SecretExists() error = %v", err)
	}
	if exists {
		t.Error("SecretExists() = true; want false for a deletion-requested secret")
	}
}

// TestWriteOwnershipGuard mirrors the AWS provider's ownership contract:
// creates stamp the managed-by marker into the memo, pushes to a secret without
// the marker fail loudly, and deletions of an unmanaged secret are silently
// skipped - whole-secret and single-property alike, so a cleanup can never
// wedge on one.
func TestWriteOwnershipGuard(t *testing.T) {
	const id = "acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac"
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}
	listed := listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"})

	t.Run("create stamps the marker", func(t *testing.T) {
		var gotMemo string
		mock := &countingMockClient{
			listFn: listingWith(),
			createFn: func(_ context.Context, req *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
				gotMemo = req.Memo
				return &NcloudSecretDetailResponse{Code: successCode, Data: NcloudSecretDetailData{SecretID: id}}, nil
			},
		}
		client := newMockedClient(mock)
		if err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"}); err != nil {
			t.Fatalf("PushSecret() error = %v", err)
		}
		if gotMemo != managedByMemo {
			t.Errorf("create memo = %q, want %q", gotMemo, managedByMemo)
		}
	})

	t.Run("push update to an unmanaged secret is refused", func(t *testing.T) {
		mock := &countingMockClient{listFn: listed, getSecretDetailFn: unmanagedDetail(secretStatusEnable)}
		client := newMockedClient(mock)
		err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"})
		if !errors.Is(err, ErrNotManagedByESO) {
			t.Fatalf("PushSecret() error = %v, want ErrNotManagedByESO", err)
		}
		if mock.updateStageCalls != 0 || mock.createCalls != 0 {
			t.Errorf("mutations: update=%d create=%d; want 0,0", mock.updateStageCalls, mock.createCalls)
		}
	})

	// A property deletion of an unmanaged secret is skipped rather than
	// refused, exactly like the full deletion below it. Refusing wedges the
	// caller: DeleteSecretFromProviders would fail on every attempt, the
	// PushSecret finalizer would never be removed, and the resource would stay
	// Terminating until an operator edited the remote memo or force-removed
	// the finalizer. No retry can change the outcome, because the marker only
	// appears if a human adds it.
	t.Run("property delete of an unmanaged secret is silently skipped", func(t *testing.T) {
		mock := &countingMockClient{listFn: listed, getSecretDetailFn: unmanagedDetail(secretStatusEnable)}
		client := newMockedClient(mock)
		err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred", property: "k"})
		if err != nil {
			t.Fatalf("DeleteSecret(property) error = %v, want nil (silent skip)", err)
		}
		if mock.updateStageCalls != 0 || mock.requestDeletionCalls != 0 || mock.destroyCalls != 0 {
			t.Error("an unmanaged secret must not be mutated")
		}
		if mock.getSecretValueCalls != 0 {
			t.Errorf("getSecretValueCalls = %d, want 0 (the skip precedes reading the value)",
				mock.getSecretValueCalls)
		}
		if _, found, _ := client.cache.Get("db-cred"); !found {
			t.Error("the mapping must survive: the secret still exists")
		}
	})

	// Only the ownership refusal becomes a skip. Every other failure of the
	// gating read stays fail-closed, because without proving what the secret
	// holds we cannot delete one property while preserving its siblings, and
	// such failures can be transient, so a retry is worth something.
	t.Run("property delete fails closed when ownership cannot be read", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listed,
			getSecretDetailFn: func(_ context.Context, _ string) (*NcloudSecretDetailResponse, error) {
				return nil, fmt.Errorf("%w: no permission to read the memo", ErrForbidden)
			},
		}
		client := newMockedClient(mock)
		err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred", property: "k"})
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("DeleteSecret(property) error = %v, want ErrForbidden", err)
		}
		if mock.updateStageCalls != 0 || mock.requestDeletionCalls != 0 || mock.destroyCalls != 0 {
			t.Error("an unreadable secret must not be mutated")
		}
	})

	t.Run("full delete of an unmanaged secret is silently skipped", func(t *testing.T) {
		mock := &countingMockClient{listFn: listed, getSecretDetailFn: unmanagedDetail(secretStatusEnable)}
		client := newMockedClient(mock)
		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"}); err != nil {
			t.Fatalf("DeleteSecret() error = %v, want nil (silent skip)", err)
		}
		if mock.requestDeletionCalls != 0 || mock.destroyCalls != 0 {
			t.Errorf("deletion calls: request=%d destroy=%d; want 0,0", mock.requestDeletionCalls, mock.destroyCalls)
		}
		if _, found, _ := client.cache.Get("db-cred"); !found {
			t.Error("the mapping must survive: the secret still exists")
		}
	})

	// The marker is adopted as a line of its own, which is what lets it
	// coexist with a human description without letting a memo that merely
	// mentions the phrase claim ownership.
	t.Run("an adopted secret keeps its human description", func(t *testing.T) {
		adopted := func(_ context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
			return &NcloudSecretDetailResponse{
				Code: successCode,
				Data: NcloudSecretDetailData{
					SecretID: secretID, SecretStatus: secretStatusEnable,
					Memo: "payments DB creds\n" + managedByMemo,
				},
			}, nil
		}
		mock := &countingMockClient{
			listFn:            listed,
			getSecretDetailFn: adopted,
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(`{"k":"old"}`), nil
			},
			updateStageFn: func(_ context.Context, _, _, _ string) error { return nil },
		}
		client := newMockedClient(mock)
		if err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"}); err != nil {
			t.Fatalf("PushSecret() to an adopted secret error = %v", err)
		}
		if mock.updateStageCalls != 1 {
			t.Errorf("updateStageCalls = %d, want 1", mock.updateStageCalls)
		}
	})
}

// TestIsManagedByESORequiresAWholeLine pins the ownership judgment. The memo
// is free text an operator writes, so containment would hand ownership to a
// negation or to the adoption sentence quoted out of the provider docs, and a
// false positive on the delete gate destroys a secret nobody asked us to own.
func TestIsManagedByESORequiresAWholeLine(t *testing.T) {
	for _, tc := range []struct {
		name string
		memo string
		want bool
	}{
		{"the marker alone", managedByMemo, true},
		{"a description on the line before", "payments DB creds\n" + managedByMemo, true},
		{"a description on the line after", managedByMemo + "\npayments DB creds", true},
		{"surrounding whitespace", "  " + managedByMemo + "  ", true},
		{"windows line endings", "note\r\n" + managedByMemo + "\r\n", true},
		{"a negation", "not " + managedByMemo, false},
		{"the adoption sentence from the docs", "add " + managedByMemo + " to the memo to adopt it", false},
		{"parenthesized on a shared line", "payments DB creds (" + managedByMemo + ")", false},
		{"an empty memo", "", false},
		{"an unrelated memo", "payments DB creds", false},
	} {
		if got := isManagedByESO(tc.memo); got != tc.want {
			t.Errorf("isManagedByESO(%q) = %v, want %v (%s)", tc.memo, got, tc.want, tc.name)
		}
	}
}

// TestPushSecretCreateRejectionNamesTheDeclaredBoundary pins what a rejected
// create tells the user. An endpoint serves one KMS key boundary, so a store
// on the wrong endpoint fails at create with a 400 or 404. The provider adds
// the boundary it declared, keeps the original error in the chain, and leaves
// errors that are not a client-side rejection alone.
func TestPushSecretCreateRejectionNamesTheDeclaredBoundary(t *testing.T) {
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}
	isolatedKey := func(context.Context) (*NcloudProtectionKeyListResponse, error) {
		return &NcloudProtectionKeyListResponse{Data: NcloudProtectionKeyListData{
			KeyList: []NcloudProtectionKeyEntry{{KmsBoundaryType: "ISOLATED"}},
		}}, nil
	}
	pushAgainst := func(t *testing.T, createErr error, keys func(context.Context) (*NcloudProtectionKeyListResponse, error)) error {
		t.Helper()
		mock := &countingMockClient{
			listFn:          listingWith(),
			protectionKeyFn: keys,
			createFn: func(_ context.Context, _ *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
				return nil, createErr
			},
		}
		err := newMockedClient(mock).PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"})
		if err == nil {
			t.Fatal("PushSecret() returned nil error for a rejected create")
		}
		if mock.createCalls != 1 {
			t.Errorf("createCalls = %d, want 1", mock.createCalls)
		}
		return err
	}

	t.Run("a 400 names the declared boundary and keeps the sentinel", func(t *testing.T) {
		wire := fmt.Errorf("%w: ncloud API request failed with status 400 and code 500001", ErrInvalidRequest)
		err := pushAgainst(t, wire, isolatedKey)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("PushSecret() error = %v, want it to wrap ErrInvalidRequest", err)
		}
		if !strings.Contains(err.Error(), "kmsBoundaryType=ISOLATED") {
			t.Errorf("PushSecret() error = %v, want the declared boundary named", err)
		}
	})

	t.Run("a 404 is decorated the same way", func(t *testing.T) {
		wire := fmt.Errorf("%w: ncloud API request failed with status 404 and code 501001", ErrSecretNotFound)
		err := pushAgainst(t, wire, isolatedKey)
		if !errors.Is(err, ErrSecretNotFound) || !strings.Contains(err.Error(), "kmsBoundaryType=ISOLATED") {
			t.Errorf("PushSecret() error = %v, want ErrSecretNotFound wrapped and the boundary named", err)
		}
	})

	t.Run("an omitted boundary is reported as omitted", func(t *testing.T) {
		noKeys := func(context.Context) (*NcloudProtectionKeyListResponse, error) {
			return nil, ErrServiceUnavailable
		}
		err := pushAgainst(t, fmt.Errorf("%w: status 400 and code 500000", ErrInvalidRequest), noKeys)
		if !strings.Contains(err.Error(), "kmsBoundaryType=(omitted)") {
			t.Errorf("PushSecret() error = %v, want kmsBoundaryType=(omitted)", err)
		}
	})

	t.Run("a server-side failure is not blamed on the boundary", func(t *testing.T) {
		err := pushAgainst(t, fmt.Errorf("%w: status 503", ErrServiceUnavailable), isolatedKey)
		if !errors.Is(err, ErrServiceUnavailable) {
			t.Errorf("PushSecret() error = %v, want it to wrap ErrServiceUnavailable", err)
		}
		if strings.Contains(err.Error(), "kmsBoundaryType=") {
			t.Errorf("PushSecret() error = %v, want no boundary decoration on a 5xx", err)
		}
	})

	t.Run("a boundary string this package does not know is not echoed", func(t *testing.T) {
		// The boundary comes from ListProtectionKeys, so it is server text;
		// only known values may reach the controller log.
		oddKey := func(context.Context) (*NcloudProtectionKeyListResponse, error) {
			return &NcloudProtectionKeyListResponse{Data: NcloudProtectionKeyListData{
				KeyList: []NcloudProtectionKeyEntry{{KmsBoundaryType: "<img src=x>"}},
			}}, nil
		}
		err := pushAgainst(t, fmt.Errorf("%w: status 400 and code 500000", ErrInvalidRequest), oddKey)
		if strings.Contains(err.Error(), "<img") || !strings.Contains(err.Error(), "kmsBoundaryType=(unrecognized)") {
			t.Errorf("PushSecret() error = %v, want kmsBoundaryType=(unrecognized) and no server text", err)
		}
	})
}

// TestWriteImpossibleKeysSkipTheListing pins that SecretExists and DeleteSecret
// answer a key no secret can carry without a listing sweep, as PushSecret
// already does: a multi-page account would otherwise pay two full scans and
// record a negative entry for a key that could never resolve.
func TestWriteImpossibleKeysSkipTheListing(t *testing.T) {
	for _, key := range []string{"a-name-longer-than-15-chars", "has space", "1leading-digit"} {
		t.Run(key, func(t *testing.T) {
			mock := &countingMockClient{}
			client := newMockedClient(mock)

			exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: key})
			if err != nil || exists {
				t.Errorf("SecretExists(%q) = %v, %v; want false, nil", key, exists, err)
			}
			if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: key}); err != nil {
				t.Errorf("DeleteSecret(%q) error = %v, want nil (nothing to delete)", key, err)
			}
			if mock.listCalls != 0 {
				t.Errorf("listCalls = %d, want 0: an impossible key must not be looked up", mock.listCalls)
			}
		})
	}
}

// TestPushSecretValueEncodingLeavesHTMLUnescaped pins what actually gets
// stored. The standard library escapes <, > and & when marshaling, so a plain
// json.Marshal would write \u003c into Ncloud and hand it back to anyone
// reading the secret outside ESO. Other providers avoid that through
// esutils.JSONMarshal.
func TestPushSecretValueEncodingLeavesHTMLUnescaped(t *testing.T) {
	const id = "7373737373737373737373737373737373737373737373737373737373737373"
	const raw = `<b>a&b</b>`

	var stored string
	mock := &countingMockClient{
		listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return newSecretValueResponse(`{"other":"keep"}`), nil
		},
		updateStageFn: func(_ context.Context, _, _, value string) error {
			stored = value
			return nil
		},
	}
	client := newMockedClient(mock)
	source := &corev1.Secret{Data: map[string][]byte{"markup": []byte(raw)}}

	if err := client.PushSecret(context.Background(), source, mockPushSecretData{
		remoteKey: "db-cred",
		secretKey: "markup",
		property:  "markup",
	}); err != nil {
		t.Fatalf("PushSecret() error = %v", err)
	}
	if !strings.Contains(stored, raw) {
		t.Errorf("stored value = %s, want it to carry %s verbatim", stored, raw)
	}
	if strings.Contains(stored, `\u003c`) || strings.Contains(stored, `\u0026`) {
		t.Errorf("stored value = %s, want no HTML escaping", stored)
	}
}

// TestPushSecretOccupiedNameStatusIsDescribedNotEchoed keeps the refusal
// actionable while refusing to quote a status the provider cannot place. The
// status is server controlled and the text reaches the controller log, which
// is the same reason handleErrorResponse and doOnce drop server strings.
//
// occupiedNameAdvice rather than occupiedNameError for the table:
// occupiedNameError is reachable only from createSecretLocked, which excludes
// ENABLE and ROTATING before it can be called. The refused-value-read path is
// what sees those, and it goes through the advice.
func TestPushSecretOccupiedNameStatusIsDescribedNotEchoed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status string
		want   string
		absent string
	}{
		{name: "revoke names the way out", status: secretStatusRevoke, want: "Cancel Secret Deletion"},
		{name: "disable names the way out", status: secretStatusDisable, want: "Enable Secret"},
		{name: "a known state is quoted", status: secretStatusEnable, want: `state "ENABLE"`},
		{name: "rotating too", status: secretStatusRotating, want: `state "ROTATING"`},
		{
			name:   "an unknown state is described",
			status: "SOMETHING_NEW",
			want:   "does not recognize",
			absent: "SOMETHING_NEW",
		},
		{
			// Not because a status field is a likely place to find a key, but
			// because the stated reason for refusing server strings is that
			// nothing bounds what they carry.
			name:   "a credential-shaped state is not echoed",
			status: "AKIAIOSFODNN7EXAMPLE",
			want:   "does not recognize",
			absent: "AKIA",
		},
		{
			// classifyListedSecret and createSecretLocked both treat an absent
			// status as ordinary, so calling it unrecognized would contradict
			// them.
			name:   "an absent state says so",
			status: "",
			want:   "the server did not report",
			absent: "does not recognize",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			advice := occupiedNameAdvice(tc.status)
			if !strings.Contains(advice, tc.want) {
				t.Errorf("occupiedNameAdvice(%q) = %q, want it to mention %q", tc.status, advice, tc.want)
			}
			if tc.absent != "" && strings.Contains(advice, tc.absent) {
				t.Errorf("occupiedNameAdvice(%q) = %q, want it NOT to echo %q back", tc.status, advice, tc.absent)
			}
			// The error form still carries the sentinel every caller branches on.
			if err := occupiedNameError(tc.status); !errors.Is(err, ErrInvalidStatus) {
				t.Errorf("occupiedNameError(%q) does not wrap ErrInvalidStatus", tc.status)
			}
		})
	}
}

// TestPushSecretToRevokedNameIsRejected pins the grace-period write semantics:
// a REVOKE secret still occupies its name, so a push to that name must fail
// (until Ncloud finalizes destruction after 7 days) rather than create a
// duplicate that can never take the name.
func TestPushSecretToRevokedNameIsRejected(t *testing.T) {
	const id = "abababababababababababababababababababababababababababababababab"
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}

	// The value read a REVOKE secret answers: 409 as modeled, or 400 with
	// code 501007.
	for name, refusal := range map[string]error{
		"409":             ErrInvalidStatus,
		"400 code 501007": newAPIError(ErrInvalidRequest, http.StatusBadRequest, "501007"),
	} {
		t.Run(name, func(t *testing.T) {
			mock := &countingMockClient{
				listFn: listingWith(NcloudSecretListItem{
					SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusRevoke,
				}),
				getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
					return nil, refusal
				},
				getSecretDetailFn: detailWithStatus(secretStatusRevoke),
			}
			client := newMockedClient(mock)

			err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"})
			if err == nil {
				t.Fatal("PushSecret() to a REVOKE-occupied name should fail")
			}
			if mock.createCalls != 0 {
				t.Errorf("createCalls = %d, want 0 (must not shadow the revoked secret)", mock.createCalls)
			}
			// The ordinary route to a revoked name: the listing resolves it,
			// the update path's value read is refused, and the operator has
			// to be told which state caused it.
			if !errors.Is(err, refusal) {
				t.Errorf("PushSecret() error = %v, want it to wrap the server's refusal", err)
			}
			if !strings.Contains(err.Error(), "Cancel Secret Deletion") {
				t.Errorf("PushSecret() error = %v, want it to name the way out of REVOKE", err)
			}
		})
	}
}

// TestDeleteSecretOwnershipSkipIsVisibleAtDefaultVerbosity pins the one thing
// standing between an operator and a silent non-deletion. Both skips report
// success, so the log line is the only signal that the cleanup did nothing; the
// provider page tells upgraders to look for it. funcr at Verbosity 0 is the
// controller's default level, so a line logged at V(1) would not be recorded
// here.
func TestDeleteSecretOwnershipSkipIsVisibleAtDefaultVerbosity(t *testing.T) {
	const id = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
	listed := listingWith(NcloudSecretListItem{
		SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusEnable,
	})

	for _, tc := range []struct {
		name     string
		ref      mockPushSecretRemoteRef
		wantLine string
	}{
		{
			name:     "full delete",
			ref:      mockPushSecretRemoteRef{remoteKey: "db-cred"},
			wantLine: "skipping deletion of a secret not managed by external-secrets",
		},
		{
			name:     "property delete",
			ref:      mockPushSecretRemoteRef{remoteKey: "db-cred", property: "k"},
			wantLine: "skipping property deletion on a secret not managed by external-secrets",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logged []string
			sink := funcr.New(func(prefix, args string) {
				logged = append(logged, prefix+args)
			}, funcr.Options{Verbosity: 0})

			mock := &countingMockClient{listFn: listed, getSecretDetailFn: unmanagedDetail(secretStatusEnable)}
			client := newMockedClient(mock)

			ctx := ctrllog.IntoContext(context.Background(), sink)
			if err := client.DeleteSecret(ctx, tc.ref); err != nil {
				t.Fatalf("DeleteSecret() error = %v, want nil (silent skip)", err)
			}

			joined := strings.Join(logged, "\n")
			if !strings.Contains(joined, tc.wantLine) {
				t.Errorf("nothing at default verbosity said the deletion was skipped.\ngot: %q\nwant a line containing: %q",
					joined, tc.wantLine)
			}
		})
	}
}

// TestWriteIndexResweepDropsWhatTheAbandonedSweepSaw covers the write index's
// behavior across a re-sweep. First-wins is the right rule inside one sweep: it
// keeps the index and the shared cache naming the secret the caller is about to
// mutate. Carried across a re-sweep it pins whichever ID the sweep being
// retried happened to see, and that sweep is being retried because its pages
// could not be trusted. A later writeIndex.Resolve for that name then answers
// from the index with no server call at all, and DeleteSecret treats a gone ID
// as its success case, so a delete can report success without touching the
// secret the name now addresses.
func TestWriteIndexResweepDropsWhatTheAbandonedSweepSaw(t *testing.T) {
	const (
		barWalk1 = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
		barLater = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
		anchorID = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
		freshID  = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
		vanishID = "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d"
	)
	sweep := 0
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			if pageNo == 1 {
				sweep++
			}
			// "bar" is destroyed and recreated under a new ID by another actor
			// after the first sweep read page 1.
			barID := barWalk1
			if sweep > 1 {
				barID = barLater
			}
			rows := []NcloudSecretListItem{{SecretID: barID, SecretName: "bar", SecretStatus: secretStatusEnable}}
			if sweep == 1 {
				// Seen once and never again: the re-sweep cannot correct an
				// entry it does not encounter, so this is the name that shows
				// whether the stale one was actually dropped.
				rows = append(rows, NcloudSecretListItem{
					SecretID: vanishID, SecretName: "vanish", SecretStatus: secretStatusEnable,
				})
			}
			if pageNo == 2 {
				rows = []NcloudSecretListItem{{SecretID: anchorID, SecretName: "anchor", SecretStatus: secretStatusEnable}}
			}
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: 2, SecretList: rows,
				},
			}, nil
		},
	}
	client := newMockedClient(mock)

	// Sweep 1: resolving a page-2 name reads page 1 on the way and records bar.
	if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, "anchor"); err != nil {
		t.Fatalf("writeIndex.Resolve(anchor) error = %v", err)
	}
	// A create in this reconcile. The listing need not show it yet, which is
	// the only reason this record exists.
	client.writes.Pin("fresh", freshID)

	// Resolving a missing name forces the sweep to be repeated and agreed.
	if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, "ghost"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("writeIndex.Resolve(ghost) error = %v, want ErrSecretNotFound", err)
	}
	if sweep < 2 {
		t.Fatalf("the listing was swept %d time(s); the test needs a re-sweep to mean anything", sweep)
	}

	// The sweep warms the shared name -> ID cache alongside the index, and a
	// read trusts that without re-checking. A name the re-sweep never saw again
	// is the case the index alone cannot correct: if that ID now belongs to a
	// different live secret, the read answers with its value and no error.
	if cached, found, _ := client.cache.Get("vanish"); found {
		t.Errorf("the read cache still names %s for a secret only the abandoned sweep saw", cached)
	}

	calls := mock.listCalls
	barID, err := client.writes.Resolve(context.Background(), client.client, client.cache, "bar")
	if err != nil {
		t.Fatalf("writeIndex.Resolve(bar) error = %v", err)
	}
	if barID == barWalk1 {
		t.Errorf("writeIndex.Resolve(bar) = the ID the abandoned sweep saw; the re-sweep read %s", barLater)
	}
	if barID != barLater {
		t.Errorf("writeIndex.Resolve(bar) = %s, want %s", barID, barLater)
	}

	fresh, err := client.writes.Resolve(context.Background(), client.client, client.cache, "fresh")
	if err != nil {
		t.Fatalf("writeIndex.Resolve(fresh) error = %v", err)
	}
	if fresh != freshID {
		t.Errorf("writeIndex.Resolve(fresh) = %s, want %s; a re-sweep dropped what a create recorded", fresh, freshID)
	}
	if mock.listCalls != calls {
		t.Errorf("the index lookups cost %d extra list calls, want 0", mock.listCalls-calls)
	}
}

// TestWriteIndexForgetUnpinsACreatedName pins the other half of the index's
// two maps staying in step. A create marks its name so a re-sweep keeps it; a
// delete has to clear that mark, or the name goes on being treated as this
// reconcile's own creation after the secret behind it is gone, and the next
// listing observation of that name inherits protection it never earned.
func TestWriteIndexForgetUnpinsACreatedName(t *testing.T) {
	const (
		created  = "1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d"
		anchorID = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
	)
	// A distinct ID per sweep, so the index says which sweep it is holding.
	barOfWalk := []string{
		"1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b",
		"1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c",
		"1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e",
	}
	sweep := 0
	lastBar := ""
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			if pageNo == 1 {
				sweep++
				lastBar = barOfWalk[min(sweep, len(barOfWalk))-1]
			}
			rows := []NcloudSecretListItem{{
				SecretID: lastBar, SecretName: "bar", SecretStatus: secretStatusEnable,
			}}
			if pageNo == 2 {
				rows = []NcloudSecretListItem{{SecretID: anchorID, SecretName: "anchor", SecretStatus: secretStatusEnable}}
			}
			// Sweep 2 shifts underneath itself, so it is abandoned AFTER it has
			// already observed the name. That is the only shape in which a
			// stale creation mark can shield an observation.
			total := 2
			if sweep == 2 {
				total = 2 + pageNo
			}
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: total, SecretList: rows,
				},
			}, nil
		},
	}
	client := newMockedClient(mock)

	// This reconcile creates "bar" and then deletes it. Another actor creates a
	// secret of its own under the freed name, which the sweeps below observe.
	if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, "bar"); err != nil {
		t.Fatalf("writeIndex.Resolve(bar) error = %v", err)
	}
	client.writes.Pin("bar", created)
	client.writes.Forget(created)

	// Leaves the index mid-listing, so the verdict costs several sweeps and the
	// name is observed again before one of the discards. The verdict itself is
	// not the point here: what matters is which sweep the index is left holding.
	if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, "ghost"); err == nil {
		t.Fatal("writeIndex.Resolve(ghost) found a name the listing never carried")
	}
	if sweep < 3 {
		t.Fatalf("the listing was swept %d time(s); the test needs the name re-observed before a discard", sweep)
	}

	got, err := client.writes.Resolve(context.Background(), client.client, client.cache, "bar")
	if err != nil {
		t.Fatalf("writeIndex.Resolve(bar) error = %v", err)
	}
	if got != lastBar {
		t.Errorf("writeIndex.Resolve(bar) = %s, want the last sweep's %s; a deleted creation still shields the name from a re-sweep",
			got, lastBar)
	}
}

// TestWriteIndexPromotesTheLiveRowShadowedByAStaleEntry pins what happens when
// an index entry outlives the sweep it came from (kept across a Forget rewind,
// or pinned by this reconcile's create) and the listing then shows the name
// recreated: a live row under a new ID, and the old secret's DESTROYED row. The
// live row cannot replace the entry (first wins), and the DESTROYED row drops
// the entry; without the shadow the name is gone from the index, the live
// secret resolves as absent for the rest of the reconcile, DeleteSecret
// reports success without touching it, and the shared cache records an
// absence every read trusts for the negative TTL.
func TestWriteIndexPromotesTheLiveRowShadowedByAStaleEntry(t *testing.T) {
	const (
		name   = "web-cred"
		oldID  = "4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a"
		newID  = "4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b"
		doomed = "4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c"
		filler = "4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d"
	)

	// onePage serves a single page: before the replacement, doomed and the
	// old secret; after it, doomed in REVOKE, the live replacement, and the
	// old secret's DESTROYED row listed behind it.
	onePage := func(replaced *bool) *countingMockClient {
		return &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				rows := []NcloudSecretListItem{
					{SecretID: doomed, SecretName: "doomed", SecretStatus: secretStatusEnable},
					{SecretID: oldID, SecretName: name, SecretStatus: secretStatusEnable},
				}
				if *replaced {
					rows = []NcloudSecretListItem{
						{SecretID: doomed, SecretName: "doomed", SecretStatus: secretStatusRevoke},
						{SecretID: newID, SecretName: name, SecretStatus: secretStatusEnable},
						{SecretID: oldID, SecretName: name, SecretStatus: secretStatusDestroyed},
					}
				}
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{TotalPageNo: 1, CurrentPageNo: pageNo, TotalCount: len(rows), SecretList: rows},
				}, nil
			},
			getSecretDetailFn: detailWithStatus(secretStatusEnable),
			requestDeletionFn: func(_ context.Context, _ string) error { return nil },
		}
	}

	assertLiveWins := func(t *testing.T, client *Client, mock *countingMockClient) {
		t.Helper()
		got, err := client.writes.Resolve(context.Background(), client.client, client.cache, name)
		if err != nil {
			t.Fatalf("writeIndex.Resolve(%s) = %v; the listing holds a live row under %s", name, err, newID)
		}
		if got != newID {
			t.Errorf("writeIndex.Resolve(%s) = %s, want the live %s", name, got, newID)
		}
		if cached, found, negative := client.cache.Get(name); !found || negative || cached != newID {
			t.Errorf("shared cache = (%q, %v, %v), want the promoted live mapping to %s", cached, found, negative, newID)
		}
		deletions := mock.requestDeletionCalls
		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: name}); err != nil {
			t.Fatalf("DeleteSecret(%s) error = %v", name, err)
		}
		if mock.requestDeletionCalls != deletions+1 {
			t.Errorf("DeleteSecret(%s) issued %d deletion requests, want 1 for the live %s", name, mock.requestDeletionCalls-deletions, newID)
		}
	}

	t.Run("entry kept across a Forget rewind", func(t *testing.T) {
		replaced := false
		mock := onePage(&replaced)
		client := newMockedClient(mock)

		// Sweep 1 records the old mapping while resolving another name.
		if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, "doomed"); err != nil {
			t.Fatalf("writeIndex.Resolve(doomed) error = %v", err)
		}
		// A delete in this reconcile rewinds the sweep and keeps what it
		// observed (see TestWriteIndexForgetKeepsWhatItAlreadyResolved).
		replaced = true
		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "doomed"}); err != nil {
			t.Fatalf("DeleteSecret(doomed) error = %v", err)
		}
		// Sweep 2, for an unrelated absent name, reads the page holding both
		// rows of the replaced name.
		if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, "ghost"); !errors.Is(err, ErrSecretNotFound) {
			t.Fatalf("writeIndex.Resolve(ghost) error = %v, want ErrSecretNotFound", err)
		}
		assertLiveWins(t, client, mock)
	})

	t.Run("entry pinned by this reconcile's create", func(t *testing.T) {
		replaced := false
		mock := onePage(&replaced)
		client := newMockedClient(mock)

		client.writes.Pin(name, oldID)
		replaced = true
		if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, "ghost"); !errors.Is(err, ErrSecretNotFound) {
			t.Fatalf("writeIndex.Resolve(ghost) error = %v, want ErrSecretNotFound", err)
		}
		assertLiveWins(t, client, mock)
	})

	t.Run("live replacement on page 1, destroyed row on page 2", func(t *testing.T) {
		// Two pages, so an absence needs a confirming sweep. The replacement
		// lands between the first sweep and its repeat: the repeat is what
		// confirms, so nothing re-reads the pages after it, and the shadow has
		// to carry the live row from page 1 to the DESTROYED row on page 2.
		sweeps := 0
		mock := &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				if pageNo == 1 {
					sweeps++
				}
				var page1, page2 []NcloudSecretListItem
				if sweeps <= 1 {
					page1 = []NcloudSecretListItem{{SecretID: oldID, SecretName: name, SecretStatus: secretStatusEnable}}
					page2 = []NcloudSecretListItem{{SecretID: filler, SecretName: "filler", SecretStatus: secretStatusEnable}}
				} else {
					page1 = []NcloudSecretListItem{{SecretID: newID, SecretName: name, SecretStatus: secretStatusEnable}}
					page2 = []NcloudSecretListItem{
						{SecretID: oldID, SecretName: name, SecretStatus: secretStatusDestroyed},
						{SecretID: filler, SecretName: "filler", SecretStatus: secretStatusEnable},
					}
				}
				rows := page1
				if pageNo == 2 {
					rows = page2
				}
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: len(page1) + len(page2), SecretList: rows},
				}, nil
			},
			getSecretDetailFn: detailWithStatus(secretStatusEnable),
			requestDeletionFn: func(_ context.Context, _ string) error { return nil },
		}
		client := newMockedClient(mock)

		client.writes.Pin(name, oldID)
		if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, "ghost"); !errors.Is(err, ErrSecretNotFound) {
			t.Fatalf("writeIndex.Resolve(ghost) error = %v, want ErrSecretNotFound", err)
		}
		if sweeps != 2 {
			t.Fatalf("the listing was swept %d time(s); the test needs the replacement read by the confirming sweep", sweeps)
		}
		assertLiveWins(t, client, mock)
	})
}

// TestWriteIndexShadowBelongsToItsSweep pins the three rules that keep the
// shadow (see writeIndex.shadowed) from promoting a row the listing no longer
// vouches for. Each subtest pins name to an old secret, so the live rows the
// listing shows under the name are shadowed rather than recorded, then sweeps
// for an unrelated absent name and checks what the index resolves the name
// to afterwards.
func TestWriteIndexShadowBelongsToItsSweep(t *testing.T) {
	const (
		name    = "web-cred"
		oldID   = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
		firstID = "5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b"
		laterID = "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c"
		otherID = "5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d"
	)
	row := func(id, rowName, status string) NcloudSecretListItem {
		return NcloudSecretListItem{SecretID: id, SecretName: rowName, SecretStatus: status}
	}
	// pages serves one declared page per sweep: the n-th sweep reads
	// sweeps[n-1], and the last one repeats.
	pages := func(sweeps ...[]NcloudSecretListItem) *countingMockClient {
		n := 0
		return &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				if pageNo == 1 && n < len(sweeps) {
					n++
				}
				rows := sweeps[n-1]
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{TotalPageNo: 1, CurrentPageNo: pageNo, TotalCount: len(rows), SecretList: rows},
				}, nil
			},
		}
	}
	resolve := func(t *testing.T, client *Client, key string) (string, error) {
		t.Helper()
		return client.writes.Resolve(context.Background(), client.client, client.cache, key)
	}

	t.Run("a rewind discards the shadow its sweep recorded", func(t *testing.T) {
		// Sweep 1 shadows a live row under the name. A Forget rewinds the
		// sweep before the old secret's DESTROYED row turns up, and sweep 2
		// lists only that row: the shadowed secret is gone too, so the name
		// must resolve as absent, not to the shadow sweep 1 left behind.
		client := newMockedClient(pages(
			[]NcloudSecretListItem{row(otherID, "other", secretStatusEnable), row(firstID, name, secretStatusEnable)},
			[]NcloudSecretListItem{row(oldID, name, secretStatusDestroyed)},
		))
		client.writes.Pin(name, oldID)
		if _, err := resolve(t, client, "other"); err != nil {
			t.Fatalf("Resolve(other) error = %v", err)
		}
		client.writes.Forget(otherID)
		if _, err := resolve(t, client, "ghost"); !errors.Is(err, ErrSecretNotFound) {
			t.Fatalf("Resolve(ghost) error = %v, want ErrSecretNotFound", err)
		}
		if got, err := resolve(t, client, name); !errors.Is(err, ErrSecretNotFound) {
			t.Errorf("Resolve(%s) = (%s, %v), want ErrSecretNotFound: %s is not in the current listing", name, got, err, firstID)
		}
	})

	t.Run("the first live row is the one promoted", func(t *testing.T) {
		// Two live rows under the name, then the old secret's DESTROYED row:
		// the promotion follows first-wins, as every other resolver does.
		client := newMockedClient(pages([]NcloudSecretListItem{
			row(firstID, name, secretStatusEnable),
			row(laterID, name, secretStatusEnable),
			row(oldID, name, secretStatusDestroyed),
		}))
		client.writes.Pin(name, oldID)
		if _, err := resolve(t, client, "ghost"); !errors.Is(err, ErrSecretNotFound) {
			t.Fatalf("Resolve(ghost) error = %v, want ErrSecretNotFound", err)
		}
		if got, err := resolve(t, client, name); err != nil || got != firstID {
			t.Errorf("Resolve(%s) = (%s, %v), want the first live row %s", name, got, err, firstID)
		}
	})

	t.Run("a promoted row that turns up DESTROYED is not promoted again", func(t *testing.T) {
		// The shadow is promoted by the old secret's DESTROYED row, and the
		// promoted secret's own DESTROYED row follows on the same page. That
		// lists one ID twice, so the sweep can conclude no absence (see
		// listSweep.incomplete), but a key found live on the page is answered
		// before the sweep is judged, and the index it leaves must not hand
		// the name to the destroyed secret.
		client := newMockedClient(pages([]NcloudSecretListItem{
			row(firstID, name, secretStatusEnable),
			row(oldID, name, secretStatusDestroyed),
			row(firstID, name, secretStatusDestroyed),
			row(otherID, "other", secretStatusEnable),
		}))
		client.writes.Pin(name, oldID)
		if got, err := resolve(t, client, "other"); err != nil || got != otherID {
			t.Fatalf("Resolve(other) = (%s, %v), want %s", got, err, otherID)
		}
		if got, ok := client.writes.names[name]; ok && got == firstID {
			t.Errorf("write index maps %s to %s, which was destroyed after its promotion", name, got)
		}
	})
}

// TestWriteIndexResolvesPastARevokedNameToTheLiveSecret is the write half of
// TestResolveSecretIDLooksPastARevokedNameToTheLiveSecret. The write path may
// resolve to a REVOKE secret, because DeleteSecret finalizes from there and a
// conflicting create has to fail with a reason - but only when no live row
// holds the name. Preferring the tombstone over a live namesake makes
// DeleteSecret report success without issuing a deletion call at all, so a
// PushSecret with deletionPolicy Delete drops its finalizer while the remote
// secret is still there.
func TestWriteIndexResolvesPastARevokedNameToTheLiveSecret(t *testing.T) {
	const (
		revoked   = "3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a"
		live      = "4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b"
		unrelated = "6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d"
	)
	// Split across pages as well, because the index is built page by page: the
	// tombstone's claim has to stay provisional until the sweep has looked.
	for _, tc := range []struct {
		name  string
		pages map[int][]NcloudSecretListItem
	}{
		{name: "both rows on one page", pages: map[int][]NcloudSecretListItem{1: {
			{SecretID: revoked, SecretName: "dup", SecretStatus: secretStatusRevoke},
			{SecretID: live, SecretName: "dup", SecretStatus: secretStatusEnable},
		}}},
		{name: "the live row is a page later", pages: map[int][]NcloudSecretListItem{
			1: {{SecretID: revoked, SecretName: "dup", SecretStatus: secretStatusRevoke}},
			2: {{SecretID: live, SecretName: "dup", SecretStatus: secretStatusEnable}},
		}},
		// The sweep stops on page 1 for an unrelated name, so the tombstone's
		// claim is all the index holds when the next call asks. Answering from
		// it there would never read the page the live row is on.
		{name: "the sweep stopped before reaching the live row", pages: map[int][]NcloudSecretListItem{
			1: {
				{SecretID: unrelated, SecretName: "other", SecretStatus: secretStatusEnable},
				{SecretID: revoked, SecretName: "dup", SecretStatus: secretStatusRevoke},
			},
			2: {{SecretID: live, SecretName: "dup", SecretStatus: secretStatusEnable}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pages := len(tc.pages)
			newMock := func() *countingMockClient {
				return &countingMockClient{
					listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
						return &NcloudListSecretsResponse{
							Code: successCode,
							Data: NcloudListSecretsData{
								TotalPageNo: pages, CurrentPageNo: pageNo, TotalCount: 2,
								SecretList: tc.pages[pageNo],
							},
						}, nil
					},
					getSecretDetailFn: detailWithStatus(secretStatusEnable),
					requestDeletionFn: func(_ context.Context, secretID string) error {
						if secretID != live {
							t.Errorf("RequestSecretDeletion(%s), want the live secret %s", secretID, live)
						}
						return nil
					},
				}
			}

			resolver := newMockedClient(newMock())
			// Resolving the page-1 name first leaves the sweep parked there,
			// which is what makes the tombstone the only thing the index has.
			if tc.pages[1][0].SecretName == "other" {
				if _, err := resolver.writes.Resolve(context.Background(), resolver.client, resolver.cache, "other"); err != nil {
					t.Fatalf("writeIndex.Resolve(other) error = %v", err)
				}
			}
			got, err := resolver.writes.Resolve(context.Background(), resolver.client, resolver.cache, "dup")
			if err != nil {
				t.Fatalf("writeIndex.Resolve() error = %v", err)
			}
			if got != live {
				t.Errorf("writeIndex.Resolve() = %s, want the live secret %s", got, live)
			}
			// The second resolution is the one that reads the index rather than
			// the listing, so it is where a tombstone left in the index shows up.
			again, err := resolver.writes.Resolve(context.Background(), resolver.client, resolver.cache, "dup")
			if err != nil {
				t.Fatalf("second writeIndex.Resolve() error = %v", err)
			}
			if again != got {
				t.Errorf("second writeIndex.Resolve() = %s, first said %s; the index kept the tombstone", again, got)
			}

			mock := newMock()
			client := newMockedClient(mock)
			if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "dup"}); err != nil {
				t.Fatalf("DeleteSecret() error = %v", err)
			}
			if mock.requestDeletionCalls != 1 {
				t.Errorf("DeleteSecret issued %d deletion calls, want 1; it reported success without deleting anything",
					mock.requestDeletionCalls)
			}
		})
	}
}

// TestWriteIndexHoldsARevokedNameToTheStabilityBar is the write-path half of
// listingRowFor's rule that a REVOKE row must clear the same bar as an absence.
// The first sweep sees only the REVOKE row while the listing grows under it, so
// the live secret that holds the name may be on a page the sweep read before
// the row arrived. Answering with the REVOKE row there would finish a delete
// without touching the live secret, and the finalizer would let the PushSecret
// go while the remote secret stays.
func TestWriteIndexHoldsARevokedNameToTheStabilityBar(t *testing.T) {
	const (
		revoked = "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c"
		live    = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"
		other   = "8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e"
	)
	newMock := func(t *testing.T) (*countingMockClient, *int) {
		sweeps := 0
		return &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				if pageNo == 1 {
					sweeps++
				}
				// The first sweep reads page 1 before the live secret is
				// listed and page 2 after, so its declared total moves
				// between pages.
				rows := map[int][]NcloudSecretListItem{
					1: {{SecretID: revoked, SecretName: "dup", SecretStatus: secretStatusRevoke}},
					2: {
						{SecretID: other, SecretName: "other", SecretStatus: secretStatusEnable},
						{SecretID: live, SecretName: "dup", SecretStatus: secretStatusEnable},
					},
				}
				total := 3
				if sweeps == 1 {
					rows[2] = rows[2][:1]
					if pageNo == 1 {
						total = 2
					}
				}
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{
						TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: total,
						SecretList: rows[pageNo],
					},
				}, nil
			},
			getSecretDetailFn: func(_ context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
				status := secretStatusEnable
				if secretID == revoked {
					status = secretStatusRevoke
				}
				return detailWithStatus(status)(context.Background(), secretID)
			},
			requestDeletionFn: func(_ context.Context, secretID string) error {
				if secretID != live {
					t.Errorf("RequestSecretDeletion(%s), want the live secret %s", secretID, live)
				}
				return nil
			},
		}, &sweeps
	}
	for _, tc := range []struct {
		name string
		// first is resolved before the delete. Resolving "other" finishes the
		// shifting sweep on a live match, so the REVOKE row is already in the
		// index when the delete asks, and the answer comes from the index
		// rather than from a sweep.
		first string
	}{
		{name: "the delete runs the sweep"},
		{name: "the index already holds the REVOKE row", first: "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock, sweeps := newMock(t)
			client := newMockedClient(mock)
			if tc.first != "" {
				if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, tc.first); err != nil {
					t.Fatalf("writeIndex.Resolve(%s) error = %v", tc.first, err)
				}
			}
			if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "dup"}); err != nil {
				t.Fatalf("DeleteSecret() error = %v", err)
			}
			if mock.requestDeletionCalls != 1 {
				t.Errorf("DeleteSecret issued %d deletion calls after %d sweeps, want 1; the REVOKE row "+
					"from the sweep that shifted was taken as the answer", mock.requestDeletionCalls, *sweeps)
			}
		})
	}
}

// TestWriteIndexForgetDropsTheRevokedClaims covers the REVOKE entries a
// Forget leaves behind. They answer only on a confirmed sweep, Forget withdraws
// the confirmation, and a one-page re-sweep is confirmed on its first pass
// without clearing what the earlier sweep recorded. A REVOKE row that left the
// listing in between must not answer for the name then.
func TestWriteIndexForgetDropsTheRevokedClaims(t *testing.T) {
	const (
		revoked = "1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d"
		live    = "2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e"
		other   = "3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f"
	)
	rows := []NcloudSecretListItem{
		{SecretID: revoked, SecretName: "dup", SecretStatus: secretStatusRevoke},
		{SecretID: live, SecretName: "x", SecretStatus: secretStatusEnable},
	}
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 1, CurrentPageNo: pageNo, TotalCount: len(rows), SecretList: rows,
				},
			}, nil
		},
	}
	client := newMockedClient(mock)
	ctx := context.Background()
	if got, err := client.writes.Resolve(ctx, client.client, client.cache, "x"); err != nil || got != live {
		t.Fatalf("writeIndex.Resolve(x) = %s, %v; want %s", got, err, live)
	}
	client.writes.Forget(live)
	rows = []NcloudSecretListItem{{SecretID: other, SecretName: "other", SecretStatus: secretStatusEnable}}

	got, err := client.writes.Resolve(ctx, client.client, client.cache, "dup")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("writeIndex.Resolve(dup) = %s, %v; want ErrSecretNotFound, the REVOKE row is no longer listed", got, err)
	}
}

// TestWriteIndexForgetRewindsTheSweep covers what a completed sweep is
// evidence OF. The index's absence verdict rests on it: a name a finished sweep
// never recorded is a name the listing did not carry. That reasoning survives
// only while the sweep still describes the account, and a delete this reconcile
// performed is exactly what ends that.
//
// The sequence is ordinary. Property-mode pushes call DeleteSecret more than
// once for one remote key in a single reconcile, so delete-then-resolve on the
// same name is routine rather than contrived.
func TestWriteIndexForgetRewindsTheSweep(t *testing.T) {
	const shared = "7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"

	deleted := false
	status := func() string {
		if deleted {
			return secretStatusRevoke
		}
		return secretStatusEnable
	}
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 1, CurrentPageNo: pageNo, TotalCount: 1,
					SecretList: []NcloudSecretListItem{
						{SecretID: shared, SecretName: "shared", SecretStatus: status()},
					},
				},
			}, nil
		},
		getSecretDetailFn: func(_ context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
			return &NcloudSecretDetailResponse{
				Code: successCode,
				Data: NcloudSecretDetailData{SecretID: secretID, SecretStatus: status(), Memo: managedByMemo},
			}, nil
		},
		requestDeletionFn: func(_ context.Context, _ string) error {
			deleted = true
			return nil
		},
	}
	client := newMockedClient(mock)

	if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, "shared"); err != nil {
		t.Fatalf("writeIndex.Resolve() error = %v", err)
	}
	if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "shared"}); err != nil {
		t.Fatalf("DeleteSecret() error = %v", err)
	}

	swept := mock.listCalls
	got, err := client.writes.Resolve(context.Background(), client.client, client.cache, "shared")
	if mock.listCalls == swept {
		t.Error("the second resolution read no page at all; it answered from a sweep taken before the delete")
	}
	// The row is REVOKE now, and REVOKE holds its name: that is what the write
	// path resolves to when nothing live holds it. Absence is the one answer
	// that is wrong, because it is the answer that gets cached.
	if err != nil {
		t.Errorf("writeIndex.Resolve() after the delete = %v, want the revoked secret still holding the name", err)
	}
	if got != shared {
		t.Errorf("writeIndex.Resolve() = %s, want %s", got, shared)
	}
	if _, found, negative := client.cache.Get("shared"); found && negative {
		t.Error("a name held by a secret in its recovery window was negative-cached into the shared cache")
	}

	t.Run("the next absence is corroborated from scratch", func(t *testing.T) {
		// An absence verdict rests on two sweeps that agree. Both of those
		// sweeps have to describe the account as it is after the delete, so
		// neither the agreement nor the page counts behind it carry over.
		const other = "8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f"
		pageMock := &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				rows := []NcloudSecretListItem{{SecretID: other, SecretName: "other", SecretStatus: secretStatusEnable}}
				if pageNo == 2 {
					rows = nil
				}
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{
						TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: 1, SecretList: rows,
					},
				}, nil
			},
			getSecretDetailFn: detailWithStatus(secretStatusEnable),
			requestDeletionFn: func(_ context.Context, _ string) error { return nil },
		}
		pageClient := newMockedClient(pageMock)

		// One absence conclusion, which is what licenses later ones.
		if _, err := pageClient.writes.Resolve(context.Background(), pageClient.client, pageClient.cache, "ghost"); !errors.Is(err, ErrSecretNotFound) {
			t.Fatalf("writeIndex.Resolve(ghost) error = %v, want ErrSecretNotFound", err)
		}
		corroborated := pageMock.listCalls
		if corroborated != 4 {
			t.Fatalf("the first absence cost %d list calls, want 4 (two two-page sweeps)", corroborated)
		}

		if err := pageClient.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "other"}); err != nil {
			t.Fatalf("DeleteSecret() error = %v", err)
		}

		before := pageMock.listCalls
		if _, err := pageClient.writes.Resolve(context.Background(), pageClient.client, pageClient.cache, "ghost-two"); !errors.Is(err, ErrSecretNotFound) {
			// A sweep left describing the earlier sweep double-counts the pages
			// it re-reads, which surfaces here as a spurious instability.
			t.Fatalf("writeIndex.Resolve(ghost-two) error = %v, want ErrSecretNotFound", err)
		}
		if got := pageMock.listCalls - before; got != 4 {
			t.Errorf("the absence after the delete cost %d list calls, want 4; it leaned on an agreement reached before the delete", got)
		}

		// A purge that removed nothing changed nothing, so it must not spend a
		// sweep. Reads call forgetResolutionByID for every tombstone they list,
		// and a Client that both reads and writes would otherwise re-sweep the
		// whole listing once per tombstone on the account.
		settled := pageMock.listCalls
		pageClient.forgetResolutionByID("9999999999999999999999999999999999999999999999999999999999999999")
		if _, err := pageClient.writes.Resolve(context.Background(), pageClient.client, pageClient.cache, "ghost-three"); !errors.Is(err, ErrSecretNotFound) {
			t.Fatalf("writeIndex.Resolve(ghost-three) error = %v, want ErrSecretNotFound", err)
		}
		if got := pageMock.listCalls - settled; got != 0 {
			t.Errorf("a purge of an ID the index never held cost %d list calls, want 0", got)
		}
	})
}

// TestWriteIndexPurgeInsideASweepKeepsItsStabilityCounts guards the seam
// between the two reasons the index drops an entry. A delete that this
// reconcile performed invalidates the sweep, because the account no longer
// matches it. A purge of a DESTROYED row that the sweep itself just listed does
// not: it is part of reading the listing, and resetting the sweep there erases
// the stability evidence of every page already read, leaving a sweep that
// shifted underneath itself looking like a fresh single-page sweep.
func TestWriteIndexPurgeInsideASweepKeepsItsStabilityCounts(t *testing.T) {
	const (
		reused = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"
		other  = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"
	)
	// The sweep records the secret on page 1 and meets its own tombstone on
	// page 2, so the purge fires mid-sweep. The declared size collapses from 9
	// to 1 across the sweep, which is the shift that must be reported.
	rows := map[int][]NcloudSecretListItem{
		1: {{SecretID: reused, SecretName: "aaa", SecretStatus: secretStatusEnable}},
		2: {{SecretID: reused, SecretName: "aaa", SecretStatus: secretStatusDestroyed}},
		3: {{SecretID: other, SecretName: "bbb", SecretStatus: secretStatusEnable}},
	}
	totals := map[int]int{1: 9, 2: 9, 3: 1}
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 3, CurrentPageNo: pageNo,
					TotalCount: totals[pageNo], SecretList: rows[pageNo],
				},
			}, nil
		},
	}
	client := newMockedClient(mock)

	_, err := client.writes.Resolve(context.Background(), client.client, client.cache, "ghost")
	if !errors.Is(err, ErrListingUnstable) {
		t.Errorf("writeIndex.Resolve() error = %v after %d list calls, want ErrListingUnstable; "+
			"the mid-sweep purge erased what the earlier pages had established", err, mock.listCalls)
	}
	if _, found, negative := client.cache.Get("ghost"); found && negative {
		t.Error("a verdict from a listing that shifted underneath the sweep was negative-cached process-wide")
	}
}

// TestWriteIndexSweepNeverCachesARevokedName is the write-path half of the rule
// TestResolveSecretIDLooksPastARevokedNameToTheLiveSecret states for reads. The
// write index may hold a REVOKE row; the name -> ID cache it shares with every
// reader may not, because a read that lands there reports the name as absent
// while a live secret is serving it. Asserting it needs a sweep that parks
// before the live row, since a sweep that reaches the live row corrects the
// cache anyway.
func TestWriteIndexSweepNeverCachesARevokedName(t *testing.T) {
	const (
		revoked = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"
		live    = "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
		anchor  = "e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3"
	)
	const tail = "f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4"
	pages := map[int][]NcloudSecretListItem{
		1: {
			{SecretID: anchor, SecretName: "other", SecretStatus: secretStatusEnable},
			{SecretID: revoked, SecretName: "dup", SecretStatus: secretStatusRevoke},
		},
		2: {
			{SecretID: live, SecretName: "dup", SecretStatus: secretStatusEnable},
			{SecretID: tail, SecretName: "xx", SecretStatus: secretStatusEnable},
		},
		3: {{SecretID: tail, SecretName: "yy", SecretStatus: secretStatusEnable}},
	}
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 3, CurrentPageNo: pageNo, TotalCount: 5, SecretList: pages[pageNo],
				},
			}, nil
		},
	}
	client := newMockedClient(mock)

	// Parks the sweep on page 1, with the tombstone recorded and the live row
	// on a page nobody has read.
	if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, "other"); err != nil {
		t.Fatalf("writeIndex.Resolve(other) error = %v", err)
	}
	if cached, found, _ := client.cache.Get("dup"); found {
		t.Errorf("the shared read cache names %s for dup; a read would report the name absent", cached)
	}

	// Reading on to page 2 for an unrelated name passes the live row, which
	// takes the entry over. The mark has to go with it: left behind, it keeps
	// calling a live entry provisional, and the next resolution of that name
	// pays for the rest of the listing to re-learn what the index already knows.
	if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, "xx"); err != nil {
		t.Fatalf("writeIndex.Resolve(xx) error = %v", err)
	}

	calls := mock.listCalls
	got, err := client.writes.Resolve(context.Background(), client.client, client.cache, "dup")
	if err != nil {
		t.Fatalf("writeIndex.Resolve(dup) error = %v", err)
	}
	if got != live {
		t.Errorf("writeIndex.Resolve(dup) = %s, want the live secret %s", got, live)
	}
	if spent := mock.listCalls - calls; spent != 0 {
		t.Errorf("answering from the index cost %d list calls, want 0; the mark outlived the entry it describes", spent)
	}
}

// TestWriteIndexForgetKeepsWhatItAlreadyResolved pins the half of the sweep
// invalidation that is a deliberate NON-action. A delete ends the sweep's claim
// to describe the account; it does not make what the index already resolved
// untrue. Discarding those entries as well is the riskier direction, not the
// safer one: one remote key would then resolve to two different secrets inside
// a single reconcile, which is what the index exists to stop.
func TestWriteIndexForgetKeepsWhatItAlreadyResolved(t *testing.T) {
	const (
		keepBefore = "a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7"
		keepAfter  = "b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8"
		doomed     = "c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9"
	)
	// Another actor replaces "keep" behind our back. Everything this reconcile
	// already resolved has to go on meaning what it meant.
	replaced := false
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			keep := keepBefore
			if replaced {
				keep = keepAfter
			}
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 1, CurrentPageNo: pageNo, TotalCount: 2,
					SecretList: []NcloudSecretListItem{
						{SecretID: keep, SecretName: "keep", SecretStatus: secretStatusEnable},
						{SecretID: doomed, SecretName: "doomed", SecretStatus: secretStatusEnable},
					},
				},
			}, nil
		},
		getSecretDetailFn: detailWithStatus(secretStatusEnable),
		requestDeletionFn: func(_ context.Context, _ string) error { return nil },
	}
	client := newMockedClient(mock)

	first, err := client.writes.Resolve(context.Background(), client.client, client.cache, "keep")
	if err != nil || first != keepBefore {
		t.Fatalf("writeIndex.Resolve(keep) = %s, %v; want %s", first, err, keepBefore)
	}

	replaced = true
	if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "doomed"}); err != nil {
		t.Fatalf("DeleteSecret(doomed) error = %v", err)
	}

	again, err := client.writes.Resolve(context.Background(), client.client, client.cache, "keep")
	if err != nil {
		t.Fatalf("writeIndex.Resolve(keep) after the delete error = %v", err)
	}
	if again != first {
		t.Errorf("writeIndex.Resolve(keep) = %s, first said %s; one key resolved to two secrets in one reconcile", again, first)
	}
}

// TestDeleteSecretRefusalDoesNotEchoTheServersStatus drives the delete refusal
// through DeleteSecret rather than rendering the message here. Asserting on a
// locally built string only proves describeSecretStatus sanitizes its own
// output, which it does by construction; it says nothing about whether the
// call site passes the raw status, which is what this guards.
func TestDeleteSecretRefusalDoesNotEchoTheServersStatus(t *testing.T) {
	const id = "5656565656565656565656565656565656565656565656565656565656565656"

	for _, tc := range []struct {
		name   string
		status string
		want   string
		absent string
	}{
		{
			name:   "a known state is quoted",
			status: secretStatusRotating,
			want:   `state "ROTATING"`,
		},
		{
			name:   "an unknown state is described",
			status: "AKIAIOSFODNN7EXAMPLE",
			want:   "does not recognize",
			absent: "AKIA",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &countingMockClient{
				listFn: listingWith(NcloudSecretListItem{
					SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusEnable,
				}),
				getSecretDetailFn: detailWithStatus(tc.status),
			}
			client := newMockedClient(mock)

			err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
			if err == nil {
				t.Fatalf("DeleteSecret() in status %q should be refused", tc.status)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("DeleteSecret() error = %v, want it to mention %q", err, tc.want)
			}
			if tc.absent != "" && strings.Contains(err.Error(), tc.absent) {
				t.Errorf("DeleteSecret() error = %v, want it NOT to echo %q back", err, tc.absent)
			}
		})
	}
}

// TestWriteIndexMultiPageAbsenceIsConfirmed covers the other half of the same
// hole. writeIndex.Resolve is a separate resolver behind SecretExists,
// PushSecret and DeleteSecret, and it writes the same process-wide negative
// cache that resolveSecretID trusts without re-checking. Strengthening only the
// read resolver left the ordinary bidirectional topology exposed: a PushSecret
// reconcile poisons the cache, and an ExternalSecret with deletionPolicy:
// Delete reading the same name deletes a live Kubernetes Secret.
func TestWriteIndexMultiPageAbsenceIsConfirmed(t *testing.T) {
	const id = "3434343434343434343434343434343434343434343434343434343434343434"

	newMock := func(target NcloudSecretListItem) *countingMockClient {
		sweep := 0
		return &countingMockClient{
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
				// Sweep 1 misses the target: it shifted into page 1 after page
				// 1 was served, and a create elsewhere kept totalCount at 4.
				if sweep == 1 {
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
			getSecretDetailFn: detailWithStatus(secretStatusEnable),
		}
	}
	target := NcloudSecretListItem{SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusEnable}

	t.Run("SecretExists does not report a missed name as absent", func(t *testing.T) {
		client := newMockedClient(newMock(target))

		exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
		if err != nil {
			t.Fatalf("SecretExists() error = %v", err)
		}
		if !exists {
			t.Error("SecretExists() = false for a secret the second sweep saw")
		}
		if _, _, negative := client.cache.Get("db-cred"); negative {
			t.Error("a single sweep that missed the name negative-cached it")
		}
	})

	// The sequence that costs data: the write path poisons the shared cache,
	// and a read on another resource believes it without re-checking.
	t.Run("a poisoned entry does not reach the read path", func(t *testing.T) {
		client := newMockedClient(newMock(target))

		if _, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"}); err != nil {
			t.Fatalf("SecretExists() error = %v", err)
		}
		got, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
		if err != nil {
			t.Fatalf("GetSecret() after the write path error = %v, want the secret", err)
		}
		if string(got) != "v" {
			t.Errorf("GetSecret() = %q, want %q", got, "v")
		}
	})

	t.Run("a name neither sweep sees is still absent", func(t *testing.T) {
		client := newMockedClient(newMock(NcloudSecretListItem{
			SecretID: testSecretID("zzz"), SecretName: "zzz", SecretStatus: secretStatusEnable,
		}))

		exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
		if err != nil {
			t.Fatalf("SecretExists() error = %v", err)
		}
		if exists {
			t.Error("SecretExists() = true for a name no sweep saw")
		}
		if _, found, negative := client.cache.Get("db-cred"); !found || !negative {
			t.Error("an absence both sweeps agree on should still be negative-cached")
		}
	})
}

// TestPushSecretKeepsTheServersErrorBehindTheHint pins that the refused-read
// hint is added to the server's error rather than substituted for it. The hint
// is derived from a read that finished before the call that failed, so it can
// name a state that is no longer current; the service code cannot, and it is
// the only machine-readable handle an operator can look up.
func TestPushSecretKeepsTheServersErrorBehindTheHint(t *testing.T) {
	const id = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}

	// What the transport really produces for a 409: a sentinel plus the status
	// and the numeric service code.
	serverErr := newAPIError(ErrInvalidStatus, http.StatusConflict, "501003")

	mock := &countingMockClient{
		listFn: listingWith(NcloudSecretListItem{
			SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusRevoke,
		}),
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return nil, serverErr
		},
		getSecretDetailFn: detailWithStatus(secretStatusRevoke),
	}
	client := newMockedClient(mock)

	err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"})
	if err == nil {
		t.Fatal("PushSecret() to a REVOKE-occupied name should fail")
	}
	if _, ok := errors.AsType[*apiError](err); !ok {
		t.Fatalf("PushSecret() error = %v, want the server's *apiError still reachable", err)
	}
	if !strings.Contains(err.Error(), "501003") {
		t.Errorf("PushSecret() error = %v, want it to carry the service code 501003", err)
	}
	if !strings.Contains(err.Error(), "Cancel Secret Deletion") {
		t.Errorf("PushSecret() error = %v, want the hint alongside the server's error", err)
	}
	if !errors.Is(err, ErrInvalidStatus) {
		t.Errorf("PushSecret() error = %v, want it to wrap ErrInvalidStatus", err)
	}
}

// TestPushSecretGivesTheLifecycleHintOnlyForALifecycleState covers the other
// side of the hint: a 400 is also what an ENABLE secret answers to a request
// the server refuses for another reason, and the hint there would tell the
// operator the secret is in a state it is not in.
func TestPushSecretGivesTheLifecycleHintOnlyForALifecycleState(t *testing.T) {
	const id = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}
	mock := &countingMockClient{
		listFn: listingWith(NcloudSecretListItem{
			SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusEnable,
		}),
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return nil, newAPIError(ErrInvalidRequest, http.StatusBadRequest, "501007")
		},
		getSecretDetailFn: detailWithStatus(secretStatusEnable),
	}
	client := newMockedClient(mock)

	err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("PushSecret() error = %v, want the server's ErrInvalidRequest", err)
	}
	if strings.Contains(err.Error(), "the detail read just before it saw") {
		t.Errorf("PushSecret() error = %v, want no lifecycle hint for an ENABLE secret", err)
	}
}

// TestWriteIndexSharesPagesAcrossKeys pins that K write-path keys on
// one Client cost at most one full sweep, not one sweep per key.
func TestWriteIndexSharesPagesAcrossKeys(t *testing.T) {
	ids := map[string]string{
		"key-a": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"key-b": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"key-c": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	mock := &countingMockClient{
		listFn: twoPageListing(
			[]NcloudSecretListItem{{SecretID: ids["key-a"], SecretName: "key-a"}},
			[]NcloudSecretListItem{{SecretID: ids["key-b"], SecretName: "key-b"}, {SecretID: ids["key-c"], SecretName: "key-c"}},
		),
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return newSecretValueResponse("old"), nil
		},
		updateStageFn: func(_ context.Context, _, _, _ string) error { return nil },
	}
	client := newMockedClient(mock)
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}

	for _, key := range []string{"key-a", "key-b", "key-c"} {
		if err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: key, secretKey: "k"}); err != nil {
			t.Fatalf("PushSecret(%s) error = %v", key, err)
		}
	}
	// key-a hits page 1 (1 call); key-b forces page 2 (1 more); key-c is
	// recorded. 2 total - with per-key fresh sweeps this would be 5.
	if mock.listCalls != 2 {
		t.Errorf("listCalls = %d, want 2 (pages shared across keys)", mock.listCalls)
	}
	if mock.updateStageCalls != 3 {
		t.Errorf("updateStageCalls = %d, want 3", mock.updateStageCalls)
	}
}

// TestWriteIndexSharedBySecretExists pins the IfNotExists pairing:
// SecretExists + PushSecret for the same key share one listing.
func TestWriteIndexSharedBySecretExists(t *testing.T) {
	const id = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	mock := &countingMockClient{
		listFn:            listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"}),
		getSecretDetailFn: detailWithStatus(secretStatusEnable),
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return newSecretValueResponse("old"), nil
		},
		updateStageFn: func(_ context.Context, _, _, _ string) error { return nil },
	}
	client := newMockedClient(mock)

	exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
	if err != nil || !exists {
		t.Fatalf("SecretExists() = (%v, %v), want (true, nil)", exists, err)
	}
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}
	if err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"}); err != nil {
		t.Fatalf("PushSecret() error = %v", err)
	}
	if mock.listCalls != 1 {
		t.Errorf("listCalls = %d, want 1 (index shared between SecretExists and PushSecret)", mock.listCalls)
	}
}

// TestWriteIndexTracksCreateAndDelete pins index coherence within one
// reconcile: a created name updates on re-push, and a deleted name re-creates.
func TestWriteIndexTracksCreateAndDelete(t *testing.T) {
	const id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}

	t.Run("push after create updates instead of re-creating", func(t *testing.T) {
		mock := &countingMockClient{
			listFn: listingWith(),
			createFn: func(_ context.Context, _ *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
				return &NcloudSecretDetailResponse{Code: successCode, Data: NcloudSecretDetailData{SecretID: id}}, nil
			},
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse("old"), nil
			},
			updateStageFn: func(_ context.Context, secretID, _, _ string) error {
				if secretID != id {
					t.Errorf("update addressed %q, want %q", secretID, id)
				}
				return nil
			},
		}
		client := newMockedClient(mock)

		if err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"}); err != nil {
			t.Fatalf("first PushSecret() error = %v", err)
		}
		if err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"}); err != nil {
			t.Fatalf("second PushSecret() error = %v", err)
		}
		if mock.createCalls != 1 || mock.updateStageCalls != 1 {
			t.Errorf("createCalls = %d, updateStageCalls = %d; want 1, 1", mock.createCalls, mock.updateStageCalls)
		}
	})

	t.Run("push after delete creates fresh instead of writing to the destroyed ID", func(t *testing.T) {
		destroyed := false
		mock := &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				status := secretStatusEnable
				if destroyed {
					status = secretStatusDestroyed
				}
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{
						CurrentPageNo: pageNo,
						TotalPageNo:   1,
						SecretList: []NcloudSecretListItem{{
							SecretID: id, SecretName: "db-cred", SecretStatus: status,
						}},
					},
				}, nil
			},
			getSecretDetailFn: detailWithStatus(secretStatusEnable),
			requestDeletionFn: func(_ context.Context, _ string) error { return nil },
			destroyFn: func(_ context.Context, _ string) error {
				destroyed = true
				return nil
			},
			createFn: func(_ context.Context, req *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
				return &NcloudSecretDetailResponse{Code: successCode, Data: NcloudSecretDetailData{SecretID: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}, nil
			},
		}
		client := newForceMockedClient(mock)

		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"}); err != nil {
			t.Fatalf("DeleteSecret() error = %v", err)
		}
		if err := client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"}); err != nil {
			t.Fatalf("PushSecret() after delete error = %v", err)
		}
		if mock.createCalls != 1 {
			t.Errorf("createCalls = %d, want 1 (index must forget the destroyed ID)", mock.createCalls)
		}
		if mock.updateStageCalls != 0 {
			t.Errorf("updateStageCalls = %d, want 0 (no write to the destroyed ID)", mock.updateStageCalls)
		}
	})
}

// TestDeleteSecretEmptyListedIDIsNotAbsence pins that "already gone" comes from
// the listing's verdict and nothing else. A row whose secretId is empty is a
// malformed listing, not an absent secret: the delete still goes on to the
// detail read, which is where an unaddressable ID has to fail, instead of
// reporting a deletion that never happened as done.
func TestDeleteSecretEmptyListedIDIsNotAbsence(t *testing.T) {
	var detailIDs []string
	mock := &countingMockClient{
		listFn: listingWith(NcloudSecretListItem{SecretID: "", SecretName: "db-cred", SecretStatus: secretStatusEnable}),
		getSecretDetailFn: func(_ context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
			detailIDs = append(detailIDs, secretID)
			return nil, fmt.Errorf("%w: empty ID", ErrInvalidRequest)
		},
	}
	client := newMockedClient(mock)

	err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
	if err == nil {
		t.Fatal("DeleteSecret() = nil, want the detail read's error for an empty listed ID")
	}
	if len(detailIDs) != 1 || detailIDs[0] != "" {
		t.Errorf("detail reads = %q, want one read of the listed (empty) ID", detailIDs)
	}
}

// TestPushSecretNamesTheKeyBoundaryOfARefusedUpdate pins that a 409 on the
// value update of a writable secret names the boundary of its key, the cause
// when the store's endpoint does not serve that boundary, and that nothing
// else gets the hint.
func TestPushSecretNamesTheKeyBoundaryOfARefusedUpdate(t *testing.T) {
	const id = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}
	for _, tc := range []struct {
		name      string
		status    string
		boundary  string
		updateErr error
		delete    bool
		wantHint  string
	}{
		{name: "409 on an ISOLATED-key secret", boundary: kmsBoundaryIsolated, updateErr: newAPIError(ErrInvalidStatus, http.StatusConflict, "501002"), wantHint: "kmsBoundaryType=ISOLATED"},
		{name: "409 on a property delete", boundary: kmsBoundaryIsolated, updateErr: newAPIError(ErrInvalidStatus, http.StatusConflict, "501002"), delete: true, wantHint: "kmsBoundaryType=ISOLATED"},
		{name: "server text is not echoed", boundary: "<b>", updateErr: newAPIError(ErrInvalidStatus, http.StatusConflict, "501002"), wantHint: "kmsBoundaryType=(unrecognized)"},
		{name: "400 is a bad request, not a boundary", boundary: kmsBoundaryIsolated, updateErr: newAPIError(ErrInvalidRequest, http.StatusBadRequest, "501007")},
		{name: "409 on a ROTATING secret may be the rotation", status: secretStatusRotating, boundary: kmsBoundaryIsolated, updateErr: newAPIError(ErrInvalidStatus, http.StatusConflict, "501002")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &countingMockClient{
				listFn: listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusEnable}),
				getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
					return newSecretValueResponse(`{"a":"1","k":"2"}`), nil
				},
				getSecretDetailFn: func(ctx context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
					status := tc.status
					if status == "" {
						status = secretStatusEnable
					}
					detail, _ := detailWithStatus(status)(ctx, secretID)
					detail.Data.ProtectionKey = &NcloudSecretProtectionKey{KmsBoundaryType: tc.boundary}
					return detail, nil
				},
				updateStageFn: func(_ context.Context, _, _, _ string) error { return tc.updateErr },
			}
			client := newMockedClient(mock)
			var err error
			if tc.delete {
				err = client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred", property: "k"})
			} else {
				err = client.PushSecret(context.Background(), k8sSecret, mockPushSecretData{remoteKey: "db-cred", secretKey: "k"})
			}
			if !errors.Is(err, tc.updateErr) {
				t.Fatalf("PushSecret() error = %v, want the server's error wrapped", err)
			}
			if got := strings.Contains(err.Error(), "point the store at the matching endpoint"); got != (tc.wantHint != "") {
				t.Fatalf("PushSecret() error = %v, hint present = %v, want %v", err, got, tc.wantHint != "")
			}
			if tc.wantHint != "" && !strings.Contains(err.Error(), tc.wantHint) {
				t.Errorf("PushSecret() error = %v, want it to name %q", err, tc.wantHint)
			}
		})
	}
}

// TestWriteIndexResweepKeepsReadPathTombstones pins that a re-sweep drops
// only the mappings a listing page gave. A tombstone the read path wrote for
// a REVOKE name is a later verdict, and the re-sweep never writes REVOKE rows
// to the cache, so dropping it would cost the next read a fresh sweep after
// every push that re-sweeps.
func TestWriteIndexResweepKeepsReadPathTombstones(t *testing.T) {
	const (
		goneID   = "2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e"
		anchorID = "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
	)
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			rows := []NcloudSecretListItem{{SecretID: goneID, SecretName: "gone", SecretStatus: secretStatusRevoke}}
			if pageNo == 2 {
				rows = []NcloudSecretListItem{{SecretID: anchorID, SecretName: "anchor", SecretStatus: secretStatusEnable}}
			}
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: 2, SecretList: rows,
				},
			}, nil
		},
	}
	client := newMockedClient(mock)

	// Sweep 1 reads page 1 on the way to anchor and records gone's REVOKE row.
	if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, "anchor"); err != nil {
		t.Fatalf("writeIndex.Resolve(anchor) error = %v", err)
	}
	// A read in the same reconcile found gone in its deletion window.
	client.cache.SetTombstoned("gone", goneID)

	// A missing name forces the sweep to be repeated, which drops what the
	// first sweep observed.
	if _, err := client.writes.Resolve(context.Background(), client.client, client.cache, "ghost"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("writeIndex.Resolve(ghost) error = %v, want ErrSecretNotFound", err)
	}
	if id, found, negative := client.cache.Get("gone"); !found || !negative || id != goneID {
		t.Errorf("cache after the re-sweep = (%q, %v, %v), want the read path's tombstone for %s kept", id, found, negative, goneID)
	}
}

// TestWriteIndexAbsenceDoesNotOverruleACreateThatLandedMeanwhile is the write
// index's half of TestListingAbsenceDoesNotOverruleACreateThatLandedMeanwhile:
// its sweep reads the cache's write sequence at its first page and leaves a
// mapping written after that alone.
func TestWriteIndexAbsenceDoesNotOverruleACreateThatLandedMeanwhile(t *testing.T) {
	const id = "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2"
	var client *Client
	mock := &countingMockClient{}
	mock.listFn = func(ctx context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
		client.cache.Set("db-cred", id)
		return listingWith()(ctx, pageNo)
	}
	client = newMockedClient(mock)

	exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
	if err != nil || exists {
		t.Fatalf("SecretExists() = %v, %v; want false from the sweep that found nothing", exists, err)
	}
	if got, found, negative := client.cache.Get("db-cred"); !found || negative || got != id {
		t.Errorf("cache = (%q, %v, %v), want the create's mapping to %s kept", got, found, negative, id)
	}

	// A mapping older than the sweep is replaced by its absence verdict.
	stale := &countingMockClient{listFn: listingWith()}
	client = newMockedClient(stale)
	client.cache.Set("db-cred", id)
	if exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"}); err != nil || exists {
		t.Fatalf("SecretExists() = %v, %v; want false", exists, err)
	}
	if _, found, negative := client.cache.Get("db-cred"); !found || !negative {
		t.Errorf("cache kept a mapping older than the sweep that found the name absent")
	}
}

// TestWriteIndexResweepKeepsTheFirstSweepsSequence pins that a verdict which
// needed a confirming sweep is dated from the first one. Both sweeps are what
// it rests on, so a create that landed while the first ran is one neither may
// have seen; dated from the repeat, the absence would replace its mapping.
func TestWriteIndexResweepKeepsTheFirstSweepsSequence(t *testing.T) {
	const id = "e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4"
	var client *Client
	mock := &countingMockClient{}
	mock.listFn = func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
		if mock.listCalls == 1 {
			// The first sweep's first page is in flight when the create's
			// cache write lands.
			client.cache.Set("db-cred", id)
		}
		// Two pages, so an absence needs a second, agreeing sweep.
		row := NcloudSecretListItem{SecretID: testSecretID("a"), SecretName: "other-a", SecretStatus: secretStatusEnable}
		if pageNo == 2 {
			row = NcloudSecretListItem{SecretID: testSecretID("b"), SecretName: "other-b", SecretStatus: secretStatusEnable}
		}
		return &NcloudListSecretsResponse{
			Code: successCode,
			Data: NcloudListSecretsData{TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: 2, SecretList: []NcloudSecretListItem{row}},
		}, nil
	}
	client = newMockedClient(mock)

	exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred"})
	if err != nil || exists {
		t.Fatalf("SecretExists() = %v, %v; want false from the sweeps that found nothing", exists, err)
	}
	if mock.listCalls != 4 {
		t.Fatalf("ListSecrets calls = %d, want 4: two sweeps of two pages", mock.listCalls)
	}
	if got, found, negative := client.cache.Get("db-cred"); !found || negative || got != id {
		t.Errorf("cache = (%q, %v, %v), want the create's mapping to %s kept", got, found, negative, id)
	}
}

// TestWriteIndexPinOnAFreshIndexHolds pins that a pin made before any
// resolution is not lost: a later Resolve answers from it instead of sweeping
// and, missing the fresh secret, creating the name again.
func TestWriteIndexPinOnAFreshIndexHolds(t *testing.T) {
	const id = "e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3"
	mock := &countingMockClient{listFn: listingWith()}
	var w writeIndex
	w.Pin("db-cred", id)

	got, err := w.Resolve(context.Background(), mock, nil, "db-cred")
	if err != nil || got != id {
		t.Fatalf("Resolve() = %q, %v; want the pinned %s", got, err, id)
	}
	if mock.listCalls != 0 {
		t.Errorf("ListSecrets calls = %d, want 0: the pin answers", mock.listCalls)
	}
}

// TestCreateRefusesAResponseIDTheAPIDoesNotIssue pins that a create response
// whose ID is malformed is a contract violation: nothing is pinned, cached or
// locked on it, and the pre-create negative entry is cleared so the next
// reconcile resolves the secret from the listing.
func TestCreateRefusesAResponseIDTheAPIDoesNotIssue(t *testing.T) {
	mock := &countingMockClient{
		listFn: listingWith(),
		createFn: func(context.Context, *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
			return &NcloudSecretDetailResponse{Code: successCode, Data: NcloudSecretDetailData{SecretID: "../collection", Memo: managedByMemo}}, nil
		},
	}
	client := newMockedClient(mock)
	client.cache.SetNegative("db-cred")

	err := client.PushSecret(context.Background(), &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}, mockPushSecretData{secretKey: "k", remoteKey: "db-cred"})
	if err == nil || !strings.Contains(err.Error(), "no usable secret ID") {
		t.Fatalf("PushSecret() error = %v, want the malformed response ID refused", err)
	}
	if _, found, _ := client.cache.Get("db-cred"); found {
		t.Errorf("cache still holds an entry for the name; the pre-create negative must be cleared")
	}
	if mock.updateStageCalls != 0 {
		t.Errorf("update calls = %d, want 0: nothing may be written through a malformed ID", mock.updateStageCalls)
	}
}

// TestWriteErrorsQuoteTheKeyAndProperty extends
// TestPropertyErrorsAreBoundedAndQuoted to the write side: a PushSecret's
// secretKey and property, and a property deletion's property, are manifest
// text of any length too, and their errors reach the controller log. Each one
// is quoted and cut to 40 characters, so a long value cannot flood the log
// and a newline cannot split a log line.
func TestWriteErrorsQuoteTheKeyAndProperty(t *testing.T) {
	id := testSecretID("quote")
	k8sSecret := &corev1.Secret{Data: map[string][]byte{"username": []byte("admin")}}
	listed := listingWith(NcloudSecretListItem{SecretID: id, SecretName: "db-cred"})
	valueOf := func(raw string) func(context.Context, string) (*NcloudSecretValueResponse, error) {
		return func(context.Context, string) (*NcloudSecretValueResponse, error) {
			return newSecretValueResponse(raw), nil
		}
	}

	cases := map[string]func(text string) error{
		"push of a missing secretKey": func(text string) error {
			client := newMockedClient(&countingMockClient{})
			return client.PushSecret(context.Background(), k8sSecret,
				mockPushSecretData{remoteKey: "db-cred", secretKey: text})
		},
		"property push into a non-object value": func(text string) error {
			client := newMockedClient(&countingMockClient{listFn: listed, getSecretValueFn: valueOf("plain-text")})
			return client.PushSecret(context.Background(), k8sSecret,
				mockPushSecretData{remoteKey: "db-cred", secretKey: "username", property: text})
		},
		"property delete from a non-object value": func(text string) error {
			client := newMockedClient(&countingMockClient{listFn: listed, getSecretValueFn: valueOf(`"not-an-object"`)})
			return client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred", property: text})
		},
		"property delete from a paused secret": func(text string) error {
			client := newMockedClient(&countingMockClient{
				listFn: listed,
				getSecretValueFn: func(context.Context, string) (*NcloudSecretValueResponse, error) {
					return nil, ErrInvalidStatus
				},
				getSecretDetailFn: detailWithStatus(secretStatusDisable),
			})
			return client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: "db-cred", property: text})
		},
	}
	for name, write := range cases {
		t.Run(name, func(t *testing.T) {
			err := write(strings.Repeat("p", 4096))
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), strings.Repeat("p", 41)) || !strings.Contains(err.Error(), `"pppp`) {
				t.Errorf("error = %.200q..., want the text quoted and cut to 40 characters", err)
			}

			err = write("a\nb")
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), "\n") || !strings.Contains(err.Error(), `"a\nb"`) {
				t.Errorf("error = %q, want the newline escaped by quoting", err)
			}
		})
	}
}

// TestWritePathRechecksANameWhoseIndexedSecretIsGone: the write index
// answers a name from any sweep this reconcile read, so the ID it hands
// SecretExists or DeleteSecret can be minutes old. When another writer
// destroyed that secret and created the name again in the meantime, a 404
// or DESTROYED on the old ID says nothing about the name. Reading it as
// absence let IfNotExists push over the new secret and DeleteSecret report
// success without deleting it; the name must be resolved again first, as
// the read path does (absentUnlessListingDisagrees).
func TestWritePathRechecksANameWhoseIndexedSecretIsGone(t *testing.T) {
	const (
		name    = "db-cred"
		firstID = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
		oldID   = "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2"
		newID   = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
	)

	// newMock serves one declared page: "first" and the name under oldID (in
	// oldStatus) until replaced, then "first" and the name under newID. oldID
	// answers 404 once replaced; every other ID is an ESO-managed ENABLE
	// secret.
	newMock := func(t *testing.T, replaced *bool, oldStatus string) *countingMockClient {
		return &countingMockClient{
			listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
				rows := []NcloudSecretListItem{
					{SecretID: firstID, SecretName: "first", SecretStatus: secretStatusEnable},
					{SecretID: oldID, SecretName: name, SecretStatus: oldStatus},
				}
				if *replaced {
					rows[1] = NcloudSecretListItem{SecretID: newID, SecretName: name, SecretStatus: secretStatusEnable}
				}
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{TotalPageNo: 1, CurrentPageNo: pageNo, TotalCount: len(rows), SecretList: rows},
				}, nil
			},
			getSecretDetailFn: func(ctx context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
				if secretID == oldID && *replaced {
					return nil, fmt.Errorf("%w: destroyed by another writer", ErrSecretNotFound)
				}
				return detailWithStatus(secretStatusEnable)(ctx, secretID)
			},
			getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(`{"k":"theirs"}`), nil
			},
			updateStageFn: func(_ context.Context, secretID, _, value string) error {
				t.Errorf("UpdateSecretStageValue(%s, %s) overwrote the value of a secret that existed when SecretExists was asked", secretID, value)
				return nil
			},
			requestDeletionFn: func(_ context.Context, _ string) error { return nil },
		}
	}

	// buildIndex is the reconcile's first entry: its sweep records the name
	// under oldID. Then the other writer replaces the secret.
	buildIndex := func(t *testing.T, client *Client, replaced *bool) {
		t.Helper()
		if exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "first"}); err != nil || !exists {
			t.Fatalf("SecretExists(first) = (%v, %v), want (true, nil)", exists, err)
		}
		if got := client.writes.names[name]; got != oldID {
			t.Fatalf("write index maps %s to %q after the first entry, want %s", name, got, oldID)
		}
		*replaced = true
	}

	// ifNotExists is the controller's pushSecretEntry under updatePolicy
	// IfNotExists for the name, after the first entry built the index.
	ifNotExists := func(t *testing.T, oldStatus string) {
		replaced := false
		mock := newMock(t, &replaced, oldStatus)
		client := newMockedClient(mock)
		buildIndex(t, client, &replaced)

		exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: name})
		if err != nil {
			t.Fatalf("SecretExists(%s) error = %v", name, err)
		}
		if exists {
			return // the controller skips the push, which is the correct outcome
		}
		t.Logf("SecretExists(%s) = false although %s holds the name", name, newID)
		_ = client.PushSecret(context.Background(), &corev1.Secret{Data: map[string][]byte{"k": []byte("ours")}},
			mockPushSecretData{remoteKey: name, secretKey: "k"})
		if mock.updateStageCalls != 0 {
			t.Errorf("updateStageCalls = %d, want 0: IfNotExists pushed over %s, which held the name before SecretExists answered",
				mock.updateStageCalls, newID)
		}
	}

	t.Run("IfNotExists sees the replacement", func(t *testing.T) {
		ifNotExists(t, secretStatusEnable)
	})

	t.Run("IfNotExists sees a writer that took a name its grace period freed", func(t *testing.T) {
		// The index read the name in REVOKE; the service destroyed it at the
		// end of the 7-day grace period and another writer, refused until
		// then, created the name.
		ifNotExists(t, secretStatusRevoke)
	})

	t.Run("IfNotExists with a property sees a replacement made after the detail read", func(t *testing.T) {
		// The old secret passes the detail read and is destroyed before the
		// value read that checks the property, and another writer creates
		// the name again in between. The 404 on the value says nothing about
		// the name either.
		replaced := false
		mock := newMock(t, &replaced, secretStatusEnable)
		mock.getSecretValueFn = func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			if secretID == oldID {
				replaced = true
				return nil, fmt.Errorf("%w: destroyed by another writer", ErrSecretNotFound)
			}
			return newSecretValueResponse(`{"k":"theirs"}`), nil
		}
		client := newMockedClient(mock)
		if exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: "first"}); err != nil || !exists {
			t.Fatalf("SecretExists(first) = (%v, %v), want (true, nil)", exists, err)
		}
		exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: name, property: "k"})
		if err != nil || !exists {
			t.Errorf("SecretExists(%s, k) = (%v, %v), want (true, nil): %s holds the name and the property", name, exists, err, newID)
		}
	})
	t.Run("an ID-shaped key keeps its value read's NotFound", func(t *testing.T) {
		replaced := false
		mock := newMock(t, &replaced, secretStatusEnable)
		mock.getSecretValueFn = func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return nil, fmt.Errorf("%w: destroyed", ErrSecretNotFound)
		}
		client := newMockedClient(mock)
		exists, err := client.SecretExists(context.Background(), mockPushSecretRemoteRef{remoteKey: oldID, property: "k"})
		if err != nil || exists {
			t.Errorf("SecretExists(%s, k) = (%v, %v), want (false, nil)", oldID, exists, err)
		}
		if mock.listCalls != 0 {
			t.Errorf("listCalls = %d, want 0: an ID key names the secret itself", mock.listCalls)
		}
	})
	t.Run("DeleteSecret deletes the replacement", func(t *testing.T) {
		// TestWriteIndexPromotesTheLiveRowShadowedByAStaleEntry requires one
		// deletion request for the live replacement. It holds only while the
		// listing still shows the old ID as DESTROYED; here the old row is
		// simply gone from the listing.
		replaced := false
		mock := newMock(t, &replaced, secretStatusEnable)
		client := newMockedClient(mock)
		buildIndex(t, client, &replaced)

		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: name}); err != nil {
			t.Fatalf("DeleteSecret(%s) error = %v", name, err)
		}
		if mock.requestDeletionCalls != 1 {
			t.Errorf("DeleteSecret(%s) issued %d deletion requests, want 1 for the live %s", name, mock.requestDeletionCalls, newID)
		}
	})

	gone := fmt.Errorf("%w: destroyed by another writer", ErrSecretNotFound)
	// failSecondDetail makes oldID pass the ownership read, refuse its value
	// with a status the property path cannot read through, and answer the
	// detail read that explains the refusal with second.
	failSecondDetail := func(mock *countingMockClient, second func(context.Context, string) (*NcloudSecretDetailResponse, error)) {
		reads := 0
		mock.getSecretDetailFn = func(ctx context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
			if secretID == oldID {
				reads++
				if reads > 1 {
					return second(ctx, secretID)
				}
			}
			return detailWithStatus(secretStatusEnable)(ctx, secretID)
		}
		read := mock.getSecretValueFn
		mock.getSecretValueFn = func(ctx context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			if secretID == oldID {
				return nil, ErrInvalidStatus
			}
			return read(ctx, secretID)
		}
	}
	t.Run("DeleteSecret with a property removes it from the replacement", func(t *testing.T) {
		// The old ID can turn out gone at every step of the property path,
		// and no such answer says anything about the name: the delete has to
		// resolve it once more, as the whole delete does.
		for _, tc := range []struct {
			name string
			// failOld makes oldID fail at one step once the index is built.
			failOld func(mock *countingMockClient, replaced *bool)
		}{
			{"detail 404", func(*countingMockClient, *bool) {}},
			{"detail DESTROYED", func(mock *countingMockClient, replaced *bool) {
				mock.getSecretDetailFn = func(ctx context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
					if secretID == oldID && *replaced {
						return detailWithStatus(secretStatusDestroyed)(ctx, secretID)
					}
					return detailWithStatus(secretStatusEnable)(ctx, secretID)
				}
			}},
			{"detail DESTROYED without the ownership marker", func(mock *countingMockClient, replaced *bool) {
				// The whole delete exempts a DESTROYED row from the ownership
				// check (deleteSecretFully); the property path has to as well,
				// whether or not the memo survives destruction.
				mock.getSecretDetailFn = func(ctx context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
					if secretID == oldID && *replaced {
						return unmanagedDetail(secretStatusDestroyed)(ctx, secretID)
					}
					return detailWithStatus(secretStatusEnable)(ctx, secretID)
				}
			}},
			{"value 404 after an ENABLE detail", func(mock *countingMockClient, _ *bool) {
				mock.getSecretDetailFn = detailWithStatus(secretStatusEnable)
				read := mock.getSecretValueFn
				mock.getSecretValueFn = func(ctx context.Context, secretID string) (*NcloudSecretValueResponse, error) {
					if secretID == oldID {
						return nil, gone
					}
					return read(ctx, secretID)
				}
			}},
			{"value unreadable, then a DESTROYED detail", func(mock *countingMockClient, _ *bool) {
				failSecondDetail(mock, func(ctx context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
					return detailWithStatus(secretStatusDestroyed)(ctx, secretID)
				})
			}},
			{"value unreadable, then a detail 404", func(mock *countingMockClient, _ *bool) {
				failSecondDetail(mock, func(context.Context, string) (*NcloudSecretDetailResponse, error) {
					return nil, gone
				})
			}},
			{"value update 404", func(mock *countingMockClient, _ *bool) {
				mock.getSecretDetailFn = detailWithStatus(secretStatusEnable)
				write := mock.updateStageFn
				mock.updateStageFn = func(ctx context.Context, secretID, stage, value string) error {
					if secretID == oldID {
						return gone
					}
					return write(ctx, secretID, stage, value)
				}
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				replaced := false
				mock := newMock(t, &replaced, secretStatusEnable)
				mock.getSecretValueFn = func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
					return newSecretValueResponse(`{"k":"ours","other":"theirs"}`), nil
				}
				var updated []string
				mock.updateStageFn = func(_ context.Context, secretID, _, value string) error {
					updated = append(updated, secretID+" "+value)
					return nil
				}
				tc.failOld(mock, &replaced)
				client := newMockedClient(mock)
				buildIndex(t, client, &replaced)

				err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: name, property: "k"})
				if err != nil {
					t.Fatalf("DeleteSecret(%s, k) error = %v", name, err)
				}
				if want := newID + ` {"other":"theirs"}`; !slices.Contains(updated, want) {
					t.Errorf("updates = %q, want %q: %s holds the name, and its k was left in place", updated, want, newID)
				}
				if mock.requestDeletionCalls != 0 {
					t.Errorf("requestDeletionCalls = %d, want 0: a property deletion never deletes the secret", mock.requestDeletionCalls)
				}
			})
		}
	})
	t.Run("DeleteSecret deletes the replacement when the deletion request finds the old ID gone", func(t *testing.T) {
		replaced := false
		mock := newMock(t, &replaced, secretStatusEnable)
		mock.getSecretDetailFn = detailWithStatus(secretStatusEnable)
		var requested []string
		mock.requestDeletionFn = func(_ context.Context, secretID string) error {
			requested = append(requested, secretID)
			if secretID == oldID {
				return gone
			}
			return nil
		}
		client := newMockedClient(mock)
		buildIndex(t, client, &replaced)

		if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: name}); err != nil {
			t.Fatalf("DeleteSecret(%s) error = %v", name, err)
		}
		if !slices.Contains(requested, newID) {
			t.Errorf("deletion requests = %q, want one for %s, which holds the name", requested, newID)
		}
	})
	t.Run("force mode DeleteSecret deletes the replacement when the destroy finds the old ID gone", func(t *testing.T) {
		// The destroy runs after a deletion request that succeeded, or on a
		// REVOKE secret. Its 404 means another actor destroyed the secret in
		// between, which frees the name exactly as a deletion request's 404
		// does.
		for _, oldStatus := range []string{secretStatusEnable, secretStatusRevoke} {
			t.Run("old secret "+oldStatus, func(t *testing.T) {
				replaced := false
				mock := newMock(t, &replaced, oldStatus)
				mock.getSecretDetailFn = func(ctx context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
					if secretID == oldID {
						return detailWithStatus(oldStatus)(ctx, secretID)
					}
					return detailWithStatus(secretStatusEnable)(ctx, secretID)
				}
				var destroyed []string
				mock.destroyFn = func(_ context.Context, secretID string) error {
					destroyed = append(destroyed, secretID)
					if secretID == oldID {
						return gone
					}
					return nil
				}
				client := newForceMockedClient(mock)
				buildIndex(t, client, &replaced)

				if err := client.DeleteSecret(context.Background(), mockPushSecretRemoteRef{remoteKey: name}); err != nil {
					t.Fatalf("DeleteSecret(%s) error = %v", name, err)
				}
				if !slices.Contains(destroyed, newID) {
					t.Errorf("destroys = %q, want one for %s, which holds the name", destroyed, newID)
				}
			})
		}
	})
}
