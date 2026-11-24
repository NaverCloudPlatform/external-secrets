// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

func TestReferentClientValidateAndClose(t *testing.T) {
	client := NewReferentClient()

	result, err := client.Validate()
	if err != nil {
		t.Fatalf("Validate() returned error: %v", err)
	}
	if result != esv1.ValidationResultUnknown {
		t.Errorf("Validate() = %v, want %v", result, esv1.ValidationResultUnknown)
	}

	if err := client.Close(context.Background()); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestReferentClientOperationsFailClosed(t *testing.T) {
	ctx := context.Background()
	client := NewReferentClient()

	secret, err := client.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{})
	if secret != nil {
		t.Errorf("GetSecret() = %v, want nil", secret)
	}
	assertUninitializedClientError(t, "GetSecret", err)

	secretMap, err := client.GetSecretMap(ctx, esv1.ExternalSecretDataRemoteRef{})
	if secretMap != nil {
		t.Errorf("GetSecretMap() = %v, want nil", secretMap)
	}
	assertUninitializedClientError(t, "GetSecretMap", err)

	allSecrets, err := client.GetAllSecrets(ctx, esv1.ExternalSecretFind{})
	if allSecrets != nil {
		t.Errorf("GetAllSecrets() = %v, want nil", allSecrets)
	}
	assertUninitializedClientError(t, "GetAllSecrets", err)

	exists, err := client.SecretExists(ctx, nil)
	if exists {
		t.Error("SecretExists() = true, want false")
	}
	assertUninitializedClientError(t, "SecretExists", err)

	err = client.PushSecret(ctx, &corev1.Secret{}, nil)
	assertUninitializedClientError(t, "PushSecret", err)

	err = client.DeleteSecret(ctx, nil)
	assertUninitializedClientError(t, "DeleteSecret", err)
}

func assertUninitializedClientError(t *testing.T, operation string, err error) {
	t.Helper()

	if !errors.Is(err, ErrUninitializedClient) {
		t.Errorf("%s() error = %v, want errors.Is ErrUninitializedClient", operation, err)
	}
}
