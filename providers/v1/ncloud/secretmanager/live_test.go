//go:build ncloud_live

// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esv1alpha1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	"github.com/external-secrets/external-secrets/providers/v1/ncloud/secretmanager"
)

const defaultLiveEndpoint = "https://ocapi-kr.ncloud.com/secretmanager"

// TestLiveClientLifecycle is an opt-in provider-client integration test
// against Ncloud Secret Manager. It does not exercise the Kubernetes
// controllers or reconciliation lifecycle.
func TestLiveClientLifecycle(t *testing.T) {
	if os.Getenv("RUN_NCLOUD_E2E") != "true" {
		t.Skip("set RUN_NCLOUD_E2E=true to run the live Ncloud client integration test")
	}

	accessKeyID := requireLiveEnv(t, "NCLOUD_ACCESS_KEY_ID")
	secretKey := requireLiveEnv(t, "NCLOUD_SECRET_KEY")
	endpoint := os.Getenv("NCLOUD_ENDPOINT")
	if endpoint == "" {
		endpoint = defaultLiveEndpoint
	}

	config := &secretmanager.Config{
		AccessKeyID: accessKeyID,
		SecretKey:   secretKey,
		Endpoint:    endpoint,
		// The lifecycle test must actually destroy its fixtures: a REVOKE
		// leftover would occupy the name and bill for 7 more days.
		ForceDeleteWithoutRecovery: true,
	}
	client, err := secretmanager.NewClient(config)
	if err != nil {
		t.Fatalf("create Ncloud client: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(context.Background()); err != nil {
			t.Errorf("close Ncloud client: %v", err)
		}
	})

	secretName := uniqueLiveSecretName(t)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		deleteLiveSecretWithRetry(t, cleanupCtx, client, secretName)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	password := []byte("live-password-value")
	source := &corev1.Secret{
		Data: map[string][]byte{
			"password": password,
		},
	}
	passwordPush := esv1alpha1.PushSecretData{
		Match: esv1alpha1.PushSecretMatch{
			SecretKey: "password",
			RemoteRef: esv1alpha1.PushSecretRemoteRef{
				RemoteKey: secretName,
			},
		},
	}
	if err := client.PushSecret(ctx, source, passwordPush); err != nil {
		t.Fatalf("create selected password in Ncloud: %v", err)
	}

	gotPassword, err := client.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
		Key:      secretName,
		Property: "password",
	})
	if err != nil {
		t.Fatalf("read password property from Ncloud: %v", err)
	}
	if !bytes.Equal(gotPassword, password) {
		t.Fatal("password property did not match the selected Kubernetes Secret value")
	}

	passwordExists, err := client.SecretExists(ctx, esv1alpha1.PushSecretRemoteRef{
		RemoteKey: secretName,
		Property:  "password",
	})
	if err != nil {
		t.Fatalf("check password property existence: %v", err)
	}
	if !passwordExists {
		t.Fatal("password property does not exist after create")
	}

	siblingPush := esv1alpha1.PushSecretData{
		Match: esv1alpha1.PushSecretMatch{
			SecretKey: "username",
			RemoteRef: esv1alpha1.PushSecretRemoteRef{
				RemoteKey: secretName,
				Property:  "username",
			},
		},
	}
	source.Data["username"] = []byte("first-user")
	if err := client.PushSecret(ctx, source, siblingPush); err != nil {
		t.Fatalf("add sibling property in Ncloud: %v", err)
	}

	updatedUsername := []byte("second-user")
	source.Data["username"] = updatedUsername
	if err := client.PushSecret(ctx, source, siblingPush); err != nil {
		t.Fatalf("update sibling property in Ncloud: %v", err)
	}
	gotUsername, err := client.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
		Key:      secretName,
		Property: "username",
	})
	if err != nil {
		t.Fatalf("read updated sibling property from Ncloud: %v", err)
	}
	if !bytes.Equal(gotUsername, updatedUsername) {
		t.Fatal("sibling property did not contain its updated value")
	}

	if err := client.DeleteSecret(ctx, esv1alpha1.PushSecretRemoteRef{
		RemoteKey: secretName,
		Property:  "username",
	}); err != nil {
		t.Fatalf("delete sibling property from Ncloud: %v", err)
	}
	usernameExists, err := client.SecretExists(ctx, esv1alpha1.PushSecretRemoteRef{
		RemoteKey: secretName,
		Property:  "username",
	})
	if err != nil {
		t.Fatalf("check sibling property existence after deletion: %v", err)
	}
	if usernameExists {
		t.Fatal("sibling property still exists after deletion")
	}

	gotPassword, err = client.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
		Key:      secretName,
		Property: "password",
	})
	if err != nil {
		t.Fatalf("read password after sibling deletion: %v", err)
	}
	if !bytes.Equal(gotPassword, password) {
		t.Fatal("deleting the sibling property changed the password property")
	}

	// Re-add the sibling, then try to remove the create-time rotation target.
	// Ncloud fixes rotation targets at create and rejects any value that
	// omits one; the provider refuses locally rather than forwarding the request.
	// This asserts the refusal AND that it left the secret untouched, which is
	// what makes the failure recoverable: an operator can still read both fields
	// and decide to recreate the secret.
	if err := client.PushSecret(ctx, source, siblingPush); err != nil {
		t.Fatalf("re-add sibling before target-property deletion in Ncloud: %v", err)
	}
	if err := client.DeleteSecret(ctx, esv1alpha1.PushSecretRemoteRef{
		RemoteKey: secretName,
		Property:  "password",
	}); err == nil {
		t.Fatal("deleting the create-time rotation target succeeded; Ncloud rejects a value that omits it")
	}
	gotPassword, err = client.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
		Key:      secretName,
		Property: "password",
	})
	if err != nil {
		t.Fatalf("read rotation-target property after the refused deletion: %v", err)
	}
	if !bytes.Equal(gotPassword, password) {
		t.Fatal("the refused deletion changed the rotation-target property")
	}
	gotUsername, err = client.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
		Key:      secretName,
		Property: "username",
	})
	if err != nil {
		t.Fatalf("read sibling after the refused deletion: %v", err)
	}
	if !bytes.Equal(gotUsername, updatedUsername) {
		t.Fatal("the refused deletion changed the sibling property")
	}

	if err := client.DeleteSecret(ctx, esv1alpha1.PushSecretRemoteRef{
		RemoteKey: secretName,
	}); err != nil {
		t.Fatalf("delete live Ncloud secret: %v", err)
	}
	verificationClient, err := secretmanager.NewClient(config)
	if err != nil {
		t.Fatalf("create fresh Ncloud client for deletion verification: %v", err)
	}
	t.Cleanup(func() {
		if err := verificationClient.Close(context.Background()); err != nil {
			t.Errorf("close deletion-verification Ncloud client: %v", err)
		}
	})

	secretExists, err := verificationClient.SecretExists(ctx, esv1alpha1.PushSecretRemoteRef{
		RemoteKey: secretName,
	})
	if err != nil {
		t.Fatalf("check live Ncloud secret absence: %v", err)
	}
	if secretExists {
		t.Fatal("live Ncloud secret still exists after full deletion")
	}
}

func deleteLiveSecretWithRetry(
	t *testing.T,
	ctx context.Context,
	client esv1.SecretsClient,
	secretName string,
) {
	t.Helper()

	var lastErr error
	for attempt := range 4 {
		if err := client.DeleteSecret(ctx, esv1alpha1.PushSecretRemoteRef{
			RemoteKey: secretName,
		}); err == nil {
			return
		} else {
			lastErr = err
		}

		timer := time.NewTimer(time.Second << attempt)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Errorf("clean up live Ncloud secret before timeout: %v", lastErr)
			return
		case <-timer.C:
		}
	}

	t.Errorf("clean up live Ncloud secret after retries: %v", lastErr)
}

func requireLiveEnv(t *testing.T, name string) string {
	t.Helper()

	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s must be set when RUN_NCLOUD_E2E=true", name)
	}
	return value
}

func uniqueLiveSecretName(t *testing.T) string {
	t.Helper()

	var random [5]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatalf("generate unique live secret name: %v", err)
	}
	return "e2e" + hex.EncodeToString(random[:])
}
