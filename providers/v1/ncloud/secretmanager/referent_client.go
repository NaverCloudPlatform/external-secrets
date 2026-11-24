// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

var _ esv1.SecretsClient = &referentClient{}

// referentClient lets ClusterSecretStore readiness validation defer credential
// resolution until an ExternalSecret supplies its namespace. It must never
// perform provider operations.
type referentClient struct{}

// NewReferentClient returns a no-network client for ClusterSecretStore
// readiness checks whose credentials depend on the consumer namespace.
func NewReferentClient() esv1.SecretsClient {
	return &referentClient{}
}

func (c *referentClient) GetSecret(context.Context, esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	return nil, ErrUninitializedClient
}

func (c *referentClient) PushSecret(context.Context, *corev1.Secret, esv1.PushSecretData) error {
	return ErrUninitializedClient
}

func (c *referentClient) DeleteSecret(context.Context, esv1.PushSecretRemoteRef) error {
	return ErrUninitializedClient
}

func (c *referentClient) SecretExists(context.Context, esv1.PushSecretRemoteRef) (bool, error) {
	return false, ErrUninitializedClient
}

func (c *referentClient) Validate() (esv1.ValidationResult, error) {
	return esv1.ValidationResultUnknown, nil
}

func (c *referentClient) GetSecretMap(context.Context, esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	return nil, ErrUninitializedClient
}

func (c *referentClient) GetAllSecrets(context.Context, esv1.ExternalSecretFind) (map[string][]byte, error) {
	return nil, ErrUninitializedClient
}

func (c *referentClient) Close(context.Context) error {
	return nil
}
