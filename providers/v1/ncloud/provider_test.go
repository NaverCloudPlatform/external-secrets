// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package ncloud

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

const (
	testNamespace         = "test-ns"
	testExplicitNamespace = "credentials-ns"
	testSecretName        = "ncloud-credentials"
	testEndpoint          = "https://ocapi-kr.ncloud.com/secretmanager"
)

// newNcloudStore builds a SecretStore wired to the given Ncloud provider config.
func newNcloudStore(prov *esv1.NcloudProvider) esv1.GenericStore {
	return &esv1.SecretStore{
		Kind:      esv1.SecretStoreKind,
		Name:      "ncloud-store",
		Namespace: testNamespace,
		Spec: esv1.SecretStoreSpec{
			Provider: &esv1.SecretStoreProvider{Ncloud: prov},
		},
	}
}

// newNcloudClusterStore builds a ClusterSecretStore wired to the given config.
func newNcloudClusterStore(prov *esv1.NcloudProvider) esv1.GenericStore {
	return &esv1.ClusterSecretStore{
		Kind: esv1.ClusterSecretStoreKind,
		Name: "ncloud-cluster-store",
		Spec: esv1.SecretStoreSpec{
			Provider: &esv1.SecretStoreProvider{Ncloud: prov},
		},
	}
}

// validProvider returns an Ncloud provider config referencing testSecretName.
func validProvider() *esv1.NcloudProvider {
	return &esv1.NcloudProvider{
		Endpoint: testEndpoint,
		Auth: esv1.NcloudAuth{
			SecretRef: &esv1.NcloudAuthSecretRef{
				AccessKeyID: esmeta.SecretKeySelector{Name: testSecretName, Key: "access-key-id"},
				SecretKey:   esmeta.SecretKeySelector{Name: testSecretName, Key: "secret-key"},
			},
		},
	}
}

func TestValidateStoreEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantErr  bool
	}{
		{
			name:     "API gateway endpoint",
			endpoint: "https://secretmanager.apigw.ntruss.com",
		},
		{
			name:     "Korea endpoint",
			endpoint: "https://ocapi-kr.ncloud.com/secretmanager",
		},
		{
			name:     "Japan endpoint",
			endpoint: "https://ocapi-jp.ncloud.com/secretmanager",
		},
		{
			name:     "trailing slash normalized",
			endpoint: "https://ocapi-kr.ncloud.com/secretmanager///",
		},
		{
			name:     "uppercase host normalized",
			endpoint: "https://OCAPI-KR.NCLOUD.COM/secretmanager",
		},
		{
			name:     "undocumented HTTPS host accepted",
			endpoint: "https://secretmanager-proxy.internal.example/secretmanager",
		},
		{
			name:     "explicit port accepted",
			endpoint: "https://ocapi-kr.ncloud.com:443/secretmanager",
		},
		{
			name:     "HTTP rejected",
			endpoint: "http://ocapi-kr.ncloud.com/secretmanager",
			wantErr:  true,
		},
		{
			name:     "userinfo rejected",
			endpoint: "https://user@ocapi-kr.ncloud.com/secretmanager",
			wantErr:  true,
		},
		{
			name:     "bare query rejected",
			endpoint: "https://ocapi-kr.ncloud.com/secretmanager?",
			wantErr:  true,
		},
		{
			name:     "bare fragment rejected",
			endpoint: "https://ocapi-kr.ncloud.com/secretmanager#",
			wantErr:  true,
		},
		{
			name:     "dot path rejected",
			endpoint: "https://ocapi-kr.ncloud.com/secretmanager/.",
			wantErr:  true,
		},
		{
			name:     "encoded path rejected",
			endpoint: "https://ocapi-kr.ncloud.com/secretmanager/%2e%2e",
			wantErr:  true,
		},
		{
			name:     "whitespace rejected",
			endpoint: " https://ocapi-kr.ncloud.com/secretmanager",
			wantErr:  true,
		},
	}

	p := &Provider{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := validProvider()
			provider.Endpoint = tt.endpoint

			warnings, err := p.ValidateStore(newNcloudStore(provider))
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateStore() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(warnings) != 0 {
				t.Errorf("ValidateStore() warnings = %v, want none", warnings)
			}
		})
	}
}

// credentialsSecret returns a Kubernetes Secret holding valid credentials.
func credentialsSecret() *corev1.Secret {
	return credentialsSecretInNamespace(testNamespace)
}

func credentialsSecretInNamespace(namespace string) *corev1.Secret {
	return &corev1.Secret{
		Name: testSecretName, Namespace: namespace,
		Data: map[string][]byte{
			"access-key-id": []byte("AKID"),
			"secret-key":    []byte("SECRET"),
		},
	}
}

func newKubeClient(objs ...kclient.Object) kclient.Client {
	return clientfake.NewClientBuilder().WithObjects(objs...).Build()
}

func newKubeClientForCredentialNamespaces(namespaces ...string) kclient.Client {
	objects := make([]kclient.Object, 0, len(namespaces))
	for _, namespace := range namespaces {
		objects = append(objects, credentialsSecretInNamespace(namespace))
	}
	return newKubeClient(objects...)
}

type credentialSelectorFieldCase struct {
	name      string
	wantField string
	mutate    func(*esv1.NcloudAuthSecretRef)
}

func credentialSelectorFieldCases() []credentialSelectorFieldCase {
	return []credentialSelectorFieldCase{
		{
			name:      "AccessKeyID name",
			wantField: "auth.secretRef.accessKeyIDSecretRef.name",
			mutate: func(ref *esv1.NcloudAuthSecretRef) {
				ref.AccessKeyID.Name = ""
			},
		},
		{
			name:      "AccessKeyID key",
			wantField: "auth.secretRef.accessKeyIDSecretRef.key",
			mutate: func(ref *esv1.NcloudAuthSecretRef) {
				ref.AccessKeyID.Key = ""
			},
		},
		{
			name:      "SecretKey name",
			wantField: "auth.secretRef.secretKeySecretRef.name",
			mutate: func(ref *esv1.NcloudAuthSecretRef) {
				ref.SecretKey.Name = ""
			},
		},
		{
			name:      "SecretKey key",
			wantField: "auth.secretRef.secretKeySecretRef.key",
			mutate: func(ref *esv1.NcloudAuthSecretRef) {
				ref.SecretKey.Key = ""
			},
		},
	}
}

func TestCapabilities(t *testing.T) {
	if got := (&Provider{}).Capabilities(); got != esv1.SecretStoreReadWrite {
		t.Errorf("Capabilities() = %v, want %v", got, esv1.SecretStoreReadWrite)
	}
}

func TestNewProvider(t *testing.T) {
	p := NewProvider()
	if p == nil {
		t.Fatal("NewProvider() returned nil")
	}
	if _, ok := p.(*Provider); !ok {
		t.Errorf("NewProvider() type = %T, want *Provider", p)
	}
}

func TestProviderSpec(t *testing.T) {
	spec := ProviderSpec()
	if spec == nil || spec.Ncloud == nil {
		t.Fatal("ProviderSpec() must return a non-nil spec with Ncloud set")
	}
}

func TestMaintenanceStatus(t *testing.T) {
	if got := MaintenanceStatus(); got != esv1.MaintenanceStatusMaintained {
		t.Errorf("MaintenanceStatus() = %v, want %v", got, esv1.MaintenanceStatusMaintained)
	}
}

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		store   esv1.GenericStore
		kube    kclient.Client
		wantErr bool
	}{
		{
			name:    "valid store resolves credentials",
			store:   newNcloudStore(validProvider()),
			kube:    newKubeClient(credentialsSecret()),
			wantErr: false,
		},
		{
			name: "trailing slash endpoint resolves credentials",
			store: func() esv1.GenericStore {
				provider := validProvider()
				provider.Endpoint += "///"
				return newNcloudStore(provider)
			}(),
			kube:    newKubeClient(credentialsSecret()),
			wantErr: false,
		},
		{
			name:    "nil ncloud provider",
			store:   newNcloudStore(nil),
			kube:    newKubeClient(),
			wantErr: true,
		},
		{
			name: "missing auth secretRef",
			store: newNcloudStore(&esv1.NcloudProvider{
				Endpoint: testEndpoint,
				Auth:     esv1.NcloudAuth{SecretRef: nil},
			}),
			kube:    newKubeClient(),
			wantErr: true,
		},
		{
			name:    "credentials secret absent from kube",
			store:   newNcloudStore(validProvider()),
			kube:    newKubeClient(),
			wantErr: true,
		},
		{
			name:  "secret missing secret-key entry",
			store: newNcloudStore(validProvider()),
			kube: newKubeClient(&corev1.Secret{
				Name: testSecretName, Namespace: testNamespace,
				Data: map[string][]byte{"access-key-id": []byte("AKID")},
			}),
			wantErr: true,
		},
		{
			name: "empty endpoint fails client construction",
			store: newNcloudStore(&esv1.NcloudProvider{
				Endpoint: "",
				Auth:     validProvider().Auth,
			}),
			kube:    newKubeClient(credentialsSecret()),
			wantErr: true,
		},
	}

	p := &Provider{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := p.NewClient(context.Background(), tt.store, tt.kube, testNamespace)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && client == nil {
				t.Error("NewClient() returned nil client without error")
			}
		})
	}
}

func TestNewClientEnforcesEndpointAtRuntime(t *testing.T) {
	p := &Provider{}
	tests := []string{
		"http://ocapi-kr.ncloud.com/secretmanager",
		"https://user@ocapi-kr.ncloud.com/secretmanager",
		"https://ocapi-kr.ncloud.com/secretmanager?",
		"https://ocapi-kr.ncloud.com/secretmanager#",
		"https://ocapi-kr.ncloud.com/secretmanager/%2e%2e",
	}

	for _, endpoint := range tests {
		t.Run(endpoint, func(t *testing.T) {
			provider := validProvider()
			provider.Endpoint = endpoint

			// The empty Kubernetes client proves endpoint validation happens
			// before attempting to resolve either credential.
			_, err := p.NewClient(context.Background(), newNcloudStore(provider), newKubeClient(), testNamespace)
			if err == nil {
				t.Fatal("NewClient() returned nil error")
			}
			if !strings.Contains(err.Error(), "invalid endpoint") {
				t.Errorf("NewClient() error = %v, want endpoint validation error", err)
			}
		})
	}
}

func TestValidateStoreNilInputs(t *testing.T) {
	p := &Provider{}
	if _, err := p.ValidateStore(nil); err == nil {
		t.Error("ValidateStore(nil) should error")
	}
	if _, err := p.ValidateStore(newNcloudStore(nil)); err == nil {
		t.Error("ValidateStore() with nil ncloud provider should error")
	}
}

func TestNewClientNilStore(t *testing.T) {
	p := &Provider{}
	// A nil store must be rejected up front, not panic in store.GetSpec().
	_, err := p.NewClient(context.Background(), nil, nil, testNamespace)
	if err == nil {
		t.Fatal("NewClient() with nil store should error")
	}
	if !errors.Is(err, errInvalidNcloudStore) {
		t.Errorf("NewClient(nil) error = %v, want errors.Is errInvalidNcloudStore", err)
	}
}

func TestProviderErrorsAreClassifiable(t *testing.T) {
	p := &Provider{}
	// The provider boundary must preserve the sentinel chain so callers can
	// errors.Is a store without an auth method rather than string-match the
	// message.
	store := newNcloudStore(&esv1.NcloudProvider{
		Endpoint: testEndpoint,
		Auth:     esv1.NcloudAuth{SecretRef: nil},
	})
	_, err := p.NewClient(context.Background(), store, newKubeClient(), testNamespace)
	if !errors.Is(err, errAuthMethod) {
		t.Errorf("NewClient() no-auth-method error = %v, want errors.Is errAuthMethod", err)
	}
}

func TestValidateStoreSecretRef(t *testing.T) {
	p := &Provider{}

	// A store without Auth.SecretRef can never produce a working client
	// (NewClient rejects it), so admission must reject it as well.
	store := newNcloudStore(&esv1.NcloudProvider{
		Endpoint: testEndpoint,
		Auth:     esv1.NcloudAuth{SecretRef: nil},
	})
	if _, err := p.ValidateStore(store); err == nil {
		t.Error("ValidateStore() with nil Auth.SecretRef should error")
	}

	if _, err := p.ValidateStore(newNcloudStore(validProvider())); err != nil {
		t.Errorf("ValidateStore() with valid SecretRef returned error: %v", err)
	}
}

func TestValidateStoreCredentialSelectorFields(t *testing.T) {
	p := &Provider{}

	for _, tt := range credentialSelectorFieldCases() {
		t.Run(tt.name, func(t *testing.T) {
			provider := validProvider()
			tt.mutate(provider.Auth.SecretRef)

			_, err := p.ValidateStore(newNcloudStore(provider))
			if err == nil {
				t.Fatal("ValidateStore() returned nil error")
			}
			if !strings.Contains(err.Error(), tt.wantField) {
				t.Errorf("ValidateStore() error = %v, want field %q", err, tt.wantField)
			}
		})
	}
}

func TestNewClientCredentialSelectorFieldsAtRuntime(t *testing.T) {
	p := &Provider{}
	storeKinds := []struct {
		name      string
		newStore  func(*esv1.NcloudProvider) esv1.GenericStore
		namespace string
	}{
		{
			name:      "SecretStore",
			newStore:  newNcloudStore,
			namespace: testNamespace,
		},
		{
			name:      "ClusterSecretStore readiness",
			newStore:  newNcloudClusterStore,
			namespace: "",
		},
	}

	for _, storeKind := range storeKinds {
		t.Run(storeKind.name, func(t *testing.T) {
			for _, tt := range credentialSelectorFieldCases() {
				t.Run(tt.name, func(t *testing.T) {
					provider := validProvider()
					tt.mutate(provider.Auth.SecretRef)

					// No credentials exist, so a field-specific error proves
					// runtime validation precedes credential resolution and
					// ClusterSecretStore referent placeholder creation.
					_, err := p.NewClient(
						context.Background(),
						storeKind.newStore(provider),
						newKubeClient(),
						storeKind.namespace,
					)
					if err == nil {
						t.Fatal("NewClient() returned nil error")
					}
					if !strings.Contains(err.Error(), tt.wantField) {
						t.Errorf("NewClient() error = %v, want field %q", err, tt.wantField)
					}
				})
			}
		})
	}
}

func TestCredentialSelectorNamespaceValidation(t *testing.T) {
	p := &Provider{}
	foreignNamespace := "foreign-ns"
	tests := []struct {
		name      string
		wantField string
		mutate    func(*esv1.NcloudAuthSecretRef)
	}{
		{
			name:      "AccessKeyID",
			wantField: "auth.secretRef.accessKeyIDSecretRef",
			mutate: func(ref *esv1.NcloudAuthSecretRef) {
				ref.AccessKeyID.Namespace = &foreignNamespace
			},
		},
		{
			name:      "SecretKey",
			wantField: "auth.secretRef.secretKeySecretRef",
			mutate: func(ref *esv1.NcloudAuthSecretRef) {
				ref.SecretKey.Namespace = &foreignNamespace
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := validProvider()
			tt.mutate(provider.Auth.SecretRef)
			store := newNcloudStore(provider)

			_, err := p.ValidateStore(store)
			if err == nil || !strings.Contains(err.Error(), tt.wantField) {
				t.Errorf("ValidateStore() error = %v, want field %q", err, tt.wantField)
			}

			_, err = p.NewClient(context.Background(), store, newKubeClient(), testNamespace)
			if err == nil || !strings.Contains(err.Error(), tt.wantField) {
				t.Errorf("NewClient() error = %v, want field %q", err, tt.wantField)
			}
		})
	}
}

// TestNewClientScopesSelectorNamespacesByStoreKind pins that the namespace
// rule NewClient re-checks is keyed by store.GetKind(), which is hardcoded per
// type, and not by TypeMeta, which a typed object read outside the manager's
// cache can leave empty. With TypeMeta empty, a TypeMeta-keyed check would
// read a ClusterSecretStore as namespaced and refuse its explicit namespaces.
func TestNewClientScopesSelectorNamespacesByStoreKind(t *testing.T) {
	p := &Provider{}
	explicit := new(testExplicitNamespace)

	t.Run("a ClusterSecretStore without TypeMeta keeps its cluster scope", func(t *testing.T) {
		prov := validProvider()
		prov.Auth.SecretRef.AccessKeyID.Namespace = explicit
		prov.Auth.SecretRef.SecretKey.Namespace = explicit
		store := newNcloudClusterStore(prov).(*esv1.ClusterSecretStore)
		store.TypeMeta = metav1.TypeMeta{}

		kube := newKubeClientForCredentialNamespaces(testExplicitNamespace)
		if _, err := p.NewClient(context.Background(), store, kube, ""); err != nil {
			t.Fatalf("NewClient() error = %v, want the explicit namespaces accepted without TypeMeta", err)
		}
	})

	t.Run("a serverRole ClusterSecretStore without TypeMeta is still accepted", func(t *testing.T) {
		store := newNcloudClusterStore(serverRoleProvider()).(*esv1.ClusterSecretStore)
		store.TypeMeta = metav1.TypeMeta{}
		if _, err := p.NewClient(context.Background(), store, newKubeClient(), ""); err != nil {
			t.Fatalf("NewClient() error = %v, want serverRole accepted in a ClusterSecretStore without TypeMeta", err)
		}
	})

	t.Run("a serverRole SecretStore without TypeMeta is still refused", func(t *testing.T) {
		store := newNcloudStore(serverRoleProvider()).(*esv1.SecretStore)
		store.TypeMeta = metav1.TypeMeta{}
		_, err := p.NewClient(context.Background(), store, newKubeClient(), testNamespace)
		if !errors.Is(err, errControllerIdentityScope) {
			t.Fatalf("NewClient() error = %v, want errControllerIdentityScope", err)
		}
		if want := "serverRole may be used only in a ClusterSecretStore"; !strings.Contains(err.Error(), want) {
			t.Errorf("NewClient() error = %q, want it to contain %q", err, want)
		}
	})

	t.Run("a podIdentity SecretStore without TypeMeta is still refused", func(t *testing.T) {
		store := newNcloudStore(podIdentityProvider()).(*esv1.SecretStore)
		store.TypeMeta = metav1.TypeMeta{}
		_, err := podIdentityInjectedProvider().NewClient(context.Background(), store, newKubeClient(), testNamespace)
		if !errors.Is(err, errControllerIdentityScope) {
			t.Fatalf("NewClient() error = %v, want errControllerIdentityScope", err)
		}
		if want := "podIdentity may be used only in a ClusterSecretStore"; !strings.Contains(err.Error(), want) {
			t.Errorf("NewClient() error = %q, want it to contain %q", err, want)
		}
	})

	t.Run("a SecretStore without TypeMeta still refuses another namespace", func(t *testing.T) {
		prov := validProvider()
		prov.Auth.SecretRef.AccessKeyID.Namespace = explicit
		store := newNcloudStore(prov).(*esv1.SecretStore)
		store.TypeMeta = metav1.TypeMeta{}

		_, err := p.NewClient(context.Background(), store, newKubeClient(credentialsSecret()), testNamespace)
		if !errors.Is(err, errSelectorNamespaceNotAllowed) {
			t.Fatalf("NewClient() error = %v, want errSelectorNamespaceNotAllowed", err)
		}
	})
}

func TestNewClientClusterSecretStoreCredentialNamespaces(t *testing.T) {
	p := &Provider{}
	explicitNamespace := new(testExplicitNamespace)

	tests := []struct {
		name                      string
		accessKeyNamespace        *string
		secretKeyNamespace        *string
		wantReadinessPlaceholder  bool
		readinessSecretNamespaces []string
		consumerSecretNamespaces  []string
	}{
		{
			name:                     "both selectors use referent namespace",
			wantReadinessPlaceholder: true,
			consumerSecretNamespaces: []string{testNamespace},
		},
		{
			name:                     "AccessKeyID uses referent namespace",
			secretKeyNamespace:       explicitNamespace,
			wantReadinessPlaceholder: true,
			consumerSecretNamespaces: []string{testNamespace, testExplicitNamespace},
		},
		{
			name:                     "SecretKey uses referent namespace",
			accessKeyNamespace:       explicitNamespace,
			wantReadinessPlaceholder: true,
			consumerSecretNamespaces: []string{testExplicitNamespace, testNamespace},
		},
		{
			name:                      "both selectors use explicit namespace",
			accessKeyNamespace:        explicitNamespace,
			secretKeyNamespace:        explicitNamespace,
			readinessSecretNamespaces: []string{testExplicitNamespace},
			consumerSecretNamespaces:  []string{testExplicitNamespace},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := validProvider()
			provider.Auth.SecretRef.AccessKeyID.Namespace = tt.accessKeyNamespace
			provider.Auth.SecretRef.SecretKey.Namespace = tt.secretKeyNamespace
			store := newNcloudClusterStore(provider)

			if _, err := p.ValidateStore(store); err != nil {
				t.Fatalf("ValidateStore() returned error: %v", err)
			}

			t.Run("readiness", func(t *testing.T) {
				var kube kclient.Client
				if !tt.wantReadinessPlaceholder {
					kube = newKubeClientForCredentialNamespaces(tt.readinessSecretNamespaces...)
				}

				client, err := p.NewClient(context.Background(), store, kube, "")
				if err != nil {
					t.Fatalf("NewClient() returned error: %v", err)
				}
				if client == nil {
					t.Fatal("NewClient() returned nil client")
				}

				if tt.wantReadinessPlaceholder {
					result, err := client.Validate()
					if err != nil {
						t.Fatalf("placeholder Validate() returned error: %v", err)
					}
					if result != esv1.ValidationResultUnknown {
						t.Errorf("placeholder Validate() = %v, want %v", result, esv1.ValidationResultUnknown)
					}
				}
			})

			t.Run("consumer resolution", func(t *testing.T) {
				kube := newKubeClientForCredentialNamespaces(tt.consumerSecretNamespaces...)
				client, err := p.NewClient(context.Background(), store, kube, testNamespace)
				if err != nil {
					t.Fatalf("NewClient() returned error: %v", err)
				}
				if client == nil {
					t.Fatal("NewClient() returned nil client")
				}
			})
		})
	}
}
