// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package ncloud

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

const (
	// crdBundleDir holds the generated CRD bundle the chart installs; make
	// test regenerates it before the suite runs.
	crdBundleDir = "../../../deploy/crds"
	// snippetsGlob selects the YAML examples docs/provider/ncloud.md includes.
	snippetsGlob = "../../../docs/snippets/ncloud-*.yaml"

	// Keys of the ncloud provider block, as a store spells them.
	fieldAuth         = "auth"
	fieldEndpoint     = "endpoint"
	fieldRole         = "role"
	fieldName         = "name"
	fieldKey          = "key"
	methodSecretRef   = "secretRef"
	methodServerRole  = "serverRole"
	methodPodIdentity = "podIdentity"

	// authPath is where the API server reports a violation of the auth union.
	authPath = "spec.provider.ncloud.auth"

	// apiServerNamespace is the namespace every API server has; the envtest
	// server starts with no other.
	apiServerNamespace = "default"
)

// startAPIServer boots an envtest API server that serves the generated CRD
// bundle and returns a client for it. Like the fork's live controller test it
// skips when the envtest binaries are not on hand; make test exports
// KUBEBUILDER_ASSETS before running the suite, and CI runs make test.
func startAPIServer(t *testing.T) kclient.Client {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS must point at envtest binaries; run via `make` or set it explicitly")
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{crdBundleDir},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("envtest Start() error = %v", err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("envtest Stop() error = %v", err)
		}
	})
	scheme := runtime.NewScheme()
	if err := esv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme() error = %v", err)
	}
	c, err := kclient.New(cfg, kclient.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("client.New() error = %v", err)
	}
	return c
}

// decodeSnippet reads one YAML example into an unstructured object, so that
// the API server, not a Go type, decides what the example means.
func decodeSnippet(t *testing.T, path string) *unstructured.Unstructured {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	obj := &unstructured.Unstructured{}
	if err := utilyaml.Unmarshal(data, &obj.Object); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return obj
}

// admit runs an unstructured store through the validator type the webhook
// serves, typed the way the webhook types it, with the provider registered
// the way pkg/register registers it. ForceRegister is idempotent, so every
// call may register again.
func admit(t *testing.T, obj *unstructured.Unstructured) (admission.Warnings, error) {
	t.Helper()
	esv1.ForceRegister(NewProvider(), ProviderSpec(), MaintenanceStatus())
	switch obj.GetKind() {
	case esv1.SecretStoreKind:
		store := &esv1.SecretStore{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, store); err != nil {
			t.Fatalf("convert %s: %v", obj.GetName(), err)
		}
		return (&esv1.GenericStoreValidator{}).ValidateCreate(t.Context(), store)
	case esv1.ClusterSecretStoreKind:
		store := &esv1.ClusterSecretStore{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, store); err != nil {
			t.Fatalf("convert %s: %v", obj.GetName(), err)
		}
		return (&esv1.GenericClusterStoreValidator{}).ValidateCreate(t.Context(), store)
	default:
		t.Fatalf("%s is not a store kind", obj.GetKind())
		return nil, nil
	}
}

// isStoreKind reports whether the example is one admission validates.
func isStoreKind(obj *unstructured.Unstructured) bool {
	return obj.GetKind() == esv1.SecretStoreKind || obj.GetKind() == esv1.ClusterSecretStoreKind
}

// ncloudStore returns an unstructured SecretStore or ClusterSecretStore whose
// ncloud provider block is the given map, for probing the schema with values
// a Go type could not express, such as a missing required field.
func ncloudStore(kind, name string, provider map[string]any) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion(esv1.SchemeGroupVersion.String())
	obj.SetKind(kind)
	obj.SetName(name)
	if kind == esv1.SecretStoreKind {
		obj.SetNamespace(apiServerNamespace)
	}
	obj.Object["spec"] = map[string]any{
		"provider": map[string]any{"ncloud": provider},
	}
	return obj
}

// secretRefAuth is the auth block of the documented SecretStore example.
func secretRefAuth() map[string]any {
	return map[string]any{
		methodSecretRef: map[string]any{
			"accessKeyIDSecretRef": map[string]any{fieldName: testSecretName, fieldKey: "access-key-id"},
			"secretKeySecretRef":   map[string]any{fieldName: testSecretName, fieldKey: "secret-key"},
		},
	}
}

// TestDocsSnippetsPassTheGeneratedCRDsAndAdmission applies every YAML example
// docs/provider/ncloud.md includes to an API server that serves the generated
// CRD bundle, then runs the store examples through the validator type the
// webhook serves. The page is the promise a reader copies from: an example it
// shows must get past kubectl apply and past admission, and the
// ClusterSecretStore examples carry conditions, so none of them may draw the
// every-namespace warning. The examples are alternatives and reuse names (both
// ClusterSecretStore examples are ncloud-cluster-store), so each is created
// under its file stem. The stores whose auth method is an empty object are
// read back typed, to pin that the API server keeps the empty object rather
// than pruning it: a pruned serverRole or podIdentity would come back as a
// store with no auth method at all.
func TestDocsSnippetsPassTheGeneratedCRDsAndAdmission(t *testing.T) {
	c := startAPIServer(t)
	ctx := t.Context()

	snippets, err := filepath.Glob(snippetsGlob)
	if err != nil || len(snippets) == 0 {
		t.Fatalf("no ncloud snippets found under %s: %v", snippetsGlob, err)
	}
	stem := func(path string) string { return strings.TrimSuffix(filepath.Base(path), ".yaml") }
	for _, path := range snippets {
		t.Run(filepath.Base(path), func(t *testing.T) {
			obj := decodeSnippet(t, path)
			obj.SetName(stem(path))
			if obj.GetKind() != esv1.ClusterSecretStoreKind {
				obj.SetNamespace(apiServerNamespace)
			}
			if err := c.Create(ctx, obj); err != nil {
				t.Fatalf("the API server refused the documented example: %v", err)
			}
			if !isStoreKind(obj) {
				return
			}
			warnings, err := admit(t, decodeSnippet(t, path))
			if err != nil {
				t.Errorf("admission refused the documented example: %v", err)
			}
			if len(warnings) != 0 {
				t.Errorf("admission warned about the documented example: %v", warnings)
			}
		})
	}

	t.Run("an empty auth method object survives the API server", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			method string
			isSet  func(*esv1.NcloudAuth) bool
		}{
			{"ncloud-secret-store-pod-identity", methodPodIdentity, func(a *esv1.NcloudAuth) bool { return a.PodIdentity != nil }},
			{"ncloud-secret-store-server-role", methodServerRole, func(a *esv1.NcloudAuth) bool { return a.ServerRole != nil }},
			{"ncloud-secret-store-switch-role", methodServerRole, func(a *esv1.NcloudAuth) bool { return a.ServerRole != nil }},
		} {
			stored := &esv1.ClusterSecretStore{}
			if err := c.Get(ctx, kclient.ObjectKey{Name: tc.name}, stored); err != nil {
				t.Fatalf("get %s: %v", tc.name, err)
			}
			if !tc.isSet(&stored.Spec.Provider.Ncloud.Auth) {
				t.Errorf("%s came back from the API server without %s: the empty object was pruned", tc.name, tc.method)
			}
			if warnings, err := (&Provider{}).ValidateStore(stored); err != nil || len(warnings) != 0 {
				t.Errorf("ValidateStore() on the stored %s = %v, %v; want it accepted without warnings", tc.name, warnings, err)
			}
		}
	})
}

// TestCRDGatesMatchTheDocumentation probes the generated schema with the
// stores the provider page says the CRD refuses, and with the ones it says
// the CRD lets through for the webhook to catch. The schema is the first gate
// and the only one enforced where the webhook is absent or set to
// failurePolicy Ignore, so each promise is checked against a real API server
// rather than against the markers that generate it. The unit tests next to
// this one cover the webhook's side of the same promises.
func TestCRDGatesMatchTheDocumentation(t *testing.T) {
	c := startAPIServer(t)
	ctx := t.Context()

	// withEndpoint fills in the documented endpoint unless the probe is
	// about the endpoint itself.
	withEndpoint := func(provider map[string]any) map[string]any {
		if _, ok := provider[fieldEndpoint]; !ok {
			provider[fieldEndpoint] = testEndpoint
		}
		return provider
	}

	refused := []struct {
		name     string
		kind     string
		provider map[string]any
		want     string
	}{
		{
			name:     "no auth method",
			kind:     esv1.SecretStoreKind,
			provider: map[string]any{fieldAuth: map[string]any{}},
			want:     authPath,
		},
		{
			name: "two auth methods",
			kind: esv1.ClusterSecretStoreKind,
			provider: func() map[string]any {
				auth := secretRefAuth()
				auth[methodServerRole] = map[string]any{}
				return map[string]any{fieldAuth: auth}
			}(),
			want: authPath,
		},
		{
			name:     "plain http endpoint",
			kind:     esv1.SecretStoreKind,
			provider: map[string]any{fieldAuth: secretRefAuth(), fieldEndpoint: "http://ocapi-kr.ncloud.com/secretmanager"},
			want:     "spec.provider.ncloud.endpoint",
		},
		{
			name:     "role without the nrn prefix",
			kind:     esv1.ClusterSecretStoreKind,
			provider: map[string]any{fieldAuth: map[string]any{methodServerRole: map[string]any{}}, fieldRole: "Role/abcdef"},
			want:     "spec.provider.ncloud.role",
		},
		{
			name:     "no auth at all",
			kind:     esv1.SecretStoreKind,
			provider: map[string]any{},
			want:     authPath,
		},
	}
	for _, tc := range refused {
		t.Run("CRD refuses "+tc.name, func(t *testing.T) {
			obj := ncloudStore(tc.kind, "refused-"+strings.ReplaceAll(tc.name, " ", "-"), withEndpoint(tc.provider))
			err := c.Create(ctx, obj)
			if err == nil {
				t.Fatal("the API server accepted a store the documentation says the CRD refuses")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("rejection = %v, want it to name %s", err, tc.want)
			}
		})
	}

	t.Run("CRD lets an empty selector through and admission refuses it", func(t *testing.T) {
		// docs/provider/ncloud.md, Permanent access key: a store written
		// with accessKeyIDSecretRef: {} is accepted by kubectl apply where
		// the webhook is absent, and the webhook names the field.
		obj := ncloudStore(esv1.SecretStoreKind, "empty-selector", withEndpoint(map[string]any{
			fieldAuth: map[string]any{methodSecretRef: map[string]any{
				"accessKeyIDSecretRef": map[string]any{},
				"secretKeySecretRef":   map[string]any{fieldName: testSecretName, fieldKey: "secret-key"},
			}},
		}))
		if err := c.Create(ctx, obj); err != nil {
			t.Fatalf("the API server refused what the documentation says it accepts: %v", err)
		}
		_, err := admit(t, obj)
		if err == nil || !strings.Contains(err.Error(), accessKeyIDSelectorField+".name") {
			t.Errorf("admission error = %v, want it to name %s.name", err, accessKeyIDSelectorField)
		}
	})

	t.Run("CRD lets serverRole into a SecretStore and admission refuses it", func(t *testing.T) {
		// The schema cannot know the store's kind, so the webhook is the
		// gate, and NewClient repeats the rule where admission did not run.
		obj := ncloudStore(esv1.SecretStoreKind, "namespaced-server-role", withEndpoint(map[string]any{
			fieldAuth: map[string]any{methodServerRole: map[string]any{}},
		}))
		if err := c.Create(ctx, obj); err != nil {
			t.Fatalf("the API server refused the store: %v", err)
		}
		_, err := admit(t, obj)
		if err == nil || !strings.Contains(err.Error(), "serverRole may be used only in a ClusterSecretStore") {
			t.Errorf("admission error = %v, want the ClusterSecretStore-only refusal", err)
		}
	})
}
