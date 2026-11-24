//go:build ncloud_live

// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

// Package ncloudlive runs the real ExternalSecret and PushSecret controllers
// against a real Ncloud Secret Manager account.
//
// It exists because every other Ncloud test stops at the SecretsClient
// boundary: the unit suite mocks the API, and the provider's own live tests
// call the client directly and say so ("does not exercise the Kubernetes
// controllers or reconciliation lifecycle"). The layer in between - credential
// resolution from a SecretStore, the reconcilers' use of the provider's
// errors, and finalizer handling - was therefore never executed against the
// real service. That layer is where a wedged PushSecret finalizer and a
// deletionPolicy that acts on the wrong error live, and neither is visible to
// a mock.
//
// Requires an API server binary (envtest) plus real credentials, and it
// creates and destroys real remote secrets. See providers/v1/ncloud/README.md.
package ncloudlive

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esv1alpha1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	ctrlcommon "github.com/external-secrets/external-secrets/pkg/controllers/common"
	"github.com/external-secrets/external-secrets/pkg/controllers/externalsecret"
	"github.com/external-secrets/external-secrets/pkg/controllers/pushsecret"
	"github.com/external-secrets/external-secrets/providers/v1/ncloud/secretmanager"

	// Blank import registers the Ncloud provider. It is itself gated behind
	// the `ncloud` tag, so run this suite with -tags 'ncloud ncloud_live'.
	_ "github.com/external-secrets/external-secrets/pkg/register"
)

const (
	// pollInterval and pollTimeout bound every wait. The timeout is generous
	// because each reconcile makes real API calls, and a name resolution that
	// misses the cache pays a full paginated listing scan.
	pollInterval = 2 * time.Second
	pollTimeout  = 90 * time.Second

	testNamespace  = "ncloud-live"
	credSecretName = "ncloud-credentials"
	storeName      = "ncloud-live-store"
)

// liveEnv is the resolved opt-in configuration.
type liveEnv struct {
	accessKeyID string
	secretKey   string
	endpoint    string
}

// requireLiveEnv gates the suite. The endpoint must be one the provider
// accepts: unlike the provider-level probes, this suite drives the real
// SecretStore -> NewClient path, where the CRD pattern and NormalizeEndpoint
// both require an https:// base URL. Any https host qualifies; a plain-http
// endpoint cannot be exercised here.
func requireLiveEnv(t *testing.T) liveEnv {
	t.Helper()

	if os.Getenv("RUN_NCLOUD_E2E") != "true" {
		t.Skip("set RUN_NCLOUD_E2E=true to run the live Ncloud reconcile suite")
	}

	env := liveEnv{
		accessKeyID: os.Getenv("NCLOUD_ACCESS_KEY_ID"),
		secretKey:   os.Getenv("NCLOUD_SECRET_KEY"),
		endpoint:    os.Getenv("NCLOUD_ENDPOINT"),
	}
	if env.accessKeyID == "" || env.secretKey == "" {
		t.Fatal("NCLOUD_ACCESS_KEY_ID and NCLOUD_SECRET_KEY must be set when RUN_NCLOUD_E2E=true")
	}
	if env.endpoint == "" {
		env.endpoint = "https://ocapi-kr.ncloud.com/secretmanager"
	}
	if _, err := secretmanager.NormalizeEndpoint(env.endpoint); err != nil {
		t.Skipf("NCLOUD_ENDPOINT=%q is not an endpoint the provider accepts (%v), so a SecretStore "+
			"cannot name it and this suite cannot run against it.", env.endpoint, err)
	}
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS must point at envtest binaries; run via `make` or set it explicitly")
	}
	return env
}

// TestLiveReconcileLifecycle drives the real controllers through the paths a
// mock cannot reach: a PushSecret creating a remote secret, an ExternalSecret
// reading it back, deletionPolicy acting on a genuinely absent remote secret,
// and a PushSecret finalizer completing against the real service.
func TestLiveReconcileLifecycle(t *testing.T) {
	env := requireLiveEnv(t)

	// t.Context is canceled during cleanup, which stops the manager started
	// below before envtest is torn down.
	ctx := t.Context()

	k8s := startTestEnv(ctx, t)
	remote := newRemoteClient(t, env)

	remoteKey := uniqueRemoteKey(t)
	t.Cleanup(func() { destroyRemote(t, remote, remoteKey) })

	createNamespace(ctx, t, k8s)
	createCredentials(ctx, t, k8s, env)
	createStore(ctx, t, k8s, env)

	t.Run("PushSecret creates the remote secret", func(t *testing.T) {
		source := &corev1.Secret{
			Name: "source", Namespace: testNamespace,
			Data: map[string][]byte{"password": []byte("live-reconcile-value")},
		}
		mustCreate(ctx, t, k8s, source)

		ps := &esv1alpha1.PushSecret{
			Name: "push", Namespace: testNamespace,
			Spec: esv1alpha1.PushSecretSpec{
				DeletionPolicy: esv1alpha1.PushSecretDeletionPolicyDelete,
				SecretStoreRefs: []esv1alpha1.PushSecretStoreRef{{
					Name: storeName, Kind: esv1.SecretStoreKind,
				}},
				Selector: esv1alpha1.PushSecretSelector{
					Secret: &esv1alpha1.PushSecretSecret{Name: "source"},
				},
				Data: []esv1alpha1.PushSecretData{{
					Match: esv1alpha1.PushSecretMatch{
						SecretKey: "password",
						RemoteRef: esv1alpha1.PushSecretRemoteRef{RemoteKey: remoteKey},
					},
				}},
			},
		}
		mustCreate(ctx, t, k8s, ps)

		// The remote value is the assertion, not the CR status: a status can
		// go Ready on a code path that never reached the API.
		waitFor(t, "the remote secret to carry the pushed value", func() error {
			value, err := remote.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{
				Key: remoteKey, Property: "password",
			})
			if err != nil {
				return err
			}
			if got := string(value); got != "live-reconcile-value" {
				return fmt.Errorf("remote value = %q, want live-reconcile-value", got)
			}
			return nil
		})
	})

	t.Run("ExternalSecret syncs the remote secret into a Secret", func(t *testing.T) {
		es := &esv1.ExternalSecret{
			Name: "pull", Namespace: testNamespace,
			Spec: esv1.ExternalSecretSpec{
				RefreshInterval: &metav1.Duration{Duration: 5 * time.Second},
				SecretStoreRef:  esv1.SecretStoreRef{Name: storeName, Kind: esv1.SecretStoreKind},
				Target: esv1.ExternalSecretTarget{
					Name:           "synced",
					DeletionPolicy: esv1.DeletionPolicyDelete,
				},
				Data: []esv1.ExternalSecretData{{
					SecretKey: "password",
					RemoteRef: esv1.ExternalSecretDataRemoteRef{
						Key: remoteKey, Property: "password",
					},
				}},
			},
		}
		mustCreate(ctx, t, k8s, es)

		waitFor(t, "the target Secret to hold the remote value", func() error {
			var synced corev1.Secret
			if err := k8s.Get(ctx, client.ObjectKey{Name: "synced", Namespace: testNamespace}, &synced); err != nil {
				return err
			}
			if got := string(synced.Data["password"]); got != "live-reconcile-value" {
				return fmt.Errorf("synced value = %q, want live-reconcile-value", got)
			}
			return nil
		})
	})

	// The highest-value assertion here. deletionPolicy: Delete fires only when
	// the provider reports esv1.NoSecretErr, and a provider that reported any
	// other error would instead leave the ExternalSecret in SyncError forever
	// with a stale Secret in place. Nothing short of a real deletion against
	// the real service exercises that agreement.
	t.Run("deletionPolicy removes the Secret once the remote secret is gone", func(t *testing.T) {
		destroyRemote(t, remote, remoteKey)

		waitFor(t, "the target Secret to be deleted", func() error {
			var synced corev1.Secret
			err := k8s.Get(ctx, client.ObjectKey{Name: "synced", Namespace: testNamespace}, &synced)
			if apierrors.IsNotFound(err) {
				return nil
			}
			if err != nil {
				return err
			}
			return errors.New("target Secret still exists")
		})
	})

	// A PushSecret with deletionPolicy: Delete holds a finalizer, and the
	// reconciler removes it only after the provider's DeleteSecret returns
	// without error. A provider that errors on a remote secret already gone
	// would pin the resource in Terminating.
	t.Run("PushSecret deletion completes its finalizer", func(t *testing.T) {
		var ps esv1alpha1.PushSecret
		if err := k8s.Get(ctx, client.ObjectKey{Name: "push", Namespace: testNamespace}, &ps); err != nil {
			t.Fatalf("get PushSecret: %v", err)
		}
		if err := k8s.Delete(ctx, &ps); err != nil {
			t.Fatalf("delete PushSecret: %v", err)
		}

		waitFor(t, "the PushSecret to be fully removed", func() error {
			var got esv1alpha1.PushSecret
			err := k8s.Get(ctx, client.ObjectKey{Name: "push", Namespace: testNamespace}, &got)
			if apierrors.IsNotFound(err) {
				return nil
			}
			if err != nil {
				return err
			}
			return fmt.Errorf("still present with finalizers %v", got.Finalizers)
		})
	})
}

// startTestEnv boots an API server with the fork's CRDs and starts the two
// reconcilers under test, wired as the production command wires them.
func startTestEnv(ctx context.Context, t *testing.T) client.Client {
	t.Helper()

	testEnv := &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "..", "..", "deploy", "crds")},
	}
	cfg, err := testEnv.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		if err := testEnv.Stop(); err != nil {
			t.Logf("stop envtest: %v", err)
		}
	})

	if err := esv1.AddToScheme(scheme.Scheme); err != nil {
		t.Fatalf("add esv1 to scheme: %v", err)
	}
	if err := esv1alpha1.AddToScheme(scheme.Scheme); err != nil {
		t.Fatalf("add esv1alpha1 to scheme: %v", err)
	}
	if err := genv1alpha1.AddToScheme(scheme.Scheme); err != nil {
		t.Fatalf("add genv1alpha1 to scheme: %v", err)
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme.Scheme,
		Metrics: server.Options{BindAddress: "0"},
		Client: client.Options{
			Cache: &client.CacheOptions{
				DisableFor: []client.Object{&corev1.Secret{}, &corev1.ConfigMap{}},
			},
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}

	secretClient, err := ctrlcommon.BuildManagedSecretClient(mgr, "")
	if err != nil {
		t.Fatalf("build managed secret client: %v", err)
	}
	opts := controller.Options{MaxConcurrentReconciles: 1, RateLimiter: ctrlcommon.BuildRateLimiter()}

	if err := (&externalsecret.Reconciler{
		Client:                             mgr.GetClient(),
		SecretClient:                       secretClient,
		EnableSecretAPIReadOnCacheMismatch: true,
		RestConfig:                         cfg,
		Scheme:                             mgr.GetScheme(),
		Log:                                ctrl.Log.WithName("live").WithName("ExternalSecrets"),
		RequeueInterval:                    time.Second,
		ClusterSecretStoreEnabled:          true,
	}).SetupWithManager(ctx, mgr, opts); err != nil {
		t.Fatalf("set up ExternalSecret reconciler: %v", err)
	}

	k8s, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	if err := (&pushsecret.Reconciler{
		Client:          k8s,
		Scheme:          mgr.GetScheme(),
		Log:             ctrl.Log.WithName("live").WithName("PushSecret"),
		RestConfig:      cfg,
		RequeueInterval: time.Second,
	}).SetupWithManager(ctx, mgr, opts); err != nil {
		t.Fatalf("set up PushSecret reconciler: %v", err)
	}

	go func() {
		if err := mgr.Start(ctx); err != nil {
			t.Errorf("manager stopped: %v", err)
		}
	}()

	return k8s
}

func createNamespace(ctx context.Context, t *testing.T, k8s client.Client) {
	t.Helper()
	ns := &corev1.Namespace{Name: testNamespace}
	if err := k8s.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace: %v", err)
	}
}

func createCredentials(ctx context.Context, t *testing.T, k8s client.Client, env liveEnv) {
	t.Helper()
	mustCreate(ctx, t, k8s, &corev1.Secret{
		Name: credSecretName, Namespace: testNamespace,
		Data: map[string][]byte{
			"access-key-id": []byte(env.accessKeyID),
			"secret-key":    []byte(env.secretKey),
		},
	})
}

// createStore builds the SecretStore the reconcilers resolve credentials
// through. forceDeleteWithoutRecovery is set so the suite's own fixtures are
// destroyed rather than parked in REVOKE, where they would occupy the name and
// keep billing for seven days.
func createStore(ctx context.Context, t *testing.T, k8s client.Client, env liveEnv) {
	t.Helper()
	mustCreate(ctx, t, k8s, &esv1.SecretStore{
		Name: storeName, Namespace: testNamespace,
		Spec: esv1.SecretStoreSpec{
			Provider: &esv1.SecretStoreProvider{
				Ncloud: &esv1.NcloudProvider{
					Endpoint:                   env.endpoint,
					ForceDeleteWithoutRecovery: true,
					Auth: esv1.NcloudAuth{
						SecretRef: &esv1.NcloudAuthSecretRef{
							AccessKeyID: esmeta.SecretKeySelector{Name: credSecretName, Key: "access-key-id"},
							SecretKey:   esmeta.SecretKeySelector{Name: credSecretName, Key: "secret-key"},
						},
					},
				},
			},
		},
	})
}

// newRemoteClient builds a provider client the test uses directly, to observe
// and clean up remote state independently of the controllers it is verifying.
func newRemoteClient(t *testing.T, env liveEnv) esv1.SecretsClient {
	t.Helper()
	remote, err := secretmanager.NewClient(&secretmanager.Config{
		AccessKeyID:                env.accessKeyID,
		SecretKey:                  env.secretKey,
		Endpoint:                   env.endpoint,
		ForceDeleteWithoutRecovery: true,
	})
	if err != nil {
		t.Fatalf("create verification client: %v", err)
	}
	t.Cleanup(func() {
		if err := remote.Close(context.Background()); err != nil {
			t.Logf("close verification client: %v", err)
		}
	})
	return remote
}

// destroyRemote removes a remote secret and is safe to call twice: the
// provider's delete is idempotent.
func destroyRemote(t *testing.T, remote esv1.SecretsClient, remoteKey string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := remote.DeleteSecret(ctx, esv1alpha1.PushSecretRemoteRef{RemoteKey: remoteKey}); err != nil {
		t.Logf("clean up remote secret %s: %v", remoteKey, err)
	}
}

func mustCreate(ctx context.Context, t *testing.T, k8s client.Client, obj client.Object) {
	t.Helper()
	if err := k8s.Create(ctx, obj); err != nil {
		t.Fatalf("create %T %s: %v", obj, obj.GetName(), err)
	}
}

// waitFor polls until check succeeds, reporting the last failure on timeout.
func waitFor(t *testing.T, what string, check func() error) {
	t.Helper()
	deadline := time.Now().Add(pollTimeout)
	var last error
	for time.Now().Before(deadline) {
		if last = check(); last == nil {
			return
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("timed out waiting for %s: %v", what, last)
}

// uniqueRemoteKey returns a name within Ncloud's 3-15 character constraint.
func uniqueRemoteKey(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("rec%d", time.Now().UnixNano()%1_000_000_000)
}
