// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package ncloud

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/providers/v1/ncloud/secretmanager"
	"github.com/external-secrets/external-secrets/runtime/feature"
)

const (
	testRoleNRN              = "nrn:PUB:IAM::1234567890:Role/abcdef0123456789"
	testMetadataEndpoint     = "http://127.0.0.1:1/metadata"
	testPodIdentityTokenFile = "/var/run/secrets/nks.ncloud.com/pod-identity/token"
	testPodIdentityEndpoint  = "https://nks.example.invalid/iam/v2/pod-identity/credentials"
)

// serverRoleProvider returns a provider config that signs with the node's
// Server Role and names no Kubernetes Secret.
func serverRoleProvider() *esv1.NcloudProvider {
	return &esv1.NcloudProvider{
		Endpoint: testEndpoint,
		Auth:     esv1.NcloudAuth{ServerRole: &esv1.NcloudAuthServerRole{}},
	}
}

// podIdentityProvider returns a provider config that signs with the
// controller pod's Pod Identity and names no Kubernetes Secret.
func podIdentityProvider() *esv1.NcloudProvider {
	return &esv1.NcloudProvider{
		Endpoint: testEndpoint,
		Auth:     esv1.NcloudAuth{PodIdentity: &esv1.NcloudAuthPodIdentity{}},
	}
}

// podIdentityInjectedProvider returns a Provider whose pod the add-on
// injected, the way NewProvider reads it from the environment.
func podIdentityInjectedProvider() *Provider {
	return &Provider{podIdentityTokenFile: testPodIdentityTokenFile, podIdentityEndpoint: testPodIdentityEndpoint}
}

func TestValidateStoreAuthMethods(t *testing.T) {
	p := &Provider{}
	tests := []struct {
		name    string
		cluster bool
		mutate  func(prov *esv1.NcloudProvider)
		wantErr error
		// wantPrefix, when set, is what the error message must begin with.
		wantPrefix string
	}{
		{
			name:   "secretRef alone is accepted",
			mutate: func(*esv1.NcloudProvider) {},
		},
		{
			name:    "serverRole alone is accepted in a ClusterSecretStore without any Secret",
			cluster: true,
			mutate: func(prov *esv1.NcloudProvider) {
				prov.Auth = esv1.NcloudAuth{ServerRole: &esv1.NcloudAuthServerRole{}}
			},
		},
		{
			name: "serverRole in a SecretStore is rejected",
			mutate: func(prov *esv1.NcloudProvider) {
				prov.Auth = esv1.NcloudAuth{ServerRole: &esv1.NcloudAuthServerRole{}}
			},
			wantErr:    errControllerIdentityScope,
			wantPrefix: "serverRole may be used only in a ClusterSecretStore",
		},
		{
			name:    "podIdentity alone is accepted in a ClusterSecretStore without any Secret",
			cluster: true,
			mutate: func(prov *esv1.NcloudProvider) {
				prov.Auth = esv1.NcloudAuth{PodIdentity: &esv1.NcloudAuthPodIdentity{}}
			},
		},
		{
			name: "podIdentity in a SecretStore is rejected",
			mutate: func(prov *esv1.NcloudProvider) {
				prov.Auth = esv1.NcloudAuth{PodIdentity: &esv1.NcloudAuthPodIdentity{}}
			},
			wantErr:    errControllerIdentityScope,
			wantPrefix: "podIdentity may be used only in a ClusterSecretStore",
		},
		{
			name:    "serverRole and podIdentity together are rejected",
			cluster: true,
			mutate: func(prov *esv1.NcloudProvider) {
				prov.Auth = esv1.NcloudAuth{ServerRole: &esv1.NcloudAuthServerRole{}, PodIdentity: &esv1.NcloudAuthPodIdentity{}}
			},
			wantErr: errAuthMethod,
		},
		{
			name: "no method is rejected",
			mutate: func(prov *esv1.NcloudProvider) {
				prov.Auth = esv1.NcloudAuth{}
			},
			wantErr: errAuthMethod,
		},
		{
			name: "two methods are rejected",
			mutate: func(prov *esv1.NcloudProvider) {
				prov.Auth.ServerRole = &esv1.NcloudAuthServerRole{}
			},
			wantErr: errAuthMethod,
		},
		{
			name: "role NRN is accepted on top of either method",
			mutate: func(prov *esv1.NcloudProvider) {
				prov.Role = testRoleNRN
			},
		},
		{
			name: "role that is not an NRN is rejected",
			mutate: func(prov *esv1.NcloudProvider) {
				prov.Role = "Role/abcdef"
			},
			wantErr: errInvalidRole,
		},
		{
			name: "the bare NRN prefix is not a role",
			mutate: func(prov *esv1.NcloudProvider) {
				prov.Role = "nrn:"
			},
			wantErr: errInvalidRole,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov := validProvider()
			tt.mutate(prov)
			store := newNcloudStore(prov)
			if tt.cluster {
				// Conditions keep the unconditioned-serverRole warning out of
				// this table; it has a test of its own.
				store = newNcloudClusterStore(prov)
				store.GetSpec().Conditions = []esv1.ClusterSecretStoreCondition{{Namespaces: []string{testNamespace}}}
			}
			warnings, err := p.ValidateStore(store)
			if len(warnings) != 0 {
				t.Errorf("ValidateStore() warnings = %v, want none", warnings)
			}
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateStore() error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateStore() error = %v, want errors.Is %v", err, tt.wantErr)
			}
			if tt.wantPrefix != "" && !strings.HasPrefix(err.Error(), tt.wantPrefix) {
				t.Errorf("ValidateStore() error = %q, want prefix %q", err, tt.wantPrefix)
			}
		})
	}
}

func TestValidateStoreWarnsOfAServerRoleStoreEveryNamespaceMayUse(t *testing.T) {
	p := &Provider{}
	wantWarning := unconditionedWarning("serverRole", "node's role")
	const preRefactorWarning = "serverRole with no conditions, or with a condition that matches every namespace, lets every namespace use the node's role through this store; list the namespaces that may use it in spec.conditions"
	if wantWarning != preRefactorWarning {
		t.Fatalf("serverRole warning = %q, want %q", wantWarning, preRefactorWarning)
	}
	t.Run("without conditions", func(t *testing.T) {
		warnings, err := p.ValidateStore(newNcloudClusterStore(serverRoleProvider()))
		if err != nil {
			t.Fatalf("ValidateStore() error = %v, want the store accepted", err)
		}
		if len(warnings) != 1 || warnings[0] != wantWarning {
			t.Errorf("ValidateStore() warnings = %v, want %q", warnings, wantWarning)
		}
	})
	for _, tc := range []struct {
		name      string
		condition esv1.ClusterSecretStoreCondition
		warn      bool
	}{
		{name: "listed namespaces", condition: esv1.ClusterSecretStoreCondition{Namespaces: []string{"team-a"}}},
		{name: "a label selector", condition: esv1.ClusterSecretStoreCondition{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}}}},
		{name: "a narrow regex", condition: esv1.ClusterSecretStoreCondition{NamespaceRegexes: []string{"^team-"}}},
		{name: "a condition that matches nothing", condition: esv1.ClusterSecretStoreCondition{}},
		{name: "an empty label selector", condition: esv1.ClusterSecretStoreCondition{NamespaceSelector: &metav1.LabelSelector{}}, warn: true},
		{name: "a dot-star regex", condition: esv1.ClusterSecretStoreCondition{NamespaceRegexes: []string{"^team-", ".*"}}, warn: true},
		{name: "an empty regex", condition: esv1.ClusterSecretStoreCondition{NamespaceRegexes: []string{""}}, warn: true},
		// The core validator rejects it; here it matches nothing, so no warning.
		{name: "a regex that does not compile", condition: esv1.ClusterSecretStoreCondition{NamespaceRegexes: []string{"["}}},
	} {
		t.Run("with "+tc.name, func(t *testing.T) {
			store := newNcloudClusterStore(serverRoleProvider())
			store.GetSpec().Conditions = []esv1.ClusterSecretStoreCondition{{Namespaces: []string{"team-b"}}, tc.condition}
			warnings, err := p.ValidateStore(store)
			if err != nil {
				t.Fatalf("ValidateStore() error = %v, want the store accepted", err)
			}
			if got := len(warnings) == 1 && warnings[0] == wantWarning; got != tc.warn || (!tc.warn && len(warnings) != 0) {
				t.Errorf("ValidateStore() warnings = %v, want the warning: %v", warnings, tc.warn)
			}
		})
	}
	t.Run("a podIdentity store without conditions is warned about in its own words", func(t *testing.T) {
		warnings, err := p.ValidateStore(newNcloudClusterStore(podIdentityProvider()))
		if err != nil {
			t.Fatalf("ValidateStore() error = %v, want the store accepted", err)
		}
		want := unconditionedWarning("podIdentity", "controller's Pod Identity role")
		if len(warnings) != 1 || warnings[0] != want {
			t.Errorf("ValidateStore() warnings = %v, want %q", warnings, want)
		}
		if !strings.HasPrefix(want, "podIdentity with no conditions") || strings.Contains(want, "node") {
			t.Errorf("warning %q should name podIdentity and not the node", want)
		}
	})
	t.Run("a secretRef store is not warned about", func(t *testing.T) {
		if warnings, err := p.ValidateStore(newNcloudClusterStore(validProvider())); err != nil || len(warnings) != 0 {
			t.Errorf("ValidateStore() = %v, %v; want no warning and no error", warnings, err)
		}
	})
}

func TestClientConfigSelectsTheCredentialSource(t *testing.T) {
	ctx := context.Background()
	p := &Provider{metadataEndpoint: testMetadataEndpoint}

	t.Run("secretRef resolves the static pair and names no source", func(t *testing.T) {
		cfg, err := p.clientConfig(ctx, newNcloudStore(validProvider()), validProvider(), newKubeClient(credentialsSecret()), testNamespace)
		if err != nil {
			t.Fatalf("clientConfig() error = %v", err)
		}
		if cfg.AccessKeyID == "" || cfg.SecretKey == "" {
			t.Errorf("clientConfig() did not resolve the static pair: %+v", cfg)
		}
		if cfg.Credentials != nil {
			t.Errorf("clientConfig() set Credentials = %v for a secretRef store", cfg.Credentials.Identity())
		}
		if cfg.Role != "" {
			t.Errorf("clientConfig() invented a role switch: role=%q", cfg.Role)
		}
	})

	t.Run("serverRole reads nothing from Kubernetes and names the metadata source", func(t *testing.T) {
		prov := serverRoleProvider()
		cfg, err := p.clientConfig(ctx, newNcloudClusterStore(prov), prov, newKubeClient(), testNamespace)
		if err != nil {
			t.Fatalf("clientConfig() error = %v", err)
		}
		if cfg.AccessKeyID != "" || cfg.SecretKey != "" {
			t.Errorf("clientConfig() filled the static pair for a serverRole store: %+v", cfg)
		}
		if cfg.Credentials == nil {
			t.Fatal("clientConfig() left Credentials nil for a serverRole store")
		}
		want := secretmanager.ServerRoleCredentials(testMetadataEndpoint).Identity()
		if got := cfg.Credentials.Identity(); got != want {
			t.Errorf("clientConfig() Credentials identity = %q, want %q (the provider's metadata endpoint)", got, want)
		}
	})

	t.Run("role is passed through and the STS endpoint is the controller's", func(t *testing.T) {
		setSTSEndpointFlag(t, otherSTSEndpoint+"/")
		prov := serverRoleProvider()
		prov.Role = testRoleNRN
		cfg, err := p.clientConfig(ctx, newNcloudClusterStore(prov), prov, newKubeClient(), testNamespace)
		if err != nil {
			t.Fatalf("clientConfig() error = %v", err)
		}
		if cfg.Role != testRoleNRN {
			t.Errorf("clientConfig() role = %q, want %q", cfg.Role, testRoleNRN)
		}
		if cfg.STSEndpoint != otherSTSEndpoint {
			t.Errorf("clientConfig() STSEndpoint = %q, want the normalized flag value %q", cfg.STSEndpoint, otherSTSEndpoint)
		}
	})

	t.Run("serverRole in a SecretStore is refused where admission did not run", func(t *testing.T) {
		prov := serverRoleProvider()
		cfg, err := p.clientConfig(ctx, newNcloudStore(prov), prov, newKubeClient(), testNamespace)
		if !errors.Is(err, errControllerIdentityScope) {
			t.Fatalf("clientConfig() = %+v, %v, want errors.Is %v", cfg, err, errControllerIdentityScope)
		}
		if want := "serverRole may be used only in a ClusterSecretStore"; !strings.HasPrefix(err.Error(), want) {
			t.Errorf("clientConfig() error = %q, want prefix %q", err, want)
		}
	})

	t.Run("referent ClusterSecretStore still defers to the consumer namespace", func(t *testing.T) {
		prov := validProvider()
		cfg, err := p.clientConfig(ctx, newNcloudClusterStore(prov), prov, newKubeClient(), "")
		if err != nil {
			t.Fatalf("clientConfig() error = %v", err)
		}
		if cfg != nil {
			t.Errorf("clientConfig() = %+v for a referent store, want nil (referent client)", cfg)
		}
	})

	t.Run("serverRole ClusterSecretStore never defers: it has no namespace to wait for", func(t *testing.T) {
		prov := serverRoleProvider()
		cfg, err := p.clientConfig(ctx, newNcloudClusterStore(prov), prov, newKubeClient(), "")
		if err != nil {
			t.Fatalf("clientConfig() error = %v", err)
		}
		if cfg == nil || cfg.Credentials == nil {
			t.Fatalf("clientConfig() = %+v for a serverRole cluster store, want a metadata-backed config", cfg)
		}
	})

	t.Run("podIdentity names the exchange source built from the pod's environment", func(t *testing.T) {
		pi := podIdentityInjectedProvider()
		prov := podIdentityProvider()
		cfg, err := pi.clientConfig(ctx, newNcloudClusterStore(prov), prov, newKubeClient(), testNamespace)
		if err != nil {
			t.Fatalf("clientConfig() error = %v", err)
		}
		if cfg.AccessKeyID != "" || cfg.SecretKey != "" {
			t.Errorf("clientConfig() filled the static pair for a podIdentity store: %+v", cfg)
		}
		if cfg.Credentials == nil {
			t.Fatal("clientConfig() left Credentials nil for a podIdentity store")
		}
		expected, err := secretmanager.PodIdentityCredentials(testPodIdentityTokenFile, testPodIdentityEndpoint)
		if err != nil {
			t.Fatalf("PodIdentityCredentials() error = %v", err)
		}
		if got, want := cfg.Credentials.Identity(), expected.Identity(); got != want {
			t.Errorf("clientConfig() Credentials identity = %q, want %q (the pod's token file and exchange endpoint)", got, want)
		}
	})

	t.Run("podIdentity without the injected environment is refused by name", func(t *testing.T) {
		prov := podIdentityProvider()
		for _, tc := range []struct {
			name string
			p    *Provider
		}{
			{"neither variable", &Provider{}},
			{"only the token file", &Provider{podIdentityTokenFile: testPodIdentityTokenFile}},
			{"only the endpoint", &Provider{podIdentityEndpoint: testPodIdentityEndpoint}},
		} {
			cfg, err := tc.p.clientConfig(ctx, newNcloudClusterStore(prov), prov, newKubeClient(), testNamespace)
			if !errors.Is(err, errPodIdentityNotInjected) {
				t.Fatalf("%s: clientConfig() = %+v, %v, want errors.Is errPodIdentityNotInjected", tc.name, cfg, err)
			}
			for _, name := range []string{podIdentityTokenFileEnv, podIdentityEndpointEnv} {
				if !strings.Contains(err.Error(), name) {
					t.Errorf("%s: error %q does not name %s", tc.name, err, name)
				}
			}
			// The add-on injects only a pod that carries this label, so a
			// chart install without it is the likeliest way to get here.
			if label := `nks.ncloud.com/pod-identity: "true"`; !strings.Contains(err.Error(), label) {
				t.Errorf("%s: error %q does not name the label %s", tc.name, err, label)
			}
		}
	})

	t.Run("podIdentity in a SecretStore is refused where admission did not run", func(t *testing.T) {
		pi := podIdentityInjectedProvider()
		prov := podIdentityProvider()
		cfg, err := pi.clientConfig(ctx, newNcloudStore(prov), prov, newKubeClient(), testNamespace)
		if !errors.Is(err, errControllerIdentityScope) {
			t.Fatalf("clientConfig() = %+v, %v, want errors.Is %v", cfg, err, errControllerIdentityScope)
		}
		if want := "podIdentity may be used only in a ClusterSecretStore"; !strings.HasPrefix(err.Error(), want) {
			t.Errorf("clientConfig() error = %q, want prefix %q", err, want)
		}
	})

	t.Run("podIdentity ClusterSecretStore never defers: it has no namespace to wait for", func(t *testing.T) {
		pi := podIdentityInjectedProvider()
		prov := podIdentityProvider()
		cfg, err := pi.clientConfig(ctx, newNcloudClusterStore(prov), prov, newKubeClient(), "")
		if err != nil {
			t.Fatalf("clientConfig() error = %v", err)
		}
		if cfg == nil || cfg.Credentials == nil {
			t.Fatalf("clientConfig() = %+v for a podIdentity cluster store, want an exchange-backed config", cfg)
		}
	})

	t.Run("role switches on top of podIdentity and stays distinct from serverRole", func(t *testing.T) {
		podProv := podIdentityProvider()
		podProv.Role = testRoleNRN
		podCfg, err := podIdentityInjectedProvider().clientConfig(ctx, newNcloudClusterStore(podProv), podProv, newKubeClient(), "")
		if err != nil {
			t.Fatalf("clientConfig() podIdentity error = %v", err)
		}
		roleProv := serverRoleProvider()
		roleProv.Role = testRoleNRN
		roleCfg, err := p.clientConfig(ctx, newNcloudClusterStore(roleProv), roleProv, newKubeClient(), "")
		if err != nil {
			t.Fatalf("clientConfig() serverRole error = %v", err)
		}
		podSwitched, err := secretmanager.SwitchRoleCredentials(podCfg.Credentials, podCfg.STSEndpoint, podCfg.Role)
		if err != nil {
			t.Fatalf("SwitchRoleCredentials() podIdentity error = %v", err)
		}
		roleSwitched, err := secretmanager.SwitchRoleCredentials(roleCfg.Credentials, roleCfg.STSEndpoint, roleCfg.Role)
		if err != nil {
			t.Fatalf("SwitchRoleCredentials() serverRole error = %v", err)
		}
		if got, want := podSwitched.Identity(), "role:"+testRoleNRN+"@"+podCfg.Credentials.Identity(); got != want {
			t.Errorf("podIdentity switched identity = %q, want %q", got, want)
		}
		if podSwitched.Identity() == roleSwitched.Identity() {
			t.Errorf("podIdentity and serverRole switched identities are both %q, want them distinct", podSwitched.Identity())
		}
	})
}

func TestNewClientServerRoleBuildsOffline(t *testing.T) {
	// The Server Role pair is fetched lazily, on the first request, so a
	// store on an unreachable metadata endpoint still builds. That is the
	// same contract the static pair has: NewClient never talks to Ncloud, and
	// Validate is where an unusable credential is reported.
	p := &Provider{metadataEndpoint: testMetadataEndpoint}
	client, err := p.NewClient(context.Background(), newNcloudClusterStore(serverRoleProvider()), newKubeClient(), "")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("NewClient() returned nil client")
	}
}

func TestNewClientPodIdentityBuildsOffline(t *testing.T) {
	// The token file is read and the exchange called on the first request,
	// not at construction, so a store builds on a pod whose token file does
	// not exist yet, and Validate is where the missing token is reported.
	p := &Provider{podIdentityTokenFile: filepath.Join(t.TempDir(), "missing"), podIdentityEndpoint: testPodIdentityEndpoint}
	client, err := p.NewClient(context.Background(), newNcloudClusterStore(podIdentityProvider()), newKubeClient(), "")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("NewClient() returned nil client")
	}
}

func TestNewProviderReadsThePodIdentityEnvironment(t *testing.T) {
	t.Setenv(podIdentityTokenFileEnv, testPodIdentityTokenFile)
	t.Setenv(podIdentityEndpointEnv, testPodIdentityEndpoint)
	p, ok := NewProvider().(*Provider)
	if !ok {
		t.Fatalf("NewProvider() = %T, want *Provider", NewProvider())
	}
	if p.podIdentityTokenFile != testPodIdentityTokenFile || p.podIdentityEndpoint != testPodIdentityEndpoint {
		t.Errorf("NewProvider() read %q and %q, want the two Pod Identity variables", p.podIdentityTokenFile, p.podIdentityEndpoint)
	}
	if podIdentityTokenFileEnv != "NCLOUD_POD_IDENTITY_TOKEN_FILE" || podIdentityEndpointEnv != "NCLOUD_POD_IDENTITY_API_ENDPOINT" {
		t.Errorf("variable names = %q, %q; they are the add-on's contract and must not drift", podIdentityTokenFileEnv, podIdentityEndpointEnv)
	}
}

func TestNewClientRejectsARoleThatIsNotAnNRN(t *testing.T) {
	p := &Provider{}
	prov := validProvider()
	prov.Role = "abcdef"
	_, err := p.NewClient(context.Background(), newNcloudStore(prov), newKubeClient(credentialsSecret()), testNamespace)
	if !errors.Is(err, errInvalidRole) {
		t.Fatalf("NewClient() error = %v, want errors.Is %v", err, errInvalidRole)
	}
}

// otherSTSEndpoint is an https host other than the default, used to see the
// flag's value reach the client. Any such host would do.
const otherSTSEndpoint = "https://sts-proxy.example.internal"

// setSTSEndpointFlag sets --ncloud-sts-endpoint for one test the way the flag
// parser would, and restores the previous value afterwards.
func setSTSEndpointFlag(t *testing.T, raw string) {
	t.Helper()
	previous := stsEndpoint.value
	if err := stsEndpoint.Set(raw); err != nil {
		t.Fatalf("Set(%q) error = %v", raw, err)
	}
	t.Cleanup(func() { stsEndpoint.value = previous })
}

func TestSTSEndpointFlag(t *testing.T) {
	t.Run("is registered under its documented name with the public service as default", func(t *testing.T) {
		var flag *pflag.Flag
		for _, f := range feature.Features() {
			if f.Flags == nil {
				continue
			}
			if found := f.Flags.Lookup(stsEndpointFlagName); found != nil {
				flag = found
			}
		}
		if flag == nil {
			t.Fatalf("no registered feature carries the --%s flag", stsEndpointFlagName)
		}
		if flag.DefValue != secretmanager.DefaultSTSEndpoint {
			t.Errorf("--%s default = %q, want %q", stsEndpointFlagName, flag.DefValue, secretmanager.DefaultSTSEndpoint)
		}
		if flag.Value != pflag.Value(stsEndpoint) {
			t.Errorf("--%s is not bound to the value clientConfig reads", stsEndpointFlagName)
		}
	})

	t.Run("normalizes an https value the way store endpoints are", func(t *testing.T) {
		setSTSEndpointFlag(t, "https://STS-Proxy.example.internal/")
		if got := stsEndpoint.String(); got != otherSTSEndpoint {
			t.Errorf("value after Set = %q, want %q", got, otherSTSEndpoint)
		}
	})

	t.Run("refuses plain http at parse time and keeps the previous value", func(t *testing.T) {
		before := stsEndpoint.String()
		err := stsEndpoint.Set("http://sts.apigw.ntruss.com")
		if !errors.Is(err, secretmanager.ErrEndpointScheme) {
			t.Fatalf("Set() error = %v, want ErrEndpointScheme", err)
		}
		if got := stsEndpoint.String(); got != before {
			t.Errorf("a refused Set changed the value from %q to %q", before, got)
		}
	})
}

// TestSTSEndpointFlagNameReachesTheDocs ties the places that spell the flag
// by hand to the Go constant, so a rename cannot leave an operator copying a
// name the controller rejects. The CRD type comments must carry it in
// backticks: the API reference generator applies smart punctuation to a bare
// "--" and renders an en dash, which loses a hyphen on the page.
func TestSTSEndpointFlagNameReachesTheDocs(t *testing.T) {
	const repoRoot = "../../.."
	flag := "--" + stsEndpointFlagName
	for rel, want := range map[string]string{
		"docs/provider/ncloud.md":                                  flag,
		"docs/snippets/ncloud-secret-store-switch-role.yaml":       flag,
		"docs/api/controller-options.md":                           "`" + flag + "`",
		"apis/externalsecrets/v1/secretstore_ncloud_types.go":      "`" + flag + "`",
		"apis/externalsecrets/v1beta1/secretstore_ncloud_types.go": "`" + flag + "`",
	} {
		data, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if !strings.Contains(string(data), want) {
			t.Errorf("%s does not mention %s", rel, want)
		}
	}
}
