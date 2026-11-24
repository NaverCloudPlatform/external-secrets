// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

// Package ncloud implements the External Secrets provider for Ncloud Secret Manager.
package ncloud

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/providers/v1/ncloud/secretmanager"
	"github.com/external-secrets/external-secrets/runtime/esutils/resolvers"
	"github.com/external-secrets/external-secrets/runtime/feature"
)

// Sentinel errors, so callers can classify configuration failures with errors.Is.
var (
	errInvalidNcloudStore = errors.New("invalid Ncloud SecretStore resource")
	errAuthMethod         = errors.New("ncloud auth must set exactly one of secretRef, serverRole or podIdentity")
	errInvalidRole        = errors.New("role must be a role NRN (a value beginning with nrn:)")
	// errControllerIdentityScope is prefixed with the method's name when
	// returned; see validateAuth.
	errControllerIdentityScope = errors.New("may be used only in a ClusterSecretStore: publish one with conditions to limit the namespaces it serves, or use secretRef in a SecretStore")
	// errPodIdentityNotInjected names both variables and the label because
	// an operator reads it in the controller log, far from the pod spec.
	errPodIdentityNotInjected = errors.New("the controller pod has no Pod Identity token: " +
		"NCLOUD_POD_IDENTITY_TOKEN_FILE and NCLOUD_POD_IDENTITY_API_ENDPOINT are not both set; " +
		"label the controller pod with " + podIdentityLabel + `: "true" (the chart's podLabels), ` +
		"install the Pod Identity add-on, register an association for the controller's namespace and ServiceAccount, " +
		"and restart the controller if its pod already carries the label, because the add-on injects the token only when a labeled pod is created")
	errSelectorNameEmpty = errors.New("selector name must not be empty")
	// errSelectorNamespaceNotAllowed mirrors esutils.errNamespaceNotAllowed,
	// which is unexported.
	errSelectorNamespaceNotAllowed = errors.New("namespace not allowed: a SecretStore can only reference Secrets in its own namespace")
	errSelectorKeyEmpty            = errors.New("selector key must not be empty")
)

// warnControllerIdentityUnconditioned is the admission warning for a
// controller-identity ClusterSecretStore that every namespace may use. The
// first verb is the auth method, the second what it signs with; see
// controllerIdentityOf.
const warnControllerIdentityUnconditioned = "%s with no conditions, or with a condition that matches every namespace, lets every namespace use the %s through this store; list the namespaces that may use it in spec.conditions"

// unconditionedWarning renders warnControllerIdentityUnconditioned for one
// method. Tests use it to state the expected text.
func unconditionedWarning(method, identity string) string {
	return fmt.Sprintf(warnControllerIdentityUnconditioned, method, identity)
}

// Format templates for wrapped errors. All wrap their argument with %w so the
// underlying error chain survives the provider boundary.
const (
	errInitNcloudProvider  = "unable to initialize Ncloud provider: %w"
	errInvalidEndpoint     = "invalid endpoint: %w"
	errInvalidSelector     = "invalid %s: %w"
	errInvalidSelectorKey  = "invalid %s.key: %w"
	errInvalidSelectorName = "invalid %s.name: %w"

	accessKeyIDSelectorField = "auth.secretRef.accessKeyIDSecretRef"
	secretKeySelectorField   = "auth.secretRef.secretKeySecretRef"

	// roleNRNPrefix starts every Ncloud Resource Name; see validateRole.
	roleNRNPrefix = "nrn:"

	// stsEndpointFlagName is the controller flag naming the Secure Token
	// Service; see stsEndpointFlag.
	stsEndpointFlagName = "ncloud-sts-endpoint"

	// podIdentityTokenFileEnv and podIdentityEndpointEnv are what the Ncloud
	// Kubernetes Service Pod Identity add-on injects into a pod that opts
	// in with podIdentityLabel: the path of the projected ServiceAccount
	// token, and the full URL of the exchange that trades the token for the
	// associated role's temporary key. The names are the official Go SDK's
	// credential provider's. They are read once, in NewProvider, because a
	// pod's environment does not change while it runs.
	podIdentityTokenFileEnv = "NCLOUD_POD_IDENTITY_TOKEN_FILE"
	podIdentityEndpointEnv  = "NCLOUD_POD_IDENTITY_API_ENDPOINT"

	// podIdentityLabel is the pod label, with the value "true", that the
	// add-on's webhook selects on. A pod without it is created untouched,
	// so the controller pod has to carry it; the chart sets none by
	// default.
	podIdentityLabel = "nks.ncloud.com/pod-identity"
)

// stsEndpointFlag is the value of --ncloud-sts-endpoint, the Secure Token
// Service every role switch goes through. It is a controller flag rather than
// a store field so that a store cannot choose the host that receives requests
// signed with the node's Server Role key. Set validates at parse time because
// feature.Initialize cannot report an error later.
type stsEndpointFlag struct{ value string }

// stsEndpoint is the parsed --ncloud-sts-endpoint value, the public service
// until the flag says otherwise.
var stsEndpoint = &stsEndpointFlag{value: secretmanager.DefaultSTSEndpoint}

var _ pflag.Value = stsEndpoint

func (f *stsEndpointFlag) String() string { return f.value }

func (f *stsEndpointFlag) Type() string { return "string" }

// Set accepts what a store's endpoint field accepts, normalized the same way.
func (f *stsEndpointFlag) Set(raw string) error {
	normalized, err := secretmanager.NormalizeEndpoint(raw)
	if err != nil {
		return err
	}
	f.value = normalized
	return nil
}

func init() {
	fs := pflag.NewFlagSet("ncloud", pflag.ExitOnError)
	fs.Var(stsEndpoint, stsEndpointFlagName,
		"https:// base URL of the Ncloud Secure Token Service used by stores that set spec.provider.ncloud.role, for example a proxy in front of the public service.")
	feature.Register(feature.Feature{Flags: fs})
}

// https://github.com/external-secrets/external-secrets/issues/644
var _ esv1.Provider = &Provider{}

// Provider implements the Ncloud Secret Manager provider for External Secrets Operator.
type Provider struct {
	// metadataEndpoint is where Server Role credentials are read from. Empty
	// selects the instance metadata address; tests point it at a local server.
	metadataEndpoint string

	// podIdentityTokenFile and podIdentityEndpoint are what the Pod Identity
	// add-on injected into this pod's environment, or empty when it did not.
	// NewProvider fills them; tests set them directly.
	podIdentityTokenFile string
	podIdentityEndpoint  string
}

// Capabilities returns the provider supported capabilities (ReadOnly, WriteOnly, ReadWrite).
func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadWrite
}

// NewClient constructs a new secrets client based on the provided store.
func (p *Provider) NewClient(ctx context.Context, store esv1.GenericStore, kube kclient.Client, namespace string) (esv1.SecretsClient, error) {
	if store == nil {
		return nil, errInvalidNcloudStore
	}
	storeSpec := store.GetSpec()
	if storeSpec == nil || storeSpec.Provider == nil || storeSpec.Provider.Ncloud == nil {
		return nil, errInvalidNcloudStore
	}
	ncloudProvider := storeSpec.Provider.Ncloud

	config, err := p.clientConfig(ctx, store, ncloudProvider, kube, namespace)
	if err != nil {
		return nil, fmt.Errorf(errInitNcloudProvider, err)
	}
	if config == nil {
		return secretmanager.NewReferentClient(), nil
	}

	client, err := secretmanager.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf(errInitNcloudProvider, err)
	}
	return client, nil
}

// clientConfig turns a store spec into the client configuration: the endpoint,
// the credential source the auth method names, and the optional role switch.
// A nil config with a nil error is the referent case, where a
// ClusterSecretStore's credentials live in a namespace not known yet.
func (p *Provider) clientConfig(ctx context.Context, store esv1.GenericStore, ncloudProvider *esv1.NcloudProvider, kube kclient.Client, namespace string) (*secretmanager.Config, error) {
	// Re-validate at runtime what admission (ValidateStore) checked: admission
	// is only enforced while the webhook is installed and failing closed.
	if err := validateAuth(store, &ncloudProvider.Auth); err != nil {
		return nil, err
	}
	endpoint, err := normalizeEndpoint(ncloudProvider.Endpoint)
	if err != nil {
		return nil, err
	}
	if err := validateRole(ncloudProvider.Role); err != nil {
		return nil, err
	}

	config := &secretmanager.Config{
		Endpoint:                   endpoint,
		Role:                       ncloudProvider.Role,
		STSEndpoint:                stsEndpoint.String(),
		ForceDeleteWithoutRecovery: ncloudProvider.ForceDeleteWithoutRecovery,
	}

	switch {
	case ncloudProvider.Auth.ServerRole != nil:
		// The node's metadata endpoint is the source, and the role attached
		// to the node is whatever the cluster gave it.
		config.Credentials = secretmanager.ServerRoleCredentials(p.metadataEndpoint)
		return config, nil
	case ncloudProvider.Auth.PodIdentity != nil:
		config.Credentials, err = p.podIdentityCredentials()
		if err != nil {
			return nil, err
		}
		return config, nil
	}
	ref := ncloudProvider.Auth.SecretRef

	// store.GetKind(), not TypeMeta; see validateCredentialSelector.
	storeKind := store.GetKind()
	if storeKind == esv1.ClusterSecretStoreKind &&
		namespace == "" &&
		(ref.AccessKeyID.Namespace == nil || ref.SecretKey.Namespace == nil) {
		return nil, nil
	}

	config.AccessKeyID, err = resolvers.SecretKeyRef(ctx, kube, storeKind, namespace, &ref.AccessKeyID)
	if err != nil {
		return nil, err
	}
	config.SecretKey, err = resolvers.SecretKeyRef(ctx, kube, storeKind, namespace, &ref.SecretKey)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// podIdentityCredentials builds the Pod Identity source from what the add-on
// injected into this pod. Both values come from the controller's environment
// (read once in NewProvider) and never from a store spec; that is what keeps
// the process-wide map of Pod Identity sources bounded, so a store must never
// be able to influence either argument. The check lives here, in the
// controller, and not in ValidateStore: admission runs in the webhook pod,
// whose environment says nothing about the controller's. A pod the add-on did
// not inject, because the add-on is not installed, the pod lacks
// podIdentityLabel or the pod predates either, is refused by name.
func (p *Provider) podIdentityCredentials() (secretmanager.CredentialsSource, error) {
	if p.podIdentityTokenFile == "" || p.podIdentityEndpoint == "" {
		return nil, errPodIdentityNotInjected
	}
	return secretmanager.PodIdentityCredentials(p.podIdentityTokenFile, p.podIdentityEndpoint)
}

// ValidateStore validates the configuration of the store.
func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	if store == nil {
		return nil, errInvalidNcloudStore
	}

	spec := store.GetSpec()
	if spec == nil || spec.Provider == nil || spec.Provider.Ncloud == nil {
		return nil, errInvalidNcloudStore
	}
	ncloudProvider := spec.Provider.Ncloud

	// A store that names no auth method, or two, can never produce a working
	// client (NewClient rejects it), so it must not pass admission either.
	if err := validateAuth(store, &ncloudProvider.Auth); err != nil {
		return nil, err
	}

	// Any https host is accepted; see secretmanager.NormalizeEndpoint for why
	// there is neither an allowlist nor a warning here.
	if _, err := normalizeEndpoint(ncloudProvider.Endpoint); err != nil {
		return nil, err
	}
	if err := validateRole(ncloudProvider.Role); err != nil {
		return nil, err
	}

	// Accepted, since a cluster may mean it, but said at apply time: without
	// conditions every namespace may use the controller's identity through
	// this store.
	if method, identity := controllerIdentityOf(&ncloudProvider.Auth); method != "" && servesEveryNamespace(spec.Conditions) {
		return admission.Warnings{unconditionedWarning(method, identity)}, nil
	}
	return nil, nil
}

// everyNamespaceProbes are namespace names a regex must all match to count
// as matching every namespace. A regex cannot be proven universal, but one
// that matches single letters and digits at both ends of the range and two
// ordinary names matches everything an administrator would write by hand.
var everyNamespaceProbes = []string{"a", "z", "0", "9", "default", "kube-system"}

// servesEveryNamespace reports whether conditions let every namespace use
// the store: none at all, or one condition that matches any namespace (an
// empty label selector, or a regex such as ".*" or ""). A condition is
// enough because the store controller admits a namespace any condition
// matches. A condition that matches nothing, such as {}, does not count.
func servesEveryNamespace(conditions []esv1.ClusterSecretStoreCondition) bool {
	if len(conditions) == 0 {
		return true
	}
	for _, condition := range conditions {
		if condition.NamespaceSelector != nil {
			if selector, err := metav1.LabelSelectorAsSelector(condition.NamespaceSelector); err == nil && selector.Empty() {
				return true
			}
		}
		if slices.ContainsFunc(condition.NamespaceRegexes, matchesEveryProbe) {
			return true
		}
	}
	return false
}

func matchesEveryProbe(expr string) bool {
	re, err := regexp.Compile(expr)
	if err != nil {
		return false
	}
	for _, probe := range everyNamespaceProbes {
		if !re.MatchString(probe) {
			return false
		}
	}
	return true
}

// controllerIdentityOf names the auth method that signs with the controller's
// own identity rather than with a key a store supplied, and says in words what
// that identity is, for messages. secretRef, and an auth that names no method,
// return "".
func controllerIdentityOf(auth *esv1.NcloudAuth) (method, identity string) {
	switch {
	case auth.ServerRole != nil:
		return "serverRole", "node's role"
	case auth.PodIdentity != nil:
		return "podIdentity", "controller's Pod Identity role"
	}
	return "", ""
}

// validateAuth checks that exactly one auth method is set, that a controller
// identity (serverRole, podIdentity) is used only by a ClusterSecretStore, and
// that a secretRef's selectors can be resolved. The CRD enforces the count
// too; this holds where the schema is old or the webhook absent. A controller
// identity is shared by every store, and a store's author picks the host that
// requests signed with it go to, so only a cluster administrator may publish
// it; conditions then limit the namespaces it serves.
func validateAuth(store esv1.GenericStore, auth *esv1.NcloudAuth) error {
	methods := 0
	if auth.SecretRef != nil {
		methods++
	}
	if auth.ServerRole != nil {
		methods++
	}
	if auth.PodIdentity != nil {
		methods++
	}
	if methods != 1 {
		return errAuthMethod
	}
	// store.GetKind(), not TypeMeta; see validateCredentialSelector.
	if method, _ := controllerIdentityOf(auth); method != "" && store.GetKind() != esv1.ClusterSecretStoreKind {
		return fmt.Errorf("%s %w", method, errControllerIdentityScope)
	}
	if auth.SecretRef != nil {
		return validateAuthSecretRef(store, auth.SecretRef)
	}
	return nil
}

// validateRole checks the optional role NRN. The CRD pattern requires the
// prefix too; see validateAuth for why the rule is repeated here.
func validateRole(role string) error {
	if role != "" && (!strings.HasPrefix(role, roleNRNPrefix) || role == roleNRNPrefix) {
		return errInvalidRole
	}
	return nil
}

func validateAuthSecretRef(store esv1.GenericStore, ref *esv1.NcloudAuthSecretRef) error {
	if err := validateCredentialSelector(store, ref.AccessKeyID, accessKeyIDSelectorField); err != nil {
		return err
	}
	return validateCredentialSelector(store, ref.SecretKey, secretKeySelectorField)
}

func validateCredentialSelector(store esv1.GenericStore, selector esmeta.SecretKeySelector, field string) error {
	if selector.Name == "" {
		return fmt.Errorf(errInvalidSelectorName, field, errSelectorNameEmpty)
	}
	if selector.Key == "" {
		return fmt.Errorf(errInvalidSelectorKey, field, errSelectorKeyEmpty)
	}
	// The same rule esutils.ValidateReferentSecretSelector applies, keyed by
	// store.GetKind() instead of TypeMeta: GetKind is hardcoded per type,
	// while TypeMeta can be empty on a typed object read outside the
	// manager's cache, and an empty kind would read a ClusterSecretStore as
	// namespaced and refuse its explicit namespaces.
	if store.GetKind() != esv1.ClusterSecretStoreKind && selector.Namespace != nil && *selector.Namespace != store.GetNamespace() {
		return fmt.Errorf(errInvalidSelector, field, errSelectorNamespaceNotAllowed)
	}
	return nil
}

func normalizeEndpoint(endpoint string) (string, error) {
	normalized, err := secretmanager.NormalizeEndpoint(endpoint)
	if err != nil {
		return "", fmt.Errorf(errInvalidEndpoint, err)
	}
	return normalized, nil
}

// NewProvider creates a new Provider instance. It reads what the Pod Identity
// add-on injected into this pod, if anything; a store that asks for
// podIdentity on a pod without it is refused when its client is built.
func NewProvider() esv1.Provider {
	return &Provider{
		podIdentityTokenFile: os.Getenv(podIdentityTokenFileEnv),
		podIdentityEndpoint:  os.Getenv(podIdentityEndpointEnv),
	}
}

// ProviderSpec returns the provider specification for registration.
func ProviderSpec() *esv1.SecretStoreProvider {
	return &esv1.SecretStoreProvider{
		Ncloud: &esv1.NcloudProvider{},
	}
}

// MaintenanceStatus returns the maintenance status of the provider.
func MaintenanceStatus() esv1.MaintenanceStatus {
	return esv1.MaintenanceStatusMaintained
}
