// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package v1beta1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// NcloudAuth selects where the provider gets the access key pair it signs
// requests with. Exactly one method must be set.
// +kubebuilder:validation:MinProperties=1
// +kubebuilder:validation:MaxProperties=1
type NcloudAuth struct {
	// SecretRef reads a permanent access key pair (a main or sub account key)
	// from a Kubernetes Secret.
	// +optional
	SecretRef *NcloudAuthSecretRef `json:"secretRef,omitempty"`

	// ServerRole signs with the temporary key of the Server Role attached to
	// the node the controller runs on, read from the instance metadata
	// endpoint, so no key is stored in the cluster. On Ncloud Kubernetes
	// Service the role is the node pool's Node IAM Role. Only a
	// ClusterSecretStore may use it; limit the namespaces it serves with
	// conditions. Every pod on the node can read the metadata endpoint (see
	// the provider documentation).
	// +optional
	ServerRole *NcloudAuthServerRole `json:"serverRole,omitempty"`

	// PodIdentity signs with the temporary key the Ncloud Kubernetes Service
	// Pod Identity exchange issues for the controller pod's ServiceAccount.
	// The token, projected with the Pod Identity audience, and the exchange
	// endpoint are injected into the controller pod by the Pod Identity
	// add-on, and the role comes from the Pod Identity association registered
	// for the controller's namespace and ServiceAccount. Nothing is stored in
	// the cluster, and only pods running as the controller's ServiceAccount
	// can obtain the key, not every pod on the node. Only a
	// ClusterSecretStore may use it; limit the namespaces it serves with
	// conditions.
	// +optional
	PodIdentity *NcloudAuthPodIdentity `json:"podIdentity,omitempty"`
}

// NcloudAuthServerRole has no fields: the role and its temporary key are
// discovered from the node's instance metadata.
type NcloudAuthServerRole struct{}

// NcloudAuthPodIdentity has no fields: the token, the exchange endpoint and
// the role are properties of the controller pod and of its Pod Identity
// association.
type NcloudAuthPodIdentity struct{}

// NcloudAuthSecretRef holds secret references for Ncloud credentials.
type NcloudAuthSecretRef struct {
	// AccessKeyID selects the Kubernetes Secret key holding the access key ID.
	AccessKeyID esmeta.SecretKeySelector `json:"accessKeyIDSecretRef"`
	// SecretKey selects the Kubernetes Secret key holding the secret key.
	SecretKey esmeta.SecretKeySelector `json:"secretKeySecretRef"`
}

// The v1beta1 slot exists so a store written against the v1beta1 API on an
// older cluster keeps validating; providers added upstream since v2 are
// v1-only. crds.unsafeServeV1Beta1 defaults to false, so the schema rides in
// the bundle without being served. Drop this file and the v1beta1 union slot
// together when that compatibility is no longer wanted. The field markers stay
// identical to the v1 fields so the two schemas cannot drift apart if this
// version is ever served or copied again.

// NcloudProvider configures a store to sync secrets using the Ncloud Secret Manager provider.
type NcloudProvider struct {
	Auth NcloudAuth `json:"auth"`
	// Ncloud Secret Manager endpoint, an https:// base URL. The documented
	// endpoints are scoped by the KMS key isolation boundary of the secrets
	// they serve, not just by region:
	// https://secretmanager.apigw.ntruss.com (KR, GLOBAL-key secrets),
	// https://ocapi-kr.ncloud.com/secretmanager (KR, ISOLATED-key secrets),
	// https://ocapi-jp.ncloud.com/secretmanager (JPN, ISOLATED-key secrets).
	// A secret is created and written only through the endpoint of its key's
	// boundary, and new secrets can only use ISOLATED keys. Any other https
	// host, such as a proxy in front of one of these, is accepted. Plain http is
	// rejected: every request carries the access key ID and an HMAC
	// signature. Trailing slashes are tolerated. A value that cannot serve as
	// a base for request paths is rejected at admission: a query, a fragment,
	// credentials, "." or ".." path segments, percent-encoding, non-ASCII
	// characters (write an internationalized host in its xn-- form), or a
	// path character sent percent-encoded such as "{".
	// +kubebuilder:validation:Pattern:=`^https://.+$`
	Endpoint string `json:"endpoint"`

	// Role is the NRN of a role to switch to through the Secure Token Service
	// once the auth method's key pair is obtained. Requests are then signed
	// with the role's temporary key, which is refreshed before it expires.
	// The Secure Token Service is the controller flag `--ncloud-sts-endpoint`,
	// not a store field.
	// +kubebuilder:validation:Pattern:=`^nrn:.+$`
	// +optional
	Role string `json:"role,omitempty"`

	// ForceDeleteWithoutRecovery skips the deletion-request grace period when
	// this provider deletes a remote secret: the secret is destroyed
	// immediately and irreversibly. By default deletion stops at the REVOKE
	// (deletion requested) state, and Ncloud finalizes destruction
	// automatically after the 7-day waiting period, during which the deletion
	// request can still be canceled from Ncloud.
	// +optional
	ForceDeleteWithoutRecovery bool `json:"forceDeleteWithoutRecovery,omitempty"`
}
