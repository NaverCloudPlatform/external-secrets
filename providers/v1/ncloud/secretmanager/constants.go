// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

// Metrics constants identify the Ncloud Secret Manager provider and API calls.
// Every call goes through one HTTP client, so the call names are the API
// operations rather than SDK method names.
const (
	ProviderNcloudSM                   = "Ncloud/SecretManager"
	CallNcloudSMGetSecretValue         = "GetSecretValue"
	CallNcloudSMGetSecretDetail        = "GetSecretDetail"
	CallNcloudSMListSecrets            = "ListSecrets"
	CallNcloudSMListProtectionKeys     = "ListProtectionKeys"
	CallNcloudSMCreateSecret           = "CreateSecret"
	CallNcloudSMUpdateSecretStageValue = "UpdateSecretStageValue"
	CallNcloudSMRequestSecretDeletion  = "RequestSecretDeletion"
	CallNcloudSMDestroySecret          = "DestroySecret"
)
