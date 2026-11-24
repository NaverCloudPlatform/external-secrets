//go:build ncloud || all_providers

// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

// Package register provides explicit registration of all providers and generators.
package register

import (
	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	ncloud "github.com/external-secrets/external-secrets/providers/v1/ncloud"
)

func init() {
	// Register ncloud provider
	esv1.Register(ncloud.NewProvider(), ncloud.ProviderSpec(), ncloud.MaintenanceStatus())
}
