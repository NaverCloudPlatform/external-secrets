//go:build ncloud_live

// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLiveSwitchRole measures the role switch against the real Secure Token
// Service, which the unit tests can only imitate: whether the request is
// accepted, what lifetime comes back, and whether Secret Manager accepts the
// switched key. It is read-only. Opt in with NCLOUD_ROLE_NRN on top of the
// usual live variables; NCLOUD_STS_ENDPOINT overrides the public service.
func TestLiveSwitchRole(t *testing.T) {
	role := os.Getenv("NCLOUD_ROLE_NRN")
	if role == "" {
		t.Skip("set NCLOUD_ROLE_NRN (with RUN_NCLOUD_E2E=true and the key variables) to exercise the role switch")
	}
	base := liveTransport(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	source, err := SwitchRoleCredentials(base.credentials, os.Getenv("NCLOUD_STS_ENDPOINT"), role)
	if err != nil {
		t.Fatalf("SwitchRoleCredentials: %v", err)
	}
	pair, err := source.Credentials(ctx)
	if err != nil {
		t.Fatalf("switch to %s: %v", role, err)
	}
	t.Logf("switched: expires %s (in %s)", pair.Expiry.Format(time.RFC3339), time.Until(pair.Expiry).Round(time.Second))

	switched := &secretManagerClient{
		config:      &Config{Endpoint: base.config.Endpoint},
		credentials: source,
		httpClient:  newHTTPTransport(),
	}
	resp, err := switched.ListSecrets(ctx, 1)
	if err != nil {
		t.Fatalf("ListSecrets with the switched key: %v", err)
	}
	t.Logf("ListSecrets with the switched key: %d secrets on %d page(s)", resp.Data.TotalCount, resp.Data.TotalPageNo)
}
