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

// liveTransport builds the low-level API client from the live environment
// opt-in shared by every test in this file.
func liveTransport(t *testing.T) *secretManagerClient {
	t.Helper()

	endpoint := os.Getenv("NCLOUD_ENDPOINT")
	if endpoint == "" {
		endpoint = "https://ocapi-kr.ncloud.com/secretmanager"
	}
	return liveTransportAt(t, endpoint)
}

// liveTransportAt is liveTransport for a caller-chosen endpoint.
func liveTransportAt(t *testing.T, endpoint string) *secretManagerClient {
	t.Helper()

	if os.Getenv("RUN_NCLOUD_E2E") != "true" {
		t.Skip("set RUN_NCLOUD_E2E=true to run the live Ncloud checks")
	}

	accessKeyID := os.Getenv("NCLOUD_ACCESS_KEY_ID")
	secretKey := os.Getenv("NCLOUD_SECRET_KEY")
	if accessKeyID == "" || secretKey == "" {
		t.Fatal("NCLOUD_ACCESS_KEY_ID and NCLOUD_SECRET_KEY must be set when RUN_NCLOUD_E2E=true")
	}

	cfg := &Config{
		AccessKeyID: accessKeyID,
		SecretKey:   secretKey,
		Endpoint:    endpoint,
	}

	if _, err := NormalizeEndpoint(endpoint); err != nil {
		t.Fatalf("NCLOUD_ENDPOINT=%q is not an endpoint the provider accepts: %v", endpoint, err)
	}

	transport, err := newClient(cfg)
	if err != nil {
		t.Fatalf("create Ncloud transport client: %v", err)
	}
	return transport
}

// TestLiveProtectionKeyDiscovery is a READ-ONLY opt-in check of the protection
// key lookup that supplies kmsBoundaryType on create. It creates and deletes
// nothing.
//
// It exists because the create path cannot reach the boundary lookup until the
// account's Secretstore is provisioned: name resolution fails first, by design
// (see ErrListingUnavailable). This test therefore covers the one piece of the
// create contract that a real account can confirm independently - that
// GET /api/v1/keys parses and that the account exposes a default key whose
// boundary we can declare.
func TestLiveProtectionKeyDiscovery(t *testing.T) {
	transport := liveTransport(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	resp, err := transport.ListProtectionKeys(ctx)
	if err != nil {
		t.Fatalf("ListProtectionKeys() error = %v", err)
	}
	if resp == nil {
		t.Fatal("ListProtectionKeys() returned no response")
	}
	if len(resp.Data.KeyList) == 0 {
		t.Fatal("account exposes no protection keys; a create cannot declare kmsBoundaryType")
	}

	client := &Client{client: transport}
	boundary := client.defaultKeyBoundaryType(ctx)
	if boundary == "" {
		t.Errorf("no untagged default key found among %d keys; create would omit kmsBoundaryType",
			len(resp.Data.KeyList))
	}
	// Only these two are documented; an unknown value would be sent verbatim and
	// rejected, so surface it here instead.
	if boundary != "" && boundary != "ISOLATED" && boundary != "GLOBAL" {
		t.Errorf("default key boundary = %q, want ISOLATED or GLOBAL", boundary)
	}
	t.Logf("default protection key boundary = %q (keys: %d)", boundary, len(resp.Data.KeyList))
}
