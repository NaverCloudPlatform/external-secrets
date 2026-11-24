//go:build ncloud || all_providers

// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package controller

import (
	"strings"
	"testing"

	"github.com/external-secrets/external-secrets/providers/v1/ncloud/secretmanager"
)

// TestNcloudSTSEndpointFlagIsOnTheRootCommand pins the flag the ncloud
// provider registers through runtime/feature from the controller's side. The
// provider's own tests see the flag in feature.Features(); this one checks
// that it reaches the root command, which depends on the provider's init
// running before this package's init reads feature.Features(). pkg/register
// is a dependency of the controllers this package imports, so it does, and a
// refactor that drops that import would silently lose every provider flag
// rather than fail a build. The flag must carry the public service as its
// default, refuse a value that is not an https URL when it is set, the way
// cobra refuses any malformed flag at parse time, keep the previous value on
// refusal, and normalize an accepted value the way store endpoints are.
func TestNcloudSTSEndpointFlagIsOnTheRootCommand(t *testing.T) {
	const name = "ncloud-sts-endpoint"
	flag := rootCmd.Flags().Lookup(name)
	if flag == nil {
		t.Fatalf("--%s is not a flag of the root command; the provider's feature registration ran after this package's init read feature.Features()", name)
	}
	if flag.DefValue != secretmanager.DefaultSTSEndpoint {
		t.Errorf("--%s default = %q, want %q", name, flag.DefValue, secretmanager.DefaultSTSEndpoint)
	}

	before := flag.Value.String()
	t.Cleanup(func() { _ = rootCmd.Flags().Set(name, before) })

	err := rootCmd.Flags().Set(name, "http://sts.apigw.ntruss.com")
	if err == nil {
		t.Fatalf("--%s accepted a plain http value", name)
	}
	if !strings.Contains(err.Error(), "https://") {
		t.Errorf("--%s rejection = %v, want it to say https:// is required", name, err)
	}
	if got := flag.Value.String(); got != before {
		t.Errorf("a refused Set changed --%s from %q to %q", name, before, got)
	}

	if err := rootCmd.Flags().Set(name, "https://STS-Proxy.example.internal/"); err != nil {
		t.Fatalf("--%s refused an https value: %v", name, err)
	}
	if got, want := flag.Value.String(), "https://sts-proxy.example.internal"; got != want {
		t.Errorf("--%s value = %q, want it normalized to %q", name, got, want)
	}
}
