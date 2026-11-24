// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/external-secrets/external-secrets/runtime/constants"
)

// apiCallCounts reads externalsecret_provider_api_calls_count for this
// provider out of the registry every other provider reports into, keyed by
// (call, status). Reading the registry rather than the package variable is
// the point: it is what a dashboard sees.
func apiCallCounts(t *testing.T) map[[2]string]float64 {
	t.Helper()
	families, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	counts := map[[2]string]float64{}
	for _, f := range families {
		if f.GetName() != "externalsecret_provider_api_calls_count" {
			continue
		}
		for _, m := range f.GetMetric() {
			var provider, call, status string
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "provider":
					provider = l.GetValue()
				case "call":
					call = l.GetValue()
				case "status":
					status = l.GetValue()
				}
			}
			if provider == ProviderNcloudSM {
				counts[[2]string{call, status}] = m.GetCounter().GetValue()
			}
		}
	}
	return counts
}

// TestEveryAPICallIsObserved drives each operation the client exposes once
// and expects exactly one increment on the series every other provider's
// dashboard reads. Once, not once per HTTP attempt: the error case below
// retries the 500 and still counts a single failed operation, because the
// metric is about what the provider asked the API for, not how the transport
// got there.
func TestEveryAPICallIsObserved(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"code":%q}`, successCode)
	}))
	defer ok.Close()
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()

	ctx := context.Background()
	calls := []struct {
		name string
		do   func(c *secretManagerClient) error
	}{
		{CallNcloudSMGetSecretValue, func(c *secretManagerClient) error {
			_, err := c.GetSecretValue(ctx, transportTestID)
			return err
		}},
		{CallNcloudSMGetSecretDetail, func(c *secretManagerClient) error {
			_, err := c.GetSecretDetail(ctx, transportTestID)
			return err
		}},
		{CallNcloudSMListSecrets, func(c *secretManagerClient) error {
			_, err := c.ListSecrets(ctx, 1)
			return err
		}},
		{CallNcloudSMListProtectionKeys, func(c *secretManagerClient) error {
			_, err := c.ListProtectionKeys(ctx)
			return err
		}},
		{CallNcloudSMCreateSecret, func(c *secretManagerClient) error {
			_, err := c.CreateSecret(ctx, &NcloudCreateSecretRequest{})
			return err
		}},
		{CallNcloudSMUpdateSecretStageValue, func(c *secretManagerClient) error {
			return c.UpdateSecretStageValue(ctx, transportTestID, stageActive, "v")
		}},
		{CallNcloudSMRequestSecretDeletion, func(c *secretManagerClient) error {
			return c.RequestSecretDeletion(ctx, transportTestID)
		}},
		{CallNcloudSMDestroySecret, func(c *secretManagerClient) error {
			return c.DestroySecret(ctx, transportTestID)
		}},
	}

	before := apiCallCounts(t)
	good := newSecretManagerHTTPTestClient(ok.URL, nil)
	bad := newSecretManagerHTTPTestClient(failing.URL, nil)
	for _, call := range calls {
		if err := call.do(good); err != nil {
			t.Fatalf("%s against a healthy server: %v", call.name, err)
		}
		if err := call.do(bad); err == nil {
			t.Fatalf("%s against a failing server returned nil", call.name)
		}
	}
	after := apiCallCounts(t)

	for _, call := range calls {
		for _, status := range []string{constants.StatusSuccess, constants.StatusError} {
			key := [2]string{call.name, status}
			if got := after[key] - before[key]; got != 1 {
				t.Errorf("%s status=%s: counter moved by %v, want 1", call.name, status, got)
			}
		}
	}
}
