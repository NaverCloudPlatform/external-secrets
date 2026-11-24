// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

func TestValidateMarksCredentialSourceFailuresAsError(t *testing.T) {
	// A store whose credential source cannot produce a pair is misconfigured
	// outside the cluster (no Node IAM Role, a role the key may not switch
	// to). Unknown would be reported as Ready=True by the store controller,
	// which is the surface an operator checks while every read is failing.
	tests := []struct {
		name string
		err  error
		want esv1.ValidationResult
	}{
		{"no Server Role on the node", fmt.Errorf(msgCredentials, fmt.Errorf(msgServerRole, ErrServerRoleUnavailable)), esv1.ValidationResultError},
		{"refused role switch", fmt.Errorf(msgCredentials, fmt.Errorf(msgSwitchRole, newAPIError(ErrSwitchRoleRejected, 404, ""))), esv1.ValidationResultError},
		{"metadata document unparsable", fmt.Errorf(msgCredentials, fmt.Errorf(msgServerRole, errMetadataDecode)), esv1.ValidationResultError},
		{"STS answer unparsable", fmt.Errorf(msgCredentials, fmt.Errorf(msgSwitchRole, errSTSDecode)), esv1.ValidationResultError},
		{"key pair incomplete", fmt.Errorf(msgCredentials, ErrTemporaryCredentialsIncomplete), esv1.ValidationResultError},
		{"metadata document reports failure", fmt.Errorf(msgCredentials, fmt.Errorf(msgServerRole, errMetadataCode)), esv1.ValidationResultError},
		{"metadata endpoint refuses", fmt.Errorf(msgCredentials, fmt.Errorf(msgServerRole, fmt.Errorf("%w: "+msgMetadataStatus, errMetadataRefused, 401))), esv1.ValidationResultError},
		{"STS unavailable", fmt.Errorf(msgCredentials, fmt.Errorf(msgSwitchRole, newAPIError(ErrServiceUnavailable, 503, ""))), esv1.ValidationResultUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newMockedClient(&countingMockClient{
				listFn: func(context.Context, int) (*NcloudListSecretsResponse, error) { return nil, tt.err },
			})
			got, err := client.Validate()
			if got != tt.want {
				t.Errorf("Validate() = %v, want %v (error: %v)", got, tt.want, err)
			}
			if !errors.Is(err, tt.err) {
				t.Errorf("Validate() error = %v does not wrap the source error", err)
			}
			// A node with no role rejected nothing, so the prefix must not
			// claim a rejection; the wrapped error says what went wrong.
			if got == esv1.ValidationResultError && !strings.HasPrefix(err.Error(), "the credentials could not be used: ") {
				t.Errorf("Validate() error = %q, want the neutral credentials prefix", err)
			}
		})
	}
}

func TestValidateReportsPodIdentityAnswers(t *testing.T) {
	// The store's Ready condition is what an operator watches while setting up
	// Pod Identity, so each answer of the exchange is pinned through Validate,
	// with the error shape the real source produces: a refusal the operator
	// must fix is Error (Ready=False), a transient one is Unknown (Ready=True
	// with ValidationUnknown).
	tests := []struct {
		name   string
		status int
		token  string
		want   esv1.ValidationResult
	}{
		{name: "accepted", status: http.StatusOK, token: "projected", want: esv1.ValidationResultReady},
		{name: "wrong audience", status: http.StatusBadRequest, token: "projected", want: esv1.ValidationResultError},
		{name: "token refused", status: http.StatusUnauthorized, token: "projected", want: esv1.ValidationResultError},
		{name: "no association", status: http.StatusForbidden, token: "projected", want: esv1.ValidationResultError},
		{name: "no exchange at this address", status: http.StatusNotFound, token: "projected", want: esv1.ValidationResultError},
		{name: "empty token file", status: http.StatusOK, token: "", want: esv1.ValidationResultError},
		{name: "upstream error", status: http.StatusServiceUnavailable, token: "projected", want: esv1.ValidationResultUnknown},
		{name: "rate limited", status: http.StatusTooManyRequests, token: "projected", want: esv1.ValidationResultUnknown},
		{name: "gateway request timeout", status: http.StatusRequestTimeout, token: "projected", want: esv1.ValidationResultUnknown},
	}
	// A transient answer is retried, and each retry waits out the failure
	// hold; shorten it so the table does not take seconds per row.
	previous := failureHold
	failureHold = 50 * time.Millisecond
	t.Cleanup(func() { failureHold = previous })
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expiry := time.Now().Add(time.Hour)
			source, _, _ := newPodIdentityFixture(t, writeToken(t, tt.token), func(string) (int, string) {
				if tt.status == http.StatusOK {
					return http.StatusOK, exchangeBody("pod-key", "pod-secret", expiry)
				}
				return tt.status, `{"error":"refused"}`
			})
			server, _ := listingServer(t)
			client := &Client{
				client: clientWithSource(server, source),
				cache:  newSecretIDCache(DefaultCacheTTL, DefaultCacheNegativeTTL),
			}

			got, err := client.Validate()
			if got != tt.want {
				t.Errorf("Validate() = %v, want %v (error: %v)", got, tt.want, err)
			}
			// The exchange's 404 is a refusal of this pod; read as the
			// listing's own 404 it would blame the Secretstore instead.
			if errors.Is(err, ErrListingUnavailable) {
				t.Errorf("Validate() error = %v, reported as an unaddressable listing", err)
			}
		})
	}
}
