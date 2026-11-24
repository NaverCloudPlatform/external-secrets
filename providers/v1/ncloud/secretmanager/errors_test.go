// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestHandleErrorResponse(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		body         string
		wantErr      error
		checkMessage string
	}{
		{
			// Only the service's own resource-not-found code means the secret
			// is gone. Ncloud answers with 501001; the gateway's not-found and
			// a bodyless 404 must not be read as absence (ErrNotFoundUnverified).
			name:       "404 with the service resource-not-found code",
			statusCode: http.StatusNotFound,
			body:       `{"error": {"errorCode": "501001", "message": "RESOURCE_NOT_FOUND", "details": "Secret not found"}}`,
			wantErr:    ErrSecretNotFound,
		},
		{
			name:       "404 from the API gateway is not absence",
			statusCode: http.StatusNotFound,
			body:       `{"error": {"errorCode": "300", "message": "Not Found Exception", "details": "null"}}`,
			wantErr:    ErrNotFoundUnverified,
		},
		{
			name:       "429 quota exceeded is not the retryable rate limit",
			statusCode: http.StatusTooManyRequests,
			body:       `{"error": {"errorCode": "400", "message": "Quota Exceeded"}}`,
			wantErr:    ErrQuotaExceeded,
		},
		{
			name:       "429 rate limited stays retryable",
			statusCode: http.StatusTooManyRequests,
			body:       `{"error": {"errorCode": "420", "message": "Rate Limited"}}`,
			wantErr:    ErrRateLimited,
		},
		{
			name:       "401 UNAUTHORIZED with error response",
			statusCode: http.StatusUnauthorized,
			body:       `{"error": {"errorCode": "UNAUTHORIZED", "message": "Unauthorized", "details": "Invalid credentials"}}`,
			wantErr:    ErrUnauthorized,
		},
		{
			name:       "403 FORBIDDEN with error response",
			statusCode: http.StatusForbidden,
			body:       `{"error": {"errorCode": "FORBIDDEN", "message": "Forbidden", "details": "Access denied"}}`,
			wantErr:    ErrForbidden,
		},
		{
			name:       "400 INVALID_REQUEST with error response",
			statusCode: http.StatusBadRequest,
			body:       `{"error": {"errorCode": "INVALID_REQUEST", "message": "Invalid request", "details": "Bad request"}}`,
			wantErr:    ErrInvalidRequest,
		},
		{
			name:       "409 INVALID_STATUS with error response",
			statusCode: http.StatusConflict,
			body:       `{"error": {"errorCode": "INVALID_STATUS", "message": "Invalid status", "details": "Conflict"}}`,
			wantErr:    ErrInvalidStatus,
		},
		{
			name:       "422 UNPROCESSABLE_ENTITY with error response",
			statusCode: http.StatusUnprocessableEntity,
			body:       `{"error": {"errorCode": "UNPROCESSABLE_ENTITY", "message": "Invalid status", "details": "Unprocessable"}}`,
			wantErr:    ErrUnprocessableEntity,
		},
		{
			name:       "500 INTERNAL_SERVER_ERROR with error response",
			statusCode: http.StatusInternalServerError,
			body:       `{"error": {"errorCode": "INTERNAL_SERVER_ERROR", "message": "Server internal error", "details": "Internal error"}}`,
			wantErr:    ErrInternalServerError,
		},
		{
			name:         "404 without error response structure",
			statusCode:   http.StatusNotFound,
			body:         `Not Found`,
			wantErr:      ErrNotFoundUnverified,
			checkMessage: "status 404",
		},
		{
			name:         "500 without error response structure",
			statusCode:   http.StatusInternalServerError,
			body:         `Internal Server Error`,
			wantErr:      ErrInternalServerError,
			checkMessage: "status 500",
		},
		{
			name:         "unknown structured error code falls back to HTTP status",
			statusCode:   http.StatusInternalServerError,
			body:         `{"error": {"errorCode": "UNKNOWN_ERROR", "message": "ignored", "details": "ignored"}}`,
			wantErr:      ErrInternalServerError,
			checkMessage: "status 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handleErrorResponse(tt.statusCode, []byte(tt.body))

			if err == nil {
				t.Error("handleErrorResponse() expected error, got nil")
				return
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("handleErrorResponse() error = %v, want error wrapping %v", err, tt.wantErr)
			}

			if tt.checkMessage != "" && !strings.Contains(err.Error(), tt.checkMessage) {
				t.Errorf("handleErrorResponse() error message = %v, want to contain %v", err.Error(), tt.checkMessage)
			}
		})
	}
}

// TestNumericErrorCode fixes the redaction boundary for surfaced error codes.
// Digits-only codes are diagnostic and carry no recoverable secret material;
// everything else is server-controlled free text and stays out of the message.
func TestNumericErrorCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		// Numeric codes.
		{name: "resource not found", in: "501001", want: "501001"},
		{name: "missing required field", in: "500000", want: "500000"},
		{name: "gateway code", in: "300", want: "300"},
		{name: "empty", in: "", want: ""},
		// Text that is not a numeric code is dropped.
		{name: "documented symbolic name", in: "NOT_FOUND", want: ""},
		{name: "identifier-shaped secret", in: "SENSITIVE_SECRET_MARKER", want: ""},
		{name: "mixed alphanumeric", in: "501001A", want: ""},
		{name: "leading sign", in: "-501001", want: ""},
		{name: "whitespace padded", in: " 501001 ", want: ""},
		{name: "newline injection", in: "501001\nmore", want: ""},
		{name: "unicode digit lookalike", in: "５０１００１", want: ""},
		{name: "over the digit bound", in: "123456789", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := numericErrorCode(tc.in); got != tc.want {
				t.Errorf("numericErrorCode(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestHandleErrorResponseSurfacesNumericCode checks the end-to-end effect: the
// sentinel comes from the HTTP status, and a numeric code reaches the message so
// an operator can look the failure up.
func TestHandleErrorResponseSurfacesNumericCode(t *testing.T) {
	err := handleErrorResponse(
		http.StatusBadRequest,
		[]byte(`{"error":{"errorCode":"500000","message":"MISSING_REQUIRED_FIELD","details":"kmsBoundaryType"}}`),
	)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("error = %v, want ErrInvalidRequest from the HTTP status", err)
	}
	got := err.Error()
	if !strings.Contains(got, "500000") {
		t.Errorf("error = %q, want the numeric code surfaced", got)
	}
	// message/details stay redacted: they are free-form and may echo secrets.
	if strings.Contains(got, "MISSING_REQUIRED_FIELD") || strings.Contains(got, "kmsBoundaryType") {
		t.Errorf("error = %q, want message/details withheld", got)
	}
}

// TestNotFoundUnverifiedNamesAnUnknownAccessKey covers the gateway's 404 on a
// request for one secret. A key that is not accepted can be answered that way,
// and a referent ClusterSecretStore reaches such a request with no readiness
// check in front of it, so the message must name the key as a cause.
func TestNotFoundUnverifiedNamesAnUnknownAccessKey(t *testing.T) {
	err := handleErrorResponse(
		http.StatusNotFound,
		[]byte(`{"error": {"errorCode": "300", "message": "Not Found Exception", "details": "null"}}`),
	)
	if !errors.Is(err, ErrNotFoundUnverified) {
		t.Fatalf("error = %v, want ErrNotFoundUnverified", err)
	}
	if got := err.Error(); !strings.Contains(got, "access key ID") || !strings.Contains(got, "code 300") {
		t.Errorf("error = %q, want it to name the access key ID and keep code 300", got)
	}
}

// TestAPIErrorWithSentinelPreservesDetail covers the re-classification helper
// the listing endpoint uses: the sentinel changes, the diagnostics do not.
func TestAPIErrorWithSentinelPreservesDetail(t *testing.T) {
	original := newAPIError(ErrSecretNotFound, http.StatusNotFound, "501001")
	remapped := original.withSentinel(ErrListingUnavailable)

	if !errors.Is(remapped, ErrListingUnavailable) {
		t.Errorf("remapped error = %v, want ErrListingUnavailable", remapped)
	}
	if errors.Is(remapped, ErrSecretNotFound) {
		t.Errorf("remapped error still reports ErrSecretNotFound: %v", remapped)
	}
	for _, want := range []string{"status 404", "501001"} {
		if !strings.Contains(remapped.Error(), want) {
			t.Errorf("remapped error = %q, want it to retain %q", remapped.Error(), want)
		}
	}
	// The original must be untouched: callers may still hold it.
	if !errors.Is(original, ErrSecretNotFound) {
		t.Error("withSentinel mutated the original error")
	}
}

func TestMapStatusCodeToSentinel(t *testing.T) {
	tests := []struct {
		statusCode int
		want       error
	}{
		{http.StatusNotFound, ErrSecretNotFound},
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusForbidden, ErrForbidden},
		{http.StatusBadRequest, ErrInvalidRequest},
		{http.StatusConflict, ErrInvalidStatus},
		{http.StatusUnprocessableEntity, ErrUnprocessableEntity},
		{http.StatusInternalServerError, ErrInternalServerError},
		{http.StatusOK, nil},
		{http.StatusCreated, nil},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("status_%d", tt.statusCode), func(t *testing.T) {
			got := mapStatusCodeToSentinel(tt.statusCode)
			if !errors.Is(got, tt.want) {
				t.Errorf("mapStatusCodeToSentinel() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNotFoundKindOf pins the one reading of a 404's code, which its sentinel
// and the refusal of a signing pair both start from.
func TestNotFoundKindOf(t *testing.T) {
	for _, tc := range []struct {
		code string
		want notFoundKind
	}{
		{codeResourceNotFound, notFoundResource},
		{codeGatewayNotFound, notFoundGateway},
		{"", notFoundUnverified},
		{"501000", notFoundUnverified},
	} {
		if got := notFoundKindOf(tc.code); got != tc.want {
			t.Errorf("notFoundKindOf(%q) = %v, want %v", tc.code, got, tc.want)
		}
	}
}

func TestHandleErrorResponseOmitsSensitiveContentAndBoundsErrors(t *testing.T) {
	const secretMarker = "SENSITIVE-SECRET-MARKER"
	huge := strings.Repeat("x", 1<<20)

	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    error
	}{
		{
			name:       "structured envelope",
			statusCode: http.StatusUnauthorized,
			body: fmt.Sprintf(
				`{"error":{"errorCode":"UNAUTHORIZED","message":%q,"details":%q}}`,
				huge+secretMarker,
				secretMarker+huge,
			),
			wantErr: ErrUnauthorized,
		},
		{
			name:       "arbitrary body with mapped status",
			statusCode: http.StatusInternalServerError,
			body:       secretMarker + huge,
			wantErr:    ErrInternalServerError,
		},
		{
			name:       "arbitrary body with unmapped status",
			statusCode: http.StatusTeapot,
			body:       secretMarker + huge,
		},
		{
			name:       "short arbitrary body with unmapped status",
			statusCode: http.StatusTeapot,
			body:       secretMarker,
		},
		{
			name:       "huge and malformed error code",
			statusCode: http.StatusTeapot,
			body: fmt.Sprintf(
				`{"error":{"errorCode":%q,"message":"ignored","details":%q}}`,
				strings.Repeat("A", 1<<20)+"\n"+secretMarker,
				secretMarker,
			),
		},
		{
			name:       "identifier-shaped secret in error code",
			statusCode: http.StatusTeapot,
			body:       `{"error":{"errorCode":"SENSITIVE_SECRET_MARKER","message":"ignored","details":"ignored"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handleErrorResponse(tt.statusCode, []byte(tt.body))
			if err == nil {
				t.Fatal("handleErrorResponse() returned nil")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want sentinel %v", err, tt.wantErr)
			}
			if got := err.Error(); len(got) > 256 {
				t.Errorf("error length = %d, want <= 256", len(got))
			} else if strings.Contains(got, secretMarker) ||
				strings.Contains(got, strings.ReplaceAll(secretMarker, "-", "_")) ||
				strings.Contains(got, huge[:128]) {
				t.Errorf("error leaked response content: %q", got)
			}
			if !strings.Contains(err.Error(), fmt.Sprint(tt.statusCode)) {
				t.Errorf("error = %q, want the HTTP status %d named", err, tt.statusCode)
			}
		})
	}
}

type timeoutTestError struct{}

func (timeoutTestError) Error() string { return "network timeout" }
func (timeoutTestError) Timeout() bool { return true }
func (timeoutTestError) Temporary() bool {
	return false
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil},
		{name: "rate limit", err: fmt.Errorf("wrapped: %w", ErrRateLimited), want: true},
		{name: "service unavailable", err: ErrServiceUnavailable, want: true},
		{name: "internal server error", err: ErrInternalServerError, want: true},
		{name: "EOF", err: fmt.Errorf("transport: %w", io.EOF), want: true},
		{name: "unexpected EOF", err: io.ErrUnexpectedEOF, want: true},
		{name: "network timeout", err: timeoutTestError{}, want: true},
		{name: "context cancellation wins over wrapped transport", err: fmt.Errorf("%w: %w", timeoutTestError{}, context.Canceled)},
		{name: "deadline exceeded", err: context.DeadlineExceeded},
		{name: "authentication", err: ErrUnauthorized},
		{name: "permanent", err: errors.New("permanent")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRetryable(tt.err); got != tt.want {
				t.Errorf("IsRetryable(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestRetryableStatusSentinels(t *testing.T) {
	cases := []struct {
		status    int
		sentinel  error
		retryable bool
	}{
		{http.StatusTooManyRequests, ErrRateLimited, true},
		{http.StatusBadGateway, ErrServiceUnavailable, true},
		{http.StatusServiceUnavailable, ErrServiceUnavailable, true},
		{http.StatusGatewayTimeout, ErrServiceUnavailable, true},
		{http.StatusNotFound, ErrNotFoundUnverified, false}, // no service code in "upstream noise"
		{http.StatusUnauthorized, ErrUnauthorized, false},
	}
	for _, tc := range cases {
		err := handleErrorResponse(tc.status, []byte("upstream noise"))
		if !errors.Is(err, tc.sentinel) {
			t.Errorf("handleErrorResponse(%d) = %v, want sentinel %v", tc.status, err, tc.sentinel)
		}
		if got := IsRetryable(err); got != tc.retryable {
			t.Errorf("IsRetryable(handleErrorResponse(%d)) = %v, want %v", tc.status, got, tc.retryable)
		}
	}

	if IsRetryable(nil) {
		t.Error("IsRetryable(nil) = true, want false")
	}
}

// TestQuotaExceededIsNotRetryable pins that the gateway's quota answer ends
// the call instead of spending the retry budget: the quota does not come back
// within a retry window, while the rate-limit answer beside it does.
func TestQuotaExceededIsNotRetryable(t *testing.T) {
	quota := handleErrorResponse(http.StatusTooManyRequests, []byte(`{"error": {"errorCode": "400", "message": "Quota Exceeded"}}`))
	if IsRetryable(quota) {
		t.Errorf("IsRetryable(%v) = true, want false for an exhausted quota", quota)
	}
	limited := handleErrorResponse(http.StatusTooManyRequests, []byte(`{"error": {"errorCode": "420", "message": "Rate Limited"}}`))
	if !IsRetryable(limited) {
		t.Errorf("IsRetryable(%v) = false, want true for a rate limit", limited)
	}
}
