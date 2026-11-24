// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeExchangePath is the path the Pod Identity add-on's endpoint carries.
// The source must post to the URL as given and append nothing.
const fakeExchangePath = "/iam/v2/pod-identity/credentials"

// exchangeCall is one request the fake Pod Identity exchange received.
type exchangeCall struct {
	method        string
	path          string
	authorization string
	bodyLen       int
}

// fakeExchange answers Pod Identity exchange requests. respond decides the
// answer from the bearer token, so a test can refuse one token and accept the
// next.
type fakeExchange struct {
	respond func(token string) (status int, body string)
	// headers are added to every response.
	headers http.Header

	mu    sync.Mutex
	calls []exchangeCall
}

func (f *fakeExchange) handler(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	call := exchangeCall{
		method:        r.Method,
		path:          r.URL.Path,
		authorization: r.Header.Get("Authorization"),
		bodyLen:       len(raw),
	}
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
	status, body := f.respond(strings.TrimPrefix(call.authorization, "Bearer "))
	maps.Copy(w.Header(), f.headers)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (f *fakeExchange) seen() []exchangeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]exchangeCall(nil), f.calls...)
}

// exchangeBody is the documented success answer. The expiration carries
// milliseconds, as the real service writes it.
func exchangeBody(id, secret string, expiry time.Time) string {
	return fmt.Sprintf(`{"accessKey":%q,"secretKey":%q,"expiration":%q}`,
		id, secret, expiry.UTC().Format("2006-01-02T15:04:05.000Z"))
}

// writeToken writes token to a file in a per-test directory, as the kubelet
// projects it, and returns the path.
func writeToken(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return path
}

func acceptAny(id, secret string, expiry time.Time) func(string) (int, string) {
	return func(string) (int, string) { return http.StatusOK, exchangeBody(id, secret, expiry) }
}

func newPodIdentityFixture(t *testing.T, tokenFile string, respond func(token string) (int, string)) (*podIdentitySource, *fakeExchange, string) {
	t.Helper()
	ex := &fakeExchange{respond: respond}
	server := httptest.NewServer(http.HandlerFunc(ex.handler))
	t.Cleanup(server.Close)
	endpoint := server.URL + fakeExchangePath
	return newPodIdentitySource(tokenFile, endpoint, server.Client()), ex, endpoint
}

func TestPodIdentitySourceExchangesTheProjectedToken(t *testing.T) {
	expiry := time.Now().Add(6 * time.Hour).Truncate(time.Second)
	tokenFile := writeToken(t, "tok-1\n")
	source, ex, endpoint := newPodIdentityFixture(t, tokenFile, func(token string) (int, string) {
		if token != "tok-1" {
			return http.StatusUnauthorized, `{"error":"InvalidToken"}`
		}
		return http.StatusOK, exchangeBody("p_key", "p_secret", expiry)
	})

	pair, err := source.Credentials(context.Background())
	if err != nil {
		t.Fatalf("Credentials() error = %v", err)
	}
	if pair.AccessKeyID != "p_key" || pair.SecretKey != "p_secret" || !pair.Expiry.Equal(expiry) {
		t.Errorf("Credentials() = %+v, want the exchanged pair with expiry %v", pair, expiry)
	}
	if got, want := source.Identity(), "podIdentity:"+tokenFile+"@"+endpoint; got != want {
		t.Errorf("Identity() = %q, want %q (constant per token file and endpoint, never the key)", got, want)
	}
	calls := ex.seen()
	if len(calls) != 1 {
		t.Fatalf("exchange calls = %d, want 1", len(calls))
	}
	if c := calls[0]; c.method != http.MethodPost || c.path != fakeExchangePath || c.authorization != "Bearer tok-1" || c.bodyLen != 0 {
		t.Errorf("exchange call = %+v, want POST %s with the bearer token (whitespace trimmed) and no body", c, fakeExchangePath)
	}

	// Inside the lifetime the pair is served from memory.
	if _, err := source.Credentials(context.Background()); err != nil {
		t.Fatalf("second Credentials() error = %v", err)
	}
	if got := len(ex.seen()); got != 1 {
		t.Errorf("exchange calls after a cached read = %d, want 1", got)
	}
}

func TestPodIdentitySourceReadsTheTokenFileOnEveryFetch(t *testing.T) {
	// The kubelet replaces the projected token before it expires; a token
	// read once would be sent after its replacement and be refused.
	expiry := time.Now().Add(time.Hour)
	tokenFile := writeToken(t, "tok-1")
	source, ex, _ := newPodIdentityFixture(t, tokenFile, acceptAny("k", "s", expiry))

	pair, err := source.Credentials(context.Background())
	if err != nil {
		t.Fatalf("Credentials() error = %v", err)
	}
	if err := os.WriteFile(tokenFile, []byte("tok-2"), 0o600); err != nil {
		t.Fatalf("rotate token: %v", err)
	}
	source.Invalidate(context.Background(), pair)
	if _, err := source.Credentials(context.Background()); err != nil {
		t.Fatalf("Credentials() after invalidation error = %v", err)
	}
	calls := ex.seen()
	if len(calls) != 2 || calls[1].authorization != "Bearer tok-2" {
		t.Errorf("exchange calls = %+v, want the second call to carry the rotated token", calls)
	}
}

func TestPodIdentitySourceReportsWhyThereIsNoPair(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr error
		// wantText must appear in the error: the documented meaning of the
		// status, so the controller log says what to check.
		wantText string
		// wantAbsent must not appear: the response body.
		wantAbsent string
	}{
		{"400 is a refused audience", http.StatusBadRequest, `{"error":"InvalidAudience","message":"bad aud"}`, ErrPodIdentityRejected, "InvalidAudience", "bad aud"},
		{"401 is a refused token", http.StatusUnauthorized, `{"error":"InvalidToken","message":"stale-body-text"}`, ErrPodIdentityRejected, "InvalidToken", "stale-body-text"},
		{"403 is a missing association", http.StatusForbidden, `{"error":"NoAssociation","message":"no mapping"}`, ErrPodIdentityRejected, "NoAssociation", "no mapping"},
		{"404 is an endpoint without the exchange", http.StatusNotFound, `{"message":"URL not found"}`, ErrPodIdentityRejected, "not available", "URL not found"},
		{"another 4xx is a rejection", http.StatusConflict, "", ErrPodIdentityRejected, "", ""},
		{"500 is a service failure", http.StatusInternalServerError, "", ErrServiceUnavailable, "", ""},
		{"503 UpstreamError is a service failure", http.StatusServiceUnavailable, `{"error":"UpstreamError"}`, ErrServiceUnavailable, "", "UpstreamError"},
		{"429 keeps the generic sentinel", http.StatusTooManyRequests, "", ErrRateLimited, "", ""},
		{"non-JSON body", http.StatusOK, "<html>oops</html>", errPodIdentityDecode, "", "oops"},
		{"unparsable expiry", http.StatusOK, `{"accessKey":"k","secretKey":"s","expiration":"later"}`, ErrTemporaryCredentialsIncomplete, "", ""},
		{"missing key material", http.StatusOK, exchangeBody("", "", expiry), ErrTemporaryCredentialsIncomplete, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, _, _ := newPodIdentityFixture(t, writeToken(t, "tok"), func(string) (int, string) {
				return tt.status, tt.body
			})
			_, err := source.Credentials(context.Background())
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Credentials() error = %v, want errors.Is %v", err, tt.wantErr)
			}
			if tt.wantText != "" && !strings.Contains(err.Error(), tt.wantText) {
				t.Errorf("Credentials() error %q does not say %q", err, tt.wantText)
			}
			if tt.wantAbsent != "" && strings.Contains(err.Error(), tt.wantAbsent) {
				t.Errorf("Credentials() error %q echoes the response body", err)
			}
			if tt.status != http.StatusOK && !strings.Contains(err.Error(), fmt.Sprint(tt.status)) {
				t.Errorf("Credentials() error %q does not name status %d", err, tt.status)
			}
		})
	}

	t.Run("a missing token file is reported before any exchange call", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing")
		source, ex, _ := newPodIdentityFixture(t, missing, acceptAny("k", "s", expiry))
		_, err := source.Credentials(context.Background())
		if !errors.Is(err, ErrPodIdentityUnavailable) {
			t.Fatalf("Credentials() error = %v, want errors.Is ErrPodIdentityUnavailable", err)
		}
		if !strings.Contains(err.Error(), missing) {
			t.Errorf("Credentials() error %q does not name the token file", err)
		}
		if got := len(ex.seen()); got != 0 {
			t.Errorf("exchange calls = %d, want 0", got)
		}
	})

	t.Run("an empty token file is no token", func(t *testing.T) {
		source, ex, _ := newPodIdentityFixture(t, writeToken(t, " \n"), acceptAny("k", "s", expiry))
		if _, err := source.Credentials(context.Background()); !errors.Is(err, ErrPodIdentityUnavailable) {
			t.Fatalf("Credentials() error = %v, want errors.Is ErrPodIdentityUnavailable", err)
		}
		if got := len(ex.seen()); got != 0 {
			t.Errorf("exchange calls = %d, want 0", got)
		}
	})

	t.Run("an unreachable exchange is retryable, not a configuration error", func(t *testing.T) {
		ex := &fakeExchange{respond: acceptAny("k", "s", expiry)}
		server := httptest.NewServer(http.HandlerFunc(ex.handler))
		source := newPodIdentitySource(writeToken(t, "secret-token"), server.URL+fakeExchangePath, server.Client())
		server.Close()
		_, err := source.Credentials(context.Background())
		if err == nil {
			t.Fatal("Credentials() error = nil, want a transport error")
		}
		if errors.Is(err, ErrPodIdentityRejected) {
			t.Errorf("Credentials() error = %v, must not be a rejection", err)
		}
		if isAuthError(err) {
			t.Errorf("isAuthError(%v) = true, want false", err)
		}
		if !IsRetryable(err) {
			t.Errorf("IsRetryable(%v) = false, want true", err)
		}
		if strings.Contains(err.Error(), "secret-token") {
			t.Errorf("Credentials() error %q carries the token", err)
		}
	})

	t.Run("an oversized body is refused without being read into memory", func(t *testing.T) {
		source, _, _ := newPodIdentityFixture(t, writeToken(t, "tok"), func(string) (int, string) {
			return http.StatusOK, strings.Repeat("a", maxPodIdentityResponseBytes+1)
		})
		_, err := source.Credentials(context.Background())
		if err == nil || !strings.Contains(err.Error(), "exceeds the") {
			t.Fatalf("Credentials() error = %v, want the size limit named", err)
		}
	})
}

func TestPodIdentitySourceCarriesRetryAfterOnRateLimit(t *testing.T) {
	source, ex, _ := newPodIdentityFixture(t, writeToken(t, "tok"), func(string) (int, string) {
		return http.StatusTooManyRequests, ""
	})
	ex.headers = http.Header{"Retry-After": []string{"7"}}

	_, err := source.Credentials(context.Background())
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Credentials() error = %v, want ErrRateLimited", err)
	}
	after, ok := retryAfterFrom(err)
	if !ok || after != 7*time.Second {
		t.Errorf("retryAfterFrom() = %v, %v; want the 7s the service asked for", after, ok)
	}
}

func TestPodIdentityCredentialsValidatesAndShares(t *testing.T) {
	const endpoint = "https://nks.example.invalid/iam/v2/pod-identity/credentials"
	tokenFile := filepath.Join(t.TempDir(), "token")

	t.Run("plain http is refused: the token travels in the request", func(t *testing.T) {
		_, err := PodIdentityCredentials(tokenFile, "http://nks.example.invalid/iam/v2/pod-identity/credentials")
		if !errors.Is(err, ErrEndpointScheme) {
			t.Errorf("PodIdentityCredentials() error = %v, want ErrEndpointScheme", err)
		}
	})

	t.Run("an empty token file path is no token", func(t *testing.T) {
		_, err := PodIdentityCredentials("", endpoint)
		if !errors.Is(err, ErrPodIdentityUnavailable) {
			t.Errorf("PodIdentityCredentials() error = %v, want ErrPodIdentityUnavailable", err)
		}
	})

	t.Run("one source per endpoint and token file", func(t *testing.T) {
		a, err := PodIdentityCredentials(tokenFile, endpoint)
		if err != nil {
			t.Fatalf("PodIdentityCredentials() error = %v", err)
		}
		b, err := PodIdentityCredentials(tokenFile, endpoint+"/")
		if err != nil {
			t.Fatalf("PodIdentityCredentials() with a trailing slash error = %v", err)
		}
		if a != b {
			t.Error("the same endpoint, with and without a trailing slash, produced two sources")
		}
		if got, want := a.Identity(), "podIdentity:"+tokenFile+"@"+endpoint; got != want {
			t.Errorf("Identity() = %q, want %q", got, want)
		}
		other, err := PodIdentityCredentials(filepath.Join(t.TempDir(), "other"), endpoint)
		if err != nil {
			t.Fatalf("PodIdentityCredentials() for another file error = %v", err)
		}
		if other == a {
			t.Error("a different token file shares the source")
		}
	})

	t.Run("the shared source uses the bounded, non-redirecting transport", func(t *testing.T) {
		source, err := PodIdentityCredentials(tokenFile, endpoint)
		if err != nil {
			t.Fatalf("PodIdentityCredentials() error = %v", err)
		}
		pi, ok := source.(*podIdentitySource)
		if !ok {
			t.Fatalf("PodIdentityCredentials() returned %T, want *podIdentitySource", source)
		}
		if pi.httpClient.CheckRedirect == nil {
			t.Fatal("CheckRedirect is nil: a redirect would carry the bearer token elsewhere")
		}
		if err := pi.httpClient.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
			t.Errorf("CheckRedirect() = %v, want http.ErrUseLastResponse", err)
		}
		if pi.httpClient.Timeout == 0 {
			t.Error("the exchange client has no timeout")
		}
	})
}

func TestPodIdentityErrorsAreConfigurationErrors(t *testing.T) {
	// The store controller reports these as Ready=False with reason
	// InvalidProviderConfig, because an operator fixes them outside the
	// cluster: the add-on, the association, or the role.
	for _, err := range []error{ErrPodIdentityRejected, ErrPodIdentityUnavailable, errPodIdentityDecode} {
		if !isAuthError(fmt.Errorf("wrapped: %w", err)) {
			t.Errorf("isAuthError(%v) = false, want true", err)
		}
	}
}
