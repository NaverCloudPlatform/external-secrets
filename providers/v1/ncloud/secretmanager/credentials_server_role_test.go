// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// fakeMetadata imitates the instance metadata endpoint's role paths. roleList
// is the body of the listing; document is served for roleID.
type fakeMetadata struct {
	roleList   string
	listStatus int
	roleID     string
	document   string
	docStatus  int

	// tokenMode models the server's Metadata API setting: "" accepts reads
	// with and without a token (v1 and v2), "required" answers a read
	// without the issued token with 401 (v2 only), "unsupported" has no
	// token endpoint, "refusing" is v2 only but answers the token request
	// itself with 400, and "empty" is v2 only but answers it with 200 and no
	// token.
	tokenMode string
	// tokenStatus, when set, is the status the token request is answered
	// with instead of a token, such as a v2-only server's momentary 503.
	tokenStatus int

	mu           sync.Mutex
	requestPaths []string
}

func (f *fakeMetadata) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requestPaths = append(f.requestPaths, r.URL.Path)
		f.mu.Unlock()
		if r.URL.Path == metadataTokenPath {
			if f.tokenMode == "unsupported" || r.Method != http.MethodPut {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if f.tokenMode == "refusing" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if f.tokenStatus != 0 {
				w.WriteHeader(f.tokenStatus)
				return
			}
			if f.tokenMode == "empty" {
				return
			}
			if r.Header.Get(metadataTokenTTLHeader) == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(fakeMetadataToken))
			return
		}
		if (f.tokenMode == "required" || f.tokenMode == "refusing" || f.tokenMode == "empty") && r.Header.Get(metadataTokenHeader) != fakeMetadataToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized."))
			return
		}
		switch r.URL.Path {
		case metadataRolePath:
			if f.listStatus != 0 {
				w.WriteHeader(f.listStatus)
			}
			_, _ = w.Write([]byte(f.roleList))
		case metadataRolePath + "/" + f.roleID:
			if f.docStatus != 0 {
				w.WriteHeader(f.docStatus)
			}
			_, _ = w.Write([]byte(f.document))
		default:
			t.Errorf("unexpected metadata path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

const fakeMetadataToken = "AQAEAFake-metadata-session-token=="

func (f *fakeMetadata) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requestPaths...)
}

func metadataDocument(id, secret string, expiry time.Time, code string) string {
	return fmt.Sprintf(`{"Type":"NCP-HMAC","AccessKeyId":%q,"SecretAccessKey":%q,"Expiration":%q,"Token":"","LastUpdated":"2026-09-21T00:00:00Z","Code":%q}`,
		id, secret, expiry.UTC().Format(time.RFC3339), code)
}

func newServerRoleFixture(t *testing.T, meta *fakeMetadata) (*serverRoleSource, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(meta.handler(t))
	t.Cleanup(server.Close)
	return newServerRoleSource(server.URL, server.Client()), server
}

func TestServerRoleSourceReadsTheAttachedRole(t *testing.T) {
	expiry := time.Now().Add(6 * time.Hour).Truncate(time.Second)
	meta := &fakeMetadata{
		roleList: "role-1", // no trailing newline, as documented
		roleID:   "role-1",
		document: metadataDocument("s_key", "s_secret", expiry, metadataSuccessCode),
	}
	source, server := newServerRoleFixture(t, meta)

	pair, err := source.Credentials(context.Background())
	if err != nil {
		t.Fatalf("Credentials() error = %v", err)
	}
	if pair.AccessKeyID != "s_key" || pair.SecretKey != "s_secret" || !pair.Expiry.Equal(expiry) {
		t.Errorf("Credentials() = %+v, want the document's pair and expiry %v", pair, expiry)
	}
	if got := source.Identity(); got != "serverRole@"+server.URL {
		t.Errorf("Identity() = %q, want it to name the metadata endpoint, not the rotating key", got)
	}
	if got, want := meta.paths(), []string{metadataTokenPath, metadataRolePath, metadataRolePath + "/role-1"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("metadata requests = %v, want %v", got, want)
	}

	// Inside the lifetime the pair is served from memory.
	if _, err := source.Credentials(context.Background()); err != nil {
		t.Fatalf("second Credentials() error = %v", err)
	}
	if got := len(meta.paths()); got != 3 {
		t.Errorf("metadata requests after a cached read = %d, want 3", got)
	}
}

func TestServerRoleSourceTakesTheFirstOfSeveralRolesAndEscapesIt(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	meta := &fakeMetadata{
		roleList: "\nrole one\nrole-2\n",
		roleID:   "role one",
		document: metadataDocument("k", "s", expiry, metadataSuccessCode),
	}
	source, _ := newServerRoleFixture(t, meta)

	if _, err := source.Credentials(context.Background()); err != nil {
		t.Fatalf("Credentials() error = %v", err)
	}
	if paths := meta.paths(); len(paths) != 3 || paths[2] != metadataRolePath+"/role one" {
		t.Errorf("metadata requests = %v, want the first listed role, path-escaped on the wire", paths)
	}
}

func TestServerRoleSourceReportsWhyThereIsNoPair(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	tests := []struct {
		name    string
		meta    *fakeMetadata
		wantErr error
		// wantAbsent is text that must not appear: the response body.
		wantAbsent string
	}{
		{
			name:    "no role attached: the listing is 404",
			meta:    &fakeMetadata{listStatus: http.StatusNotFound, roleList: "Path Not found."},
			wantErr: ErrServerRoleUnavailable,
		},
		{
			name:    "empty listing",
			meta:    &fakeMetadata{roleList: "\n"},
			wantErr: ErrServerRoleUnavailable,
		},
		{
			name:    "document 404",
			meta:    &fakeMetadata{roleList: "r", roleID: "r", docStatus: http.StatusNotFound},
			wantErr: ErrServerRoleUnavailable,
		},
		{
			name:       "document does not report Success",
			meta:       &fakeMetadata{roleList: "r", roleID: "r", document: metadataDocument("", "", expiry, "Failure")},
			wantErr:    errMetadataCode,
			wantAbsent: "Failure",
		},
		{
			name:       "document is not JSON",
			meta:       &fakeMetadata{roleList: "r", roleID: "r", document: "<html>secret-looking-body</html>"},
			wantErr:    errMetadataDecode,
			wantAbsent: "secret-looking-body",
		},
		{
			name:    "document expiry is unparsable",
			meta:    &fakeMetadata{roleList: "r", roleID: "r", document: `{"AccessKeyId":"k","SecretAccessKey":"s","Expiration":"soon","Code":"Success"}`},
			wantErr: ErrTemporaryCredentialsIncomplete,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, _ := newServerRoleFixture(t, tt.meta)
			_, err := source.Credentials(context.Background())
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Credentials() error = %v, want errors.Is %v", err, tt.wantErr)
			}
			if tt.wantAbsent != "" && strings.Contains(err.Error(), tt.wantAbsent) {
				t.Errorf("Credentials() error %q echoes the response body", err)
			}
		})
	}

	t.Run("unexpected status names the status", func(t *testing.T) {
		source, _ := newServerRoleFixture(t, &fakeMetadata{listStatus: http.StatusInternalServerError})
		_, err := source.Credentials(context.Background())
		if err == nil || !strings.Contains(err.Error(), "500") {
			t.Errorf("Credentials() error = %v, want the 500 status named", err)
		}
		if errors.Is(err, errMetadataRefused) {
			t.Errorf("Credentials() error = %v, a 5xx is not a refusal", err)
		}
	})

	t.Run("a refusal is a configuration answer", func(t *testing.T) {
		source, _ := newServerRoleFixture(t, &fakeMetadata{listStatus: http.StatusUnauthorized})
		_, err := source.Credentials(context.Background())
		if !errors.Is(err, errMetadataRefused) || !strings.Contains(err.Error(), "401") {
			t.Errorf("Credentials() error = %v, want errMetadataRefused naming 401", err)
		}
	})

	t.Run("unreachable endpoint", func(t *testing.T) {
		server := httptest.NewServer(http.NotFoundHandler())
		client := server.Client()
		server.Close()
		source := newServerRoleSource(server.URL, client)
		if _, err := source.Credentials(context.Background()); !errors.Is(err, ErrServerRoleUnavailable) {
			t.Errorf("Credentials() error = %v, want ErrServerRoleUnavailable", err)
		}
	})
}

func TestServerRoleCredentialsAreSharedPerEndpoint(t *testing.T) {
	a := ServerRoleCredentials("http://127.0.0.1:1/meta")
	b := ServerRoleCredentials("http://127.0.0.1:1/meta/")
	if a != b {
		t.Error("the same endpoint, with and without a trailing slash, produced two sources")
	}
	if a.Identity() != "serverRole@http://127.0.0.1:1/meta" {
		t.Errorf("Identity() = %q, want the normalized endpoint", a.Identity())
	}
	if other := ServerRoleCredentials("http://127.0.0.1:2/meta"); other == a {
		t.Error("a different endpoint shares the source")
	}
	if def := ServerRoleCredentials(""); def.Identity() != "serverRole@"+DefaultMetadataEndpoint {
		t.Errorf("empty endpoint Identity() = %q, want the default metadata endpoint", def.Identity())
	}
}

func TestServerRoleSourceAcceptsADocumentWithoutCode(t *testing.T) {
	// A document that omits Code but carries complete key material is a pair.
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	meta := &fakeMetadata{
		roleList: "r",
		roleID:   "r",
		document: `{"AccessKeyId":"k","SecretAccessKey":"s","Expiration":"` + expiry.UTC().Format(time.RFC3339) + `"}`,
	}
	source, _ := newServerRoleFixture(t, meta)
	pair, err := source.Credentials(context.Background())
	if err != nil || pair.AccessKeyID != "k" {
		t.Errorf("Credentials() = %+v, %v; want the pair", pair, err)
	}
}

func TestMetadataHTTPClientIsBoundedAndDoesNotFollowRedirects(t *testing.T) {
	client := metadataHTTPClient()
	if client.Timeout != metadataTimeout {
		t.Errorf("Timeout = %v, want %v", client.Timeout, metadataTimeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Errorf("Transport = %T with Proxy set: a link-local request must not go through HTTP_PROXY", client.Transport)
	}
	if client.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil: a redirect off the link-local address would be followed")
	}
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("CheckRedirect() = %v, want http.ErrUseLastResponse", err)
	}
}

// TestServerRoleSourceWorksUnderEveryMetadataSetting pins the three Metadata
// API settings a node can have: token required, token optional, and no token
// API. The token is always asked for, and an endpoint without a token API is
// read without one.
func TestServerRoleSourceWorksUnderEveryMetadataSetting(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	for _, mode := range []string{"", "required", "unsupported"} {
		t.Run("mode="+mode, func(t *testing.T) {
			meta := &fakeMetadata{
				roleList:  "role-1",
				roleID:    "role-1",
				document:  metadataDocument("k", "s", expiry, metadataSuccessCode),
				tokenMode: mode,
			}
			source, _ := newServerRoleFixture(t, meta)
			pair, err := source.Credentials(context.Background())
			if err != nil || pair.AccessKeyID != "k" {
				t.Fatalf("Credentials() = %+v, %v; want the role's pair", pair, err)
			}
		})
	}
}

// TestServerRoleSourceNamesARefusedTokenRequest covers a v2-only node whose
// token request fails. The source then reads without a token, as it must for
// an endpoint that predates Metadata v2, and the read is refused with 401.
// That refusal alone points at the read; the token request's own answer is
// the cause, so it is carried in the error.
func TestServerRoleSourceNamesARefusedTokenRequest(t *testing.T) {
	for _, tt := range []struct {
		tokenMode string
		answer    string
	}{
		{tokenMode: "refusing", answer: "status 400"},
		{tokenMode: "empty", answer: "an empty token"},
	} {
		t.Run(tt.tokenMode, func(t *testing.T) {
			meta := &fakeMetadata{
				roleList:  "role-1",
				roleID:    "role-1",
				document:  metadataDocument("k", "s", time.Now().Add(time.Hour), metadataSuccessCode),
				tokenMode: tt.tokenMode,
			}
			source, _ := newServerRoleFixture(t, meta)
			_, err := source.Credentials(context.Background())
			if !errors.Is(err, errMetadataRefused) {
				t.Fatalf("Credentials() error = %v, want errMetadataRefused", err)
			}
			if !strings.Contains(err.Error(), "token request") || !strings.Contains(err.Error(), tt.answer) {
				t.Errorf("Credentials() error = %q, want it to say the token request was answered with %s", err, tt.answer)
			}
		})
	}
}

// TestServerRoleSourceReportsAServerErrorAsTransient answers the role listing
// with a 503. The Pod Identity exchange and the Secure Token Service report a
// 5xx as ErrServiceUnavailable, which a GET's retry loop retries; the metadata
// endpoint's 5xx must be classified the same way, and neither as a refusal
// (a configuration error) nor as nothing at all.
func TestServerRoleSourceReportsAServerErrorAsTransient(t *testing.T) {
	previous := failureHold
	failureHold = 0
	t.Cleanup(func() { failureHold = previous })

	meta := &fakeMetadata{roleList: "role-1", listStatus: http.StatusServiceUnavailable, roleID: "role-1"}
	source, _ := newServerRoleFixture(t, meta)
	_, err := source.Credentials(context.Background())
	if !errors.Is(err, ErrServiceUnavailable) || !IsRetryable(err) {
		t.Fatalf("Credentials() error = %v, want ErrServiceUnavailable, retryable", err)
	}
	if isAuthError(err) || errors.Is(err, errMetadataRefused) {
		t.Errorf("Credentials() error = %v, a 5xx is not a configuration answer", err)
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("Credentials() error = %v, want the status named", err)
	}

	// Through doGet: the credential step is retried like a 503 from the
	// Secret Manager, waiting out failureHold between attempts.
	counting := &countingSource{CredentialsSource: source}
	server, _ := listingServer(t)
	c := clientWithSource(server, counting)
	if _, err := c.ListSecrets(context.Background(), 1); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("ListSecrets() error = %v, want ErrServiceUnavailable", err)
	}
	if got := counting.calls.Load(); got != maxGetRetries+1 {
		t.Errorf("the source was asked %d times for a pair, want %d: a 5xx from the metadata endpoint is retried", got, maxGetRetries+1)
	}
}

// validateWithSource runs Client.Validate against an empty listing, signing
// with source.
func validateWithSource(t *testing.T, source CredentialsSource) (esv1.ValidationResult, error) {
	t.Helper()
	server, _ := listingServer(t)
	client := &Client{
		client: clientWithSource(server, source),
		cache:  newSecretIDCache(DefaultCacheTTL, DefaultCacheNegativeTTL),
	}
	return client.Validate()
}

// TestServerRoleSourceReadsATransientTokenAnswerAsTransient covers a v2-only
// node whose token request fails for a moment. The source reads without a
// token, as it must for an endpoint that predates Metadata v2, and the read
// is refused with 401. That refusal follows from the token request's
// failure, which a retry may clear, so it must not be reported as a
// configuration answer that fails a GET at once and marks the store
// Ready=False. A node that also accepts v1 reads still gets its pair.
func TestServerRoleSourceReadsATransientTokenAnswerAsTransient(t *testing.T) {
	previous := failureHold
	failureHold = 0
	t.Cleanup(func() { failureHold = previous })

	for _, status := range []int{
		http.StatusInternalServerError, http.StatusServiceUnavailable,
		http.StatusTooManyRequests, http.StatusRequestTimeout,
	} {
		t.Run(fmt.Sprintf("v2 only, token request answered %d", status), func(t *testing.T) {
			meta := &fakeMetadata{
				roleList: "role-1", roleID: "role-1",
				document:  metadataDocument("k", "s", time.Now().Add(time.Hour), metadataSuccessCode),
				tokenMode: "required", tokenStatus: status,
			}
			source, _ := newServerRoleFixture(t, meta)
			_, err := source.Credentials(context.Background())
			if err == nil {
				t.Fatal("Credentials() succeeded, want the token request's failure")
			}
			if isAuthError(err) || errors.Is(err, errMetadataRefused) || !IsRetryable(err) {
				t.Errorf("Credentials() error = %v; isAuthError = %v, IsRetryable = %v; want a transient error",
					err, isAuthError(err), IsRetryable(err))
			}
			if !strings.Contains(err.Error(), "token request") || !strings.Contains(err.Error(), fmt.Sprint(status)) {
				t.Errorf("Credentials() error = %q, want it to name the token request and its status", err)
			}

			source, _ = newServerRoleFixture(t, meta)
			if got, verr := validateWithSource(t, source); got == esv1.ValidationResultError {
				t.Errorf("Validate() = Error (%v), want the store left to the next check", verr)
			}
		})
	}

	t.Run("a node that also accepts v1 reads gets its pair", func(t *testing.T) {
		meta := &fakeMetadata{
			roleList: "role-1", roleID: "role-1",
			document:    metadataDocument("k", "s", time.Now().Add(time.Hour), metadataSuccessCode),
			tokenStatus: http.StatusServiceUnavailable,
		}
		source, _ := newServerRoleFixture(t, meta)
		if pair, err := source.Credentials(context.Background()); err != nil || pair.AccessKeyID != "k" {
			t.Fatalf("Credentials() = %+v, %v; want the role's pair read without a token", pair, err)
		}
	})
}

// TestServerRoleSourceReportsThrottlingAsTransient answers a metadata read
// with 429 and with 408. The Secret Manager transport, the Pod Identity
// exchange and the Secure Token Service read both as transient; the metadata
// endpoint's must not be a configuration answer either.
func TestServerRoleSourceReportsThrottlingAsTransient(t *testing.T) {
	previous := failureHold
	failureHold = 0
	t.Cleanup(func() { failureHold = previous })

	for _, status := range []int{http.StatusTooManyRequests, http.StatusRequestTimeout} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			meta := &fakeMetadata{roleList: "role-1", roleID: "role-1", listStatus: status}
			source, _ := newServerRoleFixture(t, meta)
			_, err := source.Credentials(context.Background())
			if err == nil {
				t.Fatal("Credentials() succeeded, want the metadata endpoint's failure")
			}
			if isAuthError(err) || errors.Is(err, errMetadataRefused) || !IsRetryable(err) {
				t.Errorf("Credentials() error = %v; isAuthError = %v, IsRetryable = %v; want a transient error",
					err, isAuthError(err), IsRetryable(err))
			}

			source, _ = newServerRoleFixture(t, meta)
			if got, verr := validateWithSource(t, source); got == esv1.ValidationResultError {
				t.Errorf("Validate() = Error (%v), want the store left to the next check", verr)
			}
		})
	}
}
