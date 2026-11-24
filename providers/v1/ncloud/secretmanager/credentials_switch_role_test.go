// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testRole = "nrn:PUB:IAM::1234567890:Role/abcdef0123456789"

// stsCall is one request the fake Secure Token Service received.
type stsCall struct {
	accessKey string
	signature string
	timestamp string
	body      switchRoleRequest
}

// fakeSTS answers switch-role requests. respond decides the answer from the
// caller's access key so a test can refuse one key and accept another.
type fakeSTS struct {
	t       *testing.T
	respond func(accessKey string) (status int, body string)
	// headers are added to every response.
	headers http.Header

	mu    sync.Mutex
	calls []stsCall
}

func (f *fakeSTS) handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != stsSwitchRolePath {
		f.t.Errorf("unexpected STS request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	call := stsCall{
		accessKey: r.Header.Get(headerAccessKey),
		signature: r.Header.Get(headerSignature),
		timestamp: r.Header.Get(headerTimestamp),
	}
	if err := json.Unmarshal(raw, &call.body); err != nil {
		f.t.Errorf("STS body is not the documented JSON: %v", err)
	}
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
	status, body := f.respond(call.accessKey)
	maps.Copy(w.Header(), f.headers)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (f *fakeSTS) seen() []stsCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]stsCall(nil), f.calls...)
}

func stsCredentialsBody(id, secret string, expiry time.Time) string {
	return fmt.Sprintf(`{"switchedRole":%q,"credentials":{"accessKey":%q,"keySecret":%q,"createTime":"2026-09-21T00:00:00Z","expireTime":%q,"useMfa":false}}`,
		testRole, id, secret, expiry.UTC().Format(time.RFC3339))
}

func newSwitchRoleFixture(t *testing.T, base CredentialsSource, respond func(accessKey string) (int, string)) (*switchRoleSource, *fakeSTS) {
	t.Helper()
	sts := &fakeSTS{t: t, respond: respond}
	server := httptest.NewServer(http.HandlerFunc(sts.handler))
	t.Cleanup(server.Close)
	return newSwitchRoleSource(base, server.URL, testRole, server.Client()), sts
}

func TestSwitchRoleSourceExchangesTheBasePair(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	base := StaticCredentials(testAccessKeyID, "base-secret")
	source, sts := newSwitchRoleFixture(t, base, func(string) (int, string) {
		return http.StatusOK, stsCredentialsBody("ncp_iam_temp", "temp-secret", expiry)
	})

	pair, err := source.Credentials(context.Background())
	if err != nil {
		t.Fatalf("Credentials() error = %v", err)
	}
	if pair.AccessKeyID != "ncp_iam_temp" || pair.SecretKey != "temp-secret" || !pair.Expiry.Equal(expiry) {
		t.Errorf("Credentials() = %+v, want the switched pair expiring %v", pair, expiry)
	}
	if got := source.Identity(); got != "role:"+testRole+"@"+base.Identity() {
		t.Errorf("Identity() = %q, want the role and the base identity", got)
	}

	calls := sts.seen()
	if len(calls) != 1 {
		t.Fatalf("STS calls = %d, want 1", len(calls))
	}
	call := calls[0]
	if call.body.RoleNRN != testRole || call.body.DurationSec != switchRoleDurationSec {
		t.Errorf("STS body = %+v, want roleNrn %q and durationSec %d", call.body, testRole, switchRoleDurationSec)
	}
	// The switch request is signed with the BASE pair, over the switch-role
	// path, the same way a Secret Manager request is signed.
	basePair, _ := base.Credentials(context.Background())
	if call.accessKey != testAccessKeyID {
		t.Errorf("STS request access key = %q, want the base key", call.accessKey)
	}
	if want := signRequest(http.MethodPost, stsSwitchRolePath, call.timestamp, basePair); call.signature != want {
		t.Errorf("STS request signature = %q, want the base pair's signature over %s", call.signature, stsSwitchRolePath)
	}

	// Inside the lifetime the switched pair is served from memory.
	if _, err := source.Credentials(context.Background()); err != nil {
		t.Fatalf("second Credentials() error = %v", err)
	}
	if got := len(sts.seen()); got != 1 {
		t.Errorf("STS calls after a cached read = %d, want 1", got)
	}
}

func TestSwitchRoleSourceRefreshesATemporaryBaseOnceWhenRefused(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	stale := temporaryPair(staleKeyID, expiry)
	fresh := temporaryPair(freshKeyID, expiry)

	t.Run("a refreshed base that differs is retried", func(t *testing.T) {
		base := &fakeSource{pairs: []Credentials{stale, fresh}}
		source, sts := newSwitchRoleFixture(t, base, func(accessKey string) (int, string) {
			if accessKey == staleKeyID {
				return http.StatusNotFound, `{"code":404,"message":"invalid or expired credentials"}`
			}
			return http.StatusOK, stsCredentialsBody("temp", "s", expiry)
		})
		pair, err := source.Credentials(context.Background())
		if err != nil {
			t.Fatalf("Credentials() error = %v", err)
		}
		if pair.AccessKeyID != "temp" {
			t.Errorf("Credentials() = %+v, want the pair switched with the refreshed base", pair)
		}
		if base.invalidations != 1 {
			t.Errorf("base invalidations = %d, want 1", base.invalidations)
		}
		if calls := sts.seen(); len(calls) != 2 || calls[1].accessKey != freshKeyID {
			t.Errorf("STS calls = %+v, want a second call signed with the refreshed base", calls)
		}
	})

	t.Run("only a refusal of the caller key refreshes the base", func(t *testing.T) {
		// 404 is documented for an invalid or expired caller key and 401 is
		// the gateway refusing the signature; 403 refuses the switch, and
		// 400 or 409 the request itself, none of which a fresh key changes.
		for status, refreshes := range map[int]bool{
			http.StatusUnauthorized: true,
			http.StatusNotFound:     true,
			http.StatusForbidden:    false,
			http.StatusBadRequest:   false,
			http.StatusConflict:     false,
		} {
			t.Run(fmt.Sprint(status), func(t *testing.T) {
				base := &fakeSource{pairs: []Credentials{stale, fresh}}
				source, sts := newSwitchRoleFixture(t, base, func(accessKey string) (int, string) {
					if accessKey == staleKeyID {
						return status, `{"message":"refused"}`
					}
					return http.StatusOK, stsCredentialsBody("temp", "s", expiry)
				})
				pair, err := source.Credentials(context.Background())
				calls := sts.seen()
				if refreshes {
					if err != nil || pair.AccessKeyID != "temp" {
						t.Fatalf("Credentials() = %+v, %v; want the pair switched with the refreshed base", pair, err)
					}
					if base.invalidations != 1 || len(calls) != 2 || calls[1].accessKey != freshKeyID {
						t.Errorf("invalidations = %d, STS calls = %+v; want 1 and a second call signed with the refreshed base", base.invalidations, calls)
					}
					return
				}
				if !errors.Is(err, ErrSwitchRoleRejected) {
					t.Fatalf("Credentials() error = %v, want ErrSwitchRoleRejected", err)
				}
				if base.invalidations != 0 || len(calls) != 1 {
					t.Errorf("a %d caused %d base invalidations and %d STS calls, want 0 and 1: it refuses the switch, not the caller key", status, base.invalidations, len(calls))
				}
			})
		}
	})

	t.Run("a refreshed base that is the same pair is not retried", func(t *testing.T) {
		base := &fakeSource{pairs: []Credentials{stale}}
		source, sts := newSwitchRoleFixture(t, base, func(string) (int, string) {
			return http.StatusNotFound, ""
		})
		_, err := source.Credentials(context.Background())
		if !errors.Is(err, ErrSwitchRoleRejected) {
			t.Fatalf("Credentials() error = %v, want ErrSwitchRoleRejected", err)
		}
		if calls := len(sts.seen()); base.invalidations != 1 || calls != 1 {
			t.Errorf("invalidations=%d STS calls=%d, want 1 and 1: the same pair would be refused again", base.invalidations, calls)
		}
	})

	t.Run("a refresh that fails is reported with the refusal", func(t *testing.T) {
		refreshErr := errors.New("metadata endpoint unreachable")
		base := &fakeSource{pairs: []Credentials{stale}, errAfterDrop: refreshErr}
		source, _ := newSwitchRoleFixture(t, base, func(string) (int, string) {
			return http.StatusNotFound, ""
		})
		_, err := source.Credentials(context.Background())
		if !errors.Is(err, ErrSwitchRoleRejected) || !errors.Is(err, refreshErr) {
			t.Fatalf("Credentials() error = %v, want both the refusal and the refresh failure in the chain", err)
		}
	})

	t.Run("a permanent base is never refreshed", func(t *testing.T) {
		source, sts := newSwitchRoleFixture(t, StaticCredentials(testAccessKeyID, "s"), func(string) (int, string) {
			return http.StatusForbidden, ""
		})
		_, err := source.Credentials(context.Background())
		if !errors.Is(err, ErrSwitchRoleRejected) {
			t.Fatalf("Credentials() error = %v, want ErrSwitchRoleRejected", err)
		}
		if got := len(sts.seen()); got != 1 {
			t.Errorf("STS calls = %d, want 1", got)
		}
	})
}

func TestSwitchRoleSourceReportsServiceFailures(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	tests := []struct {
		name       string
		status     int
		body       string
		wantErr    error
		wantAbsent string
	}{
		{"401 is a rejection", http.StatusUnauthorized, `{"message":"Authentication Failed"}`, ErrSwitchRoleRejected, "Authentication Failed"},
		{"400 is a rejection", http.StatusBadRequest, `{"message":"invalid roleNrn"}`, ErrSwitchRoleRejected, "invalid roleNrn"},
		{"409 is a rejection", http.StatusConflict, "", ErrSwitchRoleRejected, ""},
		{"500 is a service failure", http.StatusInternalServerError, "", ErrServiceUnavailable, ""},
		{"408 is a service failure", http.StatusRequestTimeout, "", ErrServiceUnavailable, ""},
		{"429 keeps the generic sentinel", http.StatusTooManyRequests, "", ErrRateLimited, ""},
		{"non-JSON body", http.StatusOK, "<html>oops</html>", errSTSDecode, "oops"},
		{"unparsable expiry", http.StatusOK, `{"credentials":{"accessKey":"k","keySecret":"s","expireTime":"later"}}`, ErrTemporaryCredentialsIncomplete, ""},
		{"missing key material", http.StatusOK, stsCredentialsBody("", "", expiry), ErrTemporaryCredentialsIncomplete, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, _ := newSwitchRoleFixture(t, StaticCredentials(testAccessKeyID, "s"), func(string) (int, string) {
				return tt.status, tt.body
			})
			_, err := source.Credentials(context.Background())
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Credentials() error = %v, want errors.Is %v", err, tt.wantErr)
			}
			if tt.wantAbsent != "" && strings.Contains(err.Error(), tt.wantAbsent) {
				t.Errorf("Credentials() error %q echoes the response body", err)
			}
			if tt.status != http.StatusOK && !strings.Contains(err.Error(), fmt.Sprint(tt.status)) {
				t.Errorf("Credentials() error %q does not name status %d", err, tt.status)
			}
		})
	}

	t.Run("a base that cannot produce a pair fails before any STS call", func(t *testing.T) {
		boom := errors.New("no metadata")
		source, sts := newSwitchRoleFixture(t, &fakeSource{err: boom}, func(string) (int, string) {
			return http.StatusOK, ""
		})
		if _, err := source.Credentials(context.Background()); !errors.Is(err, boom) {
			t.Errorf("Credentials() error = %v, want the base error", err)
		}
		if got := len(sts.seen()); got != 0 {
			t.Errorf("STS calls = %d, want 0", got)
		}
	})
}

func TestSwitchRoleCredentialsValidatesAndShares(t *testing.T) {
	base := StaticCredentials(testAccessKeyID, "s")

	if _, err := SwitchRoleCredentials(nil, "", testRole); !errors.Is(err, ErrMissingCredentials) {
		t.Errorf("nil base error = %v, want ErrMissingCredentials", err)
	}
	if _, err := SwitchRoleCredentials(base, "", ""); !errors.Is(err, ErrMissingRole) {
		t.Errorf("empty role error = %v, want ErrMissingRole", err)
	}
	if _, err := SwitchRoleCredentials(base, "http://sts.example", testRole); !errors.Is(err, ErrEndpointScheme) {
		t.Errorf("plain http STS endpoint error = %v, want ErrEndpointScheme", err)
	}

	first, err := SwitchRoleCredentials(base, "", testRole)
	if err != nil {
		t.Fatalf("SwitchRoleCredentials() error = %v", err)
	}
	again, err := SwitchRoleCredentials(StaticCredentials(testAccessKeyID, "s"), DefaultSTSEndpoint+"/", testRole)
	if err != nil {
		t.Fatalf("SwitchRoleCredentials() error = %v", err)
	}
	if first != again {
		t.Error("the same (endpoint, role, base identity) built two sources; every reconcile would switch roles again")
	}
	if other, _ := SwitchRoleCredentials(base, "", testRole+"2"); other == first {
		t.Error("a different role shares the source")
	}
	if other, _ := SwitchRoleCredentials(StaticCredentials("OTHER", "s"), "", testRole); other == first {
		t.Error("a different base identity shares the source")
	}
	if got := first.Identity(); got != "role:"+testRole+"@"+base.Identity() {
		t.Errorf("Identity() = %q", got)
	}
}

func TestSwitchRoleCredentialsDoNotShareAcrossSecretKeys(t *testing.T) {
	// An access key ID is not a secret: it rides in every request header. A
	// store in another namespace that names the victim's ID with a wrong
	// secret must get its own source, never the victim's switched pair.
	const id = "SHARED-AKID"
	right := StaticCredentials(id, "right-secret")
	wrong := StaticCredentials(id, "wrong-secret")

	victim, err := SwitchRoleCredentials(right, "", testRole)
	if err != nil {
		t.Fatalf("SwitchRoleCredentials(right) error = %v", err)
	}
	intruder, err := SwitchRoleCredentials(wrong, "", testRole)
	if err != nil {
		t.Fatalf("SwitchRoleCredentials(wrong) error = %v", err)
	}
	if victim == intruder {
		t.Fatal("the same access key ID with another secret was handed the victim's switched-role source")
	}
	if victim.Identity() == intruder.Identity() {
		t.Error("identities collide across secret keys")
	}

	// And the intruder's own source signs with the wrong secret, which a
	// service checking the signature refuses.
	rightPair, _ := right.Credentials(context.Background())
	source, sts := newSwitchRoleFixture(t, wrong, nil)
	sts.respond = func(string) (int, string) {
		call := sts.seen()[len(sts.seen())-1]
		if call.signature == signRequest(http.MethodPost, stsSwitchRolePath, call.timestamp, rightPair) {
			return http.StatusOK, stsCredentialsBody("temp", "s", time.Now().Add(time.Hour))
		}
		return http.StatusUnauthorized, ""
	}
	if _, err := source.Credentials(context.Background()); !errors.Is(err, ErrSwitchRoleRejected) {
		t.Errorf("wrong-secret switch error = %v, want ErrSwitchRoleRejected", err)
	}
}

func TestSwitchRoleSourceCarriesRetryAfterOnRateLimit(t *testing.T) {
	source, sts := newSwitchRoleFixture(t, StaticCredentials(testAccessKeyID, "s"), func(string) (int, string) {
		return http.StatusTooManyRequests, ""
	})
	sts.headers = http.Header{"Retry-After": []string{"7"}}

	_, err := source.Credentials(context.Background())
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Credentials() error = %v, want ErrRateLimited", err)
	}
	after, ok := retryAfterFrom(err)
	if !ok || after != 7*time.Second {
		t.Errorf("retryAfterFrom() = %v, %v; want the 7s the service asked for", after, ok)
	}
}
