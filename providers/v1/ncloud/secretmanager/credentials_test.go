// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSource is a CredentialsSource whose pairs are scripted. Each Invalidate
// advances to the next scripted pair; without one the current pair is returned
// again, as a refreshing source does inside a lifetime.
type fakeSource struct {
	mu            sync.Mutex
	pairs         []Credentials
	err           error
	errAfterDrop  error // returned once Invalidate has been called
	index         int
	calls         int
	invalidations int
}

func (f *fakeSource) Credentials(context.Context) (Credentials, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return Credentials{}, f.err
	}
	if f.invalidations > 0 && f.errAfterDrop != nil {
		return Credentials{}, f.errAfterDrop
	}
	return f.pairs[f.index], nil
}

func (f *fakeSource) Invalidate(context.Context, Credentials) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invalidations++
	if f.index < len(f.pairs)-1 {
		f.index++
	}
}

func (f *fakeSource) Identity() string { return "fake" }

// Key names the tests below hand to fakes. Shared so the same word does not
// have to be spelled out in every file that scripts a pair.
const (
	testAccessKeyID = "AKID"
	staleKeyID      = "stale"
	freshKeyID      = "fresh"
)

func temporaryPair(id string, expiry time.Time) Credentials {
	return Credentials{AccessKeyID: id, SecretKey: "secret-" + id, Expiry: expiry}
}

func TestStaticCredentials(t *testing.T) {
	ctx := context.Background()

	source := StaticCredentials(testAccessKeyID, "secret")
	pair, err := source.Credentials(ctx)
	if err != nil {
		t.Fatalf("Credentials() error = %v", err)
	}
	if pair.AccessKeyID != testAccessKeyID || pair.SecretKey != "secret" {
		t.Errorf("Credentials() = %+v, want the configured pair", pair)
	}
	if pair.temporary() {
		t.Error("a permanent pair reported an expiry")
	}
	// The identity names the key ID and fingerprints the secret without
	// carrying it: the same pair maps to the same identity, another secret
	// under the same ID to another one.
	got := source.Identity()
	if !strings.HasPrefix(got, "key:"+testAccessKeyID+"/") || strings.Contains(got, "secret") {
		t.Errorf("Identity() = %q, want key:<id>/<fingerprint> without the secret", got)
	}
	// The fingerprint is the only thing keeping another namespace's wrong
	// secret under the same ID out of this source's registry entries, so it
	// keeps the full HMAC-SHA256 rather than a prefix of it.
	if fp := strings.TrimPrefix(got, "key:"+testAccessKeyID+"/"); len(fp) != 64 {
		t.Errorf("Identity() fingerprint %q has %d hex digits, want the full 64", fp, len(fp))
	}
	if StaticCredentials(testAccessKeyID, "secret").Identity() != got {
		t.Error("Identity() is not deterministic for the same pair")
	}
	if StaticCredentials(testAccessKeyID, "other-secret").Identity() == got {
		t.Error("Identity() ignores the secret key; a wrong secret under the same ID would share this source's registry entries")
	}

	// Invalidate has nothing to drop; the pair must survive it.
	source.Invalidate(context.Background(), pair)
	if again, err := source.Credentials(ctx); err != nil || again != pair {
		t.Errorf("Credentials() after Invalidate = %+v, %v; want the same pair", again, err)
	}

	for name, source := range map[string]CredentialsSource{
		"missing access key": StaticCredentials("", "secret"),
		"missing secret key": StaticCredentials(testAccessKeyID, ""),
	} {
		if _, err := source.Credentials(ctx); !errors.Is(err, ErrMissingCredentials) {
			t.Errorf("%s: Credentials() error = %v, want ErrMissingCredentials", name, err)
		}
	}
}

func TestRefreshingSourceReusesPairUntilDue(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	fetches := 0
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		fetches++
		return temporaryPair("k", now.Add(time.Hour)), nil
	})
	source.now = func() time.Time { return now }
	ctx := context.Background()

	first, err := source.Credentials(ctx)
	if err != nil {
		t.Fatalf("Credentials() error = %v", err)
	}
	// Well inside the lifetime: no fetch.
	now = now.Add(50 * time.Minute)
	if again, err := source.Credentials(ctx); err != nil || again != first || fetches != 1 {
		t.Fatalf("Credentials() inside lifetime = %+v, %v, fetches=%d; want the cached pair and 1 fetch", again, err, fetches)
	}
	// refreshLead before expiry: refreshed, and the fresh pair is what the
	// caller gets, not the one about to expire.
	now = now.Add(5 * time.Minute)
	pair, err := source.Credentials(ctx)
	if err != nil {
		t.Fatalf("Credentials() at refresh time error = %v", err)
	}
	if fetches != 2 {
		t.Errorf("fetches at refresh time = %d, want 2", fetches)
	}
	if !pair.Expiry.Equal(now.Add(time.Hour)) {
		t.Errorf("Credentials() at refresh time expiry = %v, want the freshly fetched pair", pair.Expiry)
	}
}

func TestRefreshingSourceInvalidateForcesAFetch(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	fetches := 0
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		fetches++
		return temporaryPair("k", now.Add(time.Hour)), nil
	})
	source.now = func() time.Time { return now }
	ctx := context.Background()

	first, err := source.Credentials(ctx)
	if err != nil {
		t.Fatalf("Credentials() error = %v", err)
	}
	// A refusal of some other pair is stale news: nothing is dropped.
	source.Invalidate(context.Background(), Credentials{AccessKeyID: "someone-else"})
	if _, err := source.Credentials(ctx); err != nil || fetches != 1 {
		t.Fatalf("Credentials() after a foreign Invalidate: err=%v fetches=%d, want the cached pair and 1 fetch", err, fetches)
	}
	source.Invalidate(context.Background(), first)
	if _, err := source.Credentials(ctx); err != nil {
		t.Fatalf("Credentials() after Invalidate error = %v", err)
	}
	if fetches != 2 {
		t.Errorf("fetches after Invalidate = %d, want 2", fetches)
	}
}

func TestRefreshingSourceDoesNotCacheFailuresOrIncompletePairs(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	boom := errors.New("boom")
	var script Credentials
	var scriptErr error
	fetches := 0
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		fetches++
		if scriptErr != nil {
			return Credentials{}, scriptErr
		}
		return script, nil
	})
	source.now = func() time.Time { return now }
	ctx := context.Background()

	scriptErr = boom
	if _, err := source.Credentials(ctx); !errors.Is(err, boom) {
		t.Fatalf("Credentials() with failing fetch error = %v, want the fetch error", err)
	}

	scriptErr = nil
	for name, incomplete := range map[string]Credentials{
		"no access key": {SecretKey: "s", Expiry: now.Add(time.Hour)},
		"no secret key": {AccessKeyID: "k", Expiry: now.Add(time.Hour)},
		"no expiry":     {AccessKeyID: "k", SecretKey: "s"},
	} {
		now = now.Add(failureHold + time.Second) // past the failure memo
		script = incomplete
		if _, err := source.Credentials(ctx); !errors.Is(err, ErrTemporaryCredentialsIncomplete) {
			t.Errorf("%s: Credentials() error = %v, want ErrTemporaryCredentialsIncomplete", name, err)
		}
	}

	// Nothing above was cached as a pair: a good pair is fetched, not served from a failure.
	now = now.Add(failureHold + time.Second)
	before := fetches
	script = temporaryPair("k", now.Add(time.Hour))
	if pair, err := source.Credentials(ctx); err != nil || pair.AccessKeyID != "k" || fetches != before+1 {
		t.Errorf("Credentials() after failures = %+v, %v, fetches=%d; want a fresh fetch of the good pair", pair, err, fetches)
	}
}

func TestRefreshTime(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		expiry time.Time
		want   time.Time
	}{
		{"one hour lifetime refreshes refreshLead early", now.Add(time.Hour), now.Add(55 * time.Minute)},
		{"ten minute lifetime, the service minimum, refreshes at the lead", now.Add(10 * time.Minute), now.Add(5 * time.Minute)},
		{"shorter lifetime refreshes halfway", now.Add(8 * time.Minute), now.Add(4 * time.Minute)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refreshTime(now, tt.expiry); !got.Equal(tt.want) {
				t.Errorf("refreshTime() = %v, want %v", got, tt.want)
			}
		})
	}

	// A pair that arrived expired, or whose replacement time has already
	// passed, is due failureHold from now: soon enough that a pair the
	// service refuses is replaced on the next reconcile, late enough that a
	// skewed clock does not cost a fetch per request.
	for name, expiry := range map[string]time.Time{
		"a pair that arrived expired":         now.Add(-time.Minute),
		"a pair that arrived about to expire": now.Add(time.Second),
	} {
		t.Run(name+" is due after failureHold", func(t *testing.T) {
			if got := refreshTime(now, expiry); !got.Equal(now.Add(failureHold)) {
				t.Errorf("refreshTime() = %v, want now + failureHold = %v", got, now.Add(failureHold))
			}
		})
	}
}

func TestSetAuthHeadersSignsTheRequestURI(t *testing.T) {
	pair := Credentials{AccessKeyID: testAccessKeyID, SecretKey: "secret"}
	now := time.UnixMilli(1234567890000)
	req, err := http.NewRequest(http.MethodGet, "https://example.test/api/v1/secrets?pageNo=2", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	setAuthHeaders(req, pair, now)

	if got := req.Header.Get(headerTimestamp); got != "1234567890000" {
		t.Errorf("%s = %q, want the millisecond timestamp", headerTimestamp, got)
	}
	if got := req.Header.Get(headerAccessKey); got != testAccessKeyID {
		t.Errorf("%s = %q, want the access key ID", headerAccessKey, got)
	}
	if got := req.Header.Get(headerContentType); got != "application/json" {
		t.Errorf("%s = %q, want application/json", headerContentType, got)
	}
	// The query string is part of what the gateway signs; a signature over
	// the bare path would be refused for every paginated listing.
	want := signRequest(http.MethodGet, "/api/v1/secrets?pageNo=2", "1234567890000", pair)
	if got := req.Header.Get(headerSignature); got != want {
		t.Errorf("%s = %q, want the signature over the request URI %q", headerSignature, got, want)
	}
	if bare := signRequest(http.MethodGet, "/api/v1/secrets", "1234567890000", pair); bare == want {
		t.Error("signature ignores the query string")
	}
}

func TestRefreshingSourceAnswersAFreshFailureFromMemory(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	boom := errors.New("sts down")
	fetches := 0
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		fetches++
		return Credentials{}, boom
	})
	source.now = func() time.Time { return now }
	ctx := context.Background()

	if _, err := source.Credentials(ctx); !errors.Is(err, boom) {
		t.Fatalf("Credentials() error = %v, want the fetch error", err)
	}
	// Callers that queued behind the failure get the same answer at once.
	now = now.Add(time.Second)
	if _, err := source.Credentials(ctx); !errors.Is(err, boom) || fetches != 1 {
		t.Fatalf("Credentials() inside the hold: err=%v fetches=%d, want the remembered error and no new fetch", err, fetches)
	}
	// After the hold the service is asked again.
	now = now.Add(failureHold)
	if _, err := source.Credentials(ctx); !errors.Is(err, boom) || fetches != 2 {
		t.Fatalf("Credentials() after the hold: err=%v fetches=%d, want a new fetch", err, fetches)
	}
}

func TestRefreshingSourceDoesNotRememberACallersOwnCancellation(t *testing.T) {
	fetches := 0
	ctx, cancel := context.WithCancel(context.Background())
	source := newRefreshingSource(func(ctx context.Context) (Credentials, error) {
		fetches++
		if fetches == 1 {
			cancel() // the first caller gives up mid-fetch
			return Credentials{}, ctx.Err()
		}
		return temporaryPair("k", time.Now().Add(time.Hour)), nil
	})

	if _, err := source.Credentials(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("first Credentials() error = %v, want the caller's cancellation", err)
	}
	// The next caller must not inherit that cancellation as a service failure.
	if _, err := source.Credentials(context.Background()); err != nil || fetches != 2 {
		t.Fatalf("second Credentials(): err=%v fetches=%d, want a fresh fetch that succeeds", err, fetches)
	}
}

func TestRefreshingSourceSharesOneFetchAmongConcurrentCallers(t *testing.T) {
	release := make(chan struct{})
	var fetches atomic.Int32
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		fetches.Add(1)
		<-release
		return temporaryPair("k", time.Now().Add(time.Hour)), nil
	})

	const callers = 8
	results := make(chan Credentials, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			pair, err := source.Credentials(context.Background())
			if err != nil {
				t.Errorf("Credentials() error = %v", err)
				return
			}
			results <- pair
		})
	}
	time.Sleep(50 * time.Millisecond) // let the callers queue behind the one fetch
	close(release)
	wg.Wait()
	close(results)

	if got := fetches.Load(); got != 1 {
		t.Errorf("fetches = %d, want 1 shared by %d callers", got, callers)
	}
	var first *Credentials
	for pair := range results {
		if first == nil {
			first = &pair
			continue
		}
		if pair != *first {
			t.Errorf("callers received different pairs: %+v and %+v", *first, pair)
		}
	}
}

func TestRefreshingSourceWaiterLeavesWhenItsContextEnds(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	free := func() { releaseOnce.Do(func() { close(release) }) }
	defer free()
	// A waiter that wrongly waits for the fetch gets it after 1.5s, so the
	// failure shows as a late return rather than a hung test.
	time.AfterFunc(1500*time.Millisecond, free)

	started := make(chan struct{})
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		close(started)
		<-release
		return temporaryPair("k", time.Now().Add(time.Hour)), nil
	})

	go func() { _, _ = source.Credentials(context.Background()) }()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	begin := time.Now()
	_, err := source.Credentials(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting Credentials() error = %v, want the waiter's own deadline", err)
	}
	if waited := time.Since(begin); waited > time.Second {
		t.Errorf("waiter left after %v; it should leave when its context ends, not when the fetch does", waited)
	}
}

func TestRefreshingSourceHandsOutAPairThatArrivedExpired(t *testing.T) {
	// The service, not this clock, decides whether a pair is accepted; a
	// skewed node clock must not turn into a store that never signs.
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	fetches := 0
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		fetches++
		return temporaryPair("k", now.Add(-time.Minute)), nil
	})
	source.now = func() time.Time { return now }

	pair, err := source.Credentials(context.Background())
	if err != nil || pair.AccessKeyID != "k" {
		t.Fatalf("Credentials() = %+v, %v; want the expired pair handed out", pair, err)
	}
	// A skewed clock must not turn every request into a fetch either: within
	// failureHold the pair is served again, and after it a fresh one is asked
	// for.
	if _, err := source.Credentials(context.Background()); err != nil || fetches != 1 {
		t.Errorf("second Credentials() within failureHold: err=%v fetches=%d, want the pair served again", err, fetches)
	}
	now = now.Add(failureHold)
	if _, err := source.Credentials(context.Background()); err != nil || fetches != 2 {
		t.Errorf("Credentials() after failureHold: err=%v fetches=%d, want a refetch", err, fetches)
	}
}

// TestRefreshingSourceInvalidateLeavesWithItsContext pins that a refused
// caller waiting to invalidate does not outlive its own deadline while another
// caller holds the source for a slow fetch.
func TestRefreshingSourceInvalidateLeavesWithItsContext(t *testing.T) {
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		return temporaryPair("k", time.Now().Add(time.Hour)), nil
	})
	if err := source.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer source.release()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		source.Invalidate(ctx, temporaryPair("k", time.Now().Add(time.Hour)))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Invalidate() still waiting 2s after its context ended")
	}
}

// TestRefreshingSourceKeepsAValidPairWhenItsRefreshFails pins why the refresh
// runs refreshLead early: a Secure Token Service or metadata outage during
// that window must not fail requests the current pair can still sign. Once
// the pair expires, or once the service refused it, the failure is reported.
func TestRefreshingSourceKeepsAValidPairWhenItsRefreshFails(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	boom := errors.New("sts down")
	pair := temporaryPair("k", now.Add(time.Hour))
	fail := false
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		if fail {
			return Credentials{}, boom
		}
		return pair, nil
	})
	source.now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := source.Credentials(ctx); err != nil {
		t.Fatalf("first Credentials() error = %v", err)
	}

	fail = true
	now = pair.Expiry.Add(-time.Minute) // inside refreshLead, before expiry
	if got, err := source.Credentials(ctx); err != nil || got.AccessKeyID != "k" {
		t.Fatalf("Credentials() during a failed refresh = %+v, %v; want the still-valid pair", got, err)
	}
	now = now.Add(time.Second) // inside the failure hold
	if got, err := source.Credentials(ctx); err != nil || got.AccessKeyID != "k" {
		t.Fatalf("Credentials() inside the hold = %+v, %v; want the still-valid pair", got, err)
	}

	now = pair.Expiry.Add(time.Second)
	if _, err := source.Credentials(ctx); !errors.Is(err, boom) {
		t.Fatalf("Credentials() after expiry error = %v, want the fetch error", err)
	}

	t.Run("a refused pair is not handed out again", func(t *testing.T) {
		fail = false
		now = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
		refused := newRefreshingSource(func(context.Context) (Credentials, error) {
			if fail {
				return Credentials{}, boom
			}
			return pair, nil
		})
		refused.now = func() time.Time { return now }
		if _, err := refused.Credentials(ctx); err != nil {
			t.Fatal(err)
		}
		refused.Invalidate(context.Background(), pair)
		fail = true
		if _, err := refused.Credentials(ctx); !errors.Is(err, boom) {
			t.Errorf("Credentials() after Invalidate with a failing fetch = %v, want the fetch error", err)
		}
	})
}

func TestRefreshingSourceSpacesRetriesOfAFailedRefreshWhileThePairIsValid(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	boom := errors.New("sts down")
	pair := temporaryPair("k", now.Add(time.Hour))
	fail := false
	fetches := 0
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		fetches++
		if fail {
			return Credentials{}, boom
		}
		return pair, nil
	})
	source.now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := source.Credentials(ctx); err != nil {
		t.Fatal(err)
	}

	fail = true
	now = pair.Expiry.Add(-refreshLead).Add(time.Second)
	for _, step := range []time.Duration{0, failureHold + time.Second, refetchHold - time.Second} {
		at := now.Add(step)
		source.now = func() time.Time { return at }
		if got, err := source.Credentials(ctx); err != nil || got.AccessKeyID != "k" {
			t.Fatalf("Credentials() %v into a failing refresh = %+v, %v; want the still-valid pair", step, got, err)
		}
	}
	if fetches != 2 {
		t.Fatalf("fetches within refetchHold of a failed refresh = %d, want 2 (the first pair and one refresh)", fetches)
	}
	at := now.Add(refetchHold)
	source.now = func() time.Time { return at }
	if _, err := source.Credentials(ctx); err != nil || fetches != 3 {
		t.Fatalf("Credentials() after refetchHold: err=%v fetches=%d, want the valid pair and a third fetch", err, fetches)
	}

	t.Run("the retry is not put off past the pair's expiry", func(t *testing.T) {
		at := pair.Expiry.Add(-time.Second)
		source.now = func() time.Time { return at }
		if _, err := source.Credentials(ctx); err != nil {
			t.Fatalf("Credentials() a second before expiry error = %v", err)
		}
		if source.refreshAt.After(pair.Expiry) {
			t.Fatalf("next refresh at %v, after the pair expires at %v", source.refreshAt, pair.Expiry)
		}
		at = pair.Expiry
		if _, err := source.Credentials(ctx); !errors.Is(err, boom) {
			t.Fatalf("Credentials() at expiry error = %v, want the fetch error", err)
		}
	})
}

func TestRefreshingSourceIgnoresRefusalsOfAPairTheIssuerHandsBack(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	pair := temporaryPair("k", now.Add(time.Hour))
	fetches := 0
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		fetches++
		return pair, nil
	})
	source.now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := source.Credentials(ctx); err != nil {
		t.Fatal(err)
	}

	// The first refusal refetches; the issuer hands back the same pair.
	source.Invalidate(ctx, pair)
	if _, err := source.Credentials(ctx); err != nil || fetches != 2 {
		t.Fatalf("after the first refusal: err=%v fetches=%d, want one refetch", err, fetches)
	}
	// Refusals of it within refetchHold leave it cached.
	now = now.Add(refetchHold - time.Second)
	for range 3 {
		source.Invalidate(ctx, pair)
		if _, err := source.Credentials(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if fetches != 2 {
		t.Fatalf("fetches after repeated refusals of the handed-back pair = %d, want 2", fetches)
	}
	// After the hold a refusal refetches again, once.
	now = now.Add(2 * time.Second)
	source.Invalidate(ctx, pair)
	if _, err := source.Credentials(ctx); err != nil || fetches != 3 {
		t.Fatalf("after refetchHold: err=%v fetches=%d, want a third fetch", err, fetches)
	}

	t.Run("a different pair is refetched at its first refusal", func(t *testing.T) {
		// Still inside the hold the last refetch of k began, a scheduled
		// refresh brings k2, and the hold must not carry over to it.
		pair = temporaryPair("k2", now.Add(time.Hour))
		source.refreshAt = now
		if got, err := source.Credentials(ctx); err != nil || got.AccessKeyID != "k2" || fetches != 4 {
			t.Fatalf("got=%+v err=%v fetches=%d, want a fourth fetch returning k2", got, err, fetches)
		}
		before := fetches
		source.Invalidate(ctx, pair)
		if got, err := source.Credentials(ctx); err != nil || got.AccessKeyID != "k2" || fetches != before+1 {
			t.Fatalf("got=%+v err=%v fetches=%d, want k2 refetched once on its own first refusal", got, err, fetches-before)
		}
	})
}

func TestRefreshingSourceCountsItsHoldsFromWhenTheFetchReturned(t *testing.T) {
	// An issuer that hangs fails at the client timeout, which is as long as
	// the hold: counted from the start of the fetch, the hold would be over
	// before the next caller arrived.
	start := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	now := start
	pair := temporaryPair("k", start.Add(time.Hour))
	hang := false
	fetches := 0
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		fetches++
		if hang {
			now = now.Add(refetchHold)
			return Credentials{}, errors.New("sts timed out")
		}
		return pair, nil
	})
	source.now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := source.Credentials(ctx); err != nil {
		t.Fatal(err)
	}

	hang = true
	now = pair.Expiry.Add(-refreshLead).Add(time.Second)
	for i := range 3 {
		if got, err := source.Credentials(ctx); err != nil || got.AccessKeyID != "k" {
			t.Fatalf("caller %d: %+v, %v; want the still-valid pair", i, got, err)
		}
		now = now.Add(time.Second)
	}
	if fetches != 2 {
		t.Errorf("fetches = %d, want 2: the callers after a hung refresh must be answered from memory", fetches)
	}
}

func TestRefreshingSourceCanceledCallerDoesNotPutOffTheRefresh(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	pair := temporaryPair("k", now.Add(time.Hour))
	fresh := temporaryPair("k2", now.Add(2*time.Hour))
	var cancelCaller context.CancelFunc
	fetches := 0
	source := newRefreshingSource(func(ctx context.Context) (Credentials, error) {
		fetches++
		switch fetches {
		case 1:
			return pair, nil
		case 2:
			// The caller gives up while its refresh is in flight.
			cancelCaller()
			return Credentials{}, ctx.Err()
		default:
			return fresh, nil
		}
	})
	source.now = func() time.Time { return now }
	if _, err := source.Credentials(context.Background()); err != nil {
		t.Fatal(err)
	}

	now = pair.Expiry.Add(-refreshLead).Add(time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancelCaller = cancel
	if got, err := source.Credentials(ctx); err != nil || got.AccessKeyID != "k" {
		t.Fatalf("canceled caller got %+v, %v; want the still-valid pair", got, err)
	}
	if got, err := source.Credentials(context.Background()); err != nil || got.AccessKeyID != "k2" {
		t.Errorf("next caller got %+v, %v; want the refreshed pair, not a hold the canceled caller set", got, err)
	}
}

func TestRefreshingSourceArmsTheRefusalHoldOncePerRefusal(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	pair := temporaryPair("k", now.Add(time.Hour))
	fetches := 0
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		fetches++
		return pair, nil
	})
	source.now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := source.Credentials(ctx); err != nil {
		t.Fatal(err)
	}
	source.Invalidate(ctx, pair)
	if _, err := source.Credentials(ctx); err != nil {
		t.Fatal(err)
	}

	// Past the hold, a scheduled refresh brings the same key with no
	// refusal pending; a refusal right after it must refetch.
	now = now.Add(refetchHold + time.Second)
	source.refreshAt = now
	if _, err := source.Credentials(ctx); err != nil {
		t.Fatal(err)
	}
	before := fetches
	source.Invalidate(ctx, pair)
	if _, err := source.Credentials(ctx); err != nil || fetches != before+1 {
		t.Errorf("fetches after a fresh refusal = %d, want one refetch", fetches-before)
	}
}

func TestRefreshingSourceForgetsARefusedPairOnceReplaced(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	pair := temporaryPair("k", now.Add(time.Hour))
	source := newRefreshingSource(func(context.Context) (Credentials, error) { return pair, nil })
	source.now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := source.Credentials(ctx); err != nil {
		t.Fatal(err)
	}
	refused := pair
	source.Invalidate(ctx, refused)
	pair = temporaryPair("k2", now.Add(time.Hour))
	if _, err := source.Credentials(ctx); err != nil {
		t.Fatal(err)
	}
	if source.refused != (Credentials{}) {
		t.Errorf("refused pair %q kept in memory after the issuer replaced it", source.refused.AccessKeyID)
	}
}

func TestRefreshingSourceRefusalIsNotAnsweredWithAnEarlierRefreshFailure(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	pair := temporaryPair("k", now.Add(time.Hour))
	earlier := errors.New("earlier refresh failure")
	current := errors.New("current refresh failure")
	fetchErr := error(nil)
	fetches := 0
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		fetches++
		if fetchErr != nil {
			return Credentials{}, fetchErr
		}
		return pair, nil
	})
	source.now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := source.Credentials(ctx); err != nil {
		t.Fatal(err)
	}
	// A refresh fails while the pair is still usable, so it is remembered.
	fetchErr = earlier
	now = pair.Expiry.Add(-refreshLead).Add(time.Second)
	if _, err := source.Credentials(ctx); err != nil {
		t.Fatal(err)
	}
	// The pair is then refused; the next caller must fetch and see its own
	// failure, not the remembered one.
	fetchErr = current
	source.Invalidate(ctx, pair)
	before := fetches
	if _, err := source.Credentials(ctx); !errors.Is(err, current) || fetches != before+1 {
		t.Errorf("Credentials() after a refusal = %v with %d fetches, want its own fetch and %v", err, fetches-before, current)
	}
}

// TestRefreshingSourceDoesNotFetchForACanceledCaller pins that a caller whose
// context is already done never runs a fetch: select hands a done context the
// free slot about half the time, so the check after acquire is what holds.
func TestRefreshingSourceDoesNotFetchForACanceledCaller(t *testing.T) {
	fetches := 0
	source := newRefreshingSource(func(context.Context) (Credentials, error) {
		fetches++
		return Credentials{}, errors.New("must not be called")
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 64 {
		if _, err := source.Credentials(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Credentials() error = %v, want context.Canceled", err)
		}
	}
	if fetches != 0 {
		t.Errorf("fetches = %d, want 0 for a caller that had already given up", fetches)
	}
}
