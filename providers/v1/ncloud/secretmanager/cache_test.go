// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// testSecretID derives a well-formed secret ID (64 lowercase hex characters)
// from seed. The cache drops an ID in any other form, so a test cannot use a
// readable placeholder such as "id-1" where the server would send an ID.
func testSecretID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func TestCacheRegistrySharesAndIsolates(t *testing.T) {
	r := newRegistry[*secretIDCache]("test")

	// Same (endpoint, accessKeyID) -> same cache, so a mapping cached in one
	// reconcile's client is visible to the next reconcile's client.
	a1 := r.get(newSharedSecretIDCache, "https://ep", "AKID")
	a2 := r.get(newSharedSecretIDCache, "https://ep", "AKID")
	if a1 != a2 {
		t.Error("same (endpoint, accessKeyID) must return the same cache instance")
	}

	// Different accessKeyID or endpoint -> different cache (tenant isolation).
	if r.get(newSharedSecretIDCache, "https://ep", "OTHER") == a1 {
		t.Error("different accessKeyID must not share a cache")
	}
	if r.get(newSharedSecretIDCache, "https://other", "AKID") == a1 {
		t.Error("different endpoint must not share a cache")
	}

	// The shared cache actually carries entries across lookups.
	a1.Set("name", testSecretID("1"))
	if id, found, _ := a2.Get("name"); !found || id != testSecretID("1") {
		t.Errorf("entry set via one handle not visible via the shared handle: id=%q found=%v", id, found)
	}
}

func TestNewClientReusesCacheAcrossClients(t *testing.T) {
	// Two NewClient calls for the same store (as happens each reconcile) must
	// share one cache via the process-scoped registry.
	cfg := &Config{AccessKeyID: "AKID-reuse", SecretKey: "sk", Endpoint: "https://ocapi-kr.ncloud.com/secretmanager"}
	c1, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	c2, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if c1.(*Client).cache != c2.(*Client).cache {
		t.Error("clients for the same store must share one cross-reconcile cache")
	}

	cfgWithSlash := *cfg
	cfgWithSlash.Endpoint += "///"
	c3, err := NewClient(&cfgWithSlash)
	if err != nil {
		t.Fatalf("NewClient() with normalized endpoint error = %v", err)
	}
	if c1.(*Client).cache != c3.(*Client).cache {
		t.Error("equivalent normalized endpoints must share one cross-reconcile cache")
	}
}

func TestCacheRegistryEvictsExpiredThenOldest(t *testing.T) {
	now := time.Unix(1000, 0)
	r := newRegistry[*secretIDCache]("test")
	r.maxEntries = 2
	r.idleTTL = 10 * time.Minute
	r.now = func() time.Time { return now }

	a := r.get(newSharedSecretIDCache, "https://a.example", "AKID-A")
	b := r.get(newSharedSecretIDCache, "https://b.example", "AKID-B")

	// Refresh A so only B is expired when C arrives at capacity.
	now = now.Add(6 * time.Minute)
	if got := r.get(newSharedSecretIDCache, "https://a.example", "AKID-A"); got != a {
		t.Fatal("refreshing identity A replaced its shared cache")
	}
	now = now.Add(5 * time.Minute)
	c := r.get(newSharedSecretIDCache, "https://c.example", "AKID-C")

	if _, ok := r.entries[hashIdentity("https://b.example", "AKID-B")]; ok {
		t.Error("expired identity B was retained at capacity")
	}
	if got := len(r.entries); got != 2 {
		t.Fatalf("registry size after expired eviction = %d, want 2", got)
	}

	// Nothing is expired now. C is most recent, so adding D evicts A.
	now = now.Add(time.Minute)
	d := r.get(newSharedSecretIDCache, "https://d.example", "AKID-D")
	if _, ok := r.entries[hashIdentity("https://a.example", "AKID-A")]; ok {
		t.Error("oldest live identity A was retained at capacity")
	}
	if got := len(r.entries); got != 2 {
		t.Fatalf("registry size after oldest eviction = %d, want 2", got)
	}
	if entry := r.entries[hashIdentity("https://c.example", "AKID-C")]; entry.value != c {
		t.Error("most-recent existing identity C was evicted")
	}
	if entry := r.entries[hashIdentity("https://d.example", "AKID-D")]; entry.value != d {
		t.Error("new identity D was not retained")
	}

	// B was evicted rather than merely hidden; a later lookup creates a new
	// cache instance.
	if got := r.get(newSharedSecretIDCache, "https://b.example", "AKID-B"); got == b {
		t.Error("expired identity B unexpectedly reused its evicted cache")
	}
}

func TestCacheRegistryHashesIdentity(t *testing.T) {
	const (
		endpoint    = "https://sensitive-endpoint.example"
		accessKeyID = "SENSITIVE-ACCESS-KEY"
	)
	r := newRegistry[*secretIDCache]("test")
	r.get(newSharedSecretIDCache, endpoint, accessKeyID)

	if _, ok := r.entries[hashIdentity(endpoint, accessKeyID)]; !ok {
		t.Fatal("registry did not store the expected hashed identity")
	}
	if got := fmt.Sprintf("%v", r.entries); strings.Contains(got, endpoint) || strings.Contains(got, accessKeyID) {
		t.Errorf("registry representation retained raw identity fields: %s", got)
	}
}

func TestCacheRegistryConcurrentBounded(t *testing.T) {
	r := newRegistry[*secretIDCache]("test")
	r.maxEntries = 8
	r.idleTTL = time.Hour

	const (
		goroutines = 64
		operations = 200
	)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(worker int) {
			defer wg.Done()
			for operation := range operations {
				identity := (worker + operation) % 32
				r.get(newSharedSecretIDCache, fmt.Sprintf("https://endpoint-%d.example", identity), fmt.Sprintf("AKID-%d", identity))
			}
		}(i)
	}
	wg.Wait()

	r.mu.Lock()
	defer r.mu.Unlock()
	if got := len(r.entries); got > r.maxEntries {
		t.Errorf("registry size after concurrent churn = %d, want <= %d", got, r.maxEntries)
	}
}

func TestIsSecretIDFormat(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"valid 64-hex", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true},
		{"all zeros", "0000000000000000000000000000000000000000000000000000000000000000", true},
		{"too short", "abc123", false},
		{"too long by one", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", false},
		{"uppercase rejected", "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", false},
		{"contains non-hex", "g12345z789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false},
		{"plain name", "my-secret", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSecretIDFormat(tt.in); got != tt.want {
				t.Errorf("isSecretIDFormat(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestSecretIDCacheGetSetMissExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := newSecretIDCache(10*time.Minute, 30*time.Second)
	cache.now = func() time.Time { return now }

	if _, found, _ := cache.Get("foo"); found {
		t.Fatal("expected cache miss for unset key")
	}

	cache.Set("foo", testSecretID("foo"))
	id, found, negative := cache.Get("foo")
	if !found || negative || id != testSecretID("foo") {
		t.Fatalf("Get() = %q, found=%v, negative=%v; want id-foo,true,false", id, found, negative)
	}

	now = now.Add(11 * time.Minute)
	if _, found, _ := cache.Get("foo"); found {
		t.Fatal("expected cache miss after TTL expiry")
	}
}

func TestSecretIDCacheNegative(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := newSecretIDCache(10*time.Minute, 30*time.Second)
	cache.now = func() time.Time { return now }

	cache.SetNegative("missing")
	id, found, negative := cache.Get("missing")
	if !found || !negative || id != "" {
		t.Fatalf("Get() = %q, found=%v, negative=%v; want \"\",true,true", id, found, negative)
	}

	now = now.Add(31 * time.Second)
	if _, found, _ := cache.Get("missing"); found {
		t.Fatal("expected negative entry to expire after negTTL")
	}
}

func TestSecretIDCacheInvalidate(t *testing.T) {
	cache := newSecretIDCache(10*time.Minute, 30*time.Second)
	cache.Set("foo", testSecretID("foo"))
	cache.Invalidate("foo")
	if _, found, _ := cache.Get("foo"); found {
		t.Fatal("expected cache miss after Invalidate")
	}
}

// TestSecretIDCacheInvalidatePositiveKeepsNegativeEntries pins what the write
// index relies on when it drops its observed names: a plain absence and a
// tombstone are later verdicts from the read path and survive, only a live
// mapping goes.
func TestSecretIDCacheInvalidatePositiveKeepsNegativeEntries(t *testing.T) {
	cache := newSecretIDCache(10*time.Minute, 30*time.Second)
	cache.Set("live", testSecretID("live"))
	cache.SetNegative("absent")
	cache.SetTombstoned("revoked", testSecretID("revoked"))

	for _, name := range []string{"live", "absent", "revoked", "unknown"} {
		cache.InvalidatePositive(name)
	}

	if _, found, _ := cache.Get("live"); found {
		t.Error("InvalidatePositive kept the live mapping")
	}
	if _, found, negative := cache.Get("absent"); !found || !negative {
		t.Error("InvalidatePositive dropped the plain negative entry")
	}
	if id, found, negative := cache.Get("revoked"); !found || !negative || id != testSecretID("revoked") {
		t.Errorf("InvalidatePositive dropped the tombstone: (%q, %v, %v)", id, found, negative)
	}
}

func TestSecretIDCacheInvalidateByID(t *testing.T) {
	cache := newSecretIDCache(10*time.Minute, 30*time.Second)
	cache.Set("alias-one", testSecretID("dead"))
	cache.Set("alias-two", testSecretID("dead"))
	cache.Set("survivor", testSecretID("live"))
	cache.SetNegative("missing")

	cache.InvalidateByID(testSecretID("dead"))

	for _, name := range []string{"alias-one", "alias-two"} {
		if _, found, _ := cache.Get(name); found {
			t.Errorf("Get(%q) still found after InvalidateByID", name)
		}
	}
	if id, found, _ := cache.Get("survivor"); !found || id != testSecretID("live") {
		t.Errorf("Get(survivor) = (%q, %v), want (live-id, true)", id, found)
	}
	// A plain absence carries an empty secretID, and InvalidateByID refuses an
	// empty id outright, so nothing can sweep the negative entries wholesale.
	cache.InvalidateByID("")
	if _, found, negative := cache.Get("missing"); !found || !negative {
		t.Error("negative entry should survive InvalidateByID")
	}
}

// TestSecretIDCacheInvalidateByIDClearsTombstones pins the half of
// InvalidateByID that a tombstone made reachable. A tombstone is the only
// negative entry that carries an ID, so a caller saying "this ID is dead" has
// to be able to clear it; the alternative leaves a metadata read resolving a
// name to a secret the same reconcile already proved gone.
func TestSecretIDCacheInvalidateByIDClearsTombstones(t *testing.T) {
	cache := newSecretIDCache(10*time.Minute, 30*time.Second)
	cache.SetTombstoned("revoked", testSecretID("dead"))
	cache.SetNegative("never-existed")

	cache.InvalidateByID(testSecretID("dead"))

	if _, found, _ := cache.Get("revoked"); found {
		t.Error("Get(revoked) still found: the tombstone survived InvalidateByID")
	}
	// Untouched: it points at no ID, so no ID-keyed sweep concerns it.
	if _, found, negative := cache.Get("never-existed"); !found || !negative {
		t.Error("a plain absence should survive a sweep for an unrelated ID")
	}
}

func TestSecretIDCacheLazyEvictionOnGet(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := newSecretIDCache(10*time.Minute, 30*time.Second)
	cache.now = func() time.Time { return now }

	cache.Set("foo", testSecretID("foo"))
	if got := len(cache.entries); got != 1 {
		t.Fatalf("entries before expiry = %d, want 1", got)
	}

	// Advance past TTL and trigger Get to evict.
	now = now.Add(11 * time.Minute)
	if _, found, _ := cache.Get("foo"); found {
		t.Fatal("expected cache miss after TTL")
	}
	if got := len(cache.entries); got != 0 {
		t.Errorf("entries after lazy eviction = %d, want 0", got)
	}
}

// Get reads the clock twice when the entry it read is expired: once with no
// lock held, to find it expired, and once under the write lock, to decide
// whether to evict. A Set that lands between the two must be returned, not
// reported as a miss that costs the caller a listing; a SetNegative is
// returned as the absence it records; and an Invalidate that lands there
// leaves nothing to evict. The clock hook plays the other
// goroutine: its first call, made while Get holds no lock, performs the
// other write and reports the old entry expired; every later call (the one
// inside a Set and the one under Get's write lock) reports the base time, at
// which a replacement is live.
func TestSecretIDCacheGetSeesAWriteThatLandedWhileItTookTheLock(t *testing.T) {
	base := time.Unix(1000, 0)
	cases := []struct {
		name         string
		meanwhile    func(*secretIDCache)
		wantID       string
		wantFound    bool
		wantNegative bool
		wantLen      int
	}{
		{
			name:      "a Set is returned",
			meanwhile: func(c *secretIDCache) { c.Set("foo", testSecretID("new")) },
			wantID:    testSecretID("new"),
			wantFound: true,
			wantLen:   1,
		},
		{
			name:         "a SetNegative is returned as an absence",
			meanwhile:    func(c *secretIDCache) { c.SetNegative("foo") },
			wantFound:    true,
			wantNegative: true,
			wantLen:      1,
		},
		{
			name:      "an Invalidate is a miss with nothing left to evict",
			meanwhile: func(c *secretIDCache) { c.Invalidate("foo") },
			wantLen:   0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache := newSecretIDCache(10*time.Minute, 30*time.Second)
			cache.now = func() time.Time { return base }
			cache.Set("foo", testSecretID("old"))

			calls := 0
			cache.now = func() time.Time {
				calls++
				if calls == 1 {
					tc.meanwhile(cache)
					return base.Add(11 * time.Minute)
				}
				return base
			}

			id, found, negative := cache.Get("foo")
			if found != tc.wantFound || negative != tc.wantNegative || id != tc.wantID {
				t.Fatalf("Get = (%q, %v, %v), want (%q, %v, %v)",
					id, found, negative, tc.wantID, tc.wantFound, tc.wantNegative)
			}
			if got := cache.Len(); got != tc.wantLen {
				t.Errorf("entries after Get = %d, want %d", got, tc.wantLen)
			}
		})
	}
}

func TestSecretIDCacheDefaults(t *testing.T) {
	cache := newSecretIDCache(0, 0)
	if cache.ttl != DefaultCacheTTL {
		t.Errorf("ttl = %v, want %v", cache.ttl, DefaultCacheTTL)
	}
	if cache.negTTL != DefaultCacheNegativeTTL {
		t.Errorf("negTTL = %v, want %v", cache.negTTL, DefaultCacheNegativeTTL)
	}
}

// TestCacheTTLsAreTheDocumentedOnes pins the literals rather than the
// constants. Comparing a constant to itself passes whatever the value is, so
// such a check stays green while the provider docs say something else; the TTLs
// are user-visible behavior (how long an externally created secret stays
// unnoticed) and docs/provider/ncloud.md quotes them.
func TestCacheTTLsAreTheDocumentedOnes(t *testing.T) {
	if DefaultCacheTTL != 15*time.Minute {
		t.Errorf("DefaultCacheTTL = %v, want 15m (docs/provider/ncloud.md)", DefaultCacheTTL)
	}
	if DefaultCacheNegativeTTL != 5*time.Minute {
		t.Errorf("DefaultCacheNegativeTTL = %v, want 5m (docs/provider/ncloud.md)", DefaultCacheNegativeTTL)
	}
}

func TestSecretIDCacheNegativeOverwritesPositive(t *testing.T) {
	cache := newSecretIDCache(10*time.Minute, 30*time.Second)
	cache.Set("foo", testSecretID("foo"))
	cache.SetNegative("foo")
	id, found, negative := cache.Get("foo")
	if !found || !negative || id != "" {
		t.Fatalf("Get() = %q, found=%v, negative=%v; want \"\",true,true", id, found, negative)
	}
}

func TestSecretIDCacheOverwriteAtCapacityKeepsEntries(t *testing.T) {
	cache := newSecretIDCache(10*time.Minute, 30*time.Second)
	cache.maxEntries = 2

	cache.Set("aaa", testSecretID("a"))
	cache.Set("bbb", testSecretID("b"))
	// Refreshing an existing key at capacity must not trigger the reset -
	// the map does not grow on overwrite.
	cache.Set("aaa", testSecretID("a2"))

	if id, found, _ := cache.Get("aaa"); !found || id != testSecretID("a2") {
		t.Errorf(`Get("aaa") = %q, found=%v; want refreshed id-a2`, id, found)
	}
	if _, found, _ := cache.Get("bbb"); !found {
		t.Error(`Get("bbb") lost after overwrite of "aaa" at capacity; reset must not fire on overwrites`)
	}
}

// TestSecretIDCacheResetKeepsAnOlderSweepFromRecordingAbsence pins that a full
// reset, which drops whatever was written while a sweep ran, also drops that
// sweep's absence verdict: the create's mapping it would have been compared
// with is gone, and the negative would answer every read for the negative TTL.
func TestSecretIDCacheResetKeepsAnOlderSweepFromRecordingAbsence(t *testing.T) {
	cache := newSecretIDCache(10*time.Minute, 30*time.Second)
	cache.maxEntries = 2

	cache.Set("aaa", testSecretID("a"))
	since := cache.Seq()                    // a sweep for db-cred begins
	cache.Set("db-cred", testSecretID("d")) // a create lands meanwhile
	cache.Set("ccc", testSecretID("c"))     // the cache is full: the whole map is dropped
	cache.SetNegativeSince("db-cred", since)
	if _, found, negative := cache.Get("db-cred"); found && negative {
		t.Error("a sweep that began before the reset recorded an absence for a name created meanwhile")
	}

	// A sweep that began after the reset still records its absence.
	cache.SetNegativeSince("db-cred", cache.Seq())
	if _, found, negative := cache.Get("db-cred"); !found || !negative {
		t.Error("a sweep that began after the reset did not record its absence")
	}
}

func TestSecretIDCacheBoundedGrowth(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := newSecretIDCache(10*time.Minute, 30*time.Second)
	cache.now = func() time.Time { return now }
	cache.maxEntries = 4

	// Fill to capacity with live entries; the next Set must not grow the map
	// past the bound - with everything live, the whole map is dropped.
	for i := range 4 {
		cache.Set(fmt.Sprintf("live-%d", i), testSecretID("x"))
	}
	cache.Set("one-more", testSecretID("x"))
	if got := len(cache.entries); got > 4 {
		t.Errorf("entries = %d, want <= 4 (bounded)", got)
	}
	if _, found, _ := cache.Get("one-more"); !found {
		t.Error("the entry written after the reset must be present")
	}

	// Refill to capacity from empty, expire everything, and confirm the sweep
	// path removes the expired entries without a full reset.
	cache.Invalidate("one-more")
	for i := range 4 {
		cache.Set(fmt.Sprintf("stale-%d", i), testSecretID("x"))
	}
	now = now.Add(11 * time.Minute) // all entries above are now expired
	cache.Set("fresh", testSecretID("x"))
	if got := len(cache.entries); got != 1 {
		t.Errorf("entries after expired sweep = %d, want 1 (only the fresh insert)", got)
	}
	if _, found, _ := cache.Get("fresh"); !found {
		t.Error("fresh entry must survive the sweep")
	}
}

// TestSecretIDCacheConcurrent asserts nothing itself: it fails only under the
// race detector, which make test enables, or on a deadlock.
func TestSecretIDCacheConcurrent(t *testing.T) {
	cache := newSecretIDCache(time.Minute, time.Second)
	const goroutines = 50
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("name-%d", id%10)
			for j := range opsPerGoroutine {
				cache.Set(name, testSecretID(fmt.Sprint(id)))
				cache.Get(name)
				if j%5 == 0 {
					cache.Invalidate(name)
				}
				if j%7 == 0 {
					cache.SetNegative(name)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestCacheRegistrySweepsIdleEntriesBelowCapacity(t *testing.T) {
	// A switched-role source holds its base pair, so an identity nobody has
	// asked for within the idle TTL must leave on the next lookup, whether or
	// not the registry is anywhere near its cap.
	now := time.Unix(1000, 0)
	r := newRegistry[*secretIDCache]("test")
	r.idleTTL = 10 * time.Minute
	r.now = func() time.Time { return now }

	r.get(newSharedSecretIDCache, "https://a.example", "AKID-A")
	now = now.Add(11 * time.Minute)
	b := r.get(newSharedSecretIDCache, "https://b.example", "AKID-B")
	if got := len(r.entries); got != 1 {
		t.Fatalf("registry size after an idle entry expired = %d, want 1 (only B)", got)
	}

	// The identity being looked up is refreshed, not removed.
	now = now.Add(11 * time.Minute)
	if got := r.get(newSharedSecretIDCache, "https://b.example", "AKID-B"); got != b {
		t.Error("the identity being looked up was swept and rebuilt instead of refreshed")
	}
}

func TestCacheRegistryLogsEvictionsOfLiveIdentitiesAtAnInterval(t *testing.T) {
	now := time.Unix(1000, 0)
	r := newRegistry[*secretIDCache]("test")
	r.maxEntries = 2
	r.now = func() time.Time { return now }
	type logged struct{ evicted, capacity int }
	var lines []logged
	r.logEviction = func(name string, evicted, capacity, _ int) {
		if name != "test" {
			t.Errorf("eviction logged for registry %q, want %q", name, "test")
		}
		lines = append(lines, logged{evicted, capacity})
	}

	r.get(newSharedSecretIDCache, "https://ep", "A")
	r.get(newSharedSecretIDCache, "https://ep", "B")
	if len(lines) != 0 {
		t.Fatalf("logged %v below capacity, want nothing", lines)
	}
	r.get(newSharedSecretIDCache, "https://ep", "C")
	now = now.Add(time.Minute)
	r.get(newSharedSecretIDCache, "https://ep", "D")
	if want := []logged{{1, 2}}; !slices.Equal(lines, want) {
		t.Fatalf("lines after two evictions a minute apart = %v, want %v (the second held back)", lines, want)
	}
	now = now.Add(registryEvictionLogInterval)
	r.get(newSharedSecretIDCache, "https://ep", "E")
	if want := []logged{{1, 2}, {2, 2}}; !slices.Equal(lines, want) {
		t.Fatalf("lines after the interval = %v, want %v (the held-back eviction counted)", lines, want)
	}
}

func TestCacheRegistryKeepsSeveralHundredIdentitiesUsedInTurn(t *testing.T) {
	// Stores used in turn defeat least-recently-used eviction: past the cap,
	// every lookup evicts the identity needed next. A cluster with a key per
	// team must stay below the default cap.
	r := newRegistry[*secretIDCache]("test")
	r.logEviction = func(string, int, int, int) { t.Error("evicted an identity still in use") }
	const identities = 500
	first := make([]*secretIDCache, identities)
	for i := range first {
		first[i] = r.get(newSharedSecretIDCache, "https://ep", fmt.Sprintf("key-%d", i))
	}
	for i := range first {
		if r.get(newSharedSecretIDCache, "https://ep", fmt.Sprintf("key-%d", i)) != first[i] {
			t.Fatalf("identity %d was rebuilt on its second use", i)
		}
	}
}

func TestSecretIDCacheDropsNamesTheAPICouldNotHaveAccepted(t *testing.T) {
	// A listing from an endpoint the store author controls can carry names of
	// any length; the cache must not let the server size its entries.
	c := newSharedSecretIDCache()
	long := strings.Repeat("a", 4096)
	c.Set(long, testSecretID("x"))
	c.SetNegative(long + "b")
	c.SetTombstoned(long+"c", testSecretID("x"))
	if got := len(c.entries); got != 0 {
		t.Fatalf("cache holds %d entries for names the API could not accept, want 0", got)
	}
	// The ID is the other half of an entry the server sizes.
	c.Set("db-cred", strings.Repeat("a", 4<<20))
	c.Set("db-cred", "id-1")
	c.SetTombstoned("db-cred", strings.Repeat("a", 4<<20))
	c.SetTombstoned("db-cred", "")
	if got := len(c.entries); got != 0 {
		t.Fatalf("cache holds %d entries for IDs the API could not have issued, want 0", got)
	}
	c.Set("db-cred", testSecretID("x"))
	if _, found, _ := c.Get("db-cred"); !found {
		t.Error("a valid name and ID were not cached")
	}
	c.SetTombstoned("db-cred", testSecretID("x"))
	if _, found, negative := c.Get("db-cred"); !found || !negative {
		t.Error("a valid tombstone was not cached")
	}
}

func TestCacheRegistryLogsEvictionsWithoutHoldingTheRegistry(t *testing.T) {
	r := newRegistry[*secretIDCache]("test")
	r.maxEntries = 1
	logged := false
	r.logEviction = func(string, int, int, int) {
		// TryLock fails while get still holds r.mu.
		if !r.mu.TryLock() {
			t.Error("eviction logged with the registry lock held")
			return
		}
		r.mu.Unlock()
		logged = true
	}
	r.get(newSharedSecretIDCache, "https://ep", "A")
	r.get(newSharedSecretIDCache, "https://ep", "B")
	if !logged {
		t.Fatal("the eviction was not logged")
	}
}

func TestCacheRegistryEvictsIdentitiesOverTheEntryBudget(t *testing.T) {
	// The identity cap alone leaves a worst case of that many full caches;
	// the entry budget bounds their sum, evicting least recently used
	// identities, never the one being looked up.
	r := newRegistry[*secretIDCache]("test")
	r.weigh, r.maxWeight = (*secretIDCache).Len, 5
	evicted := 0
	r.logEviction = func(_ string, n, _, budget int) {
		evicted += n
		if budget != 5 {
			t.Errorf("logged budget = %d, want 5", budget)
		}
	}
	fill := func(c *secretIDCache, n int) {
		for i := range n {
			c.Set(fmt.Sprintf("name%d", i), testSecretID(fmt.Sprint(i)))
		}
	}

	a := r.get(newSharedSecretIDCache, "https://ep", "A")
	fill(a, 4)
	b := r.get(newSharedSecretIDCache, "https://ep", "B")
	fill(b, 4)
	// 8 entries over a budget of 5: the next lookup evicts the least
	// recently used identity, A, and keeps the one being looked up.
	if r.get(newSharedSecretIDCache, "https://ep", "B") != b {
		t.Fatal("the identity being looked up was evicted")
	}
	if r.get(newSharedSecretIDCache, "https://ep", "A") == a {
		t.Error("the least recently used identity survived the entry budget")
	}
	if evicted != 1 {
		t.Errorf("evictions logged = %d, want 1", evicted)
	}

	// One identity over the budget by itself is kept: there is nothing else
	// to evict, and evicting it would only rebuild it on the next lookup.
	c := r.get(newSharedSecretIDCache, "https://ep", "C")
	fill(c, 10)
	if r.get(newSharedSecretIDCache, "https://ep", "C") != c {
		t.Error("an identity over the budget on its own was evicted")
	}
	if got := len(r.entries); got != 1 {
		t.Errorf("identities left = %d, want 1 (the others gave way to the budget)", got)
	}
}
