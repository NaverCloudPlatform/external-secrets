// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"crypto/sha256"
	"encoding/binary"
	"regexp"
	"strings"
	"sync"
	"time"

	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

// Hand-written rather than runtime's expirable.LRU because three things change
// a verdict, not a cost: a per-Client LRU dies with the Client, which is built
// per reconcile, so it would never save a sweep; "not found" needs a shorter
// TTL than a positive mapping, because a stale absence deletes a Kubernetes
// Secret while a stale mapping only 404s; and a tombstone must keep its ID for
// metadata reads and be purged by ID when the secret is destroyed.

// Default TTL values for the secret name -> ID cache.
const (
	DefaultCacheTTL = 15 * time.Minute

	// A negative entry records that a full sweep did not find the name.
	// Without it every retry costs another sweep, and a REVOKE secret would be
	// re-swept for 7 days. Kept well under DefaultCacheTTL because absence is the
	// verdict that does damage when wrong, and under the 1h default
	// refreshInterval.
	DefaultCacheNegativeTTL = 5 * time.Minute

	// defaultCacheMaxEntries bounds the name -> ID cache. One entry is a map
	// key plus a small struct, so 10k entries stay in the low megabytes while
	// covering far more secrets than a store realistically holds.
	defaultCacheMaxEntries = 10_000

	// defaultCacheRegistryMaxEntries bounds the identities retained
	// process-wide: a controller may see attacker-controlled SecretStore objects
	// over its life, so the registry is bounded like each per-store cache.
	// Entries are bounded in size too (names and IDs are refused unless they fit
	// the API's forms), and defaultCacheRegistryMaxWeight bounds their total.
	// Stores used in turn by more identities than this evict each other; that
	// is logged.
	defaultCacheRegistryMaxEntries = 1024

	// defaultCacheRegistryMaxWeight bounds the entries held across every
	// identity's cache together. The identity cap alone leaves a worst case of
	// that many full caches, about 2 GB, which a store author who controls the
	// endpoint and can mint key pairs could fill; this budget keeps it near
	// 50 MB. Past it, the least recently used identities are evicted, which is
	// logged like an eviction at capacity. The budget is enforced at lookup
	// (registry.get), not on every write: between lookups, the caches already
	// handed out grow on their own, each to defaultCacheMaxEntries at most, so
	// the bound holds at every lookup plus that much per Client in flight.
	defaultCacheRegistryMaxWeight = 200_000

	// registryEvictionLogInterval spaces the line reporting identities
	// evicted at capacity, so a registry evicting on every lookup logs a
	// count every few minutes rather than a line per reconcile.
	registryEvictionLogInterval = 10 * time.Minute

	// A registry entry not requested for this long is dropped on the next
	// lookup of any identity, not only when the registry is full: a
	// switched-role source holds its base pair, and a rotated or deleted
	// store's pair must not stay in memory for the life of the process. It
	// equals the longest per-entry cache TTL, so evicting cannot discard a
	// positive mapping a new client could still reuse.
	defaultCacheRegistryIdleTTL = DefaultCacheTTL
)

// sharedCacheRegistry holds one secret name -> ID cache per (endpoint,
// credential identity). It is process-scoped so the caches outlive the
// per-reconcile client churn (the ESO controller rebuilds the client every
// reconcile), which is what lets a name -> ID mapping be reused across
// reconciles instead of re-running a full ListSecrets sweep every time.
var sharedCacheRegistry = func() *registry[*secretIDCache] {
	r := newRegistry[*secretIDCache]("secret name cache")
	r.weigh, r.maxWeight = (*secretIDCache).Len, defaultCacheRegistryMaxWeight
	return r
}()

// newSharedSecretIDCache is what the registry builds for an identity it has
// not seen before.
func newSharedSecretIDCache() *secretIDCache {
	return newSecretIDCache(DefaultCacheTTL, DefaultCacheNegativeTTL)
}

// registry maps a hashed identity to a value shared by every client built for
// that identity: the secret name -> ID cache, keyed by (endpoint, credential
// identity), and the switched-role credential sources, keyed by (STS endpoint,
// role, base identity). Only name -> ID metadata and key pairs are held, never
// secret values. Hashing keeps endpoint and key strings out of the
// process-global map; the entry cap keeps it from growing as stores churn.
type registry[T any] struct {
	mu         sync.Mutex
	entries    map[registryKey]registryEntry[T]
	maxEntries int
	idleTTL    time.Duration
	now        func() time.Time
	recency    uint64

	// name says which registry an eviction line is about. evicted counts
	// identities evicted at capacity since evictionLoggedAt, when
	// logEviction last reported.
	name             string
	evicted          int
	evictionLoggedAt time.Time
	logEviction      func(name string, evicted, capacity, budget int)

	// weigh sizes a value and maxWeight bounds the sum over every entry; a
	// nil weigh leaves the sum unchecked. The switched-role registry holds
	// one pair per identity and sets neither.
	weigh     func(T) int
	maxWeight int
}

type registryKey [sha256.Size]byte

type registryEntry[T any] struct {
	value    T
	lastUsed time.Time
	recency  uint64
}

func newRegistry[T any](name string) *registry[T] {
	return &registry[T]{
		entries:     make(map[registryKey]registryEntry[T]),
		maxEntries:  defaultCacheRegistryMaxEntries,
		idleTTL:     defaultCacheRegistryIdleTTL,
		now:         time.Now,
		name:        name,
		logEviction: logRegistryEviction,
	}
}

// logRegistryEviction reports identities evicted while still in use. It goes
// to the package logger, not a reconcile's: the registry is reached from
// NewClient, which has no context, and the eviction is about the process.
func logRegistryEviction(name string, evicted, capacity, budget int) {
	ctrllog.Log.WithName("provider").WithName("ncloud").WithName("secretmanager").Info(
		"a process-wide registry is over its identity cap or entry budget and evicted identities still in use; each costs a full listing or a role switch on its next use",
		"registry", name, "evicted", evicted, "capacity", capacity, "entryBudget", budget)
}

// get returns the value for identity, building it with construct on first use.
// The first part of an identity is an endpoint; see hashIdentity.
func (r *registry[T]) get(construct func() T, identity ...string) T {
	key := hashIdentity(identity...)

	// Deferred before the unlock, so it runs after it: the logger is not
	// called with the registry held.
	var report func()
	defer func() {
		if report != nil {
			report()
		}
	}()
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.entries == nil {
		r.entries = make(map[registryKey]registryEntry[T])
	}

	// Pick the clock before reading it. newRegistry always sets r.now; the nil
	// case is a zero-value registry, which only a test can construct.
	clock := r.now
	if clock == nil {
		clock = time.Now
	}
	now := clock()
	r.recency++

	idleTTL := r.idleTTL
	if idleTTL <= 0 {
		idleTTL = defaultCacheRegistryIdleTTL
	}
	r.sweepIdleLocked(now, idleTTL, key)

	maxEntries := r.maxEntries
	if maxEntries <= 0 {
		maxEntries = defaultCacheRegistryMaxEntries
	}
	var value T
	if entry, ok := r.entries[key]; ok {
		entry.lastUsed = now
		entry.recency = r.recency
		r.entries[key] = entry
		value = entry.value
	} else {
		r.evictAtCapacityLocked(maxEntries, key)
		value = construct()
		r.entries[key] = registryEntry[T]{
			value:    value,
			lastUsed: now,
			recency:  r.recency,
		}
	}
	// Values grow between lookups, so the entry budget is checked on every
	// lookup, not only when an identity is added.
	r.evictOverWeightLocked(key)
	report = r.evictionLineLocked(now, maxEntries)
	return value
}

// sweepIdleLocked removes every identity not requested within idleTTL, except
// the one being looked up right now, whose entry the caller is about to
// refresh. At most defaultCacheRegistryMaxEntries entries, so it runs on every
// lookup. Callers must hold r.mu.
func (r *registry[T]) sweepIdleLocked(now time.Time, idleTTL time.Duration, keep registryKey) {
	for key, entry := range r.entries {
		if key != keep && !now.Before(entry.lastUsed.Add(idleTTL)) {
			delete(r.entries, key)
		}
	}
}

// evictAtCapacityLocked makes room for one new identity when every remaining
// entry is live: the least recently requested identity is evicted, and
// counted for the eviction log line. Callers must hold r.mu and have run
// sweepIdleLocked first, so every entry left is one still in use.
func (r *registry[T]) evictAtCapacityLocked(maxEntries int, adding registryKey) {
	if len(r.entries) < maxEntries {
		return
	}
	if key, ok := r.leastRecentLocked(adding); ok {
		delete(r.entries, key)
		r.evicted++
	}
}

// evictOverWeightLocked evicts the least recently requested identities, never
// keep, until the entries held across every value fit maxWeight. Callers
// must hold r.mu.
func (r *registry[T]) evictOverWeightLocked(keep registryKey) {
	if r.weigh == nil || r.maxWeight <= 0 {
		return
	}
	total := 0
	weights := make(map[registryKey]int, len(r.entries))
	for key, entry := range r.entries {
		weights[key] = r.weigh(entry.value)
		total += weights[key]
	}
	for total > r.maxWeight && len(r.entries) > 1 {
		key, ok := r.leastRecentLocked(keep)
		if !ok {
			return
		}
		total -= weights[key]
		delete(r.entries, key)
		r.evicted++
	}
}

// leastRecentLocked returns the least recently requested identity other than
// except. Callers must hold r.mu.
func (r *registry[T]) leastRecentLocked(except registryKey) (registryKey, bool) {
	var (
		oldestKey     registryKey
		oldestRecency uint64
		found         bool
	)
	for key, entry := range r.entries {
		if key == except {
			continue
		}
		if !found || entry.recency < oldestRecency {
			oldestKey, oldestRecency, found = key, entry.recency, true
		}
	}
	return oldestKey, found
}

// evictionLineLocked returns the log line for the evictions counted since the
// last one, to be written once r.mu is released, or nil while nothing was
// evicted or the interval has not passed. Callers must hold r.mu.
func (r *registry[T]) evictionLineLocked(now time.Time, maxEntries int) func() {
	if r.evicted == 0 || r.logEviction == nil ||
		(!r.evictionLoggedAt.IsZero() && now.Before(r.evictionLoggedAt.Add(registryEvictionLogInterval))) {
		return nil
	}
	logEviction, name, evicted, budget := r.logEviction, r.name, r.evicted, r.maxWeight
	r.evicted, r.evictionLoggedAt = 0, now
	return func() { logEviction(name, evicted, maxEntries, budget) }
}

// hashIdentity hashes length-delimited identity parts. Length delimiters make
// distinct tuples unambiguous even if a part contains separator bytes.
func hashIdentity(parts ...string) registryKey {
	hash := sha256.New()
	var length [8]byte

	for i, part := range parts {
		if i == 0 {
			// The first part is an endpoint. Production construction accepts
			// trailing slashes as a normalized form of the same endpoint;
			// hash that canonical identity so equivalent configurations
			// share one cross-reconcile value.
			part = strings.TrimRight(part, "/")
		}
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(part))
	}

	var key registryKey
	copy(key[:], hash.Sum(nil))
	return key
}

// secretIDPattern matches Ncloud secret IDs (64-character lowercase hex).
var secretIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// isSecretIDFormat reports whether s has the form of an Ncloud secret ID
// rather than a name. Ncloud secret IDs are 64-character lowercase hex
// strings.
func isSecretIDFormat(s string) bool {
	return secretIDPattern.MatchString(s)
}

// secretIDCache caches secret name -> secret ID mappings with TTL.
// Only metadata mappings are cached; secret values are always fetched fresh.
// It is safe for concurrent use.
type secretIDCache struct {
	mu         sync.RWMutex
	entries    map[string]cacheEntry
	ttl        time.Duration
	negTTL     time.Duration
	maxEntries int
	now        func() time.Time
	seq        uint64 // advanced by every write; see Seq
	resetSeq   uint64 // seq when evictIfFullLocked last dropped the whole map
}

type cacheEntry struct {
	secretID  string
	negative  bool
	expiresAt time.Time
	seq       uint64 // the cache's write sequence when the entry was written
}

// newSecretIDCache creates a cache with the given TTLs.
// Non-positive ttl or negTTL fall back to the package defaults.
func newSecretIDCache(ttl, negTTL time.Duration) *secretIDCache {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	if negTTL <= 0 {
		negTTL = DefaultCacheNegativeTTL
	}
	return &secretIDCache{
		entries:    make(map[string]cacheEntry),
		ttl:        ttl,
		negTTL:     negTTL,
		maxEntries: defaultCacheMaxEntries,
		now:        time.Now,
	}
}

// evictIfFullLocked keeps the cache bounded. At capacity it first drops all
// expired entries; if the cache is still full of live entries it drops the
// whole map - the cache is a best-effort optimization, and a rare full reset
// costs one extra ListSecrets sweep, whereas unbounded growth costs memory
// forever. Callers must hold c.mu.
func (c *secretIDCache) evictIfFullLocked(name string) {
	if len(c.entries) < c.maxEntries {
		return
	}
	// Overwriting an existing key does not grow the map, so a full cache can still
	// refresh known entries without triggering a purge or reset.
	if _, exists := c.entries[name]; exists {
		return
	}
	now := c.now()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) >= c.maxEntries {
		c.entries = make(map[string]cacheEntry)
		c.resetSeq = c.seq
	}
}

// Get returns the cached secret ID for name.
// found is true when a non-expired entry exists; negative marks "not found" entries.
// Expired entries are evicted lazily to bound memory growth.
func (c *secretIDCache) Get(name string) (id string, found, negative bool) {
	c.mu.RLock()
	entry, ok := c.entries[name]
	c.mu.RUnlock()

	if !ok {
		return "", false, false
	}

	if c.now().After(entry.expiresAt) {
		c.mu.Lock()
		defer c.mu.Unlock()
		// Re-check under the write lock: a Set or SetNegative may have
		// replaced the entry since the read above. A live replacement is
		// returned, not evicted, and only an entry still expired is dropped.
		e, ok := c.entries[name]
		if !ok {
			return "", false, false
		}
		if c.now().After(e.expiresAt) {
			delete(c.entries, name)
			return "", false, false
		}
		return e.secretID, true, e.negative
	}

	return entry.secretID, true, entry.negative
}

// Len reports the number of entries, expired ones included.
func (c *secretIDCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Set stores a positive entry. It and the other writers drop a name the API
// could not have accepted or an ID not in the form the API issues: listing
// rows come from an endpoint a store author may control, and the cache bounds
// entry count, not entry size. Such keys could never be looked up anyway.
func (c *secretIDCache) Set(name, id string) {
	if !secretNamePattern.MatchString(name) || !isSecretIDFormat(id) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictIfFullLocked(name)
	c.seq++
	c.entries[name] = cacheEntry{
		secretID:  id,
		expiresAt: c.now().Add(c.ttl),
		seq:       c.seq,
	}
}

// Seq returns the cache's write sequence, which every writer advances. A
// caller about to conclude absence from a listing reads it before the first
// page and hands it to SetNegativeSince, so a mapping written while the sweep
// ran is not overruled by a sweep that could not have seen the secret.
func (c *secretIDCache) Seq() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.seq
}

// SetNegative stores a negative cache entry indicating the name was not found.
func (c *secretIDCache) SetNegative(name string) {
	if !secretNamePattern.MatchString(name) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setNegativeLocked(name)
}

// SetNegativeSince is SetNegative for an absence concluded from a listing
// that began at write sequence since (see Seq): it leaves an entry written
// after that point alone. A create in this process can land between the
// server computing a sweep's last page and the sweep's verdict, and the
// verdict would otherwise replace the create's mapping with an absence that
// answers every read for the negative TTL. A full reset since then may have
// dropped such a mapping, leaving nothing to compare against, so the verdict
// is not recorded either.
//
// The guard sees one cache. When the registry evicts an identity, a Client
// still holding the old cache and the next lookup's new cache no longer share
// a sequence, so a create recorded in the old one cannot stop an absence
// recorded in the new one; that costs one false absence for the negative TTL
// and needs an identity evicted while its reconcile is in flight.
func (c *secretIDCache) SetNegativeSince(name string, since uint64) {
	if !secretNamePattern.MatchString(name) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.resetSeq > since {
		return
	}
	if entry, ok := c.entries[name]; ok && entry.seq > since {
		return
	}
	c.setNegativeLocked(name)
}

func (c *secretIDCache) setNegativeLocked(name string) {
	c.evictIfFullLocked(name)
	c.seq++
	c.entries[name] = cacheEntry{
		negative:  true,
		expiresAt: c.now().Add(c.negTTL),
		seq:       c.seq,
	}
}

// SetTombstoned records that name resolves to a secret whose VALUE cannot be
// read because it entered a deletion lifecycle state. It is a negative entry
// for every value read, exactly like SetNegative, but it keeps the ID: Ncloud
// still answers Get Secret Detail for a REVOKE secret, so a metadata read can
// use the mapping instead of re-deriving it with a full listing sweep.
func (c *secretIDCache) SetTombstoned(name, id string) {
	if !secretNamePattern.MatchString(name) || !isSecretIDFormat(id) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictIfFullLocked(name)
	c.seq++
	c.entries[name] = cacheEntry{
		secretID:  id,
		negative:  true,
		expiresAt: c.now().Add(c.negTTL),
		seq:       c.seq,
	}
}

// Invalidate removes any cache entry for name.
func (c *secretIDCache) Invalidate(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, name)
}

// InvalidatePositive removes the entry for name unless it is a negative entry
// or a tombstone, which record a later verdict than a mapping a listing page
// gave.
func (c *secretIDCache) InvalidatePositive(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[name]; ok && !entry.negative {
		delete(c.entries, name)
	}
}

// InvalidateByID removes every name -> id mapping that points at id. Needed
// when a secret is deleted by its ID: the entries are name-keyed, so
// Invalidate(id) alone would leave the name entry pointing at the destroyed
// secret. Deletions are rare, so a linear pass under the write lock is fine.
//
// Tombstones are cleared too. They are negative entries that carry an ID
// (SetTombstoned), so a caller asserting "this ID is dead" has to be able to
// reach them. A plain absence holds no ID, and an empty id is refused outright,
// so no caller can wipe the negative entries wholesale.
func (c *secretIDCache) InvalidateByID(id string) {
	if id == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, e := range c.entries {
		if e.secretID == id {
			delete(c.entries, name)
		}
	}
}
