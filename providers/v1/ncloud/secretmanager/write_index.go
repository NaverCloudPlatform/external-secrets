// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"context"
	"fmt"
	"sync"
)

// writeIndex is the write path's view of the listing: the name -> ID pairs one
// reconcile has read so far, and how far and how reliably it read them. The
// controller builds a Client per reconcile and calls SecretExists, PushSecret
// and DeleteSecret once per PushSecret entry; each needs a FRESH resolution
// (the shared TTL cache must not route writes), which without sharing costs a
// full sweep per entry. The index shares pages across the keys of one Client
// with per-key early exit. Creating many new names is still the expensive
// case: a multi-page absence is confirmed by a second sweep, and
// createSecretLocked re-sweeps under the name lock because an index filled
// before the lock cannot rule out a competing creator.
//
// Methods starting with a capital letter take mu; the others expect the
// caller to hold it. The zero value is ready to use.
type writeIndex struct {
	mu sync.Mutex

	names    map[string]string // name -> id from pages fetched so far
	nextPage int               // next 1-based page to fetch; -1 = exhausted
	sweep    listSweep         // pagination stability of the index's sweep

	// pinned marks the entries this reconcile pinned by creating their secret
	// under the name lock. Those survive a re-sweep, both because the index
	// does not assume that a listing already shows a secret created moments
	// earlier, and because every later operation on that name in this
	// reconcile must reach the same secret the earlier one did. Every other
	// entry is an observation and belongs to the sweep that made it.
	pinned map[string]struct{}

	// tombstoned marks the entries a REVOKE row claimed. Such a claim is
	// provisional until the sweep is confirmed: the live secret holding that
	// name may be on a page the sweep has not read yet, or on one it read
	// while the listing moved, and it wins when it turns up.
	tombstoned map[string]struct{}

	// shadowed holds, per sweep, the first live row read under a name whose
	// entry names another secret and is not provisional: an entry kept across
	// a Forget rewind, or pinned by this reconcile. First-wins keeps that
	// entry, but the DESTROYED row of the secret it names may follow on this
	// page or a later one, and dropping the name then would lose the live
	// secret for the rest of the reconcile. dropID promotes the shadowed row
	// instead; rewind clears the map with the sweep it describes.
	shadowed map[string]string

	// since is the shared cache's write sequence when the index's first
	// sweep read its first page; an absence the index concludes must not
	// overrule a mapping written after that (see
	// secretIDCache.SetNegativeSince). A re-sweep keeps it: a verdict rests
	// on the sweep it repeats as well as on the repeat, and the read path
	// likewise reads the sequence once before its retries. sinceSet marks it
	// taken, since zero is a valid sequence.
	since    uint64
	sinceSet bool

	// confirmed records that the index's sweep may answer "absent" for a name
	// it did not record, and with a REVOKE row for one it recorded only that
	// way: it was a single declared page, or it was repeated and agreed
	// (absenceConfirmed is the rule). It implies the cursor is
	// exhausted, because it is set only after a sweep that exhausted it and
	// rewind, the only thing that moves the cursor back, clears it.
	confirmed bool
}

// Resolve resolves name -> ID for the write path. The first calls fetch
// listing pages lazily (early exit on a hit, like resolveSecretIDFromListing)
// and every fetched entry is shared with later keys of the same reconcile, so
// K keys do not cost a sweep each. Freshness is preserved: the index never
// outlives the Client instance and ignores the shared TTL cache for lookups
// (it only warms it). Misses mirror resolveSecretIDFromListing's
// negative-caching so read behavior stays identical.
func (w *writeIndex) Resolve(ctx context.Context, api SecretManagerInterface, cache *secretIDCache, name string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.names == nil {
		w.names = make(map[string]string)
		w.tombstoned = make(map[string]struct{})
		w.nextPage = 1
	}
	if id, ok := w.names[name]; ok {
		// A tombstone's claim stands only on a sweep that may also answer
		// "absent": one that looked everywhere and held still. Answering from it
		// earlier would send a write to a secret with no value while the live
		// one holding the name sits unread.
		if _, provisional := w.tombstoned[name]; !provisional || w.confirmed {
			return id, nil
		}
	}

	// Seeded from the index so a sweep already confirmed this reconcile is not
	// re-confirmed, but held locally so an error on the way to confirming
	// cannot leave the index claiming a pair that never agreed.
	confirmed := w.confirmed
	for attempt := 0; ; attempt++ {
		liveID, live, err := w.sweepPages(ctx, api, cache, name)
		if err != nil {
			return "", err
		}
		if live {
			return liveID, nil
		}
		// No live row under the name. That conclusion negative-caches the name
		// or hands back a recorded REVOKE row, and a live row the sweep missed
		// would make either wrong, so it must clear the read path's bar: the
		// collection held still, delivered every declared entry, and said so
		// twice if the sweep spanned more than one page. Confirmation is per
		// sweep, so a push of many secrets pays for it once.
		if !w.sweep.shifted && !w.sweep.incomplete() {
			if absenceConfirmed(&w.sweep, confirmed) {
				// Only here does the sweep become something later keys may
				// rest on. Set on the first agreeing sweep instead, it would
				// survive a transport error on the confirming one and hand
				// every later key a verdict that had not earned it.
				w.confirmed = true
				break
			}
			if attempt >= maxListSweepRetries {
				return "", fmt.Errorf(msgResolveSecretID, name, ErrListingUnstable)
			}
			confirmed = true
		} else {
			confirmed = false
			if attempt >= maxListSweepRetries {
				return "", fmt.Errorf(msgResolveSecretID, name, ErrListingUnstable)
			}
		}
		// Re-sweep from the first page, discarding what the abandoned sweep observed.
		// First-wins (see dedupeByName) holds within a sweep, not across a re-sweep:
		// it would pin whichever ID the retried sweep happened to see, and that sweep
		// is retried because its pages may not describe one state of the account. The
		// re-read re-records everything it still sees.
		//
		// Entries a create in this reconcile pinned are kept (see pinned).
		w.dropObserved(cache)
		w.rewind()
	}

	// A confirmed sweep with no live row under the name: a REVOKE row it
	// recorded is now the answer (see isTombstone).
	if id, ok := w.names[name]; ok {
		return id, nil
	}
	// Exhausted without a match. Same invariant as resolveSecretIDFromListing:
	// never negative-cache an ID-shaped key.
	if cache != nil && !isSecretIDFormat(name) {
		cache.SetNegativeSince(name, w.since)
	}
	return "", ErrSecretNotFound
}

// sweepPages reads the index's remaining listing pages, recording every entry
// it can write to, and reports the first LIVE entry matching name. A REVOKE
// row matching the name is only recorded: Resolve answers with it once the
// sweep could also have answered "absent".
func (w *writeIndex) sweepPages(ctx context.Context, api SecretManagerInterface, cache *secretIDCache, name string) (string, bool, error) {
	sweepCtx, cancel := sweepBudget(ctx)
	defer cancel()
	for w.nextPage > 0 {
		pageNo := w.nextPage
		if pageNo == 1 && cache != nil && !w.sinceSet {
			w.since, w.sinceSet = cache.Seq(), true
		}
		resp, err := api.ListSecrets(sweepCtx, pageNo)
		if err != nil {
			return "", false, fmt.Errorf(msgResolveSecretID, name, sweepFailure(ctx, err))
		}
		w.sweep.observe(resp)
		if err := tooManyRows(&w.sweep); err != nil {
			return "", false, fmt.Errorf(msgResolveSecretID, name, err)
		}

		page := w.recordPage(cache, resp, name)

		switch {
		case !hasMorePages(pageNo, resp):
			w.nextPage = -1
		case pageNo >= maxListPages:
			// A match on this page still wins. An unmatched key must not fall
			// through to NotFound: unread pages may hold it. The cursor stays on
			// this page (advancing reads past the cap; -1 would claim a complete
			// sweep), so a later key re-reads it and may fail as
			// ErrListingUnstable instead of msgTooManyPages; both are loud. A
			// tombstone seen so far is not an answer either, since the live row
			// that overrules it may be on an unread page.
			if !page.live {
				return "", false, fmt.Errorf(msgTooManyPages, maxListPages)
			}
		default:
			w.nextPage = pageNo + 1
		}

		if page.live {
			return page.liveID, true, nil
		}
	}
	return "", false, nil
}

// pageMatch is what one listing page held under the name being resolved: the
// first live row.
type pageMatch struct {
	liveID string
	live   bool
}

// recordPage records one listing page into the index and reports what the page
// held under name.
func (w *writeIndex) recordPage(cache *secretIDCache, resp *NcloudListSecretsResponse, name string) pageMatch {
	var m pageMatch
	for _, item := range resp.Data.SecretList {
		// DESTROYED rows are dropped from index and cache but the sweep
		// continues: a live duplicate may follow. dropID, not Forget: Forget
		// rewinds and would erase the stability evidence of the pages read.
		if item.SecretStatus == secretStatusDestroyed {
			w.dropID(cache, item.SecretID)
			if cache != nil {
				cache.InvalidateByID(item.SecretID)
			}
			continue
		}
		// First LIVE occurrence wins. A REVOKE row is recorded only until a live
		// row with that name turns up, and never enters the name -> ID cache:
		// every later READ trusts that cache, and a read landing on a
		// deletion-requested secret reports the name absent (see isTombstone).
		tombstone := isTombstone(item.SecretStatus)
		held, seen := w.names[item.SecretName]
		_, provisional := w.tombstoned[item.SecretName]
		switch {
		case !seen || (provisional && !tombstone):
			w.names[item.SecretName] = item.SecretID
			if tombstone {
				w.tombstoned[item.SecretName] = struct{}{}
			} else {
				delete(w.tombstoned, item.SecretName)
				if cache != nil {
					cache.Set(item.SecretName, item.SecretID)
				}
			}
		case !tombstone && held != item.SecretID:
			// A live row under a name whose entry predates this sweep (see
			// shadowed). Kept, not recorded: the entry stands until the row
			// that proves its secret gone turns up.
			if w.shadowed == nil {
				w.shadowed = make(map[string]string)
			}
			if _, ok := w.shadowed[item.SecretName]; !ok {
				w.shadowed[item.SecretName] = item.SecretID
			}
		}
		if item.SecretName != name {
			continue
		}
		if tombstone {
			// Recorded above, not returned: the sweep keeps going because the
			// live row holding this name may be on a later page.
			continue
		}
		if !m.live {
			m.liveID = item.SecretID
			m.live = true
		}
	}
	return m
}

// Pin pins name to id for the rest of this reconcile. It is called under the
// name lock once this client has created that secret. A pinned entry survives
// a re-sweep (see pinned) and is never provisional, so any tombstone mark on
// the name goes with it.
func (w *writeIndex) Pin(name, id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.names == nil {
		// Every caller today has resolved first, which initializes the
		// index; a pin on a fresh index must still hold, or a later Resolve
		// whose sweep does not show the new secret would create the name
		// again.
		w.names = make(map[string]string)
		w.tombstoned = make(map[string]struct{})
		w.nextPage = 1
	}
	w.names[name] = id
	delete(w.tombstoned, name)
	if w.pinned == nil {
		w.pinned = make(map[string]struct{})
	}
	w.pinned[name] = struct{}{}
}

// Forget drops every entry naming id after this reconcile deleted that secret
// or saw it gone, so a later push of the name creates afresh. It rewinds only
// when it dropped something: a finished sweep taken before a deletion must not
// answer a later absence with a plain negative entry for a secret still in its
// REVOKE window, but a find that forgets every listed tombstone must not cost
// a fresh sweep each. REVOKE entries go with the rewind, since their claim
// rested on the confirmation it withdraws.
func (w *writeIndex) Forget(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dropID(nil, id) {
		w.rewind()
	}
}

// dropID removes every entry naming id and reports whether there was one. A
// name whose live row this sweep shadowed (see shadowed) is re-entered under
// that row rather than dropped: the DESTROYED row or 404 that drops the older
// entry is the proof the shadow waited for, and it outranks a pin the same
// way. The promoted mapping is written to cache when one is given, so a read
// reaches the live secret instead of the dropped one's stale entry.
func (w *writeIndex) dropID(cache *secretIDCache, id string) bool {
	dropped := false
	for n, v := range w.names {
		if v != id {
			continue
		}
		delete(w.names, n)
		delete(w.pinned, n)
		delete(w.tombstoned, n)
		dropped = true
		if live, ok := w.shadowed[n]; ok {
			w.names[n] = live
			delete(w.shadowed, n)
			if cache != nil {
				cache.Set(n, live)
			}
		}
	}
	return dropped
}

// dropObserved clears the entries that came from a listing page, keeping the
// pinned ones, and the cache entries recordPage warmed from the same pages: a
// stale cache entry is worse than a stale index entry, because a read through
// it returns another secret's value under this name with nothing to self-heal
// from.
func (w *writeIndex) dropObserved(cache *secretIDCache) {
	for name := range w.names {
		if _, pinned := w.pinned[name]; pinned {
			continue
		}
		delete(w.names, name)
		delete(w.tombstoned, name)
		if cache != nil {
			// A negative entry or a tombstone is a later verdict from the read
			// path than the live row recorded here, and the re-sweep would not
			// restore it; only the mapping goes.
			cache.InvalidatePositive(name)
		}
	}
}

// rewind makes the next resolution read the listing from the first page. It
// is the only place the cursor moves back, and it withdraws the confirmation
// with it. REVOKE entries go too: they are an answer only on a confirmed
// sweep, and kept they would answer for a name whose REVOKE row the next sweep
// no longer lists. This is not dropObserved's loop again: a one-page sweep is
// confirmed on its first pass and never reaches dropObserved, so a rewind
// through Forget is the only thing that clears its REVOKE entries. Pinned
// entries are never REVOKE entries (see Pin). Shadowed rows go with the sweep
// that read them.
func (w *writeIndex) rewind() {
	w.confirmed = false
	w.nextPage = 1
	w.sweep.reset()
	for name := range w.tombstoned {
		delete(w.names, name)
		delete(w.tombstoned, name)
	}
	clear(w.shadowed)
}
