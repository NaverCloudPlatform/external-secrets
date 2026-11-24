// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Credentials is the access key pair one request is signed with.
type Credentials struct {
	AccessKeyID string
	SecretKey   string
	// Expiry is when the pair stops being accepted. Zero for a permanent key.
	Expiry time.Time
}

// temporary reports whether the pair expires.
func (c Credentials) temporary() bool { return !c.Expiry.IsZero() }

// CredentialsSource supplies the access key pair requests are signed with.
//
// Every pair signs the same way, whichever source issued it: the permanent
// key of a main or sub account, or the temporary key issued for a Server
// Role, for a switched role or in exchange for a Pod Identity token. Only
// where the pair comes from and whether it expires differ, so that is all a
// source decides. The client asks its source for a pair on every request, so
// a source that refreshes hands out the new pair without the client being
// rebuilt.
//
// Implementations must be safe for concurrent use.
type CredentialsSource interface {
	// Credentials returns a pair that is valid now, fetching or refreshing one
	// first when needed.
	Credentials(ctx context.Context) (Credentials, error)

	// Invalidate drops the cached pair if it is still the refused one, so the
	// next Credentials call fetches a fresh pair. The client calls it when the
	// endpoint refuses a signature made with a temporary pair. Passing the
	// refused pair keeps N callers refused with the same pair from discarding
	// N successive fresh pairs: only the first of them finds it still cached.
	// A caller whose ctx ends while another holds the source gives up without
	// invalidating; the next caller refused with the same pair does it.
	Invalidate(ctx context.Context, refused Credentials)

	// Identity names the principal the pairs belong to, for the process-wide
	// registries that share state between clients. It is stable across
	// refreshes, so a cache keyed by it survives a rotation, and it never
	// carries a secret. It must also never be equal for two sources that
	// would sign differently: whatever shares by identity hands one source's
	// pairs to the other's callers.
	Identity() string
}

// StaticCredentials returns a source for a permanent key pair.
func StaticCredentials(accessKeyID, secretKey string) CredentialsSource {
	return staticCredentials{pair: Credentials{AccessKeyID: accessKeyID, SecretKey: secretKey}}
}

type staticCredentials struct{ pair Credentials }

func (s staticCredentials) Credentials(context.Context) (Credentials, error) {
	if s.pair.AccessKeyID == "" || s.pair.SecretKey == "" {
		return Credentials{}, ErrMissingCredentials
	}
	return s.pair, nil
}

func (staticCredentials) Invalidate(context.Context, Credentials) {}

// Identity is the access key ID plus a keyed fingerprint of the secret key.
// The ID alone is not enough: it is not a secret (it travels in every request
// header and shows in gateway logs), so a store in another namespace that
// names the same ID with a wrong secret would otherwise share this source's
// registry entries, and through the switched-role registry it would be
// handed the pair the right secret obtained. The fingerprint is an HMAC of a
// fixed message under the secret key: it changes when the secret changes and
// gives nothing back about the secret.
func (s staticCredentials) Identity() string {
	mac := hmac.New(sha256.New, []byte(s.pair.SecretKey))
	mac.Write([]byte("external-secrets ncloud identity\n" + s.pair.AccessKeyID))
	return "key:" + s.pair.AccessKeyID + "/" + hex.EncodeToString(mac.Sum(nil))
}

// refreshLead is how long before its expiry a temporary pair is replaced, so
// that a request signed just before the refresh still reaches the service
// inside the pair's lifetime. The shortest lifetime the Secure Token Service
// issues is 600 seconds; see refreshTime for how a pair that short is handled.
const refreshLead = 5 * time.Minute

// failureHold is how long a failed fetch is answered from memory. Callers
// that queued behind the failing fetch get the same error at once instead of
// each repeating a full-length attempt against a service that just failed.
// A GET retry waits it out before trying again (see doGet). A var so tests
// can shrink it; like maxGetElapsed, a test that changes it must not run in
// parallel with one that reads it.
var failureHold = 2 * time.Second

// refetchHold spaces fetches that cannot change what a caller gets. While
// the cached pair is still valid, a refresh that failed is retried no sooner
// than this, so an issuing service that is down costs one caller a timeout
// every refetchHold rather than every failureHold. And a fetch that handed
// back the pair just refused shows the refusal is not about a stale pair, so
// refusals of it are ignored for this long instead of each one re-reading
// the issuer for the same answer.
const refetchHold = 30 * time.Second

// refreshingSource caches a temporary pair from fetch and replaces it ahead of
// its expiry. One fetch runs at a time and the callers that arrive meanwhile
// wait for it, so concurrent reconciles that find the pair due share one
// fetch instead of each issuing their own. The wait honors the caller's
// context: a caller whose own deadline passes while it queues leaves the queue
// with that error rather than holding a reconcile worker for a fetch it can no
// longer use.
type refreshingSource struct {
	fetch func(ctx context.Context) (Credentials, error)
	now   func() time.Time

	// sem is a one-slot channel used as a context-aware mutex over the
	// fields below.
	sem       chan struct{}
	pair      Credentials
	refreshAt time.Time
	valid     bool
	lastErr   error
	failedAt  time.Time

	// refused is the pair last invalidated and not yet fetched again. A
	// fetch that returns it sets keepRefusedUntil, before which Invalidate
	// leaves it cached, and forgets it; any fetch that succeeds clears
	// keepRefusedUntil first.
	refused          Credentials
	keepRefusedUntil time.Time
}

func newRefreshingSource(fetch func(ctx context.Context) (Credentials, error)) *refreshingSource {
	return &refreshingSource{fetch: fetch, now: time.Now, sem: make(chan struct{}, 1)}
}

func (r *refreshingSource) acquire(ctx context.Context) error {
	select {
	case r.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *refreshingSource) release() { <-r.sem }

func (r *refreshingSource) Credentials(ctx context.Context) (Credentials, error) {
	if err := r.acquire(ctx); err != nil {
		return Credentials{}, err
	}
	defer r.release()
	// select picks the free slot over a context that was already done about
	// half the time; a caller that gave up must not run a fetch it will not
	// use and keep a waiter out meanwhile.
	if err := ctx.Err(); err != nil {
		return Credentials{}, err
	}

	now := r.now()
	if r.valid && now.Before(r.refreshAt) {
		return r.pair, nil
	}
	if r.lastErr != nil && now.Before(r.failedAt.Add(failureHold)) {
		if r.usable(now) {
			return r.pair, nil
		}
		return Credentials{}, r.lastErr
	}

	pair, err := r.fetch(ctx)
	// Every hold below counts from when the fetch returned: one that timed
	// out has already taken as long as a hold lasts, and a hold counted from
	// its start would have run out before the next caller arrived.
	now = r.now()
	if err == nil && (pair.AccessKeyID == "" || pair.SecretKey == "" || !pair.temporary()) {
		err = ErrTemporaryCredentialsIncomplete
	}
	if err != nil {
		return r.refreshFailed(ctx, now, err)
	}
	// The hold answers one refusal: a later fetch that brings the same key
	// with no refusal in between must not arm it again. The refused pair is
	// forgotten either way, so a key the issuer replaced does not stay in
	// memory.
	r.keepRefusedUntil = time.Time{}
	if pair.AccessKeyID == r.refused.AccessKeyID {
		r.keepRefusedUntil = now.Add(refetchHold)
	}
	r.refused = Credentials{}
	r.pair = pair
	r.refreshAt = refreshTime(now, pair.Expiry)
	r.valid = true
	r.lastErr = nil
	return pair, nil
}

// refreshFailed records a failed fetch and answers the caller: with the
// cached pair while it is still usable, otherwise with the error. Callers
// must hold the slot.
func (r *refreshingSource) refreshFailed(ctx context.Context, now time.Time, err error) (Credentials, error) {
	// A failure caused by this caller's own context says nothing about the
	// service, so it is neither remembered nor allowed to put off the next
	// caller's refresh.
	if ctx.Err() == nil {
		r.lastErr, r.failedAt = err, now
	}
	// A refresh starts refreshLead before expiry precisely so that it can
	// fail without failing the caller: the pair it was replacing is still
	// good, and is handed out until refetchHold has passed or it expires,
	// whichever comes first.
	if !r.usable(now) {
		return Credentials{}, err
	}
	if ctx.Err() == nil {
		r.refreshAt = now.Add(refetchHold)
		if r.pair.Expiry.Before(r.refreshAt) {
			r.refreshAt = r.pair.Expiry
		}
	}
	return r.pair, nil
}

// usable reports whether the cached pair may still be handed out while its
// replacement cannot be fetched: it was not refused, and it has not expired.
func (r *refreshingSource) usable(now time.Time) bool {
	return r.valid && now.Before(r.pair.Expiry)
}

// Invalidate drops the cached pair when it is the refused one. A refusal of
// a pair this source has already replaced is stale news and changes nothing,
// and so is one of a pair the issuer handed back right after its last
// refusal: fetching again would return it again.
func (r *refreshingSource) Invalidate(ctx context.Context, refused Credentials) {
	if r.acquire(ctx) != nil {
		return
	}
	defer r.release()
	if !r.valid || r.pair.AccessKeyID != refused.AccessKeyID {
		return
	}
	// Set only while the cached pair is the one last refused.
	if r.now().Before(r.keepRefusedUntil) {
		return
	}
	r.valid = false
	r.refused = refused
	// A failure remembered from an earlier refresh is about a pair that was
	// still usable then; the refusal is the newer news, and the caller about
	// to ask for a replacement should get its own fetch and its own error.
	r.lastErr = nil
}

// refreshTime picks when a pair obtained at now and expiring at expiry is
// replaced: refreshLead before expiry, or halfway through a lifetime shorter
// than twice the lead. A pair that arrives already expired or past its
// replacement time is handed out anyway and replaced no sooner than
// failureHold from now: the service, not this clock, decides acceptance, and
// refusing it here would turn a skewed node clock into a store that can never
// authenticate, while replacing it on every call would cost a fetch per
// request.
func refreshTime(now, expiry time.Time) time.Time {
	lead := refreshLead
	if lifetime := expiry.Sub(now); lifetime < 2*lead {
		lead = lifetime / 2
	}
	next := expiry.Add(-lead)
	if floor := now.Add(failureHold); next.Before(floor) {
		return floor
	}
	return next
}

// signRequest computes the x-ncp-apigw-signature-v2 value: the HMAC-SHA256 of
// "<method> <request URI>\n<timestamp>\n<access key ID>" under the secret key,
// Base64-encoded. The same signing scheme authenticates every Ncloud API
// Gateway service, Secret Manager and the Secure Token Service included.
// See https://api.ncloud-docs.com/docs/common-ncpapi.
func signRequest(method, requestURI, timestamp string, pair Credentials) string {
	message := fmt.Sprintf("%s %s\n%s\n%s", method, requestURI, timestamp, pair.AccessKeyID)
	mac := hmac.New(sha256.New, []byte(pair.SecretKey))
	mac.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// setAuthHeaders stamps req with the content type, timestamp, access key ID
// and signature the API Gateway checks. The path and query string are both
// part of the signed request URI.
func setAuthHeaders(req *http.Request, pair Credentials, now time.Time) {
	timestamp := strconv.FormatInt(now.UnixMilli(), 10)
	req.Header.Set(headerContentType, "application/json")
	req.Header.Set(headerTimestamp, timestamp)
	req.Header.Set(headerAccessKey, pair.AccessKeyID)
	req.Header.Set(headerSignature, signRequest(req.Method, req.URL.RequestURI(), timestamp, pair))
}
