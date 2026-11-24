// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

// Package secretmanager provides the Ncloud Secret Manager client implementation.
package secretmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-logr/logr"
	"github.com/tidwall/gjson"
	corev1 "k8s.io/api/core/v1"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/runtime/esutils"
	"github.com/external-secrets/external-secrets/runtime/find"
	"github.com/external-secrets/external-secrets/runtime/util/locks"
)

// https://github.com/external-secrets/external-secrets/issues/644
var _ esv1.SecretsClient = &Client{}

const (
	// validateTimeout bounds the Validate() connectivity check. The
	// SecretsClient interface gives Validate no context, so this client caps it
	// instead of inheriting the HTTP client timeout, which would otherwise block
	// reconciliation for longer.
	validateTimeout = 10 * time.Second

	// providerName namespaces the process-wide mutation locks. The second
	// component is always the resolved Ncloud secret ID, except before a
	// create where no ID exists yet and the validated secret name is stable.
	providerName = "NcloudSecretManager"

	// managedByMemo marks a secret as owned by external-secrets. It is
	// stamped into the memo (description) field on every create, and every
	// mutation of an existing secret requires it (see ErrNotManagedByESO).
	// A whole line of the memo must equal it (see isManagedByESO), so an
	// adopted secret can keep its human description on the other lines.
	managedByMemo = "managed-by: external-secrets"
)

var (
	errPushEmptyData        = errors.New("kubernetes secret data must not be empty")
	errPushEmptyDataKey     = errors.New("kubernetes secret data must not contain an empty key")
	errPushInvalidUTF8      = errors.New("kubernetes secret data must contain valid UTF-8")
	errPushEmptyObject      = errors.New("ncloud secret value must be a nonempty JSON object")
	errPushRotationTargets  = errors.New("ncloud secret rotation targets must be nonempty")
	errRotationTargetAbsent = errors.New("secret value must preserve every configured rotation " +
		"target: ncloud fixes them when the secret is created and rejects any value that omits " +
		"one, so dropping such a field requires deleting and recreating the remote secret")
	errSecretValueNotObject = errors.New("active secret value must be a JSON object")
	errEmptySecretDetail    = errors.New("ncloud API returned an empty secret detail response")
	errEmptySecretValue     = errors.New("ncloud API returned an empty secret value response")
)

// Client implements the SecretsClient interface for Ncloud Secret Manager.
type Client struct {
	client SecretManagerInterface
	cache  *secretIDCache

	// forceDelete mirrors Config.ForceDeleteWithoutRecovery: when false (the
	// default), DeleteSecret stops at the REVOKE state and leaves the 7-day
	// grace period to Ncloud; when true it destroys immediately.
	forceDelete bool

	// writes is the write path's listing index for this reconcile (see
	// writeIndex). Reads never consult it.
	writes writeIndex

	// Default protection key's KMS region-isolation boundary, resolved once per
	// Client and only when a create actually needs it (reads and updates never
	// do). boundaryDone records that the lookup ran, so an account whose keys
	// report no boundary is not re-queried on every create.
	boundaryMu   sync.Mutex
	boundaryType string
	boundaryDone bool
}

// NewClient creates a new external-secrets Client that wraps the Ncloud Secret Manager API client.
func NewClient(config *Config) (esv1.SecretsClient, error) {
	client, err := newClient(config)
	if err != nil {
		return nil, fmt.Errorf(msgCreateClient, err)
	}

	return &Client{
		client:      client,
		forceDelete: client.config.ForceDeleteWithoutRecovery,
		// One cache per (endpoint, credential identity), process-wide: the
		// controller rebuilds the client every reconcile, and a miss costs a
		// full listing sweep (see sharedCacheRegistry).
		cache: sharedCacheRegistry.get(newSharedSecretIDCache, client.config.Endpoint, client.credentials.Identity()),
	}, nil
}

// GetSecret returns a single secret from the provider. ref.Version selects a
// stage of the secret's decrypted chain; empty defaults to "active". With
// metadataPolicy=Fetch the secret's metadata is returned instead of its value.
func (c *Client) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	if c.client == nil {
		return nil, ErrUninitializedClient
	}

	if ref.MetadataPolicy == esv1.ExternalSecretMetadataPolicyFetch {
		return c.getSecretMetadata(ctx, ref)
	}

	stage, err := stageForVersion(ref.Version)
	if err != nil {
		return nil, err
	}

	resp, err := c.fetchSecretValue(ctx, ref.Key)
	if err != nil {
		return nil, asCoreNotFound(err)
	}

	secret := extractSecretForStage(resp, stage)
	if len(secret) == 0 {
		return nil, fmt.Errorf(msgEmptyStage, ErrEmptySecretData, ref.Key, stage)
	}

	if ref.Property == "" {
		return secret, nil
	}

	return extractProperty(secret, ref.Property, ref.Key)
}

// GetSecretMap returns multiple k/v pairs from the provider. ref.Version
// selects a stage of the secret's decrypted chain; empty defaults to "active".
// ref.Property narrows the parsed document to one field first - it must
// resolve to a JSON object - matching how the AWS and GCP providers derive
// their maps from GetSecret's output. With metadataPolicy=Fetch the secret's
// metadata fields are returned instead of its value.
func (c *Client) GetSecretMap(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	if c.client == nil {
		return nil, ErrUninitializedClient
	}

	if ref.MetadataPolicy == esv1.ExternalSecretMetadataPolicyFetch {
		meta, err := c.getSecretMetadata(ctx, ref)
		if err != nil {
			return nil, err
		}
		// The whole document is an object by construction; a property is
		// whatever field it named.
		if ref.Property != "" {
			if err := requireObjectProperty(meta, ref.Property, ref.Key); err != nil {
				return nil, err
			}
		}
		return parseSecretMap(meta, ref.Key)
	}

	stage, err := stageForVersion(ref.Version)
	if err != nil {
		return nil, err
	}

	resp, err := c.fetchSecretValue(ctx, ref.Key)
	if err != nil {
		return nil, asCoreNotFound(err)
	}

	secret := extractSecretForStage(resp, stage)
	if len(secret) == 0 {
		return nil, fmt.Errorf(msgEmptyStage, ErrEmptySecretData, ref.Key, stage)
	}

	// Extract the property exactly like GetSecret does, so
	// GetSecretMap(ref) is always parseSecretMap(GetSecret(ref)).
	if ref.Property != "" {
		var err error
		secret, err = extractProperty(secret, ref.Property, ref.Key)
		if err != nil {
			return nil, err
		}
		if err := requireObjectProperty(secret, ref.Property, ref.Key); err != nil {
			return nil, err
		}
	}

	return parseSecretMap(secret, ref.Key)
}

// requireObjectProperty fails a GetSecretMap whose property did not select a
// JSON object, naming the property; parseSecretMap would otherwise report the
// secret itself as malformed. The check is on the extracted bytes as GetSecret
// returns them, so a string property whose text is an object passes here
// exactly as it does through GetSecret. It parses rather than looking at the
// first byte: a string that merely starts with a brace, such as a template, is
// not an object either.
func requireObjectProperty(extracted []byte, property, secretName string) error {
	if _, ok := decodeJSONObject(extracted); !ok {
		return fmt.Errorf(msgPropertyNotObject, property, secretName)
	}
	return nil
}

// asCoreNotFound decorates a secret-not-found error with the ESO core's
// esv1.NoSecretErr sentinel while preserving the provider's own
// ErrSecretNotFound chain. The core keys deletionPolicy=Delete handling on
// errors.Is(err, esv1.NoSecretErr); without the wrap, an ExternalSecret whose
// remote secret was deleted stays in SyncError forever instead of deleting
// its target Secret.
func asCoreNotFound(err error) error {
	if errors.Is(err, ErrSecretNotFound) {
		return fmt.Errorf("%w: %w", esv1.NoSecretErr, err)
	}
	return err
}

// fetchByKey resolves key to a secret ID and invokes get with it. On a
// NotFound for a name key it re-resolves through a fresh listing (bypassing
// the cache) and retries once, covering a cached mapping that went stale. An
// ID-shaped key cannot be a name (see secretNamePattern), so its NotFound is
// final.
func fetchByKey[T any](ctx context.Context, c *Client, key string, get func(ctx context.Context, secretID string) (T, error)) (T, error) {
	return fetchResolvedBy(ctx, c, key, c.resolveSecretIDTracked, get)
}

// fetchResolvedBy is fetchByKey with the name -> ID step supplied by the
// caller. Only the metadata path needs its own resolver: a deletion tombstone
// is absence for a value read but not for a metadata read.
func fetchResolvedBy[T any](
	ctx context.Context,
	c *Client,
	key string,
	resolve func(ctx context.Context, name string) (id string, origin idOrigin, err error),
	get func(ctx context.Context, secretID string) (T, error),
) (T, error) {
	var zero T

	secretID, origin, err := resolve(ctx, key)
	if err != nil {
		return zero, err
	}

	resp, err := get(ctx, secretID)
	if err == nil {
		return resp, nil
	}
	var notFound bool
	if notFound, err = c.asDeletionLifecycleNotFound(ctx, secretID, err); notFound {
		switch origin {
		case originTombstone:
			// The listing offered this row only after finding no live row
			// with the name, so it has already spoken; the name is
			// negative-cached for the rest of the REVOKE window.
			c.tombstoneCache(key, secretID)
		case originKey:
			// An ID key names the secret itself; no listing can second-guess it.
		case originCache, originLiveRow:
			// A cached mapping can outlive the secret, and a live row can
			// enter deletion between the listing and the read while another
			// live row holds the same name, so the listing gets the final
			// word on the NAME.
			return absentUnlessListingDisagrees(ctx, c, key, secretID, err, get)
		}
		return zero, err
	}

	if !errors.Is(err, ErrSecretNotFound) || isSecretIDFormat(key) {
		return zero, err
	}

	if c.cache != nil {
		c.cache.Invalidate(key)
	}
	secretID, err = c.resolveSecretIDFromListing(ctx, key)
	if err != nil {
		return zero, err
	}
	resp, err = get(ctx, secretID)
	if err != nil {
		_, err = c.asDeletionLifecycleNotFound(ctx, secretID, err)
	}
	return resp, err
}

// absentUnlessListingDisagrees decides what a deletion tombstone on one secret
// ID means for the NAME that reached it. The ID came from the cache, which can
// outlive the secret (another cluster may have destroyed it and recreated the
// name under a new ID), or from a live row whose secret entered deletion
// between the listing and the read while a second live row kept the name
// (see isTombstone for why the resolvers allow for that). Absence from that
// ID alone would be a false negative that deletionPolicy: Delete acts on, so
// the listing gets the final word. When it agrees, the name is negative-cached
// so a secret in its 7-day REVOKE window is not re-swept on every reconcile.
func absentUnlessListingDisagrees[T any](
	ctx context.Context,
	c *Client,
	key string,
	tombstonedID string,
	wrapped error,
	get func(ctx context.Context, secretID string) (T, error),
) (T, error) {
	var zero T

	// An ID key names the tombstone directly; the listing cannot second-guess it.
	if isSecretIDFormat(key) {
		return zero, wrapped
	}

	liveID, listErr := c.resolveSecretIDFromListing(ctx, key)
	// Only a completed sweep that found nothing licenses absence. A transport or
	// auth failure has not spoken, and reading it as absence deletes a live
	// Kubernetes Secret.
	if listErr != nil && !errors.Is(listErr, ErrSecretNotFound) {
		return zero, listErr
	}
	if listErr != nil {
		// The sweep completed and the name is gone, which
		// resolveSecretIDFromListing already recorded as a plain absence, so
		// there is nothing left to cache here.
		return zero, wrapped
	}
	if liveID == tombstonedID {
		c.tombstoneCache(key, tombstonedID)
		return zero, wrapped
	}

	resp, err := get(ctx, liveID)
	if err == nil {
		return resp, nil
	}
	var notFound bool
	if notFound, err = c.asDeletionLifecycleNotFound(ctx, liveID, err); notFound {
		c.tombstoneCache(key, liveID)
	}
	return zero, err
}

// tombstoneCache records that a name resolves to a secret in a deletion
// lifecycle state. Value reads see the same absence a plain negative entry
// gives them; the ID is kept for the metadata path, which Ncloud still
// answers (see resolveSecretIDForMetadata).
func (c *Client) tombstoneCache(name, secretID string) {
	if c.cache != nil && !isSecretIDFormat(name) {
		c.cache.SetTombstoned(name, secretID)
	}
}

// deletionLifecycleCandidate reports whether a value-read error is the kind
// Ncloud gives for a secret that is not readable because of its lifecycle
// state, so the state is worth confirming with a metadata read. Such a read
// is answered with an invalid-status or invalid-request error, not with 404.
// Neither is proof on its own, a DISABLE secret answers the same way, which
// is why every caller still consults the detail before concluding absence.
func deletionLifecycleCandidate(err error) bool {
	return errors.Is(err, ErrInvalidStatus) || errors.Is(err, ErrInvalidRequest)
}

// asDeletionLifecycleNotFound promotes a lifecycle-shaped value-read error to
// ErrSecretNotFound when the secret is confirmed to be in a deletion lifecycle
// state (REVOKE or DESTROYED). With the default grace-period deletion, a
// deleted secret sits in REVOKE for up to 7 days; its value reads answer an
// error status rather than 404 (see deletionLifecycleCandidate), and without
// this promotion an ExternalSecret pointing at it would report SyncError for
// the whole window instead of the NoSecretErr the core keys deletionPolicy
// handling on.
//
// The promotion is deliberately fail-closed: it happens only when a metadata
// read proves REVOKE/DESTROYED (enteredDeletion). A DISABLE (paused) secret
// answers value reads the same way but still holds a value, so it must
// surface an error - promoting it would let deletionPolicy=Delete remove the
// target Kubernetes Secret while the data still exists.
func (c *Client) asDeletionLifecycleNotFound(ctx context.Context, secretID string, err error) (bool, error) {
	if !deletionLifecycleCandidate(err) {
		return false, err
	}
	gone, status := c.deletionState(ctx, secretID)
	if !gone {
		if status == secretStatusDisable {
			// The write path names a paused secret; a read should too.
			return false, fmt.Errorf(msgReadPausedSecret, err)
		}
		return false, err
	}
	c.forgetResolutionByID(secretID)
	return true, fmt.Errorf("%w: %w", ErrSecretNotFound, err)
}

// fetchSecretValue resolves key and fetches the secret's decrypted value chain.
func (c *Client) fetchSecretValue(ctx context.Context, key string) (*NcloudSecretValueResponse, error) {
	return fetchByKey(ctx, c, key, c.client.GetSecretValue)
}

// getSecretMetadata serves metadataPolicy=Fetch: it returns the secret's
// metadata (Get Secret Detail) instead of its value. ref.Property selects a
// single metadata field through the same literal-then-path gjson lookup used
// for values (e.g. "secretStatus" or "protectionKey.type"). ref.Version is
// ignored because metadata is not staged.
func (c *Client) getSecretMetadata(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	resp, err := fetchResolvedBy(ctx, c, ref.Key, c.resolveSecretIDForMetadata, c.client.GetSecretDetail)
	if err != nil {
		return nil, asCoreNotFound(err)
	}

	meta, err := esutils.JSONMarshal(resp.Data)
	if err != nil {
		return nil, fmt.Errorf(msgMarshalMetadata, ref.Key, err)
	}

	if ref.Property == "" {
		return meta, nil
	}

	return extractProperty(meta, ref.Property, ref.Key)
}

// GetAllSecrets returns all secrets from the provider.
func (c *Client) GetAllSecrets(ctx context.Context, ref esv1.ExternalSecretFind) (map[string][]byte, error) {
	if c.client == nil {
		return nil, ErrUninitializedClient
	}

	// An empty map is how the schema says "no tag filter", the way the AWS
	// Secrets Manager, GCP and Azure providers read it, so only a populated
	// map is refused.
	if len(ref.Tags) > 0 {
		return nil, ErrTagsNotSupported
	}

	var matcher *find.Matcher
	if ref.Name != nil {
		m, err := find.New(*ref.Name)
		if err != nil {
			return nil, fmt.Errorf(msgInvalidPattern, err)
		}
		matcher = m
	}

	// The whole listing is collected before any value is read. ESO rewrites
	// the managed Secret from the map returned here, so a sweep that silently
	// missed an entry deletes that key; collecting first also keeps a retry
	// cheap, because no value reads have happened yet.
	items, err := c.listAllSecretItems(ctx)
	if err != nil {
		return nil, err
	}

	secrets := make(map[string][]byte, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, s := range items {
		selected := (matcher == nil || matcher.MatchName(s.SecretName)) &&
			(ref.Path == nil || strings.HasPrefix(s.SecretName, *ref.Path))

		data, skip, err := c.collectListedSecret(ctx, s, selected, seen)
		if err != nil {
			return nil, err
		}
		if skip {
			continue
		}
		secrets[s.SecretName] = data
	}

	return secrets, nil
}

// listAllSecretItems pages through the whole listing. A sweep the server
// reported as changing underneath it is redone; an unstable listing fails
// rather than yield a short result. Sweeps that need confirming are unioned,
// not compared: the failure guarded is an entry one sweep never saw, and
// requiring exact agreement would fail every find on a busy account. An entry
// deleted between sweeps costs nothing: its value read 404s and is skipped.
func (c *Client) listAllSecretItems(ctx context.Context) ([]NcloudSecretListItem, error) {
	var (
		merged     []NcloudSecretListItem
		at         = make(map[string]int)      // live rows, by the name they hold
		tombstones = make(map[string]struct{}) // tombstone IDs already carried
	)
	confirmed := false
	for sweepNo := 1; ; sweepNo++ {
		sweep, items, err := c.sweepSecretItems(ctx)
		if err != nil {
			return nil, err
		}

		if sweep.shifted || sweep.incomplete() {
			confirmed = false
			if sweepNo > maxListSweepRetries {
				return nil, fmt.Errorf(msgListSecrets, ErrListingUnstable)
			}
			continue
		}

		// Within a sweep a duplicate name is first-wins (dedupeByName); across
		// sweeps the later sighting replaces the earlier, because
		// collectListedSecret marks a name seen before reading it, so a stale
		// row in front would burn the name on a read that 404s.
		for _, item := range dedupeByName(items) {
			// A tombstone never enters the name index, so it can neither take
			// a name from a live row nor be taken from by one; it rides along
			// once per ID for the sake of the cache purge collectListedSecret
			// does on it.
			if isTombstone(item.SecretStatus) {
				if _, carried := tombstones[item.SecretID]; carried {
					continue
				}
				tombstones[item.SecretID] = struct{}{}
				merged = append(merged, item)
				continue
			}
			if i, ok := at[item.SecretName]; ok {
				merged[i] = item
				continue
			}
			at[item.SecretName] = len(merged)
			merged = append(merged, item)
		}

		if absenceConfirmed(&sweep, confirmed) {
			return merged, nil
		}
		// The confirming sweep counts against the same bound, so one unstable
		// sweep between two stable ones fails closed; the caller retries.
		if sweepNo > maxListSweepRetries {
			return nil, fmt.Errorf(msgListSecrets, ErrListingUnstable)
		}
		confirmed = true
	}
}

// dedupeByName keeps the first live row that claims a name, which is what
// every other reader of this listing resolves it to. Tombstones pass through
// unchanged: collectListedSecret skips them before marking the name seen and
// purges the cache mappings that point at them (see isTombstone). A second
// live row under the same name is dropped here, so if the first enters
// deletion before its read, that read is skipped and the key leaves the find
// result rather than falling back to the second row. The provider does not
// rely on the service refusing a second live holder of a name: this function
// decides what a listing that shows one resolves to.
func dedupeByName(items []NcloudSecretListItem) []NcloudSecretListItem {
	out := make([]NcloudSecretListItem, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if isTombstone(item.SecretStatus) {
			out = append(out, item)
			continue
		}
		if _, dup := seen[item.SecretName]; dup {
			continue
		}
		seen[item.SecretName] = struct{}{}
		out = append(out, item)
	}
	return out
}

// sweepSecretItems reads the listing once, from the first page to the last.
func (c *Client) sweepSecretItems(ctx context.Context) (listSweep, []NcloudSecretListItem, error) {
	var sweep listSweep
	var items []NcloudSecretListItem

	sweepCtx, cancel := sweepBudget(ctx)
	defer cancel()
	for pageNo := 1; ; pageNo++ {
		resp, err := c.client.ListSecrets(sweepCtx, pageNo)
		if err != nil {
			return sweep, nil, fmt.Errorf(msgListSecrets, sweepFailure(ctx, err))
		}
		sweep.observe(resp)
		if err := tooManyRows(&sweep); err != nil {
			return sweep, nil, fmt.Errorf(msgListSecrets, err)
		}
		items = append(items, resp.Data.SecretList...)

		if !hasMorePages(pageNo, resp) {
			return sweep, items, nil
		}
		if pageNo >= maxListPages {
			return sweep, nil, fmt.Errorf(msgTooManyPages, maxListPages)
		}
	}
}

// listedSecretDisposition is how a listing entry's lifecycle status should be
// treated by a read that spans many secrets.
type listedSecretDisposition int

const (
	// listedSecretReadable: the value endpoint may be called.
	listedSecretReadable listedSecretDisposition = iota
	// listedSecretTombstone: on its way out. Skipping is correct and not a data
	// loss, because there is no value left to preserve.
	listedSecretTombstone
	// listedSecretUnreadable: it exists and may well hold a value we simply
	// cannot read right now. Skipping it would drop its key from the aggregate
	// map, and ESO rewrites the managed Kubernetes Secret from that map - so the
	// key would be deleted. Failing the whole find keeps the last known good
	// data instead. See the DISABLE note in docs/provider/ncloud.md.
	listedSecretUnreadable
)

// classifyListedSecret maps a listing entry's SecretStatus onto how a read
// should treat it. An empty status is tolerated for backward compatibility with
// list responses that omit the field; the subsequent value read stays
// fail-closed, so tolerating it cannot turn into a silent omission.
//
// The write path shares the rule but not the conclusion: a read skips a REVOKE
// secret outright, while a write still resolves to it when no live row holds
// the name (see isTombstone).
func classifyListedSecret(status string) listedSecretDisposition {
	switch status {
	case secretStatusRevoke, secretStatusDestroyed:
		return listedSecretTombstone
	case "", secretStatusEnable, secretStatusRotating:
		return listedSecretReadable
	default:
		return listedSecretUnreadable
	}
}

// isTombstone reports whether a listing row has no readable value and so may
// not claim its name off a live secret that reuses it. A listing can carry
// REVOKE and DESTROYED rows, and a live row can share their name: this
// provider creates over a DESTROYED row by design and refuses to create over
// a REVOKE row (createSecretLocked).
// Every name resolver must apply this, or a listing that returns the
// tombstone first answers "absent" for a live secret and ESO deletes the key
// from the managed Secret. It says only that the row does not own the name: a
// REVOKE row is still a write target when no live row holds the name
// (DeleteSecret finalizes from it; a create is refused against it).
func isTombstone(status string) bool {
	return classifyListedSecret(status) == listedSecretTombstone
}

// collectListedSecret decides what one listing entry contributes to a find and
// reads its value when it contributes one. skip covers an unmatched name, an
// entry that vanished while listing, and a later duplicate of a collected
// name. A tombstone is skipped after its cache mappings are purged. The cache
// is warmed for every lifecycle-valid entry, matched or not, since the listing
// is already paid for; warming follows the lifecycle check so a DESTROYED row
// never becomes a live name -> ID mapping.
func (c *Client) collectListedSecret(
	ctx context.Context,
	s NcloudSecretListItem,
	selected bool,
	seen map[string]struct{},
) (data []byte, skip bool, err error) {
	disposition := classifyListedSecret(s.SecretStatus)
	if disposition == listedSecretTombstone {
		c.forgetResolutionByID(s.SecretID)
		return nil, true, nil
	}

	// One value per name, whoever supplies the rows. listAllSecretItems
	// already yields at most one live row per name; this holds the rule at the
	// point where a duplicate would otherwise become two reads of one key.
	if _, dup := seen[s.SecretName]; dup {
		return nil, true, nil
	}
	seen[s.SecretName] = struct{}{}

	if disposition == listedSecretUnreadable {
		if !selected {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf(msgGetSecret, displayName(s.SecretName), ErrInvalidStatus)
	}

	if c.cache != nil {
		c.cache.Set(s.SecretName, s.SecretID)
	}
	if !selected {
		return nil, true, nil
	}

	return c.readListedSecretValue(ctx, s)
}

// readListedSecretValue reads one listed secret's active value. skip reports an
// entry that vanished or entered deletion between the listing and the read,
// which is an expected race rather than a failure.
//
// Every other failure - authorization above all - fails the whole find. A
// partial map is indistinguishable to ESO core from "these keys no longer
// exist", so returning one on a permission error silently deletes the keys the
// credential can no longer read.
func (c *Client) readListedSecretValue(
	ctx context.Context,
	s NcloudSecretListItem,
) (data []byte, skip bool, err error) {
	valResp, err := c.client.GetSecretValue(ctx, s.SecretID)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			c.forgetResolutionByID(s.SecretID)
			logFor(ctx).V(1).Info(
				"skipping secret deleted during GetAllSecrets",
				"secretName", displayName(s.SecretName), "reason", err.Error())
			return nil, true, nil
		}
		// The listing said readable but the value endpoint disagrees: re-read the
		// lifecycle to tell an ENABLE -> REVOKE race apart from a real failure.
		if deletionLifecycleCandidate(err) && c.enteredDeletion(ctx, s.SecretID) {
			c.forgetResolutionByID(s.SecretID)
			logFor(ctx).V(1).Info(
				"skipping secret that entered deletion lifecycle during GetAllSecrets",
				"secretName", displayName(s.SecretName), "reason", err.Error())
			return nil, true, nil
		}
		return nil, false, fmt.Errorf(msgGetSecret, displayName(s.SecretName), err)
	}

	data = extractSecretForStage(valResp, stageActive)
	if len(data) == 0 {
		name := displayName(s.SecretName)
		return nil, false, fmt.Errorf(
			msgGetSecret,
			name,
			fmt.Errorf(msgEmptyStage, ErrEmptySecretData, name, stageActive),
		)
	}
	return data, false, nil
}

// enteredDeletion reports whether secretID is now gone or in a deletion
// lifecycle state. An unreadable detail response answers false, keeping the
// caller fail-closed.
func (c *Client) enteredDeletion(ctx context.Context, secretID string) bool {
	gone, _ := c.deletionState(ctx, secretID)
	return gone
}

// deletionState is enteredDeletion that also returns the status the detail
// read saw when the secret is not gone, so a caller can name it.
func (c *Client) deletionState(ctx context.Context, secretID string) (gone bool, status string) {
	detail, err := c.client.GetSecretDetail(ctx, secretID)
	if errors.Is(err, ErrSecretNotFound) {
		return true, ""
	}
	if err != nil || detail == nil {
		return false, ""
	}
	status = detail.Data.SecretStatus
	return status == secretStatusRevoke || status == secretStatusDestroyed, status
}

// maxListSweepRetries bounds how many times a listing sweep is redone: after
// one that shifted or was incomplete, and to confirm an absence.
const maxListSweepRetries = 2

// listSweep tracks whether one ListSecrets sweep saw a stable collection.
//
// The listing is read page by page, so a secret removed from an already-read
// page shifts every later entry up by one. That can move a live secret out of
// the pages the sweep has left to read, and the sweep then concludes the name
// does not exist - which negative-caches it and makes a deletionPolicy: Delete
// ExternalSecret drop its target Secret.
//
// A totalCount that changes between pages marks the sweep as shifted. It
// catches the ordinary case (an entry left or joined the collection mid-sweep)
// but not a delete and a create that cancel out, which is why absence is
// confirmed by a second sweep (see absenceConfirmed). A response without the
// field reads as zero on every page, which counts as stable and leaves
// behavior unchanged.
type listSweep struct {
	total     int
	haveTotal bool
	shifted   bool
	seen      int
	ids       map[string]struct{} // secret IDs seen; see incomplete
	repeated  bool                // an ID came back a second time
	pages     int
	declared  bool // the server reported a page count at least once
}

func (s *listSweep) observe(resp *NcloudListSecretsResponse) {
	s.seen += len(resp.Data.SecretList)
	if s.ids == nil {
		s.ids = make(map[string]struct{}, len(resp.Data.SecretList))
	}
	for _, item := range resp.Data.SecretList {
		if item.SecretID == "" {
			continue
		}
		if _, dup := s.ids[item.SecretID]; dup {
			s.repeated = true
		}
		s.ids[item.SecretID] = struct{}{}
	}
	s.pages++
	if resp.Data.TotalPageNo > 0 {
		s.declared = true
	}
	switch {
	case !s.haveTotal:
		s.total = resp.Data.TotalCount
		s.haveTotal = true
	case resp.Data.TotalCount != s.total:
		s.shifted = true
	}
}

// incomplete reports a finished sweep that read some ID twice, or whose row
// count the server-declared total does not account for. shifted catches a
// total that CHANGED mid-sweep; this catches a total that held still while a
// page under- or over-delivered (a glitching server answering one page empty
// or short, or repeating rows), which would otherwise pass as a
// stable-but-partial sweep.
//
// The rows must match the total exactly. The rule assumes that every row the
// listing returns is counted in its total, REVOKE rows included. Do not
// loosen it to accept rows beyond the total: a sweep whose rows and total
// disagree may have missed a row, and accepting the extra ones does not
// read the missed one. A repeated ID fails on its own, since a row read
// twice can stand in for one never read with the count still matching, and
// a one-page sweep is believed without a second (absenceConfirmed). A zero
// total is "field absent" per the type comment above, and only the repeat
// check applies.
func (s *listSweep) incomplete() bool {
	if s.repeated {
		return true
	}
	if !s.haveTotal || s.total <= 0 {
		return false
	}
	return s.seen != s.total
}

func (s *listSweep) reset() { *s = listSweep{} }

// absenceConfirmed reports whether a stable sweep that found nothing may be
// believed. Every path that concludes absence asks it, so the rule cannot
// drift. The stability gates compare counts, and a delete and a create that
// land together leave totalCount unchanged while shifting every later name
// back a page, so a sweep can miss a secret that never stopped existing.
// The remedy is to ask twice: confirmed says the previous sweep was stable
// and agreed.
//
// A sweep the server DECLARED to be one page is exempt: there is no window
// between pages. Declared matters because hasMorePages also ends a sweep at
// page 1 when the response omits totalPageNo and carries no rows, which
// incomplete() cannot flag either. seen > 0 is the other first-hand case.
func absenceConfirmed(sweep *listSweep, confirmed bool) bool {
	firstHand := sweep.pages == 1 && (sweep.declared || sweep.seen > 0)
	return firstHand || confirmed
}

// maxListPages caps ListSecrets pagination. When TotalPageNo is absent the
// loops page until an empty response; a server that clamps an out-of-range
// pageNo to the last non-empty page would otherwise loop forever.
const maxListPages = 10_000

// maxListRows caps the rows one sweep reads across its pages. Each page is
// already bounded (maxListRowsPerPage), but a sweep accumulates rows and
// names, and maxListPages full pages would be ten million rows.
const maxListRows = 100_000

// maxSweepElapsed bounds one listing sweep in wall-clock time. Each page has
// its own 45-second budget (maxGetElapsed), so without this a server that
// answers every page just inside it, with a page count to match, could hold
// the controller's single default worker for days. A var so tests can
// shrink it.
var maxSweepElapsed = 3 * time.Minute

// sweepBudget derives the context one listing sweep runs under.
func sweepBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, maxSweepElapsed)
}

// sweepFailure names a sweep that ran out of its own budget; any other error,
// the caller's own cancellation included, is returned as it came.
func sweepFailure(parent context.Context, err error) error {
	if errors.Is(err, context.DeadlineExceeded) && parent.Err() == nil {
		return fmt.Errorf(msgSweepTooSlow, maxSweepElapsed, err)
	}
	return err
}

// tooManyRows reports a sweep that has read past maxListRows.
func tooManyRows(sweep *listSweep) error {
	if sweep.seen > maxListRows {
		return fmt.Errorf(msgTooManyRows, maxListRows)
	}
	return nil
}

// hasMorePages reports whether another page should be fetched after pageNo.
// A declared TotalPageNo is authoritative: an empty page mid-sweep must not
// end the listing, or a glitching server would silently truncate results into
// a partial-but-successful map or a false NoSecretErr. A zero TotalPageNo
// (field missing) means unknown: keep fetching until an empty page.
func hasMorePages(pageNo int, resp *NcloudListSecretsResponse) bool {
	if resp.Data.TotalPageNo > 0 {
		return pageNo < resp.Data.TotalPageNo
	}
	return len(resp.Data.SecretList) > 0
}

// SecretExists checks if a secret exists in Ncloud Secret Manager. Names are
// resolved through the fresh write-path listing so stale shared-cache entries
// cannot produce a false positive. Metadata confirms that a listed entry was
// not already destroyed. When property is set, the active value must also be
// readable and that exact top-level property must exist, matching PushSecret's
// merge/delete contract.
func (c *Client) SecretExists(ctx context.Context, ref esv1.PushSecretRemoteRef) (bool, error) {
	if c.client == nil {
		return false, ErrUninitializedClient
	}

	key := ref.GetRemoteKey()
	if !canNameASecret(key) {
		// A key no secret can carry (16+ characters, a space, a leading
		// digit) is known absent without a listing, as PushSecret already
		// refuses it without one.
		return false, nil
	}
	// An ID-shaped key cannot be a name (see secretNamePattern), so its
	// NotFound is final; a name is resolved to a secret that still exists.
	idKey := isSecretIDFormat(key)
	resolve := c.resolveLiveTarget
	if idKey {
		resolve = c.readTarget
	}
	for attempt := 0; ; attempt++ {
		secretID, detail, err := resolve(ctx, key)
		if errors.Is(err, ErrSecretNotFound) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf(msgCheckSecret, err)
		}
		// A REVOKE secret holds no readable value and the read paths report it as
		// not found. Reporting it present would let updatePolicy=IfNotExists skip
		// the push and mark the PushSecret Synced while the data exists nowhere
		// readable. Answering false makes the push run, and the occupied name then
		// fails loudly (see docs).
		if detail.Data.SecretStatus == secretStatusRevoke {
			return false, nil
		}

		if ref.GetProperty() == "" {
			return true, nil
		}

		value, err := c.client.GetSecretValue(ctx, secretID)
		if errors.Is(err, ErrSecretNotFound) {
			// Destroyed between the detail read and this one. For a name, the
			// 404 says no more than one on the detail would: the name may be
			// held again, so it is resolved once more (see resolveLiveTarget).
			c.forgetResolutionByID(secretID)
			if idKey || attempt > 0 {
				return false, nil
			}
			continue
		}
		if err != nil {
			// Forbidden, revoked/unreadable, transient, and malformed responses
			// all fail closed. Returning the error preserves the reason while the
			// false result prevents IfNotExists from treating it as present.
			return false, fmt.Errorf(msgCheckSecret, err)
		}
		return propertyPresent(value, ref.GetProperty())
	}
}

// propertyPresent reports whether the active stage of value is a JSON object
// that holds property.
func propertyPresent(value *NcloudSecretValueResponse, property string) (bool, error) {
	activeValue := extractSecretForStage(value, stageActive)
	if len(activeValue) == 0 {
		return false, fmt.Errorf(msgCheckSecret, ErrEmptySecretData)
	}
	active, ok := decodeJSONObject(activeValue)
	if !ok {
		return false, fmt.Errorf(msgCheckSecret, errSecretValueNotObject)
	}
	_, exists := active[property]
	return exists, nil
}

// Secret status enum values returned by the API.
const (
	secretStatusEnable    = "ENABLE"
	secretStatusDisable   = "DISABLE"
	secretStatusRotating  = "ROTATING"
	secretStatusRevoke    = "REVOKE"
	secretStatusDestroyed = "DESTROYED"
)

// forgetResolutionByID removes indexed and cached mappings to an ID that is
// confirmed gone or in a deletion lifecycle. InvalidateByID is deliberately
// ID-scoped so a live duplicate with the same name is not evicted.
func (c *Client) forgetResolutionByID(id string) {
	c.writes.Forget(id)
	if c.cache != nil {
		c.cache.InvalidateByID(id)
	}
}

// secretNamePattern is what the Create Secret API accepts as a name: letters,
// digits, '-' and '_', 3-15 characters, starting with a letter. Every secret in
// an account was created under it, so it bounds what a READ key can resolve to
// as well, not just what a create may ask for. Both paths use it for that
// reason: a name the write path would refuse is a name the read path can never
// find, and answering it from the syntax spares a full listing sweep and a
// cache entry.
var secretNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{2,14}$`)

// canNameASecret reports whether key could address a secret at all: a 64-char
// hex ID or a name the API would have accepted. Anything else cannot exist
// remotely, and answering from the syntax keeps it out of the listing and the
// cache, which bounds entry count, not key size.
func canNameASecret(key string) bool {
	return isSecretIDFormat(key) || secretNamePattern.MatchString(key)
}

// displayName renders a server-supplied secret name for an error or a log
// line: as is when it is a name the API accepts, otherwise quoted and cut to
// 40 characters, because the listing is server text and the message reaches
// the controller log.
func displayName(name string) string {
	if secretNamePattern.MatchString(name) {
		return name
	}
	return fmt.Sprintf("%.40q", name)
}

// unaddressableKeyError is the read path's answer for a key canNameASecret
// rejects: an error, not an absence (see ErrKeyNotAddressable). The key is
// quoted so the operator sees what was asked, and cut to 40 characters, as
// displayName cuts a name, because it is manifest text of any length and the
// error reaches the controller log. The precision counts characters, so a
// multibyte key is never cut inside a character.
func unaddressableKeyError(key string) error {
	return fmt.Errorf("%w: got %.40q", ErrKeyNotAddressable, key)
}

// PushSecret creates or updates the active value of a remote secret from a
// Kubernetes Secret. The remote key is the Ncloud secret name (or an existing
// secret's ID); data.GetSecretKey selects one key of the Kubernetes Secret
// (empty pushes the whole Data map as a JSON object), and data.GetProperty
// merges the value under a top-level key of the remote JSON object instead of
// replacing the whole value.
func (c *Client) PushSecret(ctx context.Context, secret *corev1.Secret, data esv1.PushSecretData) error {
	if c.client == nil {
		return ErrUninitializedClient
	}
	if data.GetMetadata() != nil {
		// Fail loudly instead of silently dropping metadata the user asked for.
		return ErrPushMetadataNotSupported
	}

	remoteKey := data.GetRemoteKey()
	prepared, err := preparePushValue(secret, data.GetSecretKey(), data.GetProperty())
	if err != nil {
		return err
	}

	if isSecretIDFormat(remoteKey) {
		return c.updateSecretByID(ctx, remoteKey, data.GetProperty(), prepared.value)
	}
	if !secretNamePattern.MatchString(remoteKey) {
		return fmt.Errorf(msgInvalidSecretName, remoteKey)
	}

	// Resolve through a fresh listing (shared across this reconcile's keys via
	// the write index) so a stale cache entry cannot route the write to a
	// deleted secret.
	secretID, err := c.writes.Resolve(ctx, c.client, c.cache, remoteKey)
	switch {
	case err == nil:
		pushErr := c.updateResolvedSecret(ctx, remoteKey, secretID, data.GetProperty(), prepared.value)
		if pushErr == nil || !errors.Is(pushErr, ErrSecretNotFound) {
			return pushErr
		}
		// The secret was destroyed between the resolution listing and the
		// update (same tolerance the delete path applies): drop the dead
		// mapping and create a replacement.
		c.writes.Forget(secretID)
		if c.cache != nil {
			c.cache.Invalidate(remoteKey)
			c.cache.InvalidateByID(secretID)
		}
		return c.createSecretLocked(ctx, remoteKey, data.GetProperty(), prepared, secretID)
	case !errors.Is(err, ErrSecretNotFound):
		return fmt.Errorf(msgPushSecret, remoteKey, err)
	}

	return c.createSecretLocked(ctx, remoteKey, data.GetProperty(), prepared, "")
}

// requireManagedSecret fails a mutation of a secret whose memo lacks the
// managed-by marker. The detail read doubles as the existence probe, so a
// vanished secret surfaces as ErrSecretNotFound. The detail is returned
// because callers hold the secret's lock across what follows: its lifecycle
// status explains a refused value read, and a fall-through to the full delete
// skips a second identical read. ErrNotManagedByESO comes with the detail too,
// so a property deletion can tell a DESTROYED row, whose memo may not have
// survived, from a live secret someone else owns.
func (c *Client) requireManagedSecret(ctx context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
	detail, err := c.client.GetSecretDetail(ctx, secretID)
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, errEmptySecretDetail
	}
	if !isManagedByESO(detail.Data.Memo) {
		return detail, ErrNotManagedByESO
	}
	return detail, nil
}

// isManagedByESO reports whether the memo carries the ownership marker as a
// line of its own. Containment would be wrong: the memo is free text, so a
// negation ("not managed-by: external-secrets") or a sentence copied from the
// adoption instructions would pass, and a false positive on the delete gate
// destroys a secret external-secrets does not own. A whole line rather than
// the whole memo lets the marker coexist with a human description.
func isManagedByESO(memo string) bool {
	for line := range strings.SplitSeq(memo, "\n") {
		if strings.TrimSpace(line) == managedByMemo {
			return true
		}
	}
	return false
}

// updateSecretByID updates a direct ID while holding the same lock used for
// every other mutation of it. The ownership read doubles as the existence
// probe, so no separate detail read is needed. An ID-shaped key cannot be a
// name (see secretNamePattern), so its NotFound is final and is reported as
// an invalid remote key rather than retried against the listing or answered
// with a create.
func (c *Client) updateSecretByID(ctx context.Context, secretID, property string, value []byte) error {
	unlock, err := locks.TryLock(providerName, secretID)
	if err != nil {
		return fmt.Errorf(msgPushSecret, secretID, err)
	}
	defer unlock()

	// Only the gate read's NotFound is authoritative absence; a NotFound
	// from the update path below it (destroyed concurrently) keeps its
	// sentinel for the caller.
	detail, err := c.requireManagedSecret(ctx, secretID)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			// Confirmed gone: drop any name -> this ID mapping so the rest of
			// the reconcile does not route another operation to a dead ID.
			c.forgetResolutionByID(secretID)
			return fmt.Errorf(msgSecretIDNotFound, secretID)
		}
		return fmt.Errorf(msgPushSecret, secretID, err)
	}
	return c.updateManagedSecretValue(ctx, secretID, secretID, property, value, detail.Data.SecretStatus, boundaryOf(detail))
}

// updateResolvedSecret serializes every mutation of one existing remote
// secret. In particular, the lock spans the read and update performed by a
// property merge so concurrent PushSecret/DeleteSecret calls in this process
// cannot overwrite one another's fields.
func (c *Client) updateResolvedSecret(ctx context.Context, remoteKey, secretID, property string, value []byte) error {
	unlock, err := locks.TryLock(providerName, secretID)
	if err != nil {
		return fmt.Errorf(msgPushSecret, remoteKey, err)
	}
	defer unlock()

	return c.updateSecretValue(ctx, remoteKey, secretID, property, value)
}

// updateSecretValue writes value (optionally merged under property) as the
// secret's active stage, skipping the write when nothing would change.
func (c *Client) updateSecretValue(ctx context.Context, remoteKey, secretID, property string, value []byte) error {
	// Ownership gate for every value update, matching the AWS provider: a
	// push must not overwrite a secret external-secrets does not own. Creates
	// stamp the marker below, so only externally created (or not yet adopted)
	// secrets are refused.
	detail, err := c.requireManagedSecret(ctx, secretID)
	if err != nil {
		return fmt.Errorf(msgPushSecret, remoteKey, err)
	}
	return c.updateManagedSecretValue(ctx, remoteKey, secretID, property, value, detail.Data.SecretStatus, boundaryOf(detail))
}

// updateManagedSecretValue is updateSecretValue after the ownership gate, for
// a caller that already performed the gating detail read. status and boundary
// are the lifecycle state and key boundary that read observed; they are used
// to explain a refused read or write.
func (c *Client) updateManagedSecretValue(
	ctx context.Context,
	remoteKey, secretID, property string,
	value []byte,
	status, boundary string,
) error {
	current, err := c.client.GetSecretValue(ctx, secretID)
	if err != nil {
		// A REVOKE or DISABLE secret refuses this read, and the bare error gives
		// the operator nothing to act on. status is what the gating read saw
		// under this lock, so it is offered as the observed state, and only
		// when it explains the refusal (an ENABLE secret also answers 400 to a
		// bad request). The server's error stays wrapped: its code is what an
		// operator can look up.
		if deletionLifecycleCandidate(err) && (status == secretStatusRevoke || status == secretStatusDisable) {
			return fmt.Errorf(msgPushSecret, remoteKey,
				fmt.Errorf("%w; the detail read just before it saw that %s", err, occupiedNameAdvice(status)))
		}
		return fmt.Errorf(msgPushSecret, remoteKey, err)
	}
	if current == nil {
		return fmt.Errorf(msgPushSecret, remoteKey, errEmptySecretValue)
	}
	active := extractSecretForStage(current, stageActive)

	if property != "" {
		value, err = mergePropertyValue(active, property, value)
		if err != nil {
			return fmt.Errorf(msgPushSecret, remoteKey, err)
		}
	}
	if err := validatePushObject(value); err != nil {
		return fmt.Errorf(msgPushSecret, remoteKey, err)
	}

	// Byte equality only: a stored value whose key order or whitespace is not
	// Go-canonical is re-pushed once (safe direction - a real change is never
	// skipped) and is canonical from then on.
	//
	// Checked before the rotation-target validation on purpose: a secret whose
	// stored value already lacks one of its persisted rotation targets (a
	// value written outside this provider) would otherwise fail that
	// validation forever, including for a push that changes nothing at all.
	// Writes that do change the value are still validated below.
	if bytes.Equal(active, value) {
		return nil // already up to date; avoid a pointless re-encrypt
	}

	if err := validatePersistedRotationTargets(value, current.Data.RotationTargets); err != nil {
		return fmt.Errorf(msgPushSecret, remoteKey, err)
	}

	if err := c.client.UpdateSecretStageValue(ctx, secretID, stageActive, string(value)); err != nil {
		return fmt.Errorf(msgPushSecret, remoteKey, describeUpdateRejection(err, status, boundary))
	}
	return nil
}

// describeCreateRejection adds the one fact a rejected create needs and the
// error cannot show: the KMS key boundary the request declared. Only a 400 or
// 404 is decorated; a 5xx or a timeout says nothing about boundaries. An
// endpoint serves one boundary and enforces it on create. Nothing is created,
// and the message names what was asked for so the fix (the endpoint matching
// the account's key) is obvious.
func describeCreateRejection(err error, boundary string) error {
	if !errors.Is(err, ErrInvalidRequest) && !errors.Is(err, ErrSecretNotFound) {
		return err
	}
	// The boundary came from ListProtectionKeys, so it is server text.
	return fmt.Errorf("create declared kmsBoundaryType=%s and the endpoint rejected it; "+
		"if this account's default key belongs to the other boundary, point the store at the matching endpoint "+
		"(ISOLATED-key secrets: an ocapi endpoint, legacy GLOBAL-key secrets: the apigw endpoint): %w", echoedBoundary(boundary), err)
}

// describeUpdateRejection explains a 409 on a value update of a secret the
// gating read saw ENABLE, the one state whose lifecycle gives the service no
// reason to refuse a write (the update runs only after the value read, which
// a REVOKE or DISABLE secret refuses; a ROTATING one is left alone, since a
// rotation in progress could be the reason). The remaining explanation is an
// endpoint that does not serve the secret's key boundary. The hint names the
// boundary the secret's key belongs to, so the matching endpoint is obvious.
func describeUpdateRejection(err error, status, boundary string) error {
	if !errors.Is(err, ErrInvalidStatus) || status != secretStatusEnable {
		return err
	}
	return fmt.Errorf("the secret's key has kmsBoundaryType=%s and the endpoint refused to write it; "+
		"if this endpoint serves the other boundary, point the store at the matching endpoint "+
		"(ISOLATED-key secrets: an ocapi endpoint, legacy GLOBAL-key secrets: the apigw endpoint): %w", echoedBoundary(boundary), err)
}

// boundaryOf returns the key boundary a detail read reported, or "".
func boundaryOf(detail *NcloudSecretDetailResponse) string {
	if detail == nil || detail.Data.ProtectionKey == nil {
		return ""
	}
	return detail.Data.ProtectionKey.KmsBoundaryType
}

// echoedBoundary is a boundary safe to put in an error: one of the values
// this package knows, or a placeholder for server text.
func echoedBoundary(boundary string) string {
	switch boundary {
	case "":
		return "(omitted)"
	case kmsBoundaryGlobal, kmsBoundaryIsolated:
		return boundary
	default:
		// Server text (see describeSecretStatus).
		return "(unrecognized)"
	}
}

// The two KMS boundary values Ncloud documents. echoedBoundary passes a
// boundary through only when it is one of these, since the value is server
// text.
const (
	kmsBoundaryGlobal   = "GLOBAL"
	kmsBoundaryIsolated = "ISOLATED"
)

// defaultKeyBoundaryType returns the KMS region-isolation boundary to declare
// on a create, or "" to omit the field. It is read from the account's own
// protection keys (the default key is the entry with no tag, which is what
// protectionKeyType DEFAULT selects) rather than configured: the boundary
// describes the account and region, so a store author has no basis to choose
// it. Every failure degrades to "": a create that needs the field then fails
// with the server's own MISSING_REQUIRED_FIELD rather than a guess, and an
// account that never needed it is unaffected. Only a successful listing is
// latched, so a transient failure is retried by the next create.
func (c *Client) defaultKeyBoundaryType(ctx context.Context) string {
	c.boundaryMu.Lock()
	defer c.boundaryMu.Unlock()

	if c.boundaryDone {
		return c.boundaryType
	}

	resp, err := c.client.ListProtectionKeys(ctx)
	if err != nil || resp == nil {
		if err != nil {
			// Logged at Info, not V(1): on a region-isolated account this makes
			// the create that follows fail with the server's own
			// MISSING_REQUIRED_FIELD, and the two are otherwise impossible to
			// connect. A credential that cannot list protection keys is the
			// common cause. Fires at most once per failed create.
			logFor(ctx).Info(
				"could not resolve the default protection key boundary; kmsBoundaryType will be omitted, which a region-isolated account rejects",
				"reason", err.Error(),
				"hint", "grant the credential permission to list protection keys")
		}
		return ""
	}
	c.boundaryDone = true

	for _, key := range resp.Data.KeyList {
		if key.KeyTag == "" {
			c.boundaryType = key.KmsBoundaryType
			return c.boundaryType
		}
	}
	return ""
}

// preparedPushValue carries the JSON value fragment used by the update/create
// paths and the top-level fields Ncloud requires as rotation targets on
// create. value is a complete object when property is empty; otherwise it is
// the JSON string to merge under property.
type preparedPushValue struct {
	value           []byte
	rotationTargets []string
}

// occupiedNameError explains a name that exists but cannot be written to.
// "invalid status" on its own leaves the operator guessing, and the two states
// that reach here have different answers: a deletion-requested secret frees its
// name on Ncloud's schedule, while a paused one needs a deliberate resume.
func occupiedNameError(status string) error {
	return fmt.Errorf("%w: %s", ErrInvalidStatus, occupiedNameAdvice(status))
}

// occupiedNameAdvice describes, in one operator-facing sentence, why a name in
// this state cannot be written to and what frees it. Split out from
// occupiedNameError so a caller that already has the server's own error can
// add the advice without wrapping a second copy of the sentinel.
func occupiedNameAdvice(status string) string {
	switch status {
	case secretStatusRevoke:
		return "the name is held by a secret whose deletion was requested; " +
			"the provider will not create over it until the 7-day grace period ends and Ncloud destroys it, " +
			"or restore that secret with Cancel Secret Deletion followed by Enable Secret"
	case secretStatusDisable:
		return "the name is held by a paused (DISABLE) secret; " +
			"resume it with Enable Secret before writing to it"
	default:
		// The status is server text (see describeSecretStatus).
		return "the name is held by a secret in " + describeSecretStatus(status) +
			", which cannot be written to"
	}
}

// describeSecretStatus renders a server-reported lifecycle status for an error
// that reaches the controller log. Only a status this provider declares is
// quoted back; server strings are refused on the same grounds as in
// handleErrorResponse. An absent status gets its own wording because reads
// and creates tolerate it while a delete refuses to act on a state it cannot
// see.
func describeSecretStatus(status string) string {
	switch {
	case status == "":
		return "a state the server did not report"
	case knownSecretStatus(status):
		return fmt.Sprintf("state %q", status)
	default:
		return "a state this provider does not recognize"
	}
}

// knownSecretStatus reports whether status is one of the lifecycle states this
// provider understands, and therefore safe to quote back to the operator.
func knownSecretStatus(status string) bool {
	switch status {
	case secretStatusEnable, secretStatusDisable, secretStatusRotating,
		secretStatusRevoke, secretStatusDestroyed:
		return true
	default:
		return false
	}
}

// createSecretLocked serializes creates by secret name because no provider ID
// exists until the API succeeds. Absence is rechecked while holding the lock:
// two clients can both finish their initial listing before either acquires the
// name lock, and without the recheck they could create the same name
// sequentially. A live secret the recheck finds is another writer's, and the
// create fails with ErrNameTakenMeanwhile instead of updating it (see that
// error). vanished is the exception: the secret this reconcile resolved and
// then saw answer NotFound, or "" when the resolution found the name absent.
// The recheck does not assume that the listing already reflects that the
// secret is gone, so a row with that ID is not another writer's.
func (c *Client) createSecretLocked(ctx context.Context, name, property string, prepared preparedPushValue, vanished string) error {
	unlock, err := locks.TryLock(providerName, name)
	if err != nil {
		return fmt.Errorf(msgPushSecret, name, err)
	}
	defer unlock()

	item, err := c.listingRowFor(ctx, name)
	switch {
	case err == nil:
		secretID := item.SecretID
		if item.SecretStatus == secretStatusDestroyed || (vanished != "" && secretID == vanished) {
			// A DESTROYED row, or the row of the secret this reconcile just
			// saw gone (the listing is not assumed to reflect that yet), is
			// not a competing live creator and must not wedge replacement
			// creation.
			c.writes.Forget(secretID)
			if c.cache != nil {
				c.cache.Invalidate(name)
				c.cache.InvalidateByID(secretID)
			}
			break
		}
		// Only REVOKE/DISABLE/unknown states are reported as occupied (the
		// name is held but not writable); a live row, ROTATING included, is a
		// creator that won after the pre-lock absence check.
		if item.SecretStatus != "" &&
			item.SecretStatus != secretStatusEnable &&
			item.SecretStatus != secretStatusRotating {
			return fmt.Errorf(msgPushSecret, name, occupiedNameError(item.SecretStatus))
		}
		return fmt.Errorf(msgPushSecret, name, ErrNameTakenMeanwhile)
	case !errors.Is(err, ErrSecretNotFound):
		return fmt.Errorf(msgPushSecret, name, err)
	}

	return c.createSecret(ctx, name, property, prepared)
}

// createSecret creates a new BASIC secret with rotation off and the default
// protection key, then warms the name -> ID cache with the assigned ID.
func (c *Client) createSecret(ctx context.Context, name, property string, prepared preparedPushValue) error {
	if !secretNamePattern.MatchString(name) {
		return fmt.Errorf(msgInvalidSecretName, name)
	}

	value := prepared.value
	if property != "" {
		var err error
		value, err = mergePropertyValue(nil, property, value)
		if err != nil {
			return fmt.Errorf(msgPushSecret, name, err)
		}
	}
	if err := validatePushObject(value); err != nil {
		return fmt.Errorf(msgPushSecret, name, err)
	}

	rotationTargets := append([]string(nil), prepared.rotationTargets...)
	sort.Strings(rotationTargets)
	if len(rotationTargets) == 0 {
		return fmt.Errorf(msgPushSecret, name, errPushRotationTargets)
	}
	if slices.Contains(rotationTargets, "") {
		return fmt.Errorf(msgPushSecret, name, errPushRotationTargets)
	}

	boundary := c.defaultKeyBoundaryType(ctx)
	resp, err := c.client.CreateSecret(ctx, &NcloudCreateSecretRequest{
		SecretName: name,
		Memo:       managedByMemo,
		SecretValue: NcloudSecretValuePayload{
			Value:           string(value),
			RotationTargets: rotationTargets,
		},
		SecretType:        "BASIC",
		AutoRotationYN:    "N",
		ProtectionKeyType: "DEFAULT",
		KmsBoundaryType:   boundary,
	})
	if err != nil {
		// A create that timed out or lost its answer may have created the
		// secret, so the listing miss's negative entry is cleared here too;
		// see the missing-ID case below for why it must not survive.
		if c.cache != nil {
			c.cache.Invalidate(name)
		}
		return fmt.Errorf(msgPushSecret, name, describeCreateRejection(err, boundary))
	}

	if resp == nil || !isSecretIDFormat(resp.Data.SecretID) {
		// The documented Create response always carries data.secretId in the
		// form the API issues; treat anything else as a contract violation
		// and fail loudly rather than pin, cache or lock on it. The secret
		// may well have been created, so the next
		// reconcile resolves it via the listing. Clear the pre-create negative
		// entry too, or the new secret reads as NotFound for the negative TTL,
		// which deletionPolicy=Delete acts on.
		if c.cache != nil {
			c.cache.Invalidate(name)
		}
		return fmt.Errorf(msgCreateNoID, name)
	}

	c.writes.Pin(name, resp.Data.SecretID)
	if c.cache != nil {
		c.cache.Set(name, resp.Data.SecretID)
	}
	return nil
}

// preparePushValue validates and converts Kubernetes Secret data before any
// provider API call. Every complete value sent to Ncloud is a nonempty JSON
// object whose leaves are strings. A selected key is wrapped under that key;
// with property set, the selected string becomes the value fragment merged
// under the top-level property, and a property without a key is refused.
func preparePushValue(secret *corev1.Secret, key, property string) (preparedPushValue, error) {
	var zero preparedPushValue

	// Checked before the data itself: this combination is unsatisfiable
	// whatever the Secret holds, so reporting a data problem first would send
	// the user to fix something that still would not work.
	if key == "" && property != "" {
		return zero, ErrPushWholeDataUnderProperty
	}
	if secret == nil || len(secret.Data) == 0 {
		return zero, errPushEmptyData
	}

	if !utf8.ValidString(key) || !utf8.ValidString(property) {
		return zero, errPushInvalidUTF8
	}

	if key != "" {
		return prepareSelectedKey(secret, key, property)
	}
	return prepareWholeData(secret)
}

// prepareSelectedKey is preparePushValue for a push that selects one data key.
func prepareSelectedKey(secret *corev1.Secret, key, property string) (preparedPushValue, error) {
	var zero preparedPushValue
	v, ok := secret.Data[key]
	if !ok {
		return zero, fmt.Errorf(msgPushMissingKey, key)
	}
	if !utf8.Valid(v) {
		return zero, errPushInvalidUTF8
	}

	target := key
	var value any = map[string]string{key: string(v)}
	if property != "" {
		target = property
		value = string(v)
	}
	encoded, err := esutils.JSONMarshal(value)
	if err != nil {
		return zero, err
	}
	return preparedPushValue{value: encoded, rotationTargets: []string{target}}, nil
}

// prepareWholeData is preparePushValue for a push of the whole Secret.
func prepareWholeData(secret *corev1.Secret) (preparedPushValue, error) {
	var zero preparedPushValue
	keys := make([]string, 0, len(secret.Data))
	whole := make(map[string]string, len(secret.Data))
	for k, v := range secret.Data {
		if k == "" {
			return zero, errPushEmptyDataKey
		}
		if !utf8.ValidString(k) || !utf8.Valid(v) {
			return zero, errPushInvalidUTF8
		}
		keys = append(keys, k)
		whole[k] = string(v)
	}
	sort.Strings(keys)

	encoded, err := esutils.JSONMarshal(whole)
	if err != nil {
		return zero, err
	}
	// Every data key is a rotation target, and each is a top-level field of
	// the object above. Ncloud requires targets to name fields the value
	// actually carries.
	return preparedPushValue{value: encoded, rotationTargets: keys}, nil
}

// mergePropertyValue sets property to value inside the JSON object current (an
// empty or whitespace-only current starts a fresh object). value is
// json.Marshal output, so it is safe to embed as a RawMessage. property is a
// literal top-level key, never a path: synthesizing intermediate objects from
// a dotted name would let a rename restructure a secret other writers share.
// The read side prefers the literal key too (mapSecretToGjson); see the
// property note in docs/provider/ncloud.md.
func mergePropertyValue(current []byte, property string, value []byte) ([]byte, error) {
	obj := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(current)) > 0 {
		var ok bool
		obj, ok = decodeJSONObject(current)
		if !ok {
			return nil, fmt.Errorf(msgPushNotObject, property)
		}
	}

	obj[property] = append(json.RawMessage(nil), value...)

	return esutils.JSONMarshal(obj)
}

// decodeJSONObject parses data only when its top-level JSON value is an
// object. Parser errors are deliberately discarded because they may quote a
// byte of decrypted secret material.
func decodeJSONObject(data []byte) (map[string]json.RawMessage, bool) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &obj); err != nil || obj == nil {
		return nil, false
	}
	return obj, true
}

func validatePushObject(value []byte) error {
	obj, ok := decodeJSONObject(value)
	if !ok || len(obj) == 0 {
		return errPushEmptyObject
	}
	return nil
}

// validatePersistedRotationTargets prevents value updates from orphaning the
// immutable rotation-target metadata established when Ncloud created the
// secret: a value update can change stages, not that target list.
//
// The rule is enforced unconditionally because Ncloud enforces it
// unconditionally: the service rejects a value omitting a persisted target
// whatever the rotation setting, on both the create and the update path.
func validatePersistedRotationTargets(value []byte, targets []string) error {
	obj, ok := decodeJSONObject(value)
	if !ok {
		return errPushEmptyObject
	}
	for _, target := range targets {
		if target == "" {
			return errPushRotationTargets
		}
		if _, exists := obj[target]; !exists {
			return errRotationTargetAbsent
		}
	}
	return nil
}

// DeleteSecret removes either one managed top-level property or the whole
// secret. Property deletion is a locked read-modify-write that preserves every
// sibling field; removing the final field falls through to full deletion.
// Full deletion stops at Ncloud's REVOKE (deletion requested) state by
// default, leaving the 7-day recovery window to Ncloud; with
// ForceDeleteWithoutRecovery it destroys the secret immediately. Deleting a
// missing secret/property succeeds silently.
func (c *Client) DeleteSecret(ctx context.Context, remoteRef esv1.PushSecretRemoteRef) error {
	if c.client == nil {
		return ErrUninitializedClient
	}

	key := remoteRef.GetRemoteKey()
	if !canNameASecret(key) {
		// Nothing to delete: no secret can carry such a key, so the listing
		// SecretExists and PushSecret also skip for it is not paid here.
		return nil
	}
	// The write index can name a secret that has since been destroyed, and
	// another writer may have created the name again (see
	// resolveLiveTarget). A delete that finds its target already gone
	// therefore resolves a name once more before reporting success; the
	// detail is still read only under the secret's lock.
	for attempt := 0; ; attempt++ {
		secretID, gone, err := c.resolveDeleteTarget(ctx, key)
		if err != nil {
			return fmt.Errorf(msgDeleteSecret, key, err)
		}
		if gone {
			return nil
		}
		err = c.deleteResolved(ctx, remoteRef, key, secretID)
		if !errors.Is(err, errDeleteTargetGone) {
			return err
		}
		if attempt > 0 || isSecretIDFormat(key) {
			return nil
		}
	}
}

// errDeleteTargetGone reports that the secret a delete resolved to turned
// out destroyed (a 404 or DESTROYED) at some step of the delete: its detail
// read, its value read, the value update, the deletion request or the final
// destroy. None of these says anything about the name, which another writer
// may have created again. DeleteSecret answers it with success, after
// resolving a name once more.
var errDeleteTargetGone = errors.New("the secret to delete is already gone")

// deleteResolved deletes the secret key resolved to, or one property of it,
// under the secret's lock.
func (c *Client) deleteResolved(ctx context.Context, remoteRef esv1.PushSecretRemoteRef, key, secretID string) error {
	unlock, err := locks.TryLock(providerName, secretID)
	if err != nil {
		return fmt.Errorf(msgDeleteSecret, key, err)
	}
	defer unlock()

	// Carried to the fall-through below: when a property deletion empties the
	// object, the whole-secret delete runs under this same lock, so the
	// ownership read the property branch already did still holds and does not
	// need repeating.
	var managed *NcloudSecretDetailResponse

	if property := remoteRef.GetProperty(); property != "" {
		var done bool
		managed, done, err = c.deleteSecretProperty(ctx, key, secretID, property)
		if done || err != nil {
			return err
		}
	}

	return c.deleteSecretFully(ctx, key, secretID, managed)
}

// resolveDeleteTarget resolves key to the ID DeleteSecret acts on. gone reports
// that the listing holds no such secret, so there is nothing to delete. It is a
// separate result rather than an empty ID because the ID comes from the listing
// as-is, and what an empty one leads to is the detail read's business.
func (c *Client) resolveDeleteTarget(ctx context.Context, key string) (secretID string, gone bool, err error) {
	if isSecretIDFormat(key) {
		// An ID-shaped key cannot be a name (see secretNamePattern), so its
		// NotFound is final.
		return key, false, nil
	}
	secretID, err = c.writes.Resolve(ctx, c.client, c.cache, key)
	if errors.Is(err, ErrSecretNotFound) {
		return "", true, nil
	}
	return secretID, false, err
}

// resolveLiveTarget resolves a name through the write index and reads the
// detail of the secret it names. The index answers from any sweep this
// reconcile read, so the ID can be minutes old, and when that secret has
// since been destroyed another writer may have created the name again: a
// 404 or DESTROYED on the old ID says nothing about the name. Such an ID is
// forgotten, which rewinds the index, and the name resolved once more from a
// fresh sweep, as the read path asks the listing in
// absentUnlessListingDisagrees. ErrSecretNotFound means the name is absent.
func (c *Client) resolveLiveTarget(ctx context.Context, key string) (string, *NcloudSecretDetailResponse, error) {
	for attempt := 0; ; attempt++ {
		secretID, err := c.writes.Resolve(ctx, c.client, c.cache, key)
		if err != nil {
			return "", nil, err
		}
		secretID, detail, err := c.readTarget(ctx, secretID)
		if !errors.Is(err, ErrSecretNotFound) || attempt > 0 {
			return secretID, detail, err
		}
	}
}

// readTarget reads the detail of secretID for a write. A 404 or DESTROYED
// purges every mapping to the ID (a 404 is the stronger proof of the two) and
// answers ErrSecretNotFound.
func (c *Client) readTarget(ctx context.Context, secretID string) (string, *NcloudSecretDetailResponse, error) {
	detail, err := c.client.GetSecretDetail(ctx, secretID)
	switch {
	case errors.Is(err, ErrSecretNotFound):
		c.forgetResolutionByID(secretID)
		return "", nil, ErrSecretNotFound
	case err != nil:
		return "", nil, err
	case detail == nil:
		return "", nil, errEmptySecretDetail
	case detail.Data.SecretStatus == secretStatusDestroyed:
		c.forgetResolutionByID(secretID)
		return "", nil, ErrSecretNotFound
	}
	return secretID, detail, nil
}

// deleteSecretProperty removes one top-level property under the secret's lock.
// done reports that the deletion is finished, successfully or with err. When
// it is not, removing the property would empty the object, and the caller
// falls through to the whole-secret delete with the ownership-checked detail
// returned here.
func (c *Client) deleteSecretProperty(
	ctx context.Context,
	key, secretID, property string,
) (managed *NcloudSecretDetailResponse, done bool, err error) {
	// A property deletion rewrites the secret's value, so ownership is
	// checked exactly as a push update checks it. NotFound keeps the usual
	// idempotency: the secret being gone means nothing is left to delete,
	// which DeleteSecret answers with success (see errDeleteTargetGone).
	managed, err = c.requireManagedSecret(ctx, secretID)
	// A DESTROYED row is as stale as a 404, marker or not: the whole delete
	// exempts it from the ownership check the same way (deleteSecretFully).
	if managed != nil && managed.Data.SecretStatus == secretStatusDestroyed {
		c.forgetDeletedSecret(key, secretID)
		return nil, true, errDeleteTargetGone
	}
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			c.forgetDeletedSecret(key, secretID)
			return nil, true, errDeleteTargetGone
		}
		// Unmanaged is a final state no retry changes; an error would keep the
		// PushSecret finalizer from ever completing.
		if errors.Is(err, ErrNotManagedByESO) {
			// Info, not V(1): the caller asked for a deletion and is about to be told it
			// succeeded while nothing was deleted. No retry resolves that, so it has to
			// be visible at the default verbosity.
			logFor(ctx).Info(
				"skipping property deletion on a secret not managed by external-secrets",
				"remoteKey", key, "property", property)
			return nil, true, nil
		}
		return nil, true, fmt.Errorf(msgDeleteSecret, key, err)
	}
	current, err := c.client.GetSecretValue(ctx, secretID)
	if err != nil {
		return nil, true, c.propertyValueUnreadable(ctx, key, secretID, property, err)
	}

	obj, ok := decodeJSONObject(extractSecretForStage(current, stageActive))
	if !ok {
		return nil, true, fmt.Errorf(
			msgDeleteSecret,
			key,
			fmt.Errorf("existing secret value is not a JSON object; cannot delete property %.40q from it", property),
		)
	}
	if _, exists := obj[property]; !exists {
		return nil, true, nil
	}

	delete(obj, property)
	if len(obj) == 0 {
		return managed, false, nil
	}
	value, err := esutils.JSONMarshal(obj)
	if err != nil {
		// RawMessage values originated in valid provider JSON. Avoid
		// wrapping a marshal error anyway, because it could contain a
		// fragment of decrypted material.
		return nil, true, fmt.Errorf(msgDeleteSecret, key, errors.New("unable to encode the remaining secret properties"))
	}
	if err := validatePersistedRotationTargets(value, current.Data.RotationTargets); err != nil {
		return nil, true, fmt.Errorf(msgDeleteSecret, key, err)
	}
	if err := c.client.UpdateSecretStageValue(ctx, secretID, stageActive, string(value)); err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			c.forgetDeletedSecret(key, secretID)
			return nil, true, errDeleteTargetGone
		}
		return nil, true, fmt.Errorf(msgDeleteSecret, key, describeUpdateRejection(err, managed.Data.SecretStatus, boundaryOf(managed)))
	}
	return nil, true, nil
}

// propertyValueUnreadable decides what a failed value read means for a
// property deletion: errDeleteTargetGone when the secret is gone, nil when it
// is on its way out (REVOKE still holds the name, so no other writer can have
// created it again), the error to report otherwise.
func (c *Client) propertyValueUnreadable(ctx context.Context, key, secretID, property string, err error) error {
	if errors.Is(err, ErrSecretNotFound) {
		c.forgetDeletedSecret(key, secretID)
		return errDeleteTargetGone
	}
	// The secret may be gone or on its way out, which makes the property
	// read impossible. Gone sends the name to be resolved again; on its way
	// out the property deletion is moot. Report success without escalating:
	// deleting one property must never destroy the secret and its unmanaged
	// siblings; Ncloud finalizes the pending deletion.
	detail, detailErr := c.client.GetSecretDetail(ctx, secretID)
	switch {
	case errors.Is(detailErr, ErrSecretNotFound),
		detailErr == nil && detail != nil && detail.Data.SecretStatus == secretStatusDestroyed:
		c.forgetDeletedSecret(key, secretID)
		return errDeleteTargetGone
	case detailErr == nil && detail != nil && detail.Data.SecretStatus == secretStatusRevoke:
		c.forgetDeletedSecret(key, secretID)
		return nil
	}
	// Everything else fails closed: without the active object there is no
	// proof that removing the property preserves unmanaged siblings. DISABLE
	// gets its own wording because the value still exists and the finalizer
	// stays pending until someone resumes the secret, while a whole deletion
	// from DISABLE succeeds.
	if detailErr == nil && detail != nil && detail.Data.SecretStatus == secretStatusDisable {
		return fmt.Errorf(msgDeleteSecret, key, fmt.Errorf(
			"%w: the secret is paused (DISABLE), so its value cannot be read to remove "+
				"property %.40q without discarding unmanaged fields; resume it with Enable "+
				"Secret, or delete the whole secret if that is what you want", err, property))
	}
	return fmt.Errorf(msgDeleteSecret, key, err)
}

// forgetDeletedSecret drops every mapping to a confirmed-gone secret.
// writeIndex.Resolve warms both the write index and shared cache, so every
// confirmed-gone exit must clear both or a later same-reconcile operation can
// silently use the dead ID.
func (c *Client) forgetDeletedSecret(key, secretID string) {
	if c.cache != nil {
		c.cache.Invalidate(key)
		// key may itself be an ID while the resolution listing warmed a name-keyed
		// entry for this secret; drop those entries too.
		c.cache.InvalidateByID(secretID)
	}
	c.writes.Forget(secretID)
}

// deleteSecretFully performs Ncloud's two-step soft deletion. The caller holds
// the process-wide lock for secretID.
//
// A non-nil detail is one the caller already read and ownership-checked under
// that same lock, so it is reused instead of re-read. Nothing else in this
// process can have changed the memo in between, and the ownership answer is
// what the second read was for.
func (c *Client) deleteSecretFully(
	ctx context.Context,
	key, secretID string,
	detail *NcloudSecretDetailResponse,
) error {
	if detail == nil {
		var err error
		detail, err = c.client.GetSecretDetail(ctx, secretID)
		if err != nil {
			if errors.Is(err, ErrSecretNotFound) {
				c.forgetDeletedSecret(key, secretID)
				return errDeleteTargetGone
			}
			return fmt.Errorf(msgDeleteSecret, key, err)
		}
	}
	if detail == nil {
		return fmt.Errorf(msgDeleteSecret, key, errEmptySecretDetail)
	}
	// Never destroy a secret external-secrets does not own. Skipping reports
	// success (as the AWS and GCP providers do) so a cleanup pointed at an
	// externally created secret does not wedge the reconcile; the mappings are
	// kept because the secret still exists. A DESTROYED row is exempt: there is
	// nothing left to protect.
	if detail.Data.SecretStatus != secretStatusDestroyed &&
		!isManagedByESO(detail.Data.Memo) {
		// Info, not V(1): see deleteSecretProperty. The operator has to be able to
		// see that the cleanup they asked for did nothing.
		logFor(ctx).Info(
			"skipping deletion of a secret not managed by external-secrets",
			"remoteKey", key)
		return nil
	}

	return c.deleteSecretFromDetail(ctx, key, secretID, detail)
}

// deleteSecretFromDetail completes a whole-secret deletion from an
// already-read lifecycle state. Only the full-delete path reaches it: a
// property deletion must never escalate to destroying the secret and its
// unmanaged siblings.
func (c *Client) deleteSecretFromDetail(
	ctx context.Context,
	key, secretID string,
	detail *NcloudSecretDetailResponse,
) error {
	switch detail.Data.SecretStatus {
	case secretStatusDestroyed:
		c.forgetDeletedSecret(key, secretID)
		return errDeleteTargetGone
	case secretStatusRevoke:
		// Deletion already requested; the grace period is running. Finalize
		// below only in force mode.
	case secretStatusEnable, secretStatusDisable:
		// NotFound means another actor destroyed the secret between the
		// detail read and this call, and may have created the name again,
		// so the name is resolved once more (see errDeleteTargetGone).
		if err := c.client.RequestSecretDeletion(ctx, secretID); err != nil {
			if errors.Is(err, ErrSecretNotFound) {
				c.forgetDeletedSecret(key, secretID)
				return errDeleteTargetGone
			}
			return fmt.Errorf(msgDeleteSecret, key, err)
		}
	default:
		// ROTATING (or an unknown future status) cannot be deletion-requested. The
		// status is server text (see describeSecretStatus).
		return fmt.Errorf(msgDeleteBadStatus, key, describeSecretStatus(detail.Data.SecretStatus))
	}

	if !c.forceDelete {
		// The secret is now REVOKE (deletion requested). Ncloud destroys it
		// automatically after the 7-day waiting period, during which the
		// request can still be canceled (Cancel Secret Deletion, which parks
		// the secret in DISABLE). Reads already classify REVOKE as gone, and
		// this provider's create refuses the name until final destruction
		// (createSecretLocked).
		c.forgetDeletedSecret(key, secretID)
		return nil
	}

	// NotFound here means another actor destroyed the secret after the
	// deletion request or the REVOKE read, which frees the name just as a
	// deletion request's NotFound does, so the name is resolved once more.
	if err := c.client.DestroySecret(ctx, secretID); err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			c.forgetDeletedSecret(key, secretID)
			return errDeleteTargetGone
		}
		return fmt.Errorf(msgDeleteSecret, key, err)
	}

	c.forgetDeletedSecret(key, secretID)
	return nil
}

// Close cleans up resources when the provider is done being used.
func (c *Client) Close(_ context.Context) error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// Validate checks if the provider is properly configured and ready to use.
func (c *Client) Validate() (esv1.ValidationResult, error) {
	if c.client == nil {
		return esv1.ValidationResultError, ErrUninitializedClient
	}

	ctx, cancel := context.WithTimeout(context.Background(), validateTimeout)
	defer cancel()

	if _, err := c.client.ListSecrets(ctx, 1); err != nil {
		if isAuthError(err) {
			return esv1.ValidationResultError, fmt.Errorf("the credentials could not be used: %w", err)
		}
		if errors.Is(err, ErrListingUnavailable) {
			// An unaddressable Secretstore is a configuration problem, not a
			// transient blip. Unknown would be reported by the store controller
			// as Ready=True, which is exactly the surface an operator checks
			// while every read and write against this store is failing.
			return esv1.ValidationResultError, fmt.Errorf("store validation failed: %w", err)
		}
		return esv1.ValidationResultUnknown, fmt.Errorf("unable to validate connection: %w", err)
	}

	return esv1.ValidationResultReady, nil
}

// logFor returns the context logger, so a line keeps the reconcile's keys,
// named provider.ncloud.secretmanager the way every other provider names its
// package logger, so an operator filtering on logger gets ncloud lines the
// same way they get aws or gcp lines.
func logFor(ctx context.Context) logr.Logger {
	return ctrllog.FromContext(ctx).WithName("provider").WithName("ncloud").WithName("secretmanager")
}

// isAuthError reports whether err is an authentication or authorization
// failure, including a credential source that cannot produce a pair: no Server
// Role on the node, a metadata endpoint that refuses or does not answer (it is
// link-local, so unreachable means the pod is not on a VPC server or a
// NetworkPolicy blocks it), a refused role switch, or an unreadable key pair.
// Each needs an operator to change something outside the cluster, so the
// store is marked Error rather than Unknown, which the store controller shows
// as Ready=True. Sentinels are matched, not message text.
func isAuthError(err error) bool {
	return errors.Is(err, ErrUnauthorized) ||
		errors.Is(err, ErrForbidden) ||
		errors.Is(err, ErrSwitchRoleRejected) ||
		errors.Is(err, ErrServerRoleUnavailable) ||
		errors.Is(err, errMetadataRefused) ||
		errors.Is(err, errMetadataCode) ||
		errors.Is(err, errMetadataDecode) ||
		errors.Is(err, errSTSDecode) ||
		errors.Is(err, ErrPodIdentityRejected) ||
		errors.Is(err, ErrPodIdentityUnavailable) ||
		errors.Is(err, errPodIdentityDecode) ||
		errors.Is(err, ErrTemporaryCredentialsIncomplete)
}

// resolveSecretID resolves a name for a READ: syntax gate (canNameASecret),
// then the cache (positive and negative entries; only names are cached), then
// the ID shortcut, then the listing. It is one of six resolvers that differ in
// what they trust and what a tombstone means:
//
//   - resolveSecretID: trusts the cache; a tombstone is absence.
//   - resolveSecretIDForMetadata: same, but a tombstone resolves to its ID,
//     because its lifecycle state is the answer.
//   - resolveSecretIDFromListing: bypasses the cache (the 404 fallbacks).
//     DESTROYED is absence and negative-cached; REVOKE resolves to its ID.
//   - listingRowFor: the same sweep, keeping the row's status, for callers
//     that branch on the kind of tombstone (createSecretLocked).
//   - sweepListingFor: one sweep, no retry, no verdict.
//   - writeIndex.Resolve: a WRITE. Shares one sweep across the reconcile's
//     keys; a REVOKE row is a target when nothing live holds the name.
func (c *Client) resolveSecretID(ctx context.Context, name string) (string, error) {
	id, _, err := c.resolveSecretIDTracked(ctx, name)
	return id, err
}

// idOrigin says where a resolved ID came from. A caller that then finds the
// secret in a deletion state needs it to decide what that means for the name
// (see fetchResolvedBy). It is meaningful only alongside a nil error.
type idOrigin int

const (
	originCache     idOrigin = iota // a cached mapping, which can outlive the secret
	originKey                       // the key is the ID itself
	originLiveRow                   // a live row of this call's own listing
	originTombstone                 // a tombstone row of this call's own listing
)

// resolveSecretIDTracked is resolveSecretID that also reports the ID's origin.
func (c *Client) resolveSecretIDTracked(ctx context.Context, name string) (id string, origin idOrigin, err error) {
	if !canNameASecret(name) {
		return "", originKey, unaddressableKeyError(name)
	}

	if c.cache != nil {
		if id, found, negative := c.cache.Get(name); found {
			if negative {
				return "", originCache, ErrSecretNotFound
			}
			return id, originCache, nil
		}
	}

	if isSecretIDFormat(name) {
		return name, originKey, nil
	}

	item, err := c.resolveRowFromListing(ctx, name)
	if err != nil {
		return "", originLiveRow, err
	}
	if isTombstone(item.SecretStatus) {
		return item.SecretID, originTombstone, nil
	}
	return item.SecretID, originLiveRow, nil
}

// resolveSecretIDForMetadata resolves name the way resolveSecretID does, except
// that a deletion tombstone is not absence: a metadata read asks what state a
// secret is in, and Get Secret Detail answers that for a REVOKE secret while
// value reads are refused. AWS draws the same line (DescribeSecret has no
// deletion check). Reading the tombstone as absence would also make the
// verdict depend on whether a value read had recently run.
//
// Like resolveSecretIDTracked, it reports the ID's origin.
func (c *Client) resolveSecretIDForMetadata(ctx context.Context, name string) (id string, origin idOrigin, err error) {
	if c.cache != nil {
		// Only a tombstone entry carries an ID; a plain absence does not, and
		// falls through to the ordinary resolution.
		if id, found, negative := c.cache.Get(name); found && negative && id != "" {
			return id, originCache, nil
		}
	}
	return c.resolveSecretIDTracked(ctx, name)
}

// resolveSecretIDFromListing paginates ListSecrets to resolve name -> ID.
// It bypasses the cache lookup and the ID auto-detect shortcut, so it always
// reflects the current provider state. Every live name the sweep reads is
// written to the cache; if name is not found by the end, or only a DESTROYED
// row holds it, a negative cache entry is recorded.
func (c *Client) resolveSecretIDFromListing(ctx context.Context, name string) (string, error) {
	item, err := c.resolveRowFromListing(ctx, name)
	return item.SecretID, err
}

// resolveRowFromListing is resolveSecretIDFromListing keeping the row, whose
// status tells the caller whether the name resolved to a live secret or to a
// REVOKE tombstone.
func (c *Client) resolveRowFromListing(ctx context.Context, name string) (NcloudSecretListItem, error) {
	var zero NcloudSecretListItem
	// Repeated here rather than left to resolveSecretID: this is the function
	// that writes cache entries, and the fallback paths call it directly.
	if !canNameASecret(name) {
		return zero, unaddressableKeyError(name)
	}

	since := c.cacheSeq()
	item, err := c.listingRowFor(ctx, name)
	if err != nil {
		return zero, err
	}
	if item.SecretStatus == secretStatusDestroyed {
		if c.cache != nil && !isSecretIDFormat(name) {
			c.cache.SetNegativeSince(name, since)
		}
		return zero, ErrSecretNotFound
	}
	return item, nil
}

// cacheSeq is the cache's write sequence before a listing sweep starts, or
// zero without a cache; see secretIDCache.SetNegativeSince.
func (c *Client) cacheSeq() uint64 {
	if c.cache == nil {
		return 0
	}
	return c.cache.Seq()
}

// listingRowFor is the metadata-preserving form of
// resolveSecretIDFromListing. Create rechecks need the listed lifecycle status
// as well as the ID so a DESTROYED tombstone is not mistaken for a competing
// live creator.
func (c *Client) listingRowFor(ctx context.Context, name string) (NcloudSecretListItem, error) {
	var (
		zero  NcloudSecretListItem
		item  NcloudSecretListItem
		found bool
	)

	since := c.cacheSeq()
	confirmed := false
	for attempt := 0; ; attempt++ {
		var (
			sweep listSweep
			err   error
		)
		item, found, sweep, err = c.sweepListingFor(ctx, name)
		if err != nil {
			return zero, err
		}
		// A LIVE row is a first-hand observation that pagination shifts cannot
		// invalidate. Everything else concludes ABSENCE, the dangerous direction
		// (it negative-caches the name), and a tombstone counts as absence here
		// because a shifted or short sweep may have missed a live secret sharing
		// the name. Both must clear the same stability bar.
		if found && !isTombstone(item.SecretStatus) {
			return item, nil
		}
		if !sweep.shifted && !sweep.incomplete() {
			if absenceConfirmed(&sweep, confirmed) {
				break
			}
			if attempt >= maxListSweepRetries {
				return zero, fmt.Errorf(msgResolveSecretID, name, ErrListingUnstable)
			}
			confirmed = true
			continue
		}
		// An unstable sweep says nothing, so it also cannot stand between two
		// sweeps that agree: the pair must be consecutive.
		confirmed = false
		if attempt >= maxListSweepRetries {
			return zero, fmt.Errorf(msgResolveSecretID, name, ErrListingUnstable)
		}
	}

	// A tombstone from a sweep that held still is trustworthy; the caller tells
	// DESTROYED (a free name to createSecretLocked, absence to
	// resolveSecretIDFromListing) from REVOKE (occupied, resolvable) by status.
	if found {
		return item, nil
	}

	// Never negative-cache an ID-shaped key: resolveSecretID consults the
	// negative cache before the ID shortcut, so a transient 404 would pin every
	// GetSecret(id) to NotFound for the negative TTL.
	if c.cache != nil && !isSecretIDFormat(name) {
		c.cache.SetNegativeSince(name, since)
	}
	return zero, ErrSecretNotFound
}

// sweepListingFor performs one listing sweep looking for name, stopping at the
// page that holds a live match. It reports the matching entry (preferring a
// live one over a tombstone of either kind, see isTombstone) and the stability
// of the sweep, so the caller can tell a trustworthy absence from one produced
// by a listing that shifted underneath it.
func (c *Client) sweepListingFor(ctx context.Context, name string) (NcloudSecretListItem, bool, listSweep, error) {
	var zero NcloudSecretListItem
	var tombstone listingTombstone
	var sweep listSweep
	// warmed spans the whole sweep, not one page, so first-wins (see dedupeByName)
	// holds across page boundaries.
	warmed := make(map[string]struct{})
	sweepCtx, cancel := sweepBudget(ctx)
	defer cancel()
	for pageNo := 1; ; pageNo++ {
		resp, err := c.client.ListSecrets(sweepCtx, pageNo)
		if err != nil {
			return zero, false, sweep, fmt.Errorf(msgResolveSecretID, name, sweepFailure(ctx, err))
		}
		sweep.observe(resp)
		if err := tooManyRows(&sweep); err != nil {
			return zero, false, sweep, fmt.Errorf(msgResolveSecretID, name, err)
		}

		if item, matched := c.matchListingPage(resp, name, warmed, &tombstone); matched {
			return item, true, sweep, nil
		}

		if !hasMorePages(pageNo, resp) {
			break
		}
		if pageNo >= maxListPages {
			return zero, false, sweep, fmt.Errorf(msgTooManyPages, maxListPages)
		}
	}
	if tombstone.found {
		return tombstone.item, true, sweep, nil
	}
	return zero, false, sweep, nil
}

// matchListingPage reads one page for sweepListingFor: it warms the cache from
// the page, offers any tombstone holding name to tombstone, and reports the
// first live row holding name.
func (c *Client) matchListingPage(
	resp *NcloudListSecretsResponse,
	name string,
	warmed map[string]struct{},
	tombstone *listingTombstone,
) (NcloudSecretListItem, bool) {
	// Read the full page so cache warming covers every entry, even when the
	// requested name matches an early item. Warming and the returned match are
	// both first-wins (see dedupeByName).
	var matchedItem NcloudSecretListItem
	matched := false
	for _, item := range resp.Data.SecretList {
		tombstoned := isTombstone(item.SecretStatus)
		if _, seen := warmed[item.SecretName]; !seen && !tombstoned && c.cache != nil {
			c.cache.Set(item.SecretName, item.SecretID)
			warmed[item.SecretName] = struct{}{}
		}
		if item.SecretName != name {
			continue
		}
		if tombstoned {
			if item.SecretStatus == secretStatusDestroyed {
				// A destroyed secret's ID is no longer addressable, so mappings to it are
				// stale. A REVOKE secret is still a write target (see isTombstone), so its
				// mappings stay.
				c.forgetResolutionByID(item.SecretID)
			}
			tombstone.offer(item)
			continue
		}
		if !matched {
			matchedItem = item
			matched = true
		}
	}
	return matchedItem, matched
}

// listingTombstone is the tombstone sweepListingFor answers with when no live
// row holds the name.
type listingTombstone struct {
	item  NcloudSecretListItem
	found bool
}

// offer keeps item if it is the better answer. REVOKE outranks DESTROYED: a
// deletion-requested secret still occupies the name, which createSecretLocked
// has to see rather than read an older tombstone as a free name. Otherwise the
// first one wins.
func (t *listingTombstone) offer(item NcloudSecretListItem) {
	if !t.found ||
		(item.SecretStatus == secretStatusRevoke && t.item.SecretStatus != secretStatusRevoke) {
		t.item = item
		t.found = true
	}
}

// Ncloud versions a secret as a fixed three-stage chain (rotated values move
// pending -> active -> previous) rather than by version id; remoteRef.version
// selects one of these stages.
const (
	stagePrevious = "previous"
	stageActive   = "active"
	stagePending  = "pending"
)

// stageForVersion maps an ExternalSecret remoteRef.version to an Ncloud secret
// stage. An empty version defaults to "active". The match is case-insensitive,
// with the API's lowercase stage names as the canonical form; anything else is
// rejected up front so a typo fails fast instead of silently syncing the active
// value.
func stageForVersion(version string) (string, error) {
	switch strings.ToLower(version) {
	case "", stageActive:
		return stageActive, nil
	case stagePrevious:
		return stagePrevious, nil
	case stagePending:
		return stagePending, nil
	default:
		return "", fmt.Errorf(msgInvalidVersion, version)
	}
}

// extractSecretForStage safely extracts one stage of the decrypted secret
// chain from the response. stage must come from stageForVersion.
func extractSecretForStage(resp *NcloudSecretValueResponse, stage string) []byte {
	if resp == nil {
		return nil
	}
	chain := resp.Data.DecryptedSecretChain
	switch stage {
	case stagePrevious:
		return []byte(chain.Previous)
	case stagePending:
		return []byte(chain.Pending)
	default:
		return []byte(chain.Active)
	}
}

// extractProperty resolves property inside document and renders the located
// value the same way parseSecretMap renders a map entry: a JSON string is
// unquoted, and every other type keeps its raw JSON bytes.
//
// Raw matters for numbers: gjson's String() routes non-integer numbers through
// float64, so a high-precision or exponent-form value would be silently
// reformatted (3.141592653589793238462643 -> 3.141592653589793, 1e100 -> a
// 101-digit expansion). Keeping Raw also preserves the documented equivalence
// that GetSecretMap(ref) == parseSecretMap(GetSecret(ref)).
//
// A string is unquoted by encoding/json, as parseSecretMap unquotes a map
// entry, not by gjson's String(): the two differ on a malformed surrogate
// escape, and a field must read the same through data[].remoteRef.property
// and through dataFrom.extract.
//
// A JSON null is reported as not found rather than rendered. gjson answers
// Exists() == true and String() == "" for null, which would sync an empty
// value and report success while the remote field holds no value at all.
func extractProperty(document []byte, property, secretName string) ([]byte, error) {
	val := mapSecretToGjson(document, property)
	if !val.Exists() || val.Type == gjson.Null {
		return nil, fmt.Errorf(msgPropertyNotFound, property, secretName)
	}
	if val.Type == gjson.String {
		var s string
		if err := json.Unmarshal([]byte(val.Raw), &s); err != nil {
			// Unreachable: Raw is a string literal out of a document
			// encoding/json already accepted. Keep gjson's rendering rather
			// than fail the read over it.
			return []byte(val.String()), nil
		}
		return []byte(s), nil
	}
	return []byte(val.Raw), nil
}

// mapSecretToGjson maps secret data to a gjson.Result for property extraction.
// Lookup order:
//  1. property as an exact literal key - Ncloud secrets are commonly flat maps
//     with dotted key names such as "tls.crt".
//  2. property as safe dot-separated object traversal ("db.host").
//
// A literal key always wins when a secret contains both forms. User text is
// never passed to the gjson path evaluator: modifiers, queries, wildcards,
// pipes, multipaths, and every other operator therefore have no special
// meaning.
//
// Step 2 is for the metadataPolicy=Fetch document, built from
// NcloudSecretDetailData, whose trigger and protectionKey fields are nested. On
// secret values it cannot trigger: Ncloud refuses a nested object (and any
// non-string leaf) on both create and stage-value update.
func mapSecretToGjson(secretData []byte, property string) gjson.Result {
	root, ok := decodeJSONObject(secretData)
	if !ok {
		return gjson.Result{}
	}

	if raw, exists := root[property]; exists {
		return gjson.ParseBytes(raw)
	}

	parts := strings.Split(property, ".")
	current := root
	for i, part := range parts {
		raw, exists := current[part]
		if !exists {
			return gjson.Result{}
		}
		if i == len(parts)-1 {
			return gjson.ParseBytes(raw)
		}

		current, ok = decodeJSONObject(raw)
		if !ok {
			return gjson.Result{}
		}
	}
	return gjson.Result{}
}

// parseSecretMap parses JSON secret data into a map of key-value pairs.
// String values are unquoted; numbers, booleans, null, objects, and arrays
// keep their raw JSON representation, matching how other providers expose
// non-string values instead of rejecting the whole secret.
func parseSecretMap(data []byte, secretName string) (map[string][]byte, error) {
	var kv map[string]json.RawMessage
	if err := json.Unmarshal(data, &kv); err != nil {
		// Deliberately drop err: it would echo a byte of the secret value.
		return nil, fmt.Errorf(msgUnmarshalSecret, secretName)
	}
	// A literal top-level null unmarshals into a nil map with a nil error,
	// unlike every other non-object top-level value. Without this guard it
	// would surface as an empty map with no error, and ESO rewrites the
	// managed Kubernetes Secret from that map - deleting every key it holds.
	if kv == nil {
		return nil, fmt.Errorf(msgUnmarshalSecret, secretName)
	}

	secretData := make(map[string][]byte, len(kv))
	for k, raw := range kv {
		// Only quoted values are strings. Probing with json.Unmarshal into a
		// string would misclassify null, which unmarshals into any Go type as
		// a no-op "success" and would silently become an empty string.
		if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 && trimmed[0] == '"' {
			var s string
			if err := json.Unmarshal(trimmed, &s); err == nil {
				secretData[k] = []byte(s)
				continue
			}
		}
		secretData[k] = []byte(raw)
	}

	return secretData, nil
}
