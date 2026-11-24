// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/external-secrets/external-secrets/runtime/metrics"
)

// SecretManagerInterface defines the Ncloud Secret Manager API operations the
// client needs. Tests substitute a fake for it.
type SecretManagerInterface interface { //nolint:revive
	GetSecretValue(ctx context.Context, secretID string) (*NcloudSecretValueResponse, error)
	GetSecretDetail(ctx context.Context, secretID string) (*NcloudSecretDetailResponse, error)
	ListSecrets(ctx context.Context, pageNo int) (*NcloudListSecretsResponse, error)
	ListProtectionKeys(ctx context.Context) (*NcloudProtectionKeyListResponse, error)
	CreateSecret(ctx context.Context, req *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error)
	UpdateSecretStageValue(ctx context.Context, secretID, stage, value string) error
	RequestSecretDeletion(ctx context.Context, secretID string) error
	DestroySecret(ctx context.Context, secretID string) error
	Close() error
}

// successCode is the API response code indicating a successful operation.
const successCode = "SUCCESS"

// apiResponse is the shared shape of every Ncloud API success envelope: a
// top-level status code plus endpoint-specific data. doGet decodes into it and
// validates the code without caring about the concrete response type.
type apiResponse interface {
	code() string
}

// Ncloud API header keys.
const (
	headerContentType = "Content-Type"
	headerTimestamp   = "x-ncp-apigw-timestamp"
	headerAccessKey   = "x-ncp-iam-access-key"
	headerSignature   = "x-ncp-apigw-signature-v2"
)

// Config holds the configuration for the Ncloud client.
type Config struct {
	// AccessKeyID and SecretKey are a permanent key pair, the common case.
	// Leave both empty and set Credentials instead for a pair that is
	// discovered or refreshed at runtime, such as a Server Role's; setting
	// both is refused rather than resolved by precedence.
	AccessKeyID string
	SecretKey   string
	Credentials CredentialsSource

	// Role, when set, is the NRN of a role switched to through the Secure
	// Token Service before signing: the pair above only signs the switch
	// request, and every Secret Manager request carries the role's temporary
	// key. STSEndpoint selects the service; empty means DefaultSTSEndpoint.
	Role        string
	STSEndpoint string

	Endpoint string

	// ForceDeleteWithoutRecovery makes DeleteSecret destroy the remote secret
	// immediately instead of stopping at the REVOKE (deletion requested)
	// state, which Ncloud finalizes on its own after a 7-day waiting period.
	ForceDeleteWithoutRecovery bool
}

// secretManagerClient is the HTTP implementation for Ncloud Secret Manager API.
// It implements the API calls directly via HTTP.
type secretManagerClient struct {
	config       *Config
	credentials  CredentialsSource
	httpClient   *http.Client
	retryBackoff func(attempt int) time.Duration
}

// Compile-time check that secretManagerClient implements SecretManagerInterface.
var _ SecretManagerInterface = &secretManagerClient{}

// newClient creates a new Ncloud Secret Manager API client.
func newClient(config *Config) (*secretManagerClient, error) {
	if config == nil {
		return nil, ErrMissingCredentials
	}
	credentials, err := credentialsFor(config)
	if err != nil {
		return nil, err
	}
	if config.Endpoint == "" {
		return nil, ErrMissingEndpoint
	}

	endpoint, err := NormalizeEndpoint(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf(msgInvalidEndpoint, err)
	}

	// Keep a private copy so callers cannot swap the validated endpoint after
	// construction and cause credentials to be signed for another host.
	cfg := *config
	cfg.Endpoint = endpoint

	return &secretManagerClient{
		config:      &cfg,
		credentials: credentials,
		httpClient:  newHTTPTransport(),
	}, nil
}

// credentialsFor builds the source requests are signed from: the static pair
// or the configured source, wrapped in a role switch when Role is set.
func credentialsFor(config *Config) (CredentialsSource, error) {
	var base CredentialsSource
	switch {
	case config.Credentials != nil && (config.AccessKeyID != "" || config.SecretKey != ""):
		return nil, ErrAmbiguousCredentials
	case config.Credentials != nil:
		base = config.Credentials
	case config.AccessKeyID == "" || config.SecretKey == "":
		return nil, ErrMissingCredentials
	default:
		base = StaticCredentials(config.AccessKeyID, config.SecretKey)
	}
	if config.Role == "" {
		return base, nil
	}
	return SwitchRoleCredentials(base, config.STSEndpoint, config.Role)
}

// newHTTPTransport builds the http.Client every path uses except the instance
// metadata read. It is one function rather than a literal at each construction
// site so a test exercises the transport the deployed provider gets: a property
// set here and duplicated in a test's own client is one no test can see change.
func newHTTPTransport() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		// Never follow redirects. Requests carry Ncloud auth headers
		// (x-ncp-iam-access-key, x-ncp-apigw-signature-v2, ...) that Go
		// does NOT treat as sensitive, so on a cross-host 3xx they would
		// be re-sent verbatim to the redirect target, whose body would
		// then become the synced secret. Surface the 3xx as the response
		// instead.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// maxResponseBytes caps how much of a response body is read into memory. Secret
// Manager responses are small; the limit guards against a malfunctioning or
// hostile endpoint returning a huge body and exhausting memory under concurrent
// reconciles.
const maxResponseBytes = 8 << 20 // 8 MiB

// Retry policy for transient errors. GET calls are idempotent, and unlike the
// SDK-backed providers (AWS/GCP/Azure) this client has no SDK retryer, so a
// rate-limit, HTTP 500, gateway blip, or transient network failure would
// otherwise fail the whole reconcile until the next resync. Retry only the
// errors shouldRetryGet accepts; everything else (NotFound, auth, decode,
// context cancellation) fails fast.
// Mutations (doSend) are not retried on these errors: create and
// request-deletion are not idempotent, and a failed PushSecret reconcile is
// retried by the controller anyway. The one re-send after a refused temporary
// pair is separate and applies to every method (see doOnce).
const maxGetRetries = 3

// maxCredentialsElapsed bounds obtaining the pair a request is signed with:
// queueing behind another caller's fetch plus the fetch itself. Reads are
// already inside maxGetElapsed; mutations have no budget of their own, and
// without this one a PushSecret could wait on a black-holed Secure Token
// Service for as long as the queue ahead of it takes.
const maxCredentialsElapsed = 45 * time.Second

// maxGetElapsed bounds the wall time one GET may spend across its attempts.
// Without it, maxGetRetries attempts against a black-holing endpoint each burn
// the 30s client timeout, and a paginated sweep multiplies that by its page
// count while holding the controller's single default worker. It only ever
// shortens a sequence that is already failing. A var so tests can shrink it.
var maxGetElapsed = 45 * time.Second

// maxRetryAfterWait is the longest Retry-After a GET waits out in place. A
// rate limiter asking for longer gets the error back at once, and the
// controller's per-item backoff carries the delay: the controller runs one
// reconcile at a time by default, so waiting in place for a throttled
// account would hold every other store's reconciles too.
const maxRetryAfterWait = 5 * time.Second

// retryBackoff returns the delay before the given 0-based retry attempt. The
// per-client field c.retryBackoff overrides it; that field, not this
// function, is what tests replace to neutralize the wait.
func retryBackoff(attempt int) time.Duration {
	return 200 * time.Millisecond << attempt // 200ms, 400ms, 800ms
}

// doGet issues an authenticated GET and, on a transient error, retries with
// exponential backoff up to maxGetRetries, honoring ctx cancellation. Each
// attempt rebuilds the request so the signature timestamp stays fresh.
func (c *secretManagerClient) doGet(ctx context.Context, path string, out apiResponse) error {
	// The budget bounds the attempts, not the caller: a context the caller
	// already bounded more tightly still wins. Every attempt runs under it,
	// so a late attempt cannot spend a full client timeout past the budget
	// and turn 45s into 75s. The first attempt is not shortened in practice,
	// because the client timeout is well inside the budget.
	deadline := time.Now().Add(maxGetElapsed)
	budgeted, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			// A previous attempt may have decoded part of a response into
			// out. Retrying on top of that would mix two responses together.
			resetResponse(out)
		}
		err := c.doOnce(budgeted, http.MethodGet, path, nil, out)
		if err == nil || !shouldRetryGet(ctx, err) || attempt >= maxGetRetries {
			return err
		}

		wait, retry := c.retryWait(attempt, err)
		if !retry {
			return err
		}

		// Asked before sleeping, so a caller that gave up during backoff()
		// reports its own reason rather than the budget's.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A wait that outlasts the budget buys no attempt. Returning now rather than
		// sleeping to the budget's end means a rate limiter asking for an hour frees
		// the reconcile immediately and lets the controller's own backoff carry the
		// delay, not hold it for 45s.
		if wait >= time.Until(deadline) {
			return err
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// retryWait returns how long doGet waits in place before the given 0-based
// retry, or false when err should be returned instead of waited out. No
// single wait exceeds maxRetryAfterWait, whatever lengthened it.
func (c *secretManagerClient) retryWait(attempt int, err error) (time.Duration, bool) {
	backoff := retryBackoff
	if c.retryBackoff != nil {
		backoff = c.retryBackoff
	}
	wait := backoff(attempt)
	// A 429 that names its own delay knows better than the fixed ramp, which
	// tops out at 800ms and is not what a rate limiter is asking for. Only
	// ever lengthens the wait, and only up to maxRetryAfterWait.
	if after, ok := retryAfterFrom(err); ok && after > wait {
		if after > maxRetryAfterWait {
			return 0, false
		}
		wait = after
	}
	// A failed credential fetch is answered from memory for failureHold, so
	// a retry inside that hold would re-read the memo and never reach the
	// issuer. Wait the hold out instead, under the same cap. The hold counts
	// from when the failure was recorded, which is before this wait starts,
	// so a wait of exactly failureHold ends past it.
	var credErr credentialsError
	if errors.As(err, &credErr) && wait < failureHold {
		wait = min(failureHold, maxRetryAfterWait)
	}
	return wait, true
}

// resetResponse zeroes the decode target between attempts. The concrete type
// is only known to the caller, so this goes through reflection rather than
// asking every response type for a Reset method.
func resetResponse(out apiResponse) {
	v := reflect.ValueOf(out)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return
	}
	v.Elem().Set(reflect.Zero(v.Elem().Type()))
}

// retryAfterError carries the delay a 429 response asked for alongside the
// sentinel the rest of the code matches on, so errors.Is keeps working.
type retryAfterError struct {
	err   error
	after time.Duration
}

func (e *retryAfterError) Error() string { return e.err.Error() }
func (e *retryAfterError) Unwrap() error { return e.err }

// secretPath builds a request path under one secret. Every ID that reaches
// here came from a listing row, a create response, a cache entry or a
// manifest key, all of which are checked already; the check here is the
// choke point a future caller cannot miss, because "" or ".." in the path
// would address the collection or a path of the server's choosing, signed.
func secretPath(secretID, suffix string) (string, error) {
	if !isSecretIDFormat(secretID) {
		return "", fmt.Errorf("%w: %.40q", ErrSecretIDMalformed, secretID)
	}
	return "/api/v1/secrets/" + secretID + suffix, nil
}

// retryAfterFrom reports the delay a 429 asked for, if one reached us.
func retryAfterFrom(err error) (time.Duration, bool) {
	if ra, ok := errors.AsType[*retryAfterError](err); ok {
		return ra.after, true
	}
	return 0, false
}

// parseRetryAfter reads an RFC 9110 Retry-After value, which is either
// delta-seconds or an HTTP-date. A malformed, negative or absent value is
// reported as no instruction rather than as zero delay, so the caller keeps
// its own backoff.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0, false
		}
		// Anything past a day is "do not wait in place" to every caller, and
		// multiplying the raw value would overflow into a negative duration.
		seconds = min(seconds, 24*60*60)
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	if d := when.Sub(now); d > 0 {
		return d, true
	}
	return 0, false
}

// shouldRetryGet distinguishes the caller's expired context from the
// http.Client's own per-request timeout. Both wrap context.DeadlineExceeded,
// but only the latter is retryable while the caller's context remains usable.
// A configuration error (isAuthError) fails fast whatever it wraps: a Server
// Role source reports an unreachable metadata endpoint with the network error
// inside its sentinel, and that error, or the per-call timeout, would
// otherwise read as transient and spend the retry budget on a store that
// cannot authenticate. A refused signing pair is not retried here either:
// doOnce already spent its one re-send on it, and the controller's backoff
// carries any further attempt, as it does after a 401.
func shouldRetryGet(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil || isAuthError(err) {
		return false
	}
	// Retrying would ask for a pair first, meet the failure the source just
	// memoized, and never re-send, so the last error would be the refresh
	// failure alone and the refusal's classification would be gone.
	if _, ok := errors.AsType[*refusedPairError](err); ok {
		return false
	}
	if IsRetryable(err) {
		return true
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// doSend issues an authenticated mutation (POST/PUT/DELETE) with the given
// JSON body. See the retry-policy note above for why a mutation is not
// retried on a transient error.
func (c *secretManagerClient) doSend(ctx context.Context, method, path string, body any, out apiResponse) error {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf(msgCreateRequest, err)
		}
	}
	return c.doOnce(ctx, method, path, payload, out)
}

// doOnce performs an authenticated request, re-sent at most once as described
// below: it validates the HTTP status and decodes the JSON body into out
// (which carries the shared Code field). It centralizes request building, the
// bounded body read, error mapping, and the success-code check so every
// endpoint method behaves identically.
//
// A temporary pair can be refused before its own expiry, for example after
// its role was detached or the issuing service revoked it. One refusal of
// such a pair earns one refresh and one re-send; if the source hands back the
// same pair the refusal is real and a retry would only repeat it. Re-sending
// a mutation is safe because a refused request did not run: a 401 turns the
// caller away, whether the gateway or Secret Manager answers it. A permanent
// pair is never retried: the same key would be refused the same way.
//
// Such a pair can also be refused with the gateway's 404 and code 300, for
// example past its expiry or once its Server Role is detached from the
// server. That 404 counts as a refusal of a temporary pair too, and the
// re-send is safe on the same ground: the request did not run. Code 300 is
// the gateway's own, not one of Secret Manager's (501000, 501001), so the
// request never reached the service that would have run it. A wrong base path
// gets the same 404, and the refresh it costs is bounded by the source's
// refusal hold (refetchHold), which is armed only when the source hands back
// the pair just refused.
func (c *secretManagerClient) doOnce(ctx context.Context, method, path string, body []byte, out apiResponse) error {
	pair, err := c.obtainCredentials(ctx)
	if err != nil {
		return err
	}
	err = c.doOnceWith(ctx, method, path, body, out, pair)
	if !refusesPair(err) || !pair.temporary() {
		return err
	}

	c.credentials.Invalidate(ctx, pair)
	fresh, ferr := c.obtainCredentials(ctx)
	if ferr != nil {
		// The refusal is what happened; the failed refresh is why it will
		// happen again, and it is the one an operator can act on.
		return &refusedPairError{refusal: err, refresh: ferr}
	}
	if fresh.AccessKeyID == pair.AccessKeyID {
		return err
	}
	resetResponse(out)
	return c.doOnceWith(ctx, method, path, body, out, fresh)
}

// refusedPairError carries a refusal of the signing pair together with the
// failure of the refresh that refusal earned. Both stay reachable, so a caller
// that re-classifies the refusal for its own endpoint (see ListSecrets) can
// carry the refresh failure over: it is the one an operator can act on, and
// dropping it turns "the credentials could not be refreshed" into "the store
// could not be addressed".
type refusedPairError struct {
	refusal error
	refresh error
}

func (e *refusedPairError) Error() string {
	return fmt.Sprintf("%s; refreshing the refused pair failed: %s", e.refusal, e.refresh)
}

// Unwrap exposes both, so errors.Is and errors.As reach the refusal's sentinel
// and status as well as whatever the refresh failure wraps.
func (e *refusedPairError) Unwrap() []error { return []error{e.refusal, e.refresh} }

// withRefusal returns a copy reporting a different refusal, for a caller that
// has re-classified it, keeping the refresh failure.
func (e *refusedPairError) withRefusal(refusal error) *refusedPairError {
	return &refusedPairError{refusal: refusal, refresh: e.refresh}
}

// refusesPair reports whether err refuses the pair that signed the request,
// so that the request did not run: a 401, or the gateway's own 404 (see
// doOnce). A 404 with Secret Manager's resource-not-found code, or with no
// code at all, says nothing about the pair.
func refusesPair(err error) bool {
	if errors.Is(err, ErrUnauthorized) {
		return true
	}
	var apiErr *apiError
	return errors.As(err, &apiErr) &&
		apiErr.statusCode == http.StatusNotFound &&
		notFoundKindOf(apiErr.errorCode) == notFoundGateway
}

// obtainCredentials asks the source for the pair to sign with, under
// maxCredentialsElapsed on top of the caller's own deadline.
func (c *secretManagerClient) obtainCredentials(ctx context.Context) (Credentials, error) {
	bounded, cancel := context.WithTimeout(ctx, maxCredentialsElapsed)
	defer cancel()
	pair, err := c.credentials.Credentials(bounded)
	if err != nil {
		return Credentials{}, credentialsError{fmt.Errorf(msgCredentials, err)}
	}
	return pair, nil
}

// credentialsError marks an error from the credential step of a request, as
// opposed to the exchange with the endpoint, so a GET retry can tell that it
// must wait out failureHold before the source contacts its issuer again.
type credentialsError struct{ err error }

func (e credentialsError) Error() string { return e.err.Error() }
func (e credentialsError) Unwrap() error { return e.err }

func (c *secretManagerClient) doOnceWith(ctx context.Context, method, path string, body []byte, out apiResponse, pair Credentials) error {
	req, err := c.newRequest(ctx, method, path, body, pair)
	if err != nil {
		return fmt.Errorf(msgCreateRequest, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf(msgExecuteRequest, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Bound the read: request one byte past the cap so an oversized body is
	// detected rather than silently truncated.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf(msgReadResponseBody, err)
	}
	if len(respBody) > maxResponseBytes {
		return fmt.Errorf(msgResponseTooLarge, maxResponseBytes)
	}

	// Only 200 is success. Ncloud answers every documented Secret Manager call
	// with 200 or an error, so another 2xx is refused rather than read as a
	// success that cannot be decoded. If that ever changes the failure is
	// visible: a create answering 201 is reported failed after the secret was
	// made, and the next reconcile meets an occupied name.
	if resp.StatusCode != http.StatusOK {
		err := handleErrorResponse(resp.StatusCode, respBody)
		// 429 only. RFC 9110 allows Retry-After on 503 too, but a 503 from
		// this API is an outage rather than a quota the server can schedule
		// us out of, and honoring a long one there would park a reconcile on
		// a number no one chose for us.
		if resp.StatusCode == http.StatusTooManyRequests {
			if after, ok := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); ok {
				err = &retryAfterError{err: err, after: after}
			}
		}
		return err
	}

	if err := json.Unmarshal(respBody, out); err != nil {
		// json.SyntaxError.Error() echoes the offending byte. For value-bearing
		// responses (GetSecretValue) that byte is decrypted plaintext, and the
		// error reaches the controller log - report only the offset.
		// *json.UnmarshalTypeError names Go types and JSON value kinds, but
		// for a number that does not fit its field it echoes the literal, an
		// unbounded server-controlled string - report the field and offset.
		// The remaining unmarshal errors name Go types only and stay wrapped.
		if syn, ok := errors.AsType[*json.SyntaxError](err); ok {
			return fmt.Errorf(msgDecodeResponseAt, syn.Offset)
		}
		if typ, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
			return fmt.Errorf(msgDecodeResponseField, typ.Field, typ.Offset)
		}
		return fmt.Errorf(msgDecodeResponse, err)
	}
	if out.code() != successCode {
		// The code is server-controlled. Even an uppercase identifier-shaped
		// value can be a credential or secret, so do not echo unknown content.
		return errors.New(msgNonSuccessCode)
	}
	return nil
}

// GetSecretValue retrieves a secret value from Ncloud Secret Manager.
// Returns the complete API response for flexibility.
func (c *secretManagerClient) GetSecretValue(ctx context.Context, secretID string) (*NcloudSecretValueResponse, error) {
	path, err := secretPath(secretID, "/values")
	if err != nil {
		return nil, err
	}
	var resp NcloudSecretValueResponse
	err = c.doGet(ctx, path, &resp)
	metrics.ObserveAPICall(ProviderNcloudSM, CallNcloudSMGetSecretValue, err)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetSecretDetail retrieves a secret's metadata (Get Secret Detail) from
// Ncloud Secret Manager. The response never includes the decrypted value.
func (c *secretManagerClient) GetSecretDetail(ctx context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
	path, err := secretPath(secretID, "")
	if err != nil {
		return nil, err
	}
	var resp NcloudSecretDetailResponse
	err = c.doGet(ctx, path, &resp)
	metrics.ObserveAPICall(ProviderNcloudSM, CallNcloudSMGetSecretDetail, err)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListSecrets retrieves a page of secrets from Ncloud Secret Manager.
// Returns the complete API response for flexibility.
//
// A 404 here is reported as ErrListingUnavailable rather than
// ErrSecretNotFound: this endpoint answers about the collection, so a 404 says
// the store could not be addressed, and reading it as "no such secret" would be
// acted on destructively (see ErrListingUnavailable). An empty result is 200
// with an empty list; were an empty store ever answered with 404, the first
// push would fail loudly rather than delete anything.
//
// A refusal of a temporary pair that could not be refreshed is reported with
// the refresh failure as well, so the store reads as an authentication problem
// rather than as an unaddressable listing.
func (c *secretManagerClient) ListSecrets(ctx context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
	path := fmt.Sprintf("/api/v1/secrets?pageNo=%d", pageNo)
	var resp NcloudListSecretsResponse
	err := c.doGet(ctx, path, &resp)
	// Observed before the 404 remap below: the metric records what the API
	// answered, and the remap is this client's reading of it.
	metrics.ObserveAPICall(ProviderNcloudSM, CallNcloudSMListSecrets, err)
	if err != nil {
		// Only a 404 the Secret Manager transport classified is the
		// listing's own; the credential step answers 404 too (the Secure
		// Token Service's word for a refused caller key) and that one must
		// keep its classification.
		var apiErr *apiError
		if (errors.Is(err, ErrSecretNotFound) || errors.Is(err, ErrNotFoundUnverified)) && errors.As(err, &apiErr) {
			remapped := apiErr.withSentinel(ErrListingUnavailable)
			// The refusal may have come with a failed refresh, and that
			// failure is what Validate needs to report the credentials
			// rather than the store's address.
			if refused, ok := errors.AsType[*refusedPairError](err); ok {
				return nil, refused.withRefusal(remapped)
			}
			return nil, remapped
		}
		return nil, err
	}
	return &resp, nil
}

// ListProtectionKeys retrieves the account's KMS protection keys. Only the
// region-isolation boundary of the default key is consumed (see
// NcloudCreateSecretRequest.KmsBoundaryType); key tags and names are not used
// to address anything.
func (c *secretManagerClient) ListProtectionKeys(ctx context.Context) (*NcloudProtectionKeyListResponse, error) {
	var resp NcloudProtectionKeyListResponse
	err := c.doGet(ctx, "/api/v1/keys", &resp)
	metrics.ObserveAPICall(ProviderNcloudSM, CallNcloudSMListProtectionKeys, err)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// CreateSecret creates a new secret and returns its metadata, including the
// server-assigned secret ID.
func (c *secretManagerClient) CreateSecret(ctx context.Context, req *NcloudCreateSecretRequest) (*NcloudSecretDetailResponse, error) {
	var resp NcloudSecretDetailResponse
	err := c.doSend(ctx, http.MethodPost, "/api/v1/secrets", req, &resp)
	metrics.ObserveAPICall(ProviderNcloudSM, CallNcloudSMCreateSecret, err)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// UpdateSecretStageValue replaces the value of one stage of a secret. The
// single-stage endpoint is deliberately used instead of the whole-chain
// PUT /values, which rewrites the whole chain and clears the stages a request
// leaves out.
func (c *secretManagerClient) UpdateSecretStageValue(ctx context.Context, secretID, stage, value string) error {
	path, err := secretPath(secretID, "/values/"+url.PathEscape(stage))
	if err != nil {
		return err
	}
	var resp NcloudUpdateStageValueResponse
	err = c.doSend(ctx, http.MethodPut, path, &NcloudUpdateStageValueRequest{Value: value}, &resp)
	metrics.ObserveAPICall(ProviderNcloudSM, CallNcloudSMUpdateSecretStageValue, err)
	return err
}

// RequestSecretDeletion transitions a secret into the REVOKE (deletion
// requested) state. Only ENABLE/DISABLE/REVOKE secrets may be requested.
func (c *secretManagerClient) RequestSecretDeletion(ctx context.Context, secretID string) error {
	path, err := secretPath(secretID, "/request-deletion")
	if err != nil {
		return err
	}
	var resp NcloudSecretStatusResponse
	err = c.doSend(ctx, http.MethodPost, path, nil, &resp)
	metrics.ObserveAPICall(ProviderNcloudSM, CallNcloudSMRequestSecretDeletion, err)
	return err
}

// DestroySecret finalizes destruction of a secret (the API's DELETE call).
// Named Destroy rather than Delete to keep the two-phase soft-delete model
// visible and to avoid shadowing the esv1 Client.DeleteSecret entry point.
// The API only accepts this for secrets already in the REVOKE state (see
// RequestSecretDeletion).
func (c *secretManagerClient) DestroySecret(ctx context.Context, secretID string) error {
	path, err := secretPath(secretID, "")
	if err != nil {
		return err
	}
	var resp NcloudDeleteSecretResponse
	err = c.doSend(ctx, http.MethodDelete, path, nil, &resp)
	metrics.ObserveAPICall(ProviderNcloudSM, CallNcloudSMDestroySecret, err)
	return err
}

// Close is a no-op.
func (c *secretManagerClient) Close() error {
	return nil
}

// newRequest creates a new HTTP request signed with pair.
func (c *secretManagerClient) newRequest(ctx context.Context, method, path string, body []byte, pair Credentials) (*http.Request, error) {
	u, err := url.Parse(c.config.Endpoint + path)
	if err != nil {
		return nil, fmt.Errorf(msgInvalidEndpoint, err)
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return nil, err
	}

	setAuthHeaders(req, pair, time.Now())
	return req, nil
}
