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
	"net"
	"net/http"
	"syscall"
)

// Sentinel errors for common error conditions.
var (
	// Configuration errors.
	ErrMissingCredentials   = errors.New("missing Ncloud credentials (AccessKeyID or SecretKey)")
	ErrAmbiguousCredentials = errors.New("both a credentials source and a static key pair are set; set one of them")
	ErrMissingRole          = errors.New("missing role to switch to")
	ErrMissingEndpoint      = errors.New("missing Ncloud endpoint")

	// Credential source errors. The first two, and the Pod Identity ones,
	// name a misconfiguration an operator fixes outside the cluster: a node
	// pool without a Node IAM Role, a role the caller may not switch to, a
	// pod without the Pod Identity add-on's token, or an exchange the
	// association does not allow. isAuthError lists every error reported
	// that way.
	ErrServerRoleUnavailable          = errors.New("no Server Role credentials at the instance metadata endpoint: the node has no role attached, or the endpoint is not reachable from this pod")
	ErrSwitchRoleRejected             = errors.New("the Secure Token Service rejected the role switch")
	ErrTemporaryCredentialsIncomplete = errors.New("temporary credentials response lacks the access key, the secret key, or the expiry")
	// errSwitchRoleCallerKeyRefused is the rejection that may be about the
	// caller key rather than the switch: the documented 404 for an invalid
	// or expired key and the gateway's 401 for a signature it does not
	// accept. It wraps ErrSwitchRoleRejected, so every caller matching that
	// sentinel still does; only switchRoleSource.fetch tells them apart, to
	// refresh a temporary caller pair once.
	errSwitchRoleCallerKeyRefused = fmt.Errorf("%w: the caller key was refused", ErrSwitchRoleRejected)
	errMetadataDecode             = errors.New("cannot decode the instance metadata credential document")
	errMetadataCode               = errors.New("the instance metadata credential document does not report Success")
	errMetadataRefused            = errors.New("the instance metadata endpoint refused the request")
	errSTSDecode                  = errors.New("cannot decode the Secure Token Service response")
	ErrPodIdentityRejected        = errors.New("the Pod Identity exchange refused the request")
	ErrPodIdentityUnavailable     = errors.New("no Pod Identity token in this pod")
	errPodIdentityDecode          = errors.New("cannot decode the Pod Identity exchange response")

	// Client errors.
	ErrUninitializedClient = errors.New("ncloud secret manager client is not initialized")
	ErrEmptySecretData     = errors.New("secret data is empty")

	// API errors - Ncloud Secret Manager official error codes
	// Reference: https://api.ncloud-docs.com/docs/secretmanager-api-overview (response status codes).
	ErrSecretNotFound      = errors.New("secret not found")                // 404 NOT_FOUND
	ErrUnauthorized        = errors.New("authentication failed")           // 401 UNAUTHORIZED
	ErrForbidden           = errors.New("insufficient permissions")        // 403 FORBIDDEN
	ErrInvalidRequest      = errors.New("invalid request")                 // 400 INVALID_REQUEST
	ErrInvalidStatus       = errors.New("invalid status")                  // 409 INVALID_STATUS
	ErrUnprocessableEntity = errors.New("request violates business rules") // 422 UNPROCESSABLE_ENTITY
	ErrInternalServerError = errors.New("server internal error")           // 500 INTERNAL_SERVER_ERROR

	// Transient transport-level failures. These carry no Ncloud error code;
	// they exist so callers can tell a retryable condition apart from a
	// permanent one (see IsRetryable).
	ErrRateLimited        = errors.New("rate limited")        // 429 TOO_MANY_REQUESTS
	ErrServiceUnavailable = errors.New("service unavailable") // 408, and every 5xx but 500

	// ErrQuotaExceeded is the API gateway's 429 with code 400: the account's
	// quota is used up, which no retry fixes, unlike its throttle (410) and
	// rate limit (420) answers. See
	// https://api.ncloud-docs.com/docs/common-ncpapi.
	ErrQuotaExceeded = errors.New("api quota exceeded")

	// Feature errors.
	ErrTagsNotSupported         = errors.New("finding by tags is not supported")
	ErrPushMetadataNotSupported = errors.New("pushing with metadata is not supported by the Ncloud provider")
)

// ErrPushWholeDataUnderProperty rejects a PushSecret that sets a property but
// selects no secretKey: that stores the whole Data map under one remote field
// as a nested JSON object, and Ncloud accepts only values whose leaves are
// strings, on both the create and the stage-value update endpoint. The
// request can never succeed, so it is refused here with an actionable
// message.
var ErrPushWholeDataUnderProperty = errors.New(
	"pushing the whole Kubernetes Secret data map under a property would store a nested JSON object, which Ncloud rejects: select a single entry with spec.data[].match.secretKey, or drop the property to push the map as the secret's whole value",
)

// ErrNotManagedByESO rejects a mutation of a secret that does not carry the
// managed-by memo marker this provider stamps on every secret it creates.
// Mirrors the AWS provider's contract: pushes to a secret external-secrets
// does not own fail loudly, and full deletions of such a secret are silently
// skipped. To adopt an existing secret, add the marker to its memo with the
// Update Secret Memo API (or the console) first.
var ErrNotManagedByESO = errors.New(
	"secret is not managed by external-secrets: to adopt it, add a memo line that reads exactly \"" + managedByMemo + "\"",
)

// ErrSecretIDMalformed is a secret ID that is not in the form the API issues
// (64 lowercase hex characters) where a response or a caller supplied one.
// IDs become request paths and process-wide lock keys, so one that is not
// well formed is refused before either, and a listing carrying one fails as
// a whole rather than being read with the row skipped.
var ErrSecretIDMalformed = errors.New("secret ID is not in the form the API issues (64 lowercase hex characters)")

// ErrKeyNotAddressable is a read key that is neither a secret name the Create
// Secret API would have accepted nor a 64-character lowercase hex ID. No secret can
// exist under it, but it is a configuration mistake, not an absence: reported
// as esv1.NoSecretErr it would make deletionPolicy: Delete remove the target
// Secret over a typo, which the AWS and GCP providers also do not do. It is
// answered before any API call.
var ErrKeyNotAddressable = errors.New(
	"the key cannot name an Ncloud secret: a name is 3-15 characters of letters, digits, '-' or '_' starting with a letter, an ID is 64 lowercase hex characters",
)

// ErrNotFoundUnverified is a 404 the service did not attribute to a missing
// resource. A genuinely absent secret carries service code 501001
// (RESOURCE_NOT_FOUND); the API gateway answers an unroutable path with its
// own code 300, and can answer a request signed with a key it does not accept
// the same way, whatever the secret ID. A proxy may answer with no envelope at
// all. Those must not collapse into ErrSecretNotFound, which callers read as
// "already gone" and act on destructively: GetAllSecrets drops the key,
// GetSecret promotes it to NoSecretErr so deletionPolicy: Delete removes the
// target Secret, and DeleteSecret reports success. An unattributed 404
// therefore fails closed.
var ErrNotFoundUnverified = errors.New(
	"received 404 without a resource-not-found code; treating it as a request or gateway failure rather than a missing secret; the endpoint may be wrong, or the access key ID may be one Ncloud does not know",
)

// ErrListingUnstable reports that the secret collection kept changing while a
// listing sweep was reading it, so neither "this name does not exist" nor "this
// is every secret" can be concluded from what was read. Both conclusions are
// destructive when wrong: the first negative-caches the name and makes a
// deletionPolicy: Delete ExternalSecret drop its target Secret, the second
// makes ESO rewrite a managed Secret without the keys the sweep missed.
var ErrListingUnstable = errors.New(
	"secret listing changed while it was being read; refusing to report a possibly incomplete result",
)

// ErrNameTakenMeanwhile reports a create whose name the locked recheck found
// held by a live secret that another writer created after this reconcile's
// listing found it absent. The create does not converge onto that secret:
// under updatePolicy IfNotExists the controller pushed only because
// SecretExists answered from that same listing, and updating would overwrite a
// secret the policy promises to leave alone. The reconcile fails and is
// requeued; the next one lists the secret, so IfNotExists skips it and Replace
// updates it.
var ErrNameTakenMeanwhile = errors.New(
	"the secret name was taken by another writer after this reconcile checked it; the next reconcile will see that secret",
)

// ErrListingUnavailable is a 404 from the secret listing endpoint. It can never
// mean "this secret does not exist": a reachable store with no secrets answers
// 200 with an empty list. It is a store-level failure (an unprovisioned
// Secretstore for this account and region, a wrong base path, or a key the
// gateway does not accept, answered like a wrong path) and must not collapse
// into ErrSecretNotFound. Callers read that as "already gone": DeleteSecret
// reports success without deleting, SecretExists answers false so PushSecret
// creates a duplicate that can never take the name, and an ExternalSecret with
// deletionPolicy: Delete deletes its target Kubernetes Secret.
var ErrListingUnavailable = errors.New(
	"secret listing is unavailable; the endpoint may be wrong for this account or region, the access key ID may be one Ncloud does not know, or the Ncloud Secretstore may not be provisioned",
)

// Error message templates for formatted errors.
const (
	// API layer errors.
	msgInvalidEndpoint            = "invalid endpoint: %w"
	msgInvalidSTSEndpoint         = "invalid STS endpoint: %w"
	msgCredentials                = "failed to obtain credentials: %w"
	msgServerRole                 = "failed to obtain Server Role credentials: %w"
	msgSwitchRole                 = "failed to switch to role: %w"
	msgPodIdentity                = "failed to obtain Pod Identity credentials: %w"
	msgInvalidPodIdentityEndpoint = "invalid Pod Identity endpoint: %w"
	msgMetadataStatus             = "instance metadata endpoint answered status %d"
	msgCreateRequest              = "failed to create request: %w"
	msgExecuteRequest             = "failed to execute request: %w"
	msgReadResponseBody           = "failed to read response body: %w"
	msgDecodeResponse             = "failed to decode response: %w"
	msgDecodeResponseAt           = "failed to decode response: syntax error at byte offset %d"
	// The field is the Go struct path json reports; it never carries input.
	msgDecodeResponseField = "failed to decode response: unexpected value for field %q at byte offset %d"
	msgAPIError            = "ncloud API request failed with status %d"
	msgAPIErrorCode        = "ncloud API request failed with status %d and code %s"
	msgNonSuccessCode      = "ncloud API returned non-success code"

	// Client layer errors.
	// msgPropertyNotFound and msgPropertyNotObject quote the property and the
	// key and cut them to 40 characters, as msgInvalidSecretName below does:
	// both are manifest text of any length, and the error reaches the
	// controller log. Every other message that echoes a property or a
	// Kubernetes Secret key (msgPushMissingKey, msgPushNotObject, the property
	// deletion errors in client.go) does the same.
	msgPropertyNotFound  = "property %.40q does not exist in secret %.40q"
	msgPropertyNotObject = "property %.40q of secret %.40q is not a JSON object"
	msgReadPausedSecret  = "%w; the secret is paused (DISABLE), so its value cannot be read until it is resumed with Enable Secret"
	// msgUnmarshalSecret intentionally omits the parser error: encoding/json
	// echoes the first offending byte of the input, which for a non-JSON secret
	// value would leak a byte of the secret into the controller log.
	msgUnmarshalSecret   = "failed to unmarshal secret %s as JSON"
	msgInvalidPattern    = "invalid name pattern: %w"
	msgListSecrets       = "failed to list secrets: %w"
	msgGetSecret         = "failed to get secret %s: %w"
	msgCreateClient      = "failed to create Ncloud SecretManager client: %w"
	msgCheckSecret       = "failed to check secret existence: %w"
	msgResolveSecretID   = "failed to resolve secret name %q: %w"
	msgTooManyPages      = "list secrets pagination exceeded %d pages; aborting to avoid an unbounded listing"
	msgTooManyRows       = "list secrets returned more than %d rows in one sweep; aborting to avoid an unbounded listing"
	msgTooManyRowsOnPage = "list secrets page carries more than %d rows; refusing to decode it"
	msgSweepTooSlow      = "list secrets sweep exceeded its %v budget: %w"
	msgResponseTooLarge  = "response body exceeds the %d-byte limit"
	msgInvalidVersion    = "invalid version %.40q: Ncloud versions secrets by stage; valid values are \"previous\", \"active\" and \"pending\" (empty selects active)"
	msgEmptyStage        = "%w: secret %s has no %q stage value"
	msgMarshalMetadata   = "failed to marshal metadata of secret %s: %w"
	msgPushSecret        = "failed to push secret %s: %w"
	msgPushMissingKey    = "key %.40q not found in the Kubernetes secret"
	msgPushNotObject     = "existing secret value is not a JSON object; cannot push property %.40q into it"
	// msgInvalidSecretName and msgInvalidVersion cut what they quote to 40
	// characters: it is manifest text of any length, and the error reaches
	// the controller log.
	msgInvalidSecretName = "invalid secret name %.40q: Ncloud secret names are 3-15 characters of letters, digits, '-' or '_', starting with a letter"
	msgSecretIDNotFound  = "secret ID %s not found; a remoteKey given as an ID is never created, use the secret name to create it"
	msgDeleteSecret      = "failed to delete secret %s: %w"
	msgDeleteBadStatus   = "cannot delete secret %s while it is in %s"
	msgCreateNoID        = "created secret %s but the response carried no usable secret ID"
)

// handleErrorResponse handles HTTP error responses from Ncloud Secret Manager API.
// Returns appropriate sentinel errors based on HTTP status codes.
// Reference: https://api.ncloud-docs.com/docs/secretmanager-api-overview (response status codes).
func handleErrorResponse(statusCode int, body []byte) error {
	// Parse only enough of a structured envelope to map its documented code.
	// Message and details are server-controlled and may contain credentials,
	// secret values, or arbitrarily large strings, so neither is surfaced.
	var envelope struct {
		Error struct {
			ErrorCode string `json:"errorCode"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil {
		if code := numericErrorCode(envelope.Error.ErrorCode); code != "" {
			return newAPIError(sentinelFor(statusCode, code), statusCode, code)
		}
	}

	// An arbitrary response body is opaque and may itself be a secret (for
	// example, a proxy reflecting a request). Report only the HTTP status.
	return newAPIError(sentinelFor(statusCode, ""), statusCode, "")
}

// apiError is a non-success HTTP response. It keeps the status and the numeric
// code as fields rather than only as formatted text so a caller that knows more
// about its endpoint than the generic transport does can re-classify the
// failure without losing that detail or resorting to string matching (see
// secretManagerClient.ListSecrets).
type apiError struct {
	baseErr    error
	statusCode int
	errorCode  string
}

func newAPIError(baseErr error, statusCode int, errorCode string) *apiError {
	return &apiError{
		baseErr:    baseErr,
		statusCode: statusCode,
		errorCode:  numericErrorCode(errorCode),
	}
}

func (e *apiError) Error() string {
	detail := fmt.Sprintf(msgAPIError, e.statusCode)
	if e.errorCode != "" {
		detail = fmt.Sprintf(msgAPIErrorCode, e.statusCode, e.errorCode)
	}
	if e.baseErr != nil {
		return e.baseErr.Error() + ": " + detail
	}
	return detail
}

// Unwrap exposes the sentinel so errors.Is keeps working on the returned error.
func (e *apiError) Unwrap() error { return e.baseErr }

// withSentinel returns a copy reporting a different sentinel. The status and
// numeric code are carried over unchanged; only the classification differs.
func (e *apiError) withSentinel(baseErr error) *apiError {
	clone := *e
	clone.baseErr = baseErr
	return &clone
}

// maxErrorCodeDigits bounds a surfaced code so a pathological body cannot pad
// an error message. The codes this client acts on have three or six digits.
const maxErrorCodeDigits = 8

// numericErrorCode returns errorCode when it is purely numeric, and "" for
// anything else. The HTTP status decides the sentinel; this code only tells
// apart the kinds of 404 and of 429 (see sentinelFor). The service puts a
// numeric code in error.errorCode and a name in error.message, for example
// {"errorCode":"501001","message":"RESOURCE_NOT_FOUND"}. A bounded run of
// digits is safe to surface where the message, details and raw body are not:
// those may echo a credential or decrypted secret.
func numericErrorCode(errorCode string) string {
	if errorCode == "" || len(errorCode) > maxErrorCodeDigits {
		return ""
	}
	for _, r := range errorCode {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return errorCode
}

// codeResourceNotFound is the service code Ncloud returns when the addressed
// secret does not exist; the API gateway's own not-found answer carries the
// short code 300 instead. See ErrNotFoundUnverified.
const codeResourceNotFound = "501001"

// codeGatewayNotFound is the API gateway's own code for a 404 (Not Found
// Exception). It comes with a path the gateway does not serve, and can come
// with a key the gateway does not accept: an access key ID Ncloud does not
// know, a temporary pair past its expiry, or one whose Server Role was
// detached from the server. See doOnce.
const codeGatewayNotFound = "300"

// notFoundKind is what a 404 means, read from the code it carries. The codes
// are interpreted here and nowhere else, and each decision a 404 drives
// starts from the kind: its sentinel (sentinelFor) treats only
// notFoundResource as absence, and a refusal of the signing pair
// (refusesPair) is only notFoundGateway. A listing reports every kind as
// ErrListingUnavailable, having no secret that could be absent.
type notFoundKind int

const (
	// notFoundUnverified is a 404 with no code, or with one this provider
	// does not know, such as a proxy's.
	notFoundUnverified notFoundKind = iota
	// notFoundResource is Secret Manager's own answer (codeResourceNotFound).
	notFoundResource
	// notFoundGateway is the API gateway's own answer (codeGatewayNotFound).
	notFoundGateway
)

// notFoundKindOf classifies the code of a 404.
func notFoundKindOf(errorCode string) notFoundKind {
	switch errorCode {
	case codeResourceNotFound:
		return notFoundResource
	case codeGatewayNotFound:
		return notFoundGateway
	default:
		return notFoundUnverified
	}
}

// codeQuotaExceeded is the API gateway's code for a 429 that means the quota
// is used up rather than a momentary limit (see ErrQuotaExceeded). Taken from
// the gateway's documented error table.
const codeQuotaExceeded = "400"

// sentinelFor maps a response to its sentinel. It exists so 404 can consult the
// service code: only the service's own resource-not-found answer is absence,
// every other 404 fails closed (see ErrNotFoundUnverified).
func sentinelFor(statusCode int, errorCode string) error {
	if statusCode == http.StatusNotFound && notFoundKindOf(errorCode) != notFoundResource {
		return ErrNotFoundUnverified
	}
	if statusCode == http.StatusTooManyRequests && errorCode == codeQuotaExceeded {
		return ErrQuotaExceeded
	}
	return mapStatusCodeToSentinel(statusCode)
}

// mapStatusCodeToSentinel maps HTTP status codes to sentinel errors.
func mapStatusCodeToSentinel(statusCode int) error {
	switch statusCode {
	case http.StatusNotFound:
		return ErrSecretNotFound
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusBadRequest:
		return ErrInvalidRequest
	case http.StatusConflict:
		return ErrInvalidStatus
	case http.StatusUnprocessableEntity:
		return ErrUnprocessableEntity
	case http.StatusInternalServerError:
		return ErrInternalServerError
	case http.StatusTooManyRequests:
		return ErrRateLimited
	case http.StatusRequestTimeout, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		// A gateway request timeout is as transient as the 5xx trio and is
		// retried the same way; the request never reached the service.
		return ErrServiceUnavailable
	default:
		// Any other 5xx, such as a 507 or the 520 a proxy in front of the
		// endpoint answers, is transient too, as the credential sources
		// read theirs.
		if statusCode >= http.StatusInternalServerError {
			return ErrServiceUnavailable
		}
		return nil
	}
}

// IsRetryable reports whether err represents a transient condition that is
// safe to retry (rate limiting or an unavailable upstream), as opposed to a
// permanent failure such as NotFound or an auth error.
func IsRetryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, ErrRateLimited) ||
		errors.Is(err, ErrServiceUnavailable) ||
		errors.Is(err, ErrInternalServerError) {
		return true
	}
	if errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) {
		return true
	}
	for _, transient := range []error{
		syscall.ECONNABORTED,
		syscall.ECONNREFUSED,
		syscall.ECONNRESET,
		syscall.EHOSTUNREACH,
		syscall.ENETDOWN,
		syscall.ENETUNREACH,
		syscall.EPIPE,
		syscall.ETIMEDOUT,
	} {
		if errors.Is(err, transient) {
			return true
		}
	}

	if dnsErr, ok := errors.AsType[*net.DNSError](err); ok {
		return dnsErr.IsTimeout || dnsErr.IsTemporary
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
