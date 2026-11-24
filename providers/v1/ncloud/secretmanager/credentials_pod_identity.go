// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// maxPodIdentityResponseBytes caps a Pod Identity exchange response. A
// credential document is a few hundred bytes.
const maxPodIdentityResponseBytes = 64 << 10

// PodIdentityCredentials returns the shared source for the Pod Identity of
// the pod this process runs in: the temporary key the Ncloud Kubernetes
// Service exchange issues for the projected ServiceAccount token at
// tokenFile. endpoint is the exchange URL as the Pod Identity add-on injected
// it, path included; it is normalized (a trailing slash is dropped) and
// nothing is appended to it, and it must be https because the token travels
// in the request.
//
// Sources are shared per (endpoint, token file) because the identity is a
// property of the pod, not of a store: every store gets the same pair, and
// sharing means one exchange serves them all. Both values come from the
// provider's configuration, never from a store, so the map cannot grow with
// the stores a cluster holds.
func PodIdentityCredentials(tokenFile, endpoint string) (CredentialsSource, error) {
	if tokenFile == "" {
		return nil, fmt.Errorf("%w: the token file path is empty", ErrPodIdentityUnavailable)
	}
	normalized, err := NormalizeEndpoint(endpoint)
	if err != nil {
		return nil, fmt.Errorf(msgInvalidPodIdentityEndpoint, err)
	}
	key := podIdentityKey{endpoint: normalized, tokenFile: filepath.Clean(tokenFile)}

	podIdentitySources.mu.Lock()
	defer podIdentitySources.mu.Unlock()
	if source, ok := podIdentitySources.byKey[key]; ok {
		return source, nil
	}
	source := newPodIdentitySource(key.tokenFile, key.endpoint, newHTTPTransport())
	podIdentitySources.byKey[key] = source
	return source, nil
}

type podIdentityKey struct{ endpoint, tokenFile string }

var podIdentitySources = struct {
	mu    sync.Mutex
	byKey map[podIdentityKey]*podIdentitySource
}{byKey: map[podIdentityKey]*podIdentitySource{}}

// podIdentitySource exchanges the pod's projected token for the associated
// role's temporary key and refreshes it ahead of its expiry.
type podIdentitySource struct {
	*refreshingSource
	tokenFile  string
	endpoint   string
	httpClient *http.Client
	clock      func() time.Time
}

func newPodIdentitySource(tokenFile, endpoint string, httpClient *http.Client) *podIdentitySource {
	s := &podIdentitySource{tokenFile: tokenFile, endpoint: endpoint, httpClient: httpClient, clock: time.Now}
	s.refreshingSource = newRefreshingSource(s.fetch)
	return s
}

// Identity is constant per endpoint and token file: which role the pod's
// ServiceAccount is associated with is not known until the exchange answers,
// and the key rotates, so neither can key a cache.
func (s *podIdentitySource) Identity() string {
	return "podIdentity:" + s.tokenFile + "@" + s.endpoint
}

// podIdentityResponse is the exchange's answer. The field names are the
// Pod Identity add-on's credential contract; there is no code envelope.
type podIdentityResponse struct {
	AccessKey  string `json:"accessKey"`
	SecretKey  string `json:"secretKey"`
	Expiration string `json:"expiration"`
}

func (s *podIdentitySource) fetch(ctx context.Context) (Credentials, error) {
	token, err := s.readToken()
	if err != nil {
		return Credentials{}, fmt.Errorf(msgPodIdentity, err)
	}
	pair, err := s.exchange(ctx, token)
	if err != nil {
		return Credentials{}, fmt.Errorf(msgPodIdentity, err)
	}
	return pair, nil
}

// readToken reads the projected token afresh on every fetch: the kubelet
// replaces the file before the token expires, and a token read once would be
// sent after its replacement and refused. The path comes from the
// controller's own environment, never from a store.
func (s *podIdentitySource) readToken() (string, error) {
	raw, err := os.ReadFile(filepath.Clean(s.tokenFile))
	if err != nil {
		// The error names the path; a pod the add-on did not inject has no
		// file there.
		return "", fmt.Errorf("%w: %w", ErrPodIdentityUnavailable, err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("%w: %s is empty", ErrPodIdentityUnavailable, s.tokenFile)
	}
	return token, nil
}

// exchange posts the token and reads the pair. The request carries no body
// and no Ncloud signature: the bearer token is the whole credential.
func (s *podIdentitySource) exchange(ctx context.Context, token string) (Credentials, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, http.NoBody)
	if err != nil {
		return Credentials{}, fmt.Errorf(msgCreateRequest, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return Credentials{}, fmt.Errorf(msgExecuteRequest, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPodIdentityResponseBytes+1))
	if err != nil {
		return Credentials{}, fmt.Errorf(msgReadResponseBody, err)
	}
	if len(body) > maxPodIdentityResponseBytes {
		return Credentials{}, fmt.Errorf(msgResponseTooLarge, maxPodIdentityResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return Credentials{}, s.refusal(resp)
	}

	// The document is the one place a key could be echoed from, so a decode
	// failure is reported without it, as the Secret Manager client does.
	var out podIdentityResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return Credentials{}, errPodIdentityDecode
	}
	expiry, err := time.Parse(time.RFC3339, out.Expiration)
	if err != nil {
		return Credentials{}, ErrTemporaryCredentialsIncomplete
	}
	return Credentials{AccessKeyID: out.AccessKey, SecretKey: out.SecretKey, Expiry: expiry}, nil
}

// podIdentityRefusals says what each documented refusal means, so the
// controller log names what to check: the add-on, the token, the association
// or the exchange address. The exchange also sends an error code in the
// body; the status is the authority here and the body is not surfaced, as
// with every other Ncloud error.
var podIdentityRefusals = map[int]string{
	http.StatusBadRequest:   "the token's audience is not this cluster's Pod Identity audience (InvalidAudience); the add-on that projected it is misconfigured",
	http.StatusUnauthorized: "the token was refused (InvalidToken): it is expired, from another cluster, or not bound to a running pod",
	http.StatusForbidden:    "no Pod Identity association for the controller's namespace and ServiceAccount, or its role does not have Ncloud Kubernetes Service as a target (NoAssociation)",
	http.StatusNotFound:     "the exchange API is not available at this address",
}

// refusal classifies a non-200 answer. A 429 carries the delay the service
// asked for, as the Secret Manager transport does, so a GET's retry loop can
// honor it; a 5xx (the documented 503 UpstreamError among them) or a
// gateway's 408 may pass on retry, as the Secret Manager transport treats
// them; every other status is the exchange declining this pod, which no
// retry changes.
func (s *podIdentitySource) refusal(resp *http.Response) error {
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		err := newAPIError(ErrRateLimited, resp.StatusCode, "")
		if after, ok := parseRetryAfter(resp.Header.Get("Retry-After"), s.clock()); ok {
			return &retryAfterError{err: err, after: after}
		}
		return err
	case resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode >= http.StatusInternalServerError:
		return newAPIError(ErrServiceUnavailable, resp.StatusCode, "")
	}
	rejected := newAPIError(ErrPodIdentityRejected, resp.StatusCode, "")
	if reason, ok := podIdentityRefusals[resp.StatusCode]; ok {
		return fmt.Errorf("%w: %s", rejected, reason)
	}
	return rejected
}
