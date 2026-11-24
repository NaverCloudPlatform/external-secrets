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
	"net/http"
	"time"
)

// DefaultSTSEndpoint is the public Secure Token Service.
const DefaultSTSEndpoint = "https://sts.apigw.ntruss.com"

const (
	// stsSwitchRolePath issues a temporary key for a role the caller may
	// switch to. See https://api.ncloud-docs.com/docs/switch-role.
	stsSwitchRolePath = "/api/v1/switch-role"

	// switchRoleDurationSec asks for the service's default lifetime
	// explicitly. The documented range is 600 to 43200 seconds.
	switchRoleDurationSec = 3600

	// maxSTSResponseBytes caps a Secure Token Service response. A credential
	// document is a few hundred bytes.
	maxSTSResponseBytes = 64 << 10
)

// SwitchRoleCredentials returns a source that signs with the temporary key of
// role, obtained from the Secure Token Service at stsEndpoint by a request
// signed with base. An empty stsEndpoint selects DefaultSTSEndpoint.
//
// Sources are shared per (endpoint, role, base identity), so every client
// built for the same store, one per reconcile, reuses one switched pair until
// it is due for refresh instead of asking the service again. The base
// identity covers the whole base pair (see staticCredentials.Identity), and
// an idle source leaves the registry with the base pair it holds (see
// defaultCacheRegistryIdleTTL).
func SwitchRoleCredentials(base CredentialsSource, stsEndpoint, role string) (CredentialsSource, error) {
	if base == nil {
		return nil, ErrMissingCredentials
	}
	if role == "" {
		return nil, ErrMissingRole
	}
	if stsEndpoint == "" {
		stsEndpoint = DefaultSTSEndpoint
	}
	endpoint, err := NormalizeEndpoint(stsEndpoint)
	if err != nil {
		return nil, fmt.Errorf(msgInvalidSTSEndpoint, err)
	}

	construct := func() CredentialsSource {
		return newSwitchRoleSource(base, endpoint, role, newHTTPTransport())
	}
	return sharedRoleRegistry.get(construct, endpoint, role, base.Identity()), nil
}

// sharedRoleRegistry holds one switched-role source per (STS endpoint, role,
// base identity); see registry for why it is process-scoped and bounded.
var sharedRoleRegistry = newRegistry[CredentialsSource]("switched role")

// switchRoleSource exchanges the base pair for a role's temporary key at the
// Secure Token Service and refreshes it ahead of its expiry.
type switchRoleSource struct {
	*refreshingSource
	base       CredentialsSource
	endpoint   string
	role       string
	httpClient *http.Client
	clock      func() time.Time
}

func newSwitchRoleSource(base CredentialsSource, endpoint, role string, httpClient *http.Client) *switchRoleSource {
	s := &switchRoleSource{base: base, endpoint: endpoint, role: role, httpClient: httpClient, clock: time.Now}
	s.refreshingSource = newRefreshingSource(s.fetch)
	return s
}

// Identity names the role and, through the base identity, who switched to it:
// the same role reached from two keys is two principals as far as the service
// is concerned, and it must be two cache identities here too.
func (s *switchRoleSource) Identity() string { return "role:" + s.role + "@" + s.base.Identity() }

type switchRoleRequest struct {
	RoleNRN     string `json:"roleNrn"`
	DurationSec int    `json:"durationSec"`
}

// switchRoleResponse is the part of the service's answer this source reads.
// The service does not wrap it in the Secret Manager code envelope.
type switchRoleResponse struct {
	Credentials struct {
		AccessKey  string `json:"accessKey"`
		KeySecret  string `json:"keySecret"`
		ExpireTime string `json:"expireTime"`
	} `json:"credentials"`
}

func (s *switchRoleSource) fetch(ctx context.Context) (Credentials, error) {
	base, err := s.base.Credentials(ctx)
	if err != nil {
		return Credentials{}, fmt.Errorf(msgSwitchRole, err)
	}

	pair, err := s.switchWith(ctx, base)
	if errors.Is(err, errSwitchRoleCallerKeyRefused) && base.temporary() {
		// The service answers a stale caller key the same way it answers a
		// wrong one. A temporary base pair may simply have been revoked
		// early, so give the base one refresh; if it hands back the same
		// pair the refusal stands. A refusal of the switch itself says
		// nothing about the key and earns no refresh.
		s.base.Invalidate(ctx, base)
		switch fresh, ferr := s.base.Credentials(ctx); {
		case ferr != nil:
			// The refusal is what happened; the failed refresh is why it
			// will happen again, and the one an operator can act on.
			err = fmt.Errorf("%w; refreshing the caller pair failed: %w", err, ferr)
		case fresh.AccessKeyID != base.AccessKeyID:
			pair, err = s.switchWith(ctx, fresh)
		}
	}
	if err != nil {
		return Credentials{}, fmt.Errorf(msgSwitchRole, err)
	}
	return pair, nil
}

func (s *switchRoleSource) switchWith(ctx context.Context, base Credentials) (Credentials, error) {
	payload, err := json.Marshal(switchRoleRequest{RoleNRN: s.role, DurationSec: switchRoleDurationSec})
	if err != nil {
		return Credentials{}, fmt.Errorf(msgCreateRequest, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+stsSwitchRolePath, bytes.NewReader(payload))
	if err != nil {
		return Credentials{}, fmt.Errorf(msgCreateRequest, err)
	}
	setAuthHeaders(req, base, s.clock())

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return Credentials{}, fmt.Errorf(msgExecuteRequest, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSTSResponseBytes+1))
	if err != nil {
		return Credentials{}, fmt.Errorf(msgReadResponseBody, err)
	}
	if len(body) > maxSTSResponseBytes {
		return Credentials{}, fmt.Errorf(msgResponseTooLarge, maxSTSResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		// The service documents 404 for an invalid or expired caller key,
		// and 401 is the gateway's own refusal of the signature; either can
		// be a temporary caller key the issuer has since replaced, so both
		// carry the caller-key sentinel that fetch acts on. 403 is the
		// gateway refusing the switch itself. The body is server-controlled
		// free text and is not surfaced, as with every other Ncloud error.
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusNotFound:
			return Credentials{}, newAPIError(errSwitchRoleCallerKeyRefused, resp.StatusCode, "")
		case http.StatusForbidden:
			return Credentials{}, newAPIError(ErrSwitchRoleRejected, resp.StatusCode, "")
		case http.StatusTooManyRequests:
			// Carry the delay the service asked for, as the Secret Manager
			// transport does, so a GET's retry loop can honor it.
			err := newAPIError(ErrRateLimited, resp.StatusCode, "")
			if after, ok := parseRetryAfter(resp.Header.Get("Retry-After"), s.clock()); ok {
				return Credentials{}, &retryAfterError{err: err, after: after}
			}
			return Credentials{}, err
		default:
			// A 5xx, or the gateway's 408 (it stopped waiting for the
			// service), may pass on retry; the Secret Manager transport and
			// the Pod Identity exchange classify them the same way.
			if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= http.StatusInternalServerError {
				return Credentials{}, newAPIError(ErrServiceUnavailable, resp.StatusCode, "")
			}
			// Any other refusal is the service declining this switch, such
			// as a role NRN it does not accept, which no retry changes. The
			// Secret Manager sentinels would be wrong here: a 400 or 409
			// reads as a lifecycle state on the read path.
			return Credentials{}, newAPIError(ErrSwitchRoleRejected, resp.StatusCode, "")
		}
	}

	var out switchRoleResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return Credentials{}, errSTSDecode
	}
	expiry, err := time.Parse(time.RFC3339, out.Credentials.ExpireTime)
	if err != nil {
		return Credentials{}, ErrTemporaryCredentialsIncomplete
	}
	return Credentials{AccessKeyID: out.Credentials.AccessKey, SecretKey: out.Credentials.KeySecret, Expiry: expiry}, nil
}
