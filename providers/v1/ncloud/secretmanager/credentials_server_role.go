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
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultMetadataEndpoint is where a VPC server reads its instance metadata,
// including the temporary key of the Server Role attached to it. It is plain
// http on a link-local address by design and never leaves the node.
const DefaultMetadataEndpoint = "http://169.254.169.254"

const (
	// metadataRolePath lists the ID of the attached role; with the ID
	// appended it issues that role's temporary key.
	// See https://api.ncloud-docs.com/docs/compute-vmetadata-roledata.
	metadataRolePath = "/latest/meta-data/iam/security-credentials"

	// metadataTokenPath issues a session token (Metadata v2). A server set to
	// "v2 (token required)" answers every tokenless call with 401, and a
	// server set to "v1 and v2" accepts a token too, so the token is always
	// requested first. See
	// https://api.ncloud-docs.com/docs/compute-vmetadata-metadatav2.
	metadataTokenPath      = "/latest/api/token"
	metadataTokenHeader    = "X-NCP-METADATA-TOKEN"
	metadataTokenTTLHeader = "X-NCP-METADATA-TOKEN-TTL-SECONDS"

	// metadataTokenTTL is the token lifetime asked for, in seconds. A token
	// serves the two reads of one fetch, so a minute is plenty.
	metadataTokenTTL = "60"

	// metadataTimeout bounds each metadata call. The endpoint is link-local,
	// so a slow answer means it is not there.
	metadataTimeout = 3 * time.Second

	// metadataSuccessCode is the Code a credential document carries when it
	// holds a key.
	metadataSuccessCode = "Success"

	// maxMetadataBytes caps a metadata response. A role ID and a credential
	// document are a few hundred bytes.
	maxMetadataBytes = 64 << 10
)

// ServerRoleCredentials returns the shared source for the Server Role attached
// to the node this process runs on. An empty endpoint selects
// DefaultMetadataEndpoint. Sources are shared per endpoint because the role is
// a property of the node, not of a store: every store on the node gets the same
// pair, and sharing means one refresh serves them all. The endpoint comes from
// the provider's configuration, never from a store, so the map cannot grow with
// the stores a cluster holds.
func ServerRoleCredentials(metadataEndpoint string) CredentialsSource {
	if metadataEndpoint == "" {
		metadataEndpoint = DefaultMetadataEndpoint
	}
	metadataEndpoint = strings.TrimRight(metadataEndpoint, "/")

	serverRoleSources.mu.Lock()
	defer serverRoleSources.mu.Unlock()
	if source, ok := serverRoleSources.byEndpoint[metadataEndpoint]; ok {
		return source
	}
	source := newServerRoleSource(metadataEndpoint, metadataHTTPClient())
	serverRoleSources.byEndpoint[metadataEndpoint] = source
	return source
}

var serverRoleSources = struct {
	mu         sync.Mutex
	byEndpoint map[string]*serverRoleSource
}{byEndpoint: map[string]*serverRoleSource{}}

// serverRoleSource reads the attached role's temporary key from the instance
// metadata endpoint and refreshes it ahead of its expiry.
type serverRoleSource struct {
	*refreshingSource
	endpoint   string
	httpClient *http.Client
}

func newServerRoleSource(endpoint string, httpClient *http.Client) *serverRoleSource {
	s := &serverRoleSource{endpoint: endpoint, httpClient: httpClient}
	s.refreshingSource = newRefreshingSource(s.fetch)
	return s
}

// Identity is constant per endpoint: which role a node carries is not known
// until the metadata is read, and the key rotates, so neither can key a cache.
func (s *serverRoleSource) Identity() string { return "serverRole@" + s.endpoint }

func metadataHTTPClient() *http.Client {
	// The default transport would send this through HTTP_PROXY, and a proxy
	// can never reach a link-local address, so the proxy settings are not
	// consulted at all.
	transport, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		transport = transport.Clone()
	} else {
		// Something replaced the default transport with another type; a
		// plain transport is still right for a link-local address.
		transport = &http.Transport{}
	}
	transport.Proxy = nil
	return &http.Client{
		Transport: transport,
		Timeout:   metadataTimeout,
		// A redirect off the link-local address would carry the request
		// anywhere; the endpoint never redirects, so surface one as an error.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// metadataCredentials is the document the endpoint issues for a role. Fields
// this source does not read (Type, Token, LastUpdated) are left out.
type metadataCredentials struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Expiration      string `json:"Expiration"`
	Code            string `json:"Code"`
}

func (s *serverRoleSource) fetch(ctx context.Context) (Credentials, error) {
	token, declined, err := s.token(ctx)
	if err != nil {
		return Credentials{}, fmt.Errorf(msgServerRole, err)
	}
	roleID, err := s.roleID(ctx, token)
	if err != nil {
		return Credentials{}, fmt.Errorf(msgServerRole, withTokenAnswer(err, declined))
	}

	body, err := s.get(ctx, metadataRolePath+"/"+url.PathEscape(roleID), token)
	if err != nil {
		return Credentials{}, fmt.Errorf(msgServerRole, withTokenAnswer(err, declined))
	}

	// The document is the one place a key could be echoed from, so a decode
	// failure is reported without it, as the Secret Manager client does.
	var doc metadataCredentials
	if err := json.Unmarshal(body, &doc); err != nil {
		return Credentials{}, fmt.Errorf(msgServerRole, errMetadataDecode)
	}
	// A document that names another code is refused; one that omits it is
	// judged by its key material, which the caller checks for completeness.
	if doc.Code != "" && doc.Code != metadataSuccessCode {
		return Credentials{}, fmt.Errorf(msgServerRole, errMetadataCode)
	}
	expiry, err := time.Parse(time.RFC3339, doc.Expiration)
	if err != nil {
		return Credentials{}, fmt.Errorf(msgServerRole, ErrTemporaryCredentialsIncomplete)
	}
	return Credentials{AccessKeyID: doc.AccessKeyID, SecretKey: doc.SecretAccessKey, Expiry: expiry}, nil
}

// roleID reads the attached role's ID. The listing has no trailing newline; a
// server with several roles lists one per line and the first is used.
func (s *serverRoleSource) roleID(ctx context.Context, token string) (string, error) {
	body, err := s.get(ctx, metadataRolePath, token)
	if err != nil {
		return "", err
	}
	for line := range strings.Lines(string(body)) {
		if id := strings.TrimSpace(line); id != "" {
			return id, nil
		}
	}
	return "", ErrServerRoleUnavailable
}

// tokenDecline is a token request that produced no token: what the endpoint
// answered, for the error, and the error a retry may clear when the answer
// was a transient one (see metadataTransient) rather than an endpoint without
// Metadata v2.
type tokenDecline struct {
	answer    string
	transient error
}

// token requests a Metadata v2 session token. An endpoint that answers the
// request with anything but a token, such as one predating Metadata v2, gets
// "": the reads then go without one, as Metadata v1 calls, and declined says
// what the endpoint answered instead. Not reaching the endpoint at all is the
// same answer a read would get.
func (s *serverRoleSource) token(ctx context.Context) (token string, declined tokenDecline, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.endpoint+metadataTokenPath, http.NoBody)
	if err != nil {
		return "", tokenDecline{}, fmt.Errorf(msgCreateRequest, err)
	}
	req.Header.Set(metadataTokenTTLHeader, metadataTokenTTL)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", tokenDecline{}, fmt.Errorf("%w: %w", ErrServerRoleUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	switch {
	case resp.StatusCode != http.StatusOK:
		return "", tokenDecline{
			answer:    fmt.Sprintf("status %d", resp.StatusCode),
			transient: metadataTransient(resp.StatusCode),
		}, nil
	case err != nil:
		return "", tokenDecline{answer: "a body that could not be read"}, nil
	case len(body) > maxMetadataBytes:
		return "", tokenDecline{answer: "a body over the size limit"}, nil
	}
	if token = strings.TrimSpace(string(body)); token == "" {
		return "", tokenDecline{answer: "an empty token"}, nil
	}
	return token, tokenDecline{}, nil
}

// withTokenAnswer adds the token request's answer to a refused read that went
// without a token. On a v2-only node the refusal is the symptom and the token
// request the cause, and the error should point there. When that answer was
// transient, the refusal is reported as the token request's failure, which a
// retry may clear, and not as a configuration answer: a v2-only node whose
// token endpoint fails for a moment would otherwise fail a GET at once and
// mark the store Ready=False.
func withTokenAnswer(err error, declined tokenDecline) error {
	if declined.answer == "" || !errors.Is(err, errMetadataRefused) {
		return err
	}
	if declined.transient != nil {
		return fmt.Errorf("%w; the Metadata v2 token request was answered with %s, so the read went without a token and was refused (%s)",
			declined.transient, declined.answer, err.Error())
	}
	return fmt.Errorf("%w; it was sent without a token because the Metadata v2 token request was answered with %s", err, declined.answer)
}

func (s *serverRoleSource) get(ctx context.Context, path, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+path, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf(msgCreateRequest, err)
	}
	if token != "" {
		req.Header.Set(metadataTokenHeader, token)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		// Unreachable is the answer a pod gets when it is not on a VPC
		// server, or when a NetworkPolicy keeps it from the address.
		return nil, fmt.Errorf("%w: %w", ErrServerRoleUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	if err != nil {
		return nil, fmt.Errorf(msgReadResponseBody, err)
	}
	if len(body) > maxMetadataBytes {
		return nil, fmt.Errorf(msgResponseTooLarge, maxMetadataBytes)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusNotFound:
		// The endpoint answers 404 for a path it has no data for, which for
		// the role paths means no role is attached.
		return nil, ErrServerRoleUnavailable
	default:
		// A refusal is an answer about this node's configuration, such as
		// a server set to require a metadata token. A 5xx, 408 or 429 may
		// pass on retry (see metadataTransient), so a GET's retry loop
		// treats it like the same status from the Secret Manager itself.
		if transient := metadataTransient(resp.StatusCode); transient != nil {
			return nil, transient
		}
		return nil, fmt.Errorf("%w: "+msgMetadataStatus, errMetadataRefused, resp.StatusCode)
	}
}

// metadataTransient is the error for a metadata status a retry may clear: a
// 429, the gateway's 408, or a 5xx, classified as the Pod Identity exchange
// and the Secure Token Service classify theirs. Any other status is nil.
func metadataTransient(status int) error {
	switch {
	case status == http.StatusTooManyRequests:
		return newAPIError(ErrRateLimited, status, "")
	case status == http.StatusRequestTimeout, status >= http.StatusInternalServerError:
		return newAPIError(ErrServiceUnavailable, status, "")
	}
	return nil
}
