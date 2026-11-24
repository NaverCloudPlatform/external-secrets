// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

const endpointScheme = "https://"

// ErrEndpointScheme is exported for the provider package's flag validation.
var ErrEndpointScheme = errors.New("endpoint must start with https://")

var (
	errEndpointEmpty      = errors.New("endpoint is empty")
	errEndpointWhitespace = errors.New("endpoint contains whitespace")
	errEndpointHost       = errors.New("endpoint has no host")
	errEndpointUserinfo   = errors.New("endpoint must not carry credentials in the URL")
	errEndpointQuery      = errors.New("endpoint must not carry a query or fragment")
	errEndpointPath       = errors.New("endpoint path must not contain . or .. segments or any character sent percent-encoded: percent-encoding, non-ASCII, or ASCII such as { | ^")
	errEndpointHostForm   = errors.New("endpoint host must not contain percent-encoding or non-ASCII characters; write an internationalized name in its xn-- form")
	errEndpointUnparsable = errors.New("endpoint is not a valid URL; it contains @, so the parse error is withheld in case it holds credentials")
)

// NormalizeEndpoint checks that endpoint is an HTTPS base URL this client can
// append request paths to, lowercases the host and removes trailing slashes.
// There is no host allowlist, as upstream providers with a URL field have
// none; who may point a store at a host is left to RBAC, and the provider
// docs state what that grants. Admission does not check that a store's
// author may read the Secret its secretRef names, so permission to create a
// SecretStore is permission to sign with every Ncloud key stored in its
// namespace, at a host of the author's choosing. serverRole and podIdentity
// sign with the controller's own key and are limited to ClusterSecretStore for
// that reason. The check protects the wire: every request carries the access
// key ID and an HMAC signature, and plain HTTP would expose them. The remaining
// refusals keep the value a clean base: paths are appended verbatim, so a query
// or fragment, a "." or ".." segment, or percent-encoding would change what a
// request means, and userinfo would become an Authorization header.
func NormalizeEndpoint(endpoint string) (string, error) {
	if endpoint == "" {
		return "", errEndpointEmpty
	}
	if strings.ContainsFunc(endpoint, unicode.IsSpace) {
		return "", errEndpointWhitespace
	}
	if !strings.HasPrefix(endpoint, endpointScheme) {
		return "", ErrEndpointScheme
	}
	if strings.ContainsAny(endpoint, "?#") {
		return "", errEndpointQuery
	}

	normalized := strings.TrimRight(endpoint, "/")
	u, err := url.Parse(normalized)
	if err != nil {
		return "", parseFailure(endpoint, err)
	}
	if u.User != nil {
		return "", errEndpointUserinfo
	}
	if u.Hostname() == "" {
		return "", errEndpointHost
	}
	// The host is kept as written, so it must be written the way it is sent:
	// url.Parse decodes percent-encoding in the authority (an IPv6 zone, an
	// encoded name), and a decoded host no longer lines up with the text it
	// came from.
	authority, path := normalized[len(endpointScheme):], ""
	if i := strings.IndexByte(authority, '/'); i >= 0 {
		authority, path = authority[:i], authority[i:]
	}
	if !writtenAsSent(authority) {
		return "", errEndpointHostForm
	}
	// The path is checked as written against what net/http sends for it,
	// u.EscapedPath(): a non-ASCII path, or ASCII such as {, would be sent
	// percent-encoded, while sub-delimiters such as ( are sent as written.
	// Percent-encoding is refused on its own, since a canonical encoding
	// such as %20 round-trips through EscapedPath unchanged.
	if !writtenAsSent(path) || u.EscapedPath() != path {
		return "", errEndpointPath
	}
	for segment := range strings.SplitSeq(u.Path, "/") {
		if segment == "." || segment == ".." {
			return "", errEndpointPath
		}
	}

	// DNS names are case-insensitive; keep the canonical spelling so the
	// documented endpoints compare equal however they were typed.
	return endpointScheme + strings.ToLower(authority) + path, nil
}

// parseFailure is the error for an endpoint url.Parse refused. A *url.Error
// quotes the whole value, and the userinfo check has not run yet, so a
// password in it would reach the admission response and the controller log.
// Its inner error names only the part that failed to parse, but that part can
// still be the password: a "/" in it ends the authority early and the rest is
// quoted as a port, and a bad escape quotes itself. A value with an "@"
// therefore gets no detail at all. Any other value keeps the inner error cut
// to maxParseDetail characters, since it may quote a whole port or IP literal.
func parseFailure(endpoint string, err error) error {
	if strings.Contains(endpoint, "@") {
		return errEndpointUnparsable
	}
	if urlErr, ok := errors.AsType[*url.Error](err); ok {
		err = urlErr.Err
	}
	return fmt.Errorf("endpoint is not a valid URL: %.*s", maxParseDetail, err)
}

// maxParseDetail bounds the parse detail an endpoint error carries: enough
// for "invalid port" and the start of the value it quotes.
const maxParseDetail = 80

// writtenAsSent reports whether a host or path holds neither percent-encoding
// nor non-ASCII characters, the two forms url.Parse decodes in an authority
// and may re-encode in a path. The path has a further check in
// NormalizeEndpoint for ASCII that net/http percent-encodes.
func writtenAsSent(s string) bool {
	return !strings.ContainsRune(s, '%') && !strings.ContainsFunc(s, func(r rune) bool { return r > unicode.MaxASCII })
}
