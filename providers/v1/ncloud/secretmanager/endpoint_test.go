// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package secretmanager

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The documented endpoints (docs/provider/ncloud.md lists them with their key
// boundaries). They are not a gate: NormalizeEndpoint accepts any HTTPS base
// URL, so these only seed the tests, the live probes included, which is why
// they live in an untagged test file.
const (
	secretManagerKRGlobalEndpoint   = "https://secretmanager.apigw.ntruss.com"
	secretManagerKRIsolatedEndpoint = "https://ocapi-kr.ncloud.com/secretmanager"
	secretManagerJPIsolatedEndpoint = "https://ocapi-jp.ncloud.com/secretmanager"
)

// acceptedEndpointCases is shared by the acceptance test and the CRD-pattern
// gate test: every entry is an endpoint NormalizeEndpoint accepts, with the
// value it normalizes to.
var acceptedEndpointCases = []struct {
	name     string
	endpoint string
	want     string
}{
	{name: "API gateway", endpoint: secretManagerKRGlobalEndpoint, want: secretManagerKRGlobalEndpoint},
	{name: "API gateway trailing slash", endpoint: secretManagerKRGlobalEndpoint + "/", want: secretManagerKRGlobalEndpoint},
	{name: "Korea", endpoint: secretManagerKRIsolatedEndpoint, want: secretManagerKRIsolatedEndpoint},
	{name: "Korea trailing slashes", endpoint: secretManagerKRIsolatedEndpoint + "///", want: secretManagerKRIsolatedEndpoint},
	{name: "Japan", endpoint: secretManagerJPIsolatedEndpoint, want: secretManagerJPIsolatedEndpoint},
	{name: "Japan trailing slash", endpoint: secretManagerJPIsolatedEndpoint + "/", want: secretManagerJPIsolatedEndpoint},
	{name: "uppercase host is lowercased", endpoint: "https://OCAPI-KR.NCLOUD.COM/secretmanager", want: secretManagerKRIsolatedEndpoint},
	{name: "explicit default port", endpoint: "https://ocapi-kr.ncloud.com:443/secretmanager", want: "https://ocapi-kr.ncloud.com:443/secretmanager"},
	{name: "non-default port", endpoint: "https://ocapi-kr.ncloud.com:8443/secretmanager", want: "https://ocapi-kr.ncloud.com:8443/secretmanager"},
	{name: "proxy host", endpoint: "https://secretmanager-proxy.internal.example/secretmanager/", want: "https://secretmanager-proxy.internal.example/secretmanager"},
	{name: "host suffix", endpoint: "https://ocapi-kr.ncloud.com.attacker.example/secretmanager", want: "https://ocapi-kr.ncloud.com.attacker.example/secretmanager"},
	{name: "extra path", endpoint: "https://ocapi-kr.ncloud.com/secretmanager/api", want: "https://ocapi-kr.ncloud.com/secretmanager/api"},
	{name: "host only with slash", endpoint: "https://secretmanager.apigw.ntruss.com/", want: secretManagerKRGlobalEndpoint},
	{name: "port and mixed-case path", endpoint: "https://Proxy.Example:8443/Secret/Manager/", want: "https://proxy.example:8443/Secret/Manager"},
	{name: "IPv6 literal and port", endpoint: "https://[FE80::1]:8443/base", want: "https://[fe80::1]:8443/base"},
	{name: "internationalized name in xn-- form", endpoint: "https://xn--vil-dma.example/x", want: "https://xn--vil-dma.example/x"},
	{name: "path characters sent as written", endpoint: "https://proxy.example/a$b&c+d,e;f=g@h:i~j_k-l.m", want: "https://proxy.example/a$b&c+d,e;f=g@h:i~j_k-l.m"},
	{name: "path sub-delimiters sent as written", endpoint: "https://proxy.example/v(1)!*'x[0]", want: "https://proxy.example/v(1)!*'x[0]"},
}

func TestNormalizeEndpointAcceptsHTTPSBaseURLs(t *testing.T) {
	for _, tt := range acceptedEndpointCases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeEndpoint(tt.endpoint)
			if err != nil {
				t.Fatalf("NormalizeEndpoint(%q) returned error: %v", tt.endpoint, err)
			}
			if got != tt.want {
				t.Errorf("NormalizeEndpoint(%q) = %q, want %q", tt.endpoint, got, tt.want)
			}
		})
	}
}

// rejectedEndpointCases is shared by the rejection test and the CRD-pattern
// gate test so both face the same corpus. Every entry is either not an
// https:// URL at all, or could not serve as a base that request paths are
// appended to.
var rejectedEndpointCases = []struct {
	name     string
	endpoint string
}{
	{name: "empty", endpoint: ""},
	{name: "HTTP", endpoint: "http://ocapi-kr.ncloud.com/secretmanager"},
	{name: "schemeless", endpoint: "ocapi-kr.ncloud.com/secretmanager"},
	{name: "uppercase scheme", endpoint: "HTTPS://ocapi-kr.ncloud.com/secretmanager"},
	{name: "scheme only", endpoint: "https://"},
	{name: "scheme and slashes only", endpoint: "https:///"},
	{name: "userinfo", endpoint: "https://user@ocapi-kr.ncloud.com/secretmanager"},
	{name: "password userinfo", endpoint: "https://user:password@ocapi-kr.ncloud.com/secretmanager"},
	{name: "query", endpoint: "https://ocapi-kr.ncloud.com/secretmanager?debug=1"},
	{name: "bare query", endpoint: "https://ocapi-kr.ncloud.com/secretmanager?"},
	{name: "fragment", endpoint: "https://ocapi-kr.ncloud.com/secretmanager#fragment"},
	{name: "bare fragment", endpoint: "https://ocapi-kr.ncloud.com/secretmanager#"},
	{name: "leading whitespace", endpoint: " https://ocapi-kr.ncloud.com/secretmanager"},
	{name: "trailing whitespace", endpoint: "https://ocapi-kr.ncloud.com/secretmanager "},
	{name: "newline", endpoint: "https://ocapi-kr.ncloud.com/secretmanager\n"},
	{name: "encoded slash", endpoint: "https://ocapi-kr.ncloud.com/secretmanager%2f"},
	{name: "encoded dot", endpoint: "https://ocapi-kr.ncloud.com/secretmanager/%2e"},
	{name: "encoded dot segment", endpoint: "https://ocapi-kr.ncloud.com/secretmanager/%2e%2e"},
	{name: "canonically encoded space", endpoint: "https://ocapi-kr.ncloud.com/secret%20manager"},
	{name: "non-ASCII path", endpoint: "https://ocapi-kr.ncloud.com/sécret"},
	{name: "path brace sent percent-encoded", endpoint: "https://proxy.example/base{1}"},
	{name: "path pipe sent percent-encoded", endpoint: "https://proxy.example/base|x"},
	{name: "path caret sent percent-encoded", endpoint: "https://proxy.example/base^y"},
	{name: "path quote sent percent-encoded", endpoint: "https://proxy.example/base\"z"},
	{name: "current-directory path", endpoint: "https://ocapi-kr.ncloud.com/secretmanager/."},
	{name: "parent-directory path", endpoint: "https://ocapi-kr.ncloud.com/secretmanager/.."},
	{name: "percent-encoded host", endpoint: "https://%C3%A9vil.com/x"},
	{name: "IPv6 zone", endpoint: "https://[fe80::1%25eth0]/base"},
	{name: "IPv6 zone and port", endpoint: "https://[fe80::1%25eth0]:8443/base"},
	{name: "non-ASCII host", endpoint: "https://évil.com/x"},
}

func TestNormalizeEndpointRejectsUnusableBaseURLs(t *testing.T) {
	for _, tt := range rejectedEndpointCases {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := NormalizeEndpoint(tt.endpoint); err == nil {
				t.Errorf("NormalizeEndpoint(%q) = %q, want error", tt.endpoint, got)
			}
		})
	}
}

// TestNormalizeEndpointParseErrorDoesNotEchoTheValue pins that a value
// url.Parse refuses is not repeated in the error. The parse runs before the
// userinfo check, so a value that carries a password and also fails to parse
// would otherwise put the password in the admission response and the
// controller log. A "/" in the password ends the authority early, and the
// inner error then quotes what it took for a port; a bad escape quotes itself.
func TestNormalizeEndpointParseErrorDoesNotEchoTheValue(t *testing.T) {
	for _, tc := range []struct{ endpoint, secret string }{
		{"https://user:hunter2pw@[bad", "hunter2pw"},
		{"https://user:hunter2pw@host:port", "hunter2pw"},
		{"https://user:hunter2pw/x@host", "hunter2pw"},
		{"https://user:hunter2pw%zz@host", "%zz"},
	} {
		endpoint := tc.endpoint
		_, err := NormalizeEndpoint(endpoint)
		if err == nil {
			t.Fatalf("NormalizeEndpoint(%q) succeeded, want a parse error", endpoint)
		}
		if strings.Contains(err.Error(), tc.secret) {
			t.Errorf("NormalizeEndpoint(%q) error = %q, echoes the password", endpoint, err)
		}
		if !strings.Contains(err.Error(), "not a valid URL") {
			t.Errorf("NormalizeEndpoint(%q) error = %q, want the parse failure named", endpoint, err)
		}
	}
}

// TestNormalizeEndpointParseErrorIsBounded pins that the parse error of a
// value with no credentials in it stays short. url.Parse quotes the whole
// port, and netip.ParseAddr the whole IP literal, so a long value would
// otherwise reach the admission response and the controller log whole, past
// the bound every other echo of manifest text keeps.
func TestNormalizeEndpointParseErrorIsBounded(t *testing.T) {
	long := strings.Repeat("p", 4096)
	for name, endpoint := range map[string]string{
		"port":       "https://host.example:" + long,
		"IP literal": "https://[" + long + "]",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NormalizeEndpoint(endpoint)
			if err == nil {
				t.Fatal("NormalizeEndpoint() succeeded, want a parse error")
			}
			if len(err.Error()) > 160 {
				t.Errorf("NormalizeEndpoint() error is %d bytes, want it bounded: %.120q...", len(err.Error()), err.Error())
			}
			if !strings.Contains(err.Error(), "not a valid URL") {
				t.Errorf("NormalizeEndpoint() error = %.120q, want the parse failure named", err.Error())
			}
		})
	}
	// A short value keeps the part that failed, which is what an operator
	// needs to fix it.
	if _, err := NormalizeEndpoint("https://host.example:abc"); err == nil || !strings.Contains(err.Error(), "abc") {
		t.Errorf("NormalizeEndpoint() error = %v, want it to name the port that failed", err)
	}
}

// endpointPatternMarker extracts the kubebuilder Pattern marker regex from
// the NcloudProvider.Endpoint declaration in the given apis source file. The
// CRD gate and NormalizeEndpoint live in different modules, so the marker is
// read from source; a moved file or a reshaped marker fails loudly instead of
// silently skipping the check.
func endpointPatternMarker(t *testing.T, path string) string {
	t.Helper()
	return fieldPatternMarker(t, path, "Endpoint string `json:\"endpoint\"`")
}

// fieldPatternMarker extracts the Pattern marker in the comment block right
// above the given field declaration. The file carries Pattern markers for
// two fields (endpoint, role), so the nearest marker above the field is
// taken, and it must be separated from the field by comment lines only, or
// this extractor could validate another field's rule.
func fieldPatternMarker(t *testing.T, path, field string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	before, _, found := strings.Cut(string(data), field)
	if !found {
		t.Fatalf("field %q not found in %s", field, path)
	}
	const prefix = "+kubebuilder:validation:Pattern:=`"
	head, after, ok := strings.CutLast(before, prefix)
	if !ok {
		t.Fatalf("no %s marker above %q in %s", prefix, field, path)
	}
	lineStart := strings.LastIndex(head, "\n") + 1
	for line := range strings.Lines(before[lineStart:]) {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "//") {
			t.Fatalf("the %s marker nearest to %q in %s belongs to another declaration (%q sits between them)", prefix, field, path, trimmed)
		}
	}
	pattern, _, found := strings.Cut(after, "`")
	if !found {
		t.Fatalf("unterminated Pattern marker in %s", path)
	}
	return pattern
}

// propertyPatternCount counts the schema properties named property whose
// block carries `pattern: <pattern>`.
func propertyPatternCount(yaml, property, pattern string) int {
	count := 0
	for _, block := range propertyBlocks(yaml, property) {
		if blockHasLine(block, "pattern: "+pattern) {
			count++
		}
	}
	return count
}

// propertyBlocks returns the schema block under every property named
// property: the run of lines indented deeper than the property key, which is
// how the generated YAML nests a property's schema.
func propertyBlocks(yaml, property string) []string {
	lines := strings.Split(yaml, "\n")
	var blocks []string
	for i, line := range lines {
		if strings.TrimSpace(line) != property+":" {
			continue
		}
		indent := indentOf(line)
		end := i + 1
		for end < len(lines) && (strings.TrimSpace(lines[end]) == "" || indentOf(lines[end]) > indent) {
			end++
		}
		blocks = append(blocks, strings.Join(lines[i+1:end], "\n"))
	}
	return blocks
}

// blockHasLine reports whether block carries want as one of its own lines,
// at any depth.
func blockHasLine(block, want string) bool {
	for line := range strings.Lines(block) {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

// TestEndpointPatternMarkerIsACoarseGateForNormalizeEndpoint pins the CRD
// schema pattern to NormalizeEndpoint in the direction that matters. The CRD
// is the first gate a store meets, and it must never turn away an endpoint
// the provider accepts, or `kubectl apply` rejects what the documentation
// promises. In the other direction the pattern may be coarser, because
// NormalizeEndpoint runs again at admission and at client construction; but
// it must still refuse every value that is not an https:// URL, so the wire
// guarantee does not depend on the webhook being installed. The v1 and
// v1beta1 markers must agree. kube-apiserver compiles CRD patterns with Go
// regexp too, so MatchString reproduces the apply-time verdict.
func TestEndpointPatternMarkerIsACoarseGateForNormalizeEndpoint(t *testing.T) {
	const apisDir = "../../../../apis/externalsecrets"
	v1Types := filepath.Join(apisDir, "v1", "secretstore_ncloud_types.go")
	v1beta1Types := filepath.Join(apisDir, "v1beta1", "secretstore_ncloud_types.go")
	v1Pattern := endpointPatternMarker(t, v1Types)
	v1beta1Pattern := endpointPatternMarker(t, v1beta1Types)
	if v1Pattern != v1beta1Pattern {
		t.Fatalf("v1 and v1beta1 Pattern markers differ:\nv1:      %s\nv1beta1: %s", v1Pattern, v1beta1Pattern)
	}
	// The role marker only has to agree across versions; its runtime rule is
	// the provider's NRN prefix check, not NormalizeEndpoint.
	if v1Role, v1beta1Role := fieldPatternMarker(t, v1Types, roleField), fieldPatternMarker(t, v1beta1Types, roleField); v1Role != v1beta1Role {
		t.Fatalf("v1 and v1beta1 role Pattern markers differ:\nv1:      %s\nv1beta1: %s", v1Role, v1beta1Role)
	}

	pattern, err := regexp.Compile(v1Pattern)
	if err != nil {
		t.Fatalf("Pattern marker does not compile: %v", err)
	}

	probes := make([]string, 0, len(acceptedEndpointCases)+len(rejectedEndpointCases))
	for _, tt := range acceptedEndpointCases {
		probes = append(probes, tt.endpoint)
	}
	for _, tt := range rejectedEndpointCases {
		probes = append(probes, tt.endpoint)
	}

	for _, probe := range probes {
		_, err := NormalizeEndpoint(probe)
		runtimeAccepts := err == nil
		schemaAccepts := pattern.MatchString(probe)
		if runtimeAccepts && !schemaAccepts {
			t.Errorf("CRD pattern rejects %q, which NormalizeEndpoint accepts", probe)
		}
		if !strings.HasPrefix(probe, endpointScheme) && schemaAccepts {
			t.Errorf("CRD pattern accepts %q, which is not an https:// URL", probe)
		}
	}
}

// TestEndpointPatternReachesTheGeneratedCRDs checks that the Go marker really
// does turn into a schema constraint in every generated CRD, which is the last
// link in the chain. It does not police the committed files: `make test`
// depends on `generate`, so the artifacts are rewritten from the markers
// before this runs. Drift between the markers and what is committed is `make
// check-diff`'s job. The gate test above proves the Go marker and
// NormalizeEndpoint agree, but what a cluster enforces is the generated CRD,
// and nothing else in the test suite looks at those files: the CRD snapshot
// suite renders a sample instance (every string field filled with the literal
// "string"), so it cannot carry a pattern, and its ncloud entry is an
// ignoreErrors suppression rather than coverage.
func TestEndpointPatternReachesTheGeneratedCRDs(t *testing.T) {
	const repoRoot = "../../../.."
	types := filepath.Join(repoRoot, "apis", "externalsecrets", "v1", "secretstore_ncloud_types.go")
	patterns := map[string]string{
		"endpoint": endpointPatternMarker(t, types),
		"role":     fieldPatternMarker(t, types, roleField),
	}

	// Per file, how many times the endpoint property is generated: once per
	// API version per store kind. Counting against the ncloud blocks present
	// would pass when a whole block goes missing, since both counts fall
	// together; an expected number notices. It is deliberately hardcoded, so
	// that an upstream change to the API version list fails here and someone
	// confirms the new version carries the pattern.
	for rel, want := range map[string]int{
		"deploy/crds/bundle.yaml":                                        4,
		"config/crds/bases/external-secrets.io_secretstores.yaml":        2,
		"config/crds/bases/external-secrets.io_clustersecretstores.yaml": 2,
	} {
		path := filepath.Join(repoRoot, rel)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		// Counting, not containment: a Contains check passes while every
		// occurrence but one has lost its pattern. Counted per property, so
		// the failure names the property that lost it.
		for property, pattern := range patterns {
			if got := propertyPatternCount(string(data), property, pattern); got != want {
				t.Errorf("%s carries the Pattern on the %s property %d time(s), want %d; run `make generate`",
					rel, property, got, want)
			}
		}
	}
}

// roleField is the declaration whose Pattern marker the tests above read from
// source, next to the endpoint one endpointPatternMarker names.
const roleField = "Role string `json:\"role,omitempty\"`"

// TestAuthUnionConstraintsReachTheGeneratedCRDs checks that the MinProperties
// and MaxProperties markers on NcloudAuth turn into schema constraints, and
// that every method is a property of the union, in every generated CRD. The
// provider repeats the exactly-one rule at admission and at client
// construction, but the CRD is where `kubectl apply` refuses a store that
// names two or more methods, or none, and nothing else in the suite reads the
// generated files for it: the CRD snapshot suite fills every field, so it
// trips the constraint and suppresses the error instead of asserting it.
func TestAuthUnionConstraintsReachTheGeneratedCRDs(t *testing.T) {
	const repoRoot = "../../../.."
	for rel, want := range map[string]int{
		"deploy/crds/bundle.yaml":                                        4,
		"config/crds/bases/external-secrets.io_secretstores.yaml":        2,
		"config/crds/bases/external-secrets.io_clustersecretstores.yaml": 2,
	} {
		data, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		ncloudBlocks := propertyBlocks(string(data), "ncloud")
		if len(ncloudBlocks) != want {
			t.Fatalf("%s carries %d ncloud provider blocks, want %d", rel, len(ncloudBlocks), want)
		}
		for _, ncloud := range ncloudBlocks {
			auths := propertyBlocks(ncloud, "auth")
			if len(auths) != 1 {
				t.Fatalf("%s: an ncloud block carries %d auth properties, want 1", rel, len(auths))
			}
			for _, line := range []string{"minProperties: 1", "maxProperties: 1", "secretRef:", "serverRole:", "podIdentity:"} {
				if !blockHasLine(auths[0], line) {
					t.Errorf("%s: the ncloud auth schema lacks %q; run `make generate`", rel, line)
				}
			}
		}
	}
}
