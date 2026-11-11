package tea

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

// SupportedVersions are the TEA API versions this client implements.
var SupportedVersions = []string{"1.0.0"}

// rootURLPattern is the specification's pattern for server-info rootUrl and
// for the well-known endpoint url.
var rootURLPattern = regexp.MustCompile(`^https?://[^/?#@]+(/[^?#\s]*[^/?#\s])?$`)

// semverPattern is the specification's SemVer 2.0.0 pattern for versions.
var semverPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

// validVersion reports whether v is a SemVer 2.0.0 version as the spec's
// pattern defines it (golang.org/x/mod/semver alone accepts shorthands such
// as "1.0" that the spec does not).
func validVersion(v string) bool { return semverPattern.MatchString(v) }

// supportedVersion reports whether v, a valid version, is one of
// SupportedVersions once build metadata is ignored.
func supportedVersion(v string) bool {
	if !validVersion(v) {
		return false
	}
	c := semver.Canonical("v" + v) // drops build metadata
	for _, s := range SupportedVersions {
		if semver.Compare(c, "v"+s) == 0 {
			return true
		}
	}
	return false
}

// baseURL is a parsed base used for http allowances (D4) and credential roots
// (D5): lowercase scheme and host, explicit port, escaped path without a
// trailing slash.
type baseURL struct {
	raw    string
	scheme string
	host   string
	port   string
	path   string
}

func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

func hasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}

// hasDotSegment reports whether an escaped path has a "." or ".." segment,
// also written with %2e or %2E.
func hasDotSegment(escapedPath string) bool {
	for _, seg := range strings.Split(escapedPath, "/") {
		s := strings.ReplaceAll(strings.ToLower(seg), "%2e", ".")
		if s == "." || s == ".." {
			return true
		}
	}
	return false
}

// redact returns scheme://host[:port]/path of u: never userinfo, query or
// fragment (presigned URLs carry secrets in the query).
func redact(u *url.URL) string {
	if u == nil {
		return ""
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, RawPath: u.EscapedPath(), Path: u.Path}).String()
}

// parseBase parses a configured base (WithInsecureHTTPBase, a credential
// root, a well-known location): an absolute http or https URL with a host and
// no userinfo, query, fragment, trailing "/" or dot segment.
func parseBase(raw string) (baseURL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return baseURL{}, fmt.Errorf("%q does not parse", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	switch {
	case scheme != "http" && scheme != "https":
		return baseURL{}, fmt.Errorf("%q is not an absolute http or https URL", raw)
	case u.Host == "" || u.Hostname() == "":
		return baseURL{}, fmt.Errorf("%q has no host", raw)
	case hasNonASCII(u.Host):
		return baseURL{}, fmt.Errorf("%q has a non-ASCII host", raw)
	case u.User != nil:
		return baseURL{}, fmt.Errorf("%q has userinfo", raw)
	case u.RawQuery != "" || u.ForceQuery:
		return baseURL{}, fmt.Errorf("%q has a query", raw)
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return baseURL{}, fmt.Errorf("%q has a fragment", raw)
	case strings.HasSuffix(u.EscapedPath(), "/"):
		return baseURL{}, fmt.Errorf("%q ends with /", raw)
	case hasDotSegment(u.EscapedPath()):
		return baseURL{}, fmt.Errorf("%q has a dot segment", raw)
	}
	port := u.Port()
	if port == "" {
		port = defaultPort(scheme)
	}
	return baseURL{raw: raw, scheme: scheme, host: strings.ToLower(u.Hostname()), port: port, path: u.EscapedPath()}, nil
}

// under reports whether u is under base b (architecture D4): same scheme,
// same host (compared lowercased), same port (an absent port is the scheme's
// default), and an escaped path equal to the base's path or starting with it
// followed by "/". Callers refuse dot segments before asking.
//
// This is a stated departure from the letter of discovery/readme.md
// "Selecting an API base" of the pinned TEA specification, which says an http
// allowance "is per configured base URL, never a global setting, so it cannot
// apply to a base the client learned from discovery": here an allowance also
// covers learned URLs under it (on the same scheme, host and port), so that a
// local server whose API root is a path on its origin works with the origin
// as the allowance. Nothing a server sends creates or widens an allowance.
// The same rule binds credentials to their root (D5).
func under(u *url.URL, b baseURL) bool {
	if strings.ToLower(u.Scheme) != b.scheme || strings.ToLower(u.Hostname()) != b.host {
		return false
	}
	port := u.Port()
	if port == "" {
		port = defaultPort(b.scheme)
	}
	if port != b.port {
		return false
	}
	p := u.EscapedPath()
	return p == b.path || strings.HasPrefix(p, b.path+"/")
}

// policyError builds a *URLPolicyError wrapping ErrInsecureURL.
func policyError(u *url.URL, reason string) error {
	return &URLPolicyError{URL: redact(u), Reason: reason, err: ErrInsecureURL}
}

// checkURL applies the URL policy (D4) to a URL about to be requested or
// followed.
func (c *Client) checkURL(u *url.URL) error {
	if u == nil {
		return &URLPolicyError{Reason: "no URL", err: ErrInsecureURL}
	}
	scheme := strings.ToLower(u.Scheme)
	switch {
	case scheme != "https" && scheme != "http":
		return policyError(u, "scheme is not https")
	case u.User != nil:
		return policyError(u, "URL has userinfo")
	case u.Hostname() == "":
		return policyError(u, "URL has no host")
	case hasNonASCII(u.Host):
		return policyError(u, "host is not ASCII")
	case hasDotSegment(u.EscapedPath()):
		return policyError(u, "path has a dot segment")
	}
	if scheme == "https" {
		return nil
	}
	for _, b := range c.opts.insecure {
		if under(u, b) {
			return nil
		}
	}
	return policyError(u, "http URL is not under a WithInsecureHTTPBase allowance")
}

// APIBase is one TEA API: a root URL and the version used in paths. Build it
// with ParseAPIBase (or, in discovery, from a server the client selected).
type APIBase struct {
	root    *url.URL
	rootStr string
	version string
}

// ParseAPIBase validates rootURL against the specification's rootUrl
// pattern (absolute http or https, no userinfo, query, fragment or trailing
// "/") and refuses dot segments with a *URLPolicyError; version must be a
// SemVer 2.0.0 version that is one of SupportedVersions once build metadata
// is ignored. The version is kept verbatim for paths. Whether an http root
// may be used is decided by Client.API, against the client's allowances.
func ParseAPIBase(rootURL, version string) (APIBase, error) {
	if !rootURLPattern.MatchString(rootURL) {
		return APIBase{}, fmt.Errorf("%w: root URL %q does not match the rootUrl pattern", ErrInvalidArgument, truncateArg(rootURL))
	}
	u, err := url.Parse(rootURL)
	if err != nil {
		return APIBase{}, fmt.Errorf("%w: root URL %q does not parse", ErrInvalidArgument, truncateArg(rootURL))
	}
	if hasDotSegment(u.EscapedPath()) {
		return APIBase{}, policyError(u, "path has a dot segment")
	}
	if hasNonASCII(u.Host) {
		return APIBase{}, policyError(u, "host is not ASCII")
	}
	if !validVersion(version) {
		return APIBase{}, fmt.Errorf("%w: version %q is not SemVer", ErrInvalidArgument, truncateArg(version))
	}
	if !supportedVersion(version) {
		return APIBase{}, fmt.Errorf("%w: version %q is not supported (supported: %v)", ErrInvalidArgument, truncateArg(version), SupportedVersions)
	}
	return APIBase{root: u, rootStr: rootURL, version: version}, nil
}

func truncateArg(s string) string {
	if len(s) > 128 {
		return s[:128]
	}
	return s
}

// RootURL returns the root URL as given.
func (b APIBase) RootURL() string { return b.rootStr }

// Version returns the version as given (used verbatim in paths).
func (b APIBase) Version() string { return b.version }

// String returns the API base: root + "/v" + version.
func (b APIBase) String() string {
	if b.root == nil {
		return ""
	}
	return b.rootStr + "/v" + b.version
}

// url returns the parsed API base (root + "/v" + version).
func (b APIBase) url() *url.URL {
	u, err := url.Parse(b.String())
	if err != nil {
		return nil
	}
	return u
}
