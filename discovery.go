package tea

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/mod/semver"

	"github.com/oolong-project/tea-client-go/teaapi"
	"github.com/oolong-project/tea-client-go/tei"
)

// DiscoveryResult is one entry of a /discovery answer: a product release
// and the TEA servers that serve it.
type DiscoveryResult struct {
	// ProductReleaseUUID is the resolved product release. A server may send
	// any form google/uuid decodes; the value is canonical (String() is
	// lowercase).
	ProductReleaseUUID uuid.UUID
	// Servers are the API roots that serve the release, as received and
	// validated: non-empty, each rootUrl matching the specification's
	// pattern and allowed by the URL policy, each version SemVer, each
	// priority in [0, 1]. Use SelectServer to choose one.
	Servers []teaapi.ServerInfo
	// DiscoveredAt is the API base whose /discovery gave this result
	// (informational: later calls go to a server from Servers).
	DiscoveredAt APIBase
}

// NotResolvedError is a TEA error answer with status 404 from /discovery:
// the server at Base does not resolve the identifier. Discovery stops there
// and does not fail over (discovery/readme.md "Unresolved identifiers").
type NotResolvedError struct {
	Base    APIBase
	Code    ErrorCode // the TEA error code, ErrorCodeUnknown for an unknown one
	RawCode string    // the code as received when unknown, sanitised, at most 64 bytes
}

func (e *NotResolvedError) Error() string {
	code := string(e.Code)
	if e.Code == ErrorCodeUnknown {
		code = fmt.Sprintf("unknown error code %q", e.RawCode)
	}
	return fmt.Sprintf("tea: identifier not resolved by %s: %s", e.Base.String(), code)
}

// Is matches ErrObjectUnknown when Code is OBJECT_UNKNOWN.
func (e *NotResolvedError) Is(target error) bool {
	return target == ErrObjectUnknown && e.Code == ErrorCodeObjectUnknown
}

// Attempt is one failed discovery attempt.
type Attempt struct {
	Stage  Stage  // StageWellKnown or StageAPIDiscovery
	URL    string // scheme, host, port and path: never the query (the TEI or PURL)
	Reason string // sanitised, at most 200 bytes; never response-body content
	Err    error  // the cause, e.g. wrapping ErrTimeout, ErrResponseTooLarge, ErrInsecureURL
}

// DiscoveryError is a discovery that did not reach a result: the attempt
// bound was exhausted, or the well-known document offered no endpoint with
// a supported version. Stage is the stage it ended in.
type DiscoveryError struct {
	Stage    Stage
	Attempts []Attempt
}

func (e *DiscoveryError) Error() string {
	if len(e.Attempts) == 0 {
		return fmt.Sprintf("tea: discovery failed at stage %s", e.Stage)
	}
	last := e.Attempts[len(e.Attempts)-1]
	return fmt.Sprintf("tea: discovery failed at stage %s after %d attempt(s); last: %s: %s",
		e.Stage, len(e.Attempts), last.URL, last.Reason)
}

// Unwrap returns each attempt's Err, so errors.Is(err, ErrTimeout),
// errors.Is(err, ErrTooManyResults) and the like see through a
// DiscoveryError.
func (e *DiscoveryError) Unwrap() []error {
	var errs []error
	for _, a := range e.Attempts {
		if a.Err != nil {
			errs = append(errs, a.Err)
		}
	}
	return errs
}

// errNoCandidate is the cause recorded when a well-known document lists no
// endpoint with a supported version.
var errNoCandidate = errors.New("no endpoint with a supported version")

// maxPURLBytes bounds a PURL given to DiscoverPURL (the same bound as a TEI).
const maxPURLBytes = 2048

// Discover resolves a TEI as discovery/readme.md defines it: fetch
// https://<domain>/.well-known/tea (or the WithWellKnownLocation base for
// the domain), validate it, order its endpoints by the greatest mutually
// supported version and then priority, and ask each in turn for
// /v<version>/discovery?tei=<TEI>. It returns the results of the first
// valid answer, in the server's order; it never prompts.
//
// A TEA 404 ends discovery with *NotResolvedError (no failover); 400, 401 and
// 403 end it with *APIError. A 401 with a Bearer challenge under a
// WithAPIKey or WithPreemptiveAPIKey root is first recovered as for an API
// call (one token request, one retry), and a failure to obtain the token
// ends discovery with an error matching ErrNoAccessToken. Connection, TLS
// and DNS failures, an attempt
// exceeding Limits.AttemptTimeout, 5xx, a non-TEA 404, an invalid or
// oversized body, or more than Limits.DiscoveryResults results are failed
// attempts: the client backs off (250 ms doubling, capped at 4 s, by
// default) and tries the next candidate, cycling through the candidates,
// until WithDiscoveryAttempts' bound (default 4, counted across both
// stages, the well-known fetch included) is used up, which gives a
// *DiscoveryError. The caller's context ending ends Discover with its
// error. No credential is sent except to a configured credential root.
func (c *Client) Discover(ctx context.Context, t tei.TEI) ([]DiscoveryResult, error) {
	if t.String() == "" {
		return nil, fmt.Errorf("discovering: %w: zero TEI", ErrInvalidArgument)
	}
	domain := strings.ToLower(t.Domain())
	wkBase := "https://" + domain
	if b, ok := c.opts.wellKnown[domain]; ok {
		wkBase = b.raw
	}
	wkURL, err := url.Parse(wkBase + "/.well-known/tea")
	if err != nil {
		return nil, fmt.Errorf("discovering: %w: well-known URL does not parse", ErrInvalidArgument)
	}

	r := &discoveryRun{c: c, ctx: ctx}
	var endpoints []candidate
	for {
		eps, err := r.wellKnown(wkURL)
		if err == nil {
			endpoints = eps
			break
		}
		if fatal := r.failed(StageWellKnown, wkURL, err); fatal != nil {
			return nil, fatal
		}
		if r.exhausted() {
			return nil, &DiscoveryError{Stage: StageWellKnown, Attempts: r.attempts}
		}
		if err := r.backoff(StageWellKnown); err != nil {
			return nil, err
		}
	}
	if len(endpoints) == 0 {
		r.attempts = append(r.attempts, Attempt{
			Stage: StageWellKnown, URL: redact(wkURL), Reason: errNoCandidate.Error(), Err: errNoCandidate,
		})
		return nil, &DiscoveryError{Stage: StageWellKnown, Attempts: r.attempts}
	}
	return r.discover(endpoints, "tei", t.String())
}

// DiscoverPURL resolves a PURL within the inventory of one known API base:
// /v<version>/discovery?purl=<PURL> at base. Classification, the attempt
// bound and backoff are those of Discover, with base as the only candidate.
// purl must start with "pkg:", be at most 2048 bytes of valid UTF-8 and
// have no control characters; it is sent as given, query-encoded once.
func (c *Client) DiscoverPURL(ctx context.Context, base APIBase, purl string) ([]DiscoveryResult, error) {
	const op = "discovering by PURL"
	if base.root == nil {
		return nil, fmt.Errorf("%s: %w: zero APIBase", op, ErrInvalidArgument)
	}
	if err := checkPURL(purl); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if err := c.checkURL(base.url()); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	r := &discoveryRun{c: c, ctx: ctx}
	return r.discover([]candidate{{base: base}}, "purl", purl)
}

func checkPURL(purl string) error {
	switch {
	case !strings.HasPrefix(purl, "pkg:"):
		return fmt.Errorf("%w: PURL does not start with pkg:", ErrInvalidArgument)
	case len(purl) > maxPURLBytes:
		return fmt.Errorf("%w: PURL longer than %d bytes", ErrInvalidArgument, maxPURLBytes)
	case !utf8.ValidString(purl):
		return fmt.Errorf("%w: PURL is not valid UTF-8", ErrInvalidArgument)
	}
	for _, r := range purl {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return fmt.Errorf("%w: PURL has a control character", ErrInvalidArgument)
		}
	}
	return nil
}

// SelectServer chooses the API base for a discovery result with the rules
// of the well-known selection: servers with a version in SupportedVersions
// (build metadata ignored), ordered by the greatest such version, then
// priority (absent = 1) descending, then the order received. The chosen
// rootUrl must pass the URL policy: an http root is usable only under a
// WithInsecureHTTPBase allowance (*URLPolicyError otherwise). The base
// that answered /discovery is not used unless it is listed in Servers.
func (c *Client) SelectServer(r DiscoveryResult) (APIBase, error) {
	const op = "selecting a server"
	cands := make([]candidate, 0, len(r.Servers))
	for i, s := range r.Servers {
		if !rootURLPattern.MatchString(s.RootUrl) {
			return APIBase{}, fmt.Errorf("%s: %w: server %d: rootUrl does not match the rootUrl pattern", op, ErrInvalidArgument, i)
		}
		if u, err := url.Parse(s.RootUrl); err != nil || hasDotSegment(u.EscapedPath()) || hasNonASCII(u.Host) {
			return APIBase{}, fmt.Errorf("%s: server %d: %w", op, i, policyError(u, "rootUrl has a dot segment or a non-ASCII host"))
		}
		for _, v := range s.Versions {
			if !validVersion(v) {
				return APIBase{}, fmt.Errorf("%s: %w: server %d: a version is not SemVer", op, ErrInvalidArgument, i)
			}
		}
		if s.Priority != nil && !(*s.Priority >= 0 && *s.Priority <= 1) {
			return APIBase{}, fmt.Errorf("%s: %w: server %d: priority not in [0, 1]", op, ErrInvalidArgument, i)
		}
		if cd, ok := newCandidate(s.RootUrl, s.Versions, priorityOf(s.Priority)); ok {
			cands = append(cands, cd)
		}
	}
	if len(cands) == 0 {
		return APIBase{}, fmt.Errorf("%s: %w: no server with a supported version", op, ErrInvalidArgument)
	}
	sortCandidates(cands)
	chosen := cands[0].base
	if err := c.checkURL(chosen.url()); err != nil {
		return APIBase{}, fmt.Errorf("%s: %w", op, err)
	}
	return chosen, nil
}

func priorityOf(p *float32) float64 {
	if p == nil {
		return 1
	}
	return float64(*p)
}

// candidate is an endpoint or server with its selected version.
type candidate struct {
	base     APIBase
	version  string // canonical x/mod form of the selected version, for ordering
	priority float64
}

// newCandidate picks the greatest version of versions that is supported
// (the first advertised spelling among equal ones) and builds the base with
// it, verbatim. ok is false when no version is supported.
func newCandidate(root string, versions []string, priority float64) (candidate, bool) {
	best, bestCanon := "", ""
	for _, v := range versions {
		if !supportedVersion(v) {
			continue
		}
		canon := semver.Canonical("v" + v)
		if best == "" || semver.Compare(canon, bestCanon) > 0 {
			best, bestCanon = v, canon
		}
	}
	if best == "" {
		return candidate{}, false
	}
	base, err := ParseAPIBase(root, best)
	if err != nil {
		return candidate{}, false
	}
	return candidate{base: base, version: bestCanon, priority: priority}, true
}

// sortCandidates orders by version descending, then priority descending,
// keeping the given order among ties (discovery/readme.md "Selecting an API
// base").
func sortCandidates(cs []candidate) {
	slices.SortStableFunc(cs, func(a, b candidate) int {
		if c := semver.Compare(b.version, a.version); c != 0 {
			return c
		}
		switch {
		case a.priority > b.priority:
			return -1
		case a.priority < b.priority:
			return 1
		}
		return 0
	})
}

// discoveryRun is the state of one Discover or DiscoverPURL call. Every
// GET it makes, well-known or /discovery, successful or not, is one attempt
// against the bound of WithDiscoveryAttempts (so the default 4 attempts of
// at most AttemptTimeout each, plus the backoffs, bound a whole Discover at
// about 62 s, architecture 3.4). A /discovery attempt under an API-key root
// can add at most CallTimeout (its token request) plus AttemptTimeout (its
// one retry) to that. A failure to obtain a token ends the run.
type discoveryRun struct {
	c        *Client
	ctx      context.Context
	made     int       // attempts made
	attempts []Attempt // the failed ones
	backoffs int
}

func (r *discoveryRun) exhausted() bool { return r.made >= r.c.opts.attempts }

// stopError is an answer that ends discovery at once, without failover.
type stopError struct{ err error }

func (e *stopError) Error() string { return e.err.Error() }
func (e *stopError) Unwrap() error { return e.err }

// failed records a failed attempt and reports it to the trace. It returns a
// non-nil error when discovery must end now instead: the caller's context
// ended, or the answer was one that never fails over.
func (r *discoveryRun) failed(stage Stage, u *url.URL, err error) error {
	if cerr := r.ctx.Err(); cerr != nil {
		return fmt.Errorf("discovering: %w", cerr)
	}
	var stop *stopError
	if errors.As(err, &stop) {
		return stop.err
	}
	if errors.Is(err, ErrNoAccessToken) {
		// A failed token request ends the run: the key is not posted again
		// to the next candidate or after a backoff.
		return err
	}
	a := Attempt{Stage: stage, URL: redact(u), Reason: sanitize(reasonOf(err), maxMessageBytes), Err: err}
	r.attempts = append(r.attempts, a)
	r.c.traceEvent(TraceEvent{Kind: TraceAttemptFailed, Stage: stage, Method: http.MethodGet, URL: a.URL, Reason: a.Reason})
	return nil
}

// reasonOf gives the text of a failed attempt. Every error reaching here is
// built by this package (fixed texts, redacted URLs, status codes) or comes
// from the transport (connection, TLS, DNS); none carries body content.
func reasonOf(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err.Error()
	}
	return err.Error()
}

// maxBackoff caps the wait between attempts.
const maxBackoff = 4 * time.Second

// backoffDelay is the wait before retry i (0 for the first retry): first,
// doubling each time, capped at 4 s.
func backoffDelay(first time.Duration, i int) time.Duration {
	d := first
	for ; i > 0 && d < maxBackoff; i-- {
		d *= 2
	}
	return min(d, maxBackoff)
}

// backoff waits before the next attempt, interrupted by the caller's
// context.
func (r *discoveryRun) backoff(stage Stage) error {
	d := backoffDelay(r.c.opts.firstBackoff, r.backoffs)
	r.backoffs++
	r.c.traceEvent(TraceEvent{Kind: TraceBackoff, Stage: stage, Wait: d})
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-r.ctx.Done():
		return fmt.Errorf("discovering: %w", r.ctx.Err())
	case <-t.C:
		return nil
	}
}

// discover runs the /discovery stage over the candidates, in order and then
// again from the first, until a result, a stop, or the attempt bound.
func (r *discoveryRun) discover(cands []candidate, param, value string) ([]DiscoveryResult, error) {
	if r.exhausted() {
		return nil, &DiscoveryError{Stage: StageAPIDiscovery, Attempts: r.attempts}
	}
	for i := 0; ; i++ {
		base := cands[i%len(cands)].base
		u, err := url.Parse(base.String() + "/discovery?" + param + "=" + url.QueryEscape(value))
		if err != nil {
			return nil, fmt.Errorf("discovering: %w: discovery URL does not parse", ErrInvalidArgument)
		}
		res, err := r.apiDiscovery(base, u)
		if err == nil {
			return res, nil
		}
		if fatal := r.failed(StageAPIDiscovery, u, err); fatal != nil {
			return nil, fatal
		}
		if r.exhausted() {
			return nil, &DiscoveryError{Stage: StageAPIDiscovery, Attempts: r.attempts}
		}
		if err := r.backoff(StageAPIDiscovery); err != nil {
			return nil, err
		}
	}
}

// get makes one discovery GET of kind k through the bounded doer and reads
// its body (bounded by WellKnownBytes or DiscoveryBytes, or ErrorBodyBytes
// when not 2xx, and by AttemptTimeout). A /discovery GET passes its
// candidate's base: it is sent through that API's doer, so an API-key
// credential acts on it as on an API call (a token up front, or the
// recovery of a 401); the well-known GET passes nil and never causes a token
// request. A recovered GET is still one attempt.
func (r *discoveryRun) get(k callKind, u *url.URL, base *APIBase) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(withKind(r.ctx, k), http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: request does not build", ErrInvalidArgument)
	}
	req.Header.Set("Accept", "application/json")
	r.made++
	d := &doer{c: r.c}
	if base != nil {
		d = &doer{c: r.c, base: base.url(), apiBase: *base}
	}
	resp, err := d.Do(req)
	if err != nil {
		return nil, nil, err
	}
	body, err := readBody(resp)
	if err != nil {
		return nil, nil, err
	}
	return resp, body, nil
}

// statusError is a failed attempt for an HTTP status; Unwrap gives the
// *APIError, so errors.Is(err, ErrServer) and the like hold.
type statusError struct {
	reason string
	err    *APIError
}

func (e *statusError) Error() string { return e.reason }
func (e *statusError) Unwrap() error { return e.err }

// classifyStatus sorts a non-200 answer: 400, 401 and 403 stop discovery with an
// *APIError, a TEA 404 from /discovery stops it with *NotResolvedError (when
// base is set), and everything else is a failed attempt.
func classifyStatus(op string, base *APIBase, resp *http.Response, body []byte) error {
	e := mapError(op, resp, body)
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return &stopError{err: e} // e.Error() already starts with op
	case http.StatusNotFound:
		if e.TEA && base != nil {
			return &stopError{err: &NotResolvedError{Base: *base, Code: e.Code, RawCode: e.RawCode}}
		}
		if e.TEA {
			// The reason names no code: an unknown one is server text, and
			// a reason never carries response-body content. The code stays
			// on the *APIError (Attempt.Err), sanitised.
			return &statusError{reason: "HTTP 404 (TEA error)", err: e}
		}
		return &statusError{reason: "HTTP 404 (not a TEA error)", err: e}
	}
	return &statusError{reason: fmt.Sprintf("HTTP %d", resp.StatusCode), err: e}
}

// wellKnown makes one well-known attempt and returns its candidates in
// order (none when no endpoint has a supported version).
func (r *discoveryRun) wellKnown(u *url.URL) ([]candidate, error) {
	const op = "fetching .well-known/tea"
	resp, body, err := r.get(kindWellKnown, u, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, classifyStatus(op, nil, resp, body)
	}
	return r.c.decodeWellKnown(body)
}

// apiDiscovery makes one /discovery attempt at base.
func (r *discoveryRun) apiDiscovery(base APIBase, u *url.URL) ([]DiscoveryResult, error) {
	const op = "discovery"
	resp, body, err := r.get(kindDiscovery, u, &base)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, classifyStatus(op, &base, resp, body)
	}
	res, err := r.c.decodeDiscovery(body)
	if err != nil {
		return nil, err
	}
	for i := range res {
		res[i].DiscoveredAt = base
	}
	return res, nil
}

// invalidDocument is the cause of a failed attempt whose body broke a rule.
// Its text names the rule only, never body content.
type invalidDocument struct {
	what string
	rule string
	err  error // ErrTooManyResults or a *URLPolicyError, when that is the rule
}

func (e *invalidDocument) Error() string { return "invalid " + e.what + ": " + e.rule }
func (e *invalidDocument) Unwrap() error { return e.err }

// object decodes a JSON object into its members, keys matched exactly (not
// case-insensitively, as encoding/json does for structs).
func object(raw []byte) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, false
	}
	return m, true
}

// jsonString decodes a JSON string; null and other types are refused.
func jsonString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	return s, json.Unmarshal(raw, &s) == nil
}

// jsonArray decodes a JSON array; null and other types are refused.
func jsonArray(raw json.RawMessage) ([]json.RawMessage, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return nil, false
	}
	var a []json.RawMessage
	return a, json.Unmarshal(raw, &a) == nil
}

// jsonNumber decodes a JSON number; null and other types are refused.
func jsonNumber(raw json.RawMessage) (float64, bool) {
	var n json.Number
	if len(raw) == 0 || raw[0] == '"' || json.Unmarshal(raw, &n) != nil {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

// checkRoot validates a well-known url or a server rootUrl: the
// specification's pattern, then the URL policy (https, or http under an
// allowance; no dot segment).
func (c *Client) checkRoot(what, field, s string) error {
	if !rootURLPattern.MatchString(s) {
		return &invalidDocument{what: what, rule: field + " does not match the rootUrl pattern"}
	}
	u, err := url.Parse(s)
	if err != nil {
		return &invalidDocument{what: what, rule: field + " does not parse"}
	}
	if err := c.checkURL(u); err != nil {
		return &invalidDocument{what: what, rule: field + " refused by the URL policy", err: err}
	}
	return nil
}

// versions validates a versions array: non-empty, every item a SemVer
// string.
func versions(raw json.RawMessage) ([]string, bool) {
	items, ok := jsonArray(raw)
	if !ok || len(items) == 0 {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		v, ok := jsonString(it)
		if !ok || !validVersion(v) {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}

// priority validates an optional priority: absent, or a number in [0, 1].
func priority(m map[string]json.RawMessage) (p *float64, ok bool) {
	raw, present := m["priority"]
	if !present {
		return nil, true
	}
	f, ok := jsonNumber(raw)
	if !ok || f < 0 || f > 1 {
		return nil, false
	}
	return &f, true
}

// decodeWellKnown validates a .well-known/tea document against
// tea-well-known.schema.json by hand (architecture 3.6 step 2) and returns
// its candidates in selection order (step 3). Unknown properties are
// ignored. A document that breaks a rule is an error naming the rule.
func (c *Client) decodeWellKnown(body []byte) ([]candidate, error) {
	const what = "well-known document"
	bad := func(rule string) error { return &invalidDocument{what: what, rule: rule} }
	doc, ok := object(body)
	if !ok {
		return nil, bad("not a JSON object")
	}
	if sv, ok := jsonNumber(doc["schemaVersion"]); !ok || sv != 1 {
		return nil, bad("schemaVersion is not the integer 1")
	}
	eps, ok := jsonArray(doc["endpoints"])
	if !ok || len(eps) == 0 {
		return nil, bad("endpoints is not a non-empty array")
	}
	var cands []candidate
	for i, raw := range eps {
		ep, ok := object(raw)
		if !ok {
			return nil, bad(fmt.Sprintf("endpoint %d is not an object", i))
		}
		u, ok := jsonString(ep["url"])
		if !ok {
			return nil, bad(fmt.Sprintf("endpoint %d: url is not a string", i))
		}
		if err := c.checkRoot(what, fmt.Sprintf("endpoint %d: url", i), u); err != nil {
			return nil, err
		}
		vs, ok := versions(ep["versions"])
		if !ok {
			return nil, bad(fmt.Sprintf("endpoint %d: versions is not a non-empty array of SemVer versions", i))
		}
		p, ok := priority(ep)
		if !ok {
			return nil, bad(fmt.Sprintf("endpoint %d: priority is not a number in [0, 1]", i))
		}
		prio := 1.0
		if p != nil {
			prio = *p
		}
		if cd, ok := newCandidate(u, vs, prio); ok {
			cands = append(cands, cd)
		}
	}
	sortCandidates(cands)
	return cands, nil
}

// decodeDiscovery validates a /discovery answer (architecture 3.6 step 5):
// a JSON array of one to Limits.DiscoveryResults items (more is refused
// whole with ErrTooManyResults, never truncated), each with a
// productReleaseUuid that decodes as a uuid and a non-empty servers array
// whose rootUrls match the pattern and pass the URL policy, whose versions
// are SemVer and whose priorities are in [0, 1]. Unknown properties are
// ignored.
func (c *Client) decodeDiscovery(body []byte) ([]DiscoveryResult, error) {
	const what = "discovery response"
	bad := func(rule string) error { return &invalidDocument{what: what, rule: rule} }
	items, ok := jsonArray(body)
	if !ok {
		return nil, bad("not a JSON array")
	}
	if len(items) == 0 {
		return nil, bad("empty array")
	}
	if len(items) > c.limits.DiscoveryResults {
		return nil, &invalidDocument{what: what, rule: fmt.Sprintf("more than %d results", c.limits.DiscoveryResults), err: ErrTooManyResults}
	}
	out := make([]DiscoveryResult, 0, len(items))
	for i, raw := range items {
		it, ok := object(raw)
		if !ok {
			return nil, bad(fmt.Sprintf("result %d is not an object", i))
		}
		s, ok := jsonString(it["productReleaseUuid"])
		if !ok {
			return nil, bad(fmt.Sprintf("result %d: productReleaseUuid is not a string", i))
		}
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, bad(fmt.Sprintf("result %d: productReleaseUuid is not a uuid", i))
		}
		srvs, ok := jsonArray(it["servers"])
		if !ok || len(srvs) == 0 {
			return nil, bad(fmt.Sprintf("result %d: servers is not a non-empty array", i))
		}
		res := DiscoveryResult{ProductReleaseUUID: id, Servers: make([]teaapi.ServerInfo, 0, len(srvs))}
		for j, sraw := range srvs {
			sv, ok := object(sraw)
			if !ok {
				return nil, bad(fmt.Sprintf("result %d: server %d is not an object", i, j))
			}
			root, ok := jsonString(sv["rootUrl"])
			if !ok {
				return nil, bad(fmt.Sprintf("result %d: server %d: rootUrl is not a string", i, j))
			}
			if err := c.checkRoot(what, fmt.Sprintf("result %d: server %d: rootUrl", i, j), root); err != nil {
				return nil, err
			}
			vs, ok := versions(sv["versions"])
			if !ok {
				return nil, bad(fmt.Sprintf("result %d: server %d: versions is not a non-empty array of SemVer versions", i, j))
			}
			p, ok := priority(sv)
			if !ok {
				return nil, bad(fmt.Sprintf("result %d: server %d: priority is not a number in [0, 1]", i, j))
			}
			info := teaapi.ServerInfo{RootUrl: root, Versions: vs}
			if p != nil {
				f := float32(*p)
				info.Priority = &f
			}
			res.Servers = append(res.Servers, info)
		}
		out = append(out, res)
	}
	return out, nil
}
