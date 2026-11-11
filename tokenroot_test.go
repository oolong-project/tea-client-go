package tea

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The fixture of the API-key tests: a TEA root at /tea that records every
// request and serves /token, /discovery, product releases, component
// releases and their CLEs, in one of two modes.

// rootMode is how the fixture answers a caller without the currently valid
// token.
type rootMode int

const (
	// modeChallenge: 401 with a Bearer challenge.
	modeChallenge rootMode = iota
	// modeFilter: never a 401; the anonymous caller gets less (one
	// discovery result, the public release; component A only).
	modeFilter
)

// tokenFailure is how the fixture's /token fails.
type tokenFailure int

const (
	tokenWorks tokenFailure = iota
	tokenInvalidClient
	tokenNotImplemented
	tokenRedirect
)

// The key of the fixture: characters that HTTP Basic form-encodes, so the
// encoded forms are checked too.
const (
	rigKeyID  = "rig-key:id@1"
	rigSecret = "rig-s3cret%value"
)

// Made-up identifiers of the fixture's private release and components.
var (
	privateReleaseID = uuid.MustParse("6bcf7c8e-cdb0-4cad-9fe1-8f7d9cab0bc6")
	compA            = uuid.MustParse("7cd08d9f-dec1-4dbe-8af2-9a8eadbc1cd7")
	compRelA         = uuid.MustParse("8de19ea0-efd2-4ecf-9b03-ab9fbecd2de8")
	compB            = uuid.MustParse("9ef2afb1-f0e3-4fd0-8c14-bcaacfde3ef9")
	compRelB         = uuid.MustParse("af03b0c2-01f4-4ae1-9d25-cdbbd0ef4f0a")
)

// rigRef is one record of the fixture: method, path and Authorization.
type rigRef struct{ method, path, auth string }

type tokenRoot struct {
	srv  *httptest.Server
	port string
	root string // http://localhost:<port>/tea
	mode rootMode

	mu        sync.Mutex
	log       []rigRef
	issued    int
	tokenReqs int
	valid     string // the token the server accepts
	refuseAll bool   // accept no token at all
	expires   string // expires_in of issued tokens; "" is 3600
	fail      tokenFailure
	failAfter int    // the first failAfter token requests work
	tokenTo   string // tokenRedirect target
	delay     time.Duration
	hold      chan struct{} // when set, /token waits for it to close
	entered   chan struct{} // when set, signalled on each token request
	hook      func(w http.ResponseWriter, r *http.Request) bool
}

func newTokenRoot(t *testing.T, mode rootMode) *tokenRoot {
	t.Helper()
	s := &tokenRoot{mode: mode}
	s.srv = startHTTP(t, s)
	s.port = portOf(t, s.srv)
	s.root = "http://localhost:" + s.port + "/tea"
	return s
}

func (s *tokenRoot) set(f func(s *tokenRoot)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

func (s *tokenRoot) basic() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(rigKeyID)+":"+url.QueryEscape(rigSecret)))
}

func (s *tokenRoot) authorized(auth string) bool {
	return s.valid != "" && !s.refuseAll && auth == "Bearer "+s.valid
}

func challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="tea"`)
	w.WriteHeader(http.StatusUnauthorized)
}

func teaError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, code)
}

func (s *tokenRoot) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	s.mu.Lock()
	s.log = append(s.log, rigRef{r.Method, r.URL.Path, auth})
	hook := s.hook
	s.mu.Unlock()
	if hook != nil && hook(w, r) {
		return
	}
	i := strings.Index(r.URL.Path, "/v1.0.0/")
	if i < 0 {
		teaError(w, http.StatusNotFound, "OBJECT_UNKNOWN")
		return
	}
	rest := r.URL.Path[i+len("/v1.0.0"):]
	if rest == "/token" {
		s.serveToken(w, r)
		return
	}
	s.mu.Lock()
	ok := s.authorized(auth)
	s.mu.Unlock()
	if !ok && s.mode == modeChallenge {
		challenge(w)
		return
	}
	segs := strings.Split(strings.TrimPrefix(rest, "/"), "/")
	switch {
	case rest == "/discovery":
		ids := []uuid.UUID{releaseID}
		if ok {
			ids = append(ids, privateReleaseID)
		}
		jsonHandler(resultsJSON(s.root, ids...))(w, r)
	case len(segs) == 3 && segs[2] == "cle" && (segs[0] == "productRelease" || segs[0] == "componentRelease"):
		jsonHandler(cleJSON)(w, r)
	case len(segs) == 2 && segs[0] == "productRelease":
		id, err := uuid.Parse(segs[1])
		if err != nil {
			teaError(w, http.StatusNotFound, "OBJECT_UNKNOWN")
			return
		}
		comps := `{"uuid":"` + compA.String() + `","release":"` + compRelA.String() + `"}`
		if ok {
			comps += `,{"uuid":"` + compB.String() + `","release":"` + compRelB.String() + `"}`
		}
		jsonHandler(productReleaseJSON(id, "1.0.0", comps))(w, r)
	case len(segs) == 2 && segs[0] == "componentRelease" && segs[1] == compRelA.String():
		jsonHandler(componentReleaseJSON(compRelA, compA))(w, r)
	case len(segs) == 2 && segs[0] == "componentRelease" && segs[1] == compRelB.String():
		jsonHandler(componentReleaseJSON(compRelB, compB))(w, r)
	default:
		teaError(w, http.StatusNotFound, "OBJECT_UNKNOWN")
	}
}

func (s *tokenRoot) serveToken(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.tokenReqs++
	n := s.tokenReqs
	fail := tokenWorks
	if n > s.failAfter {
		fail = s.fail
	}
	to, delay, hold, entered := s.tokenTo, s.delay, s.hold, s.entered
	s.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if hold != nil {
		select {
		case <-hold:
		case <-r.Context().Done():
			return
		}
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	switch fail {
	case tokenInvalidClient:
		teaError(w, http.StatusUnauthorized, "invalid_client")
		return
	case tokenNotImplemented:
		teaError(w, http.StatusNotFound, "NOT_IMPLEMENTED")
		return
	case tokenRedirect:
		w.Header().Set("Location", to)
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
	if r.Method != http.MethodPost || r.Header.Get("Authorization") != s.basic() {
		teaError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	s.mu.Lock()
	s.issued++
	tok := "issued-access-token-" + strconv.Itoa(s.issued)
	s.valid = tok
	exp := s.expires
	s.mu.Unlock()
	if exp == "" {
		exp = "3600"
	}
	jsonHandler(`{"access_token":"`+tok+`","token_type":"Bearer","expires_in":`+exp+`}`)(w, r)
}

// steps renders the requests seen since mark as "METHOD path auth": a uuid
// path segment is {id}, auth is "-" (none), the number of an issued token,
// "basic" (the key's Basic value) or "?" (anything else).
func (s *tokenRoot) steps(mark int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, rr := range s.log[mark:] {
		segs := strings.Split(rr.path, "/")
		for i, seg := range segs {
			if _, err := uuid.Parse(seg); err == nil {
				segs[i] = "{id}"
			}
		}
		a := "?"
		switch {
		case rr.auth == "":
			a = "-"
		case rr.auth == s.basic():
			a = "basic"
		case strings.HasPrefix(rr.auth, "Bearer issued-access-token-"):
			a = strings.TrimPrefix(rr.auth, "Bearer issued-access-token-")
		}
		out = append(out, rr.method+" "+strings.Join(segs, "/")+" "+a)
	}
	return out
}

// mark is the number of requests seen so far, for steps.
func (s *tokenRoot) mark() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.log)
}

func (s *tokenRoot) tokens() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenReqs
}

// The steps of the fixture's usual requests.
const rv = "/tea/v1.0.0"

func getDisc(tok string) string { return "GET " + rv + "/discovery " + tok }
func getRel(tok string) string  { return "GET " + rv + "/productRelease/{id} " + tok }

var postToken = "POST " + rv + "/token basic"

// rig is a fixture with the client options to reach it by host name: R on
// localhost, a well-known host on 127.0.0.1, other servers on any name,
// every one allowed over http. It collects every error and trace event its
// test hands it and checks, at the end of the test, that none carries a
// credential (T-31).
type rig struct {
	t     *testing.T
	r     *tokenRoot
	allow []Option
	rec   traceLog

	mu   sync.Mutex
	errs []error
}

func newRig(t *testing.T, mode rootMode) *rig {
	t.Helper()
	g := &rig{t: t, r: newTokenRoot(t, mode)}
	g.allow = append(g.allow, WithInsecureHTTPBase("http://localhost:"+g.r.port))
	t.Cleanup(g.checkSecrets)
	return g
}

// server starts another server, reachable as http://<host>:<port>, and
// returns its URL.
func (g *rig) server(host string, h http.Handler) string {
	g.t.Helper()
	s := startHTTP(g.t, h)
	u := "http://" + host + ":" + portOf(g.t, s)
	g.allow = append(g.allow, WithInsecureHTTPBase(u))
	return u
}

// wellKnown starts a well-known host on 127.0.0.1 serving doc and returns
// its counter and the option that points example.com at it.
func (g *rig) wellKnown(doc *guarded[string]) (*counter, Option) {
	g.t.Helper()
	h := newCounter(func(w http.ResponseWriter, r *http.Request) { jsonHandler(doc.get())(w, r) })
	u := g.server("127.0.0.1", h)
	return h, WithWellKnownLocation("example.com", u)
}

// client builds a client with the rig's allowances, the host-mapping
// transport, fast discovery backoff, the trace recorder and opts.
func (g *rig) client(opts ...Option) *Client {
	g.t.Helper()
	all := append([]Option{WithHTTPClient(localhostClient()), WithDiscoveryAttempts(4, time.Millisecond), WithTrace(g.rec.add)}, g.allow...)
	c, err := New(append(all, opts...)...)
	if err != nil {
		g.t.Fatalf("New: %v", err)
	}
	return c
}

// api returns the API of c at rootURL, version 1.0.0.
func (g *rig) api(c *Client, rootURL string) *API {
	g.t.Helper()
	base, err := ParseAPIBase(rootURL, "1.0.0")
	if err != nil {
		g.t.Fatal(err)
	}
	a, err := c.API(base)
	if err != nil {
		g.t.Fatal(err)
	}
	return a
}

// note keeps err for the end-of-test credential check and returns it.
func (g *rig) note(err error) error {
	if err != nil {
		g.mu.Lock()
		g.errs = append(g.errs, err)
		g.mu.Unlock()
	}
	return err
}

// rigSecrets are the strings no error or trace event may hold.
func rigSecrets() []string {
	basic := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(rigKeyID) + ":" + url.QueryEscape(rigSecret)))
	return []string{rigKeyID, rigSecret, url.QueryEscape(rigKeyID), url.QueryEscape(rigSecret), basic, "issued-access-token"}
}

// checkSecrets is T-31: no error the test collected (its text and %+v, and
// for a *DiscoveryError each attempt's URL, Reason and Err) and no trace
// event holds the key id, the secret, their encoded forms, the Basic value
// or a token.
func (g *rig) checkSecrets() {
	g.mu.Lock()
	errs := append([]error(nil), g.errs...)
	g.mu.Unlock()
	var texts []string
	for _, e := range errs {
		texts = append(texts, e.Error(), fmt.Sprintf("%+v", e))
		var de *DiscoveryError
		if errors.As(e, &de) {
			for _, a := range de.Attempts {
				texts = append(texts, a.URL, a.Reason)
				if a.Err != nil {
					texts = append(texts, a.Err.Error())
				}
			}
		}
	}
	for _, ev := range g.rec.events() {
		texts = append(texts, fmt.Sprintf("%+v", ev))
	}
	for _, s := range texts {
		for _, secret := range rigSecrets() {
			if strings.Contains(s, secret) {
				g.t.Errorf("%q holds a credential (%q)", s, secret)
			}
		}
	}
}

// traceLog collects trace events from concurrent calls (recorder's add
// reads and writes its slice in two steps).
type traceLog struct {
	mu  sync.Mutex
	evs []TraceEvent
}

func (l *traceLog) add(ev TraceEvent) {
	l.mu.Lock()
	l.evs = append(l.evs, ev)
	l.mu.Unlock()
}

func (l *traceLog) events() []TraceEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]TraceEvent(nil), l.evs...)
}

// ctxBG is the context of the rig tests.
var ctxBG = context.Background()
