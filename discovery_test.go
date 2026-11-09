package tea

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/oolong-project/tea-client-go/teaapi"
	"github.com/oolong-project/tea-client-go/tei"
)

// Made-up identifiers for the discovery tests.
var (
	otherReleaseID = uuid.MustParse("5abe6b7d-bcaf-4b9c-8fd0-7e6c8b9fafb5")
	discTEI        = "tei://example.com/uuid/" + releaseID.String()
)

func mustTEI(t testing.TB, s string) tei.TEI {
	t.Helper()
	v, err := tei.Parse(s)
	if err != nil {
		t.Fatalf("tei.Parse(%q): %v", s, err)
	}
	return v
}

// endpoint is one well-known endpoint as JSON; extra is appended inside the
// object (e.g. `,"priority":0.5`).
func endpoint(u string, versions string, extra string) string {
	return `{"url":"` + u + `","versions":` + versions + extra + `}`
}

func wellKnownDoc(endpoints ...string) string {
	return `{"schemaVersion":1,"endpoints":[` + strings.Join(endpoints, ",") + `]}`
}

// resultsJSON is a /discovery answer: one result per id, each served by root.
func resultsJSON(root string, ids ...uuid.UUID) string {
	var items []string
	for _, id := range ids {
		items = append(items, `{"productReleaseUuid":"`+id.String()+`","servers":[{"rootUrl":"`+root+`","versions":["1.0.0"]}]}`)
	}
	return "[" + strings.Join(items, ",") + "]"
}

// status answers code with body as content type ct.
func status(code int, ct, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
}

// discoveryClient builds a client that fetches the well-known document of
// example.com from wk, trusts the httptest certificate (shared by every
// httptest TLS server) and backs off for 1 ms. Later options win.
func discoveryClient(t *testing.T, wk *httptest.Server, opts ...Option) *Client {
	t.Helper()
	all := append([]Option{
		WithHTTPClient(wk.Client()),
		WithWellKnownLocation("example.com", wk.URL),
		WithDiscoveryAttempts(4, time.Millisecond),
	}, opts...)
	c, err := New(all...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// served starts a TLS server answering every request with h, counting them.
func served(t *testing.T, h http.HandlerFunc) (*counter, *httptest.Server) {
	t.Helper()
	c := newCounter(h)
	return c, startTLS(t, c)
}

// recorder collects trace events.
type recorder struct{ g guarded[[]TraceEvent] }

func (r *recorder) add(ev TraceEvent) { r.g.set(append(r.g.get(), ev)) }
func (r *recorder) events() []TraceEvent {
	return append([]TraceEvent(nil), r.g.get()...)
}
func (r *recorder) failed() []TraceEvent {
	var out []TraceEvent
	for _, ev := range r.events() {
		if ev.Kind == TraceAttemptFailed {
			out = append(out, ev)
		}
	}
	return out
}

func asDiscoveryError(t *testing.T, err error) *DiscoveryError {
	t.Helper()
	var de *DiscoveryError
	if !errors.As(err, &de) {
		t.Fatalf("error %v (%T), want *DiscoveryError", err, err)
	}
	return de
}

// Case 21: the request form of /discovery.
func TestDiscoverRequestForm(t *testing.T) {
	api := newCounter(nil)
	apiSrv := startTLS(t, api)
	api.h = jsonHandler(resultsJSON(apiSrv.URL, releaseID))
	wk, wkSrv := served(t, jsonHandler(wellKnownDoc(endpoint(apiSrv.URL+"/tea", `["1.0.0+build.5"]`, ""))))
	c := discoveryClient(t, wkSrv)

	// A TEI whose id needs query encoding: %, :, @, + and sub-delims.
	in := "tei://example.com/hash/SHA-256:ab%3Acd@x+y=z!$&'()*,;"
	res, err := c.Discover(context.Background(), mustTEI(t, in))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].ProductReleaseUUID != releaseID {
		t.Fatalf("results %+v", res)
	}
	if got, want := res[0].DiscoveredAt.String(), apiSrv.URL+"/tea/v1.0.0+build.5"; got != want {
		t.Errorf("DiscoveredAt %q, want %q", got, want)
	}
	wr := wk.lastReq()
	if wk.count() != 1 || wr.URL.Path != "/.well-known/tea" || wr.Header.Get("Accept") != "application/json" {
		t.Errorf("well-known request: %d, %s, Accept %q", wk.count(), wr.URL, wr.Header.Get("Accept"))
	}
	r := api.lastReq()
	if api.count() != 1 {
		t.Fatalf("discovery requests: %d", api.count())
	}
	if got := r.URL.EscapedPath(); got != "/tea/v1.0.0+build.5/discovery" {
		t.Errorf("discovery path %q, want the version verbatim with a literal +", got)
	}
	if got, want := r.URL.RawQuery, "tei="+url.QueryEscape(in); got != want {
		t.Errorf("query %q, want %q (encoded once)", got, want)
	}
	q := r.URL.Query()
	if q.Get("tei") != in || q.Has("purl") || len(q) != 1 {
		t.Errorf("decoded query %v, want tei = the TEI as given", q)
	}
	if r.Header.Get("Accept") != "application/json" {
		t.Errorf("discovery Accept %q", r.Header.Get("Accept"))
	}

	// Without WithWellKnownLocation the document is fetched from
	// https://<lowercased domain>/.well-known/tea; a location configured
	// for a domain applies whatever the TEI's case.
	seen := &guarded[[]string]{}
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen.set(append(seen.get(), r.URL.String()))
		return nil, errors.New("no network in tests")
	})
	c2, err := New(WithHTTPClient(&http.Client{Transport: rt}), WithDiscoveryAttempts(1, time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c2.Discover(context.Background(), mustTEI(t, "tei://Example.COM/uuid/x"))
	if got := seen.get(); len(got) != 1 || got[0] != "https://example.com/.well-known/tea" {
		t.Errorf("default well-known URL: %v (%v)", got, err)
	}
	if _, err := c.Discover(context.Background(), mustTEI(t, "tei://EXAMPLE.com/uuid/x")); err != nil || wk.count() != 2 {
		t.Errorf("well-known location for a differently cased domain: %v, %d requests", err, wk.count())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Case 21b (= 9b): the local-ReARM shape of the CLI's --usehttp. The origin
// allowance covers the endpoint and the servers[] root under it, and
// nothing else.
func TestDiscoverLocalReARMShape(t *testing.T) {
	other := newCounter(jsonHandler(resultsJSON("http://127.0.0.1:1/tea", releaseID)))
	otherSrv := startHTTP(t, other)
	doc := &guarded[string]{}
	h := newCounter(nil)
	srv := startHTTP(t, h)
	o := srv.URL
	h.h = func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/tea":
			jsonHandler(doc.get())(w, r)
		case "/tea/v1.0.0/discovery":
			jsonHandler(resultsJSON(o+"/tea", releaseID))(w, r)
		case "/tea/v1.0.0/productRelease/" + releaseID.String():
			jsonHandler(`{"uuid":"`+releaseID.String()+`","version":"1.0.0","createdDate":"2026-01-15T00:00:00Z","components":[]}`)(w, r)
		default:
			http.NotFound(w, r)
		}
	}
	c, err := New(WithWellKnownLocation("localhost", o), WithInsecureHTTPBase(o), WithDiscoveryAttempts(2, time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tv := mustTEI(t, "tei://localhost/uuid/"+releaseID.String())

	doc.set(wellKnownDoc(endpoint(o+"/tea", `["1.0.0"]`, "")))
	res, err := c.Discover(ctx, tv)
	if err != nil {
		t.Fatal(err)
	}
	base, err := c.SelectServer(res[0])
	if err != nil || base.RootURL() != o+"/tea" || base.Version() != "1.0.0" {
		t.Fatalf("SelectServer: %v %v", base, err)
	}
	a, err := c.API(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetProductRelease(ctx, releaseID); err != nil {
		t.Fatal(err)
	}
	if got := h.lastReq().URL.Path; got != "/tea/v1.0.0/productRelease/"+releaseID.String() {
		t.Errorf("product release requested at %s", got)
	}

	// The same document listing another port, or another host on the same
	// port, is refused: no request leaves for it and no candidate is left.
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(o, "http://"))
	for _, bad := range []string{otherSrv.URL + "/tea", "http://localhost:" + port + "/tea"} {
		before := h.count()
		doc.set(wellKnownDoc(endpoint(bad, `["1.0.0"]`, "")))
		_, err := c.Discover(ctx, tv)
		de := asDiscoveryError(t, err)
		if de.Stage != StageWellKnown || !errors.Is(err, ErrInsecureURL) {
			t.Errorf("%s: stage %s, %v; want well-known and ErrInsecureURL", bad, de.Stage, err)
		}
		if got := h.count() - before; got != 2 {
			t.Errorf("%s: %d well-known requests, want 2 (the attempt bound)", bad, got)
		}
	}
	if other.count() != 0 {
		t.Errorf("the other port received %d requests", other.count())
	}
}

// Case 22: endpoint selection.
func TestDiscoverSelection(t *testing.T) {
	ctx := context.Background()
	e1, s1 := served(t, nil)
	e2, s2 := served(t, nil)
	e3, s3 := served(t, nil)
	for _, p := range []struct {
		c *counter
		s *httptest.Server
	}{{e1, s1}, {e2, s2}, {e3, s3}} {
		p.c.h = jsonHandler(resultsJSON(p.s.URL, releaseID))
	}
	doc := &guarded[string]{}
	wk, wkSrv := served(t, func(w http.ResponseWriter, r *http.Request) { jsonHandler(doc.get())(w, r) })
	c := discoveryClient(t, wkSrv)
	tv := mustTEI(t, discTEI)
	reset := func() {
		for _, e := range []*counter{e1, e2, e3} {
			e.n.Store(0)
		}
	}
	firstCalled := func(name string, want *httptest.Server) {
		t.Helper()
		res, err := c.Discover(ctx, tv)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := res[0].DiscoveredAt.RootURL(); got != want.URL {
			t.Errorf("%s: answered by %s, want %s", name, got, want.URL)
		}
		if n := e1.count() + e2.count() + e3.count(); n != 1 {
			t.Errorf("%s: %d discovery requests, want 1", name, n)
		}
		reset()
	}

	doc.set(wellKnownDoc(
		endpoint(s1.URL, `["0.2.0-beta.2"]`, ""),
		endpoint(s2.URL, `["1.0.0"]`, `,"priority":0.5`),
		endpoint(s3.URL, `["1.0.0"]`, "")))
	firstCalled("unsupported, priority 0.5, no priority", s3)

	// Ties keep document order, with and without an explicit priority.
	doc.set(wellKnownDoc(endpoint(s1.URL, `["1.0.0"]`, ""), endpoint(s2.URL, `["1.0.0"]`, "")))
	firstCalled("tie, document order 1-2", s1)
	doc.set(wellKnownDoc(endpoint(s2.URL, `["1.0.0"]`, `,"priority":0.7`), endpoint(s1.URL, `["1.0.0"]`, `,"priority":0.7`)))
	firstCalled("tie, document order 2-1", s2)
	// Build metadata is ignored for matching.
	doc.set(wellKnownDoc(endpoint(s1.URL, `["2.0.0"]`, ""), endpoint(s2.URL, `["1.0.0+b.1"]`, `,"priority":0`)))
	firstCalled("1.0.0+b.1 only supported", s2)

	// A pre-release of 1.0.0 is not 1.0.0: no candidate, no discovery request.
	wkBefore := wk.count()
	doc.set(wellKnownDoc(endpoint(s1.URL, `["1.0.0-rc.1"]`, "")))
	_, err := c.Discover(ctx, tv)
	de := asDiscoveryError(t, err)
	if de.Stage != StageWellKnown || !errors.Is(err, errNoCandidate) || len(de.Attempts) != 1 {
		t.Errorf("1.0.0-rc.1 only: %v", err)
	}
	if e1.count() != 0 || wk.count()-wkBefore != 1 {
		t.Errorf("1.0.0-rc.1 only: %d discovery and %d well-known requests, want 0 and 1", e1.count(), wk.count()-wkBefore)
	}
}

// The ordering rule itself: greatest version first, then priority, then
// the given order (SupportedVersions has one version, so the version rule
// is exercised here directly).
func TestSortCandidates(t *testing.T) {
	cs := []candidate{
		{version: "v1.0.0", priority: 1},
		{version: "v2.0.0", priority: 0.1},
		{version: "v1.0.0", priority: 0.5},
		{version: "v2.0.0", priority: 0.9},
		{version: "v1.0.0", priority: 1},
	}
	for i := range cs {
		cs[i].base.rootStr = fmt.Sprint(i)
	}
	sortCandidates(cs)
	var got []string
	for _, c := range cs {
		got = append(got, c.base.rootStr)
	}
	if strings.Join(got, ",") != "3,1,0,4,2" {
		t.Errorf("order %v, want 3,1,0,4,2", got)
	}
}

// Case 23: well-known validation; each failure is a failed attempt and no
// discovery request is made.
func TestWellKnownValidation(t *testing.T) {
	api, apiSrv := served(t, nil)
	api.h = jsonHandler(resultsJSON(apiSrv.URL, releaseID))
	a := apiSrv.URL
	doc := &guarded[string]{}
	wk, wkSrv := served(t, func(w http.ResponseWriter, r *http.Request) { jsonHandler(doc.get())(w, r) })
	c := discoveryClient(t, wkSrv, WithDiscoveryAttempts(1, time.Millisecond))
	ctx := context.Background()
	tv := mustTEI(t, discTEI)

	for _, tc := range []struct {
		name, doc, rule string
		policy          bool // refused by the URL policy (ErrInsecureURL)
	}{
		{"schemaVersion 2", `{"schemaVersion":2,"endpoints":[` + endpoint(a, `["1.0.0"]`, "") + `]}`, "schemaVersion", false},
		{"schemaVersion string", `{"schemaVersion":"1","endpoints":[` + endpoint(a, `["1.0.0"]`, "") + `]}`, "schemaVersion", false},
		{"schemaVersion missing", `{"endpoints":[` + endpoint(a, `["1.0.0"]`, "") + `]}`, "schemaVersion", false},
		{"schemaVersion key case", `{"SchemaVersion":1,"endpoints":[` + endpoint(a, `["1.0.0"]`, "") + `]}`, "schemaVersion", false},
		{"empty endpoints", `{"schemaVersion":1,"endpoints":[]}`, "endpoints", false},
		{"endpoints null", `{"schemaVersion":1,"endpoints":null}`, "endpoints", false},
		{"endpoint not an object", wellKnownDoc(`"x"`), "endpoint 0 is not an object", false},
		{"url with query", wellKnownDoc(endpoint(a+"?x=1", `["1.0.0"]`, "")), "rootUrl pattern", false},
		{"url with userinfo", wellKnownDoc(endpoint(strings.Replace(a, "https://", "https://u@", 1), `["1.0.0"]`, "")), "rootUrl pattern", false},
		{"url with trailing slash", wellKnownDoc(endpoint(a+"/tea/", `["1.0.0"]`, "")), "rootUrl pattern", false},
		{"url with fragment", wellKnownDoc(endpoint(a+"#f", `["1.0.0"]`, "")), "rootUrl pattern", false},
		{"url not a string", wellKnownDoc(`{"url":5,"versions":["1.0.0"]}`), "url is not a string", false},
		{"url with a dot segment", wellKnownDoc(endpoint(a+"/a/../b", `["1.0.0"]`, "")), "URL policy", true},
		{"url with an encoded dot segment", wellKnownDoc(endpoint(a+"/a/%2E%2e/b", `["1.0.0"]`, "")), "URL policy", true},
		{"http url not allowed", wellKnownDoc(endpoint(strings.Replace(a, "https://", "http://", 1), `["1.0.0"]`, "")), "URL policy", true},
		{"version v1.0.0", wellKnownDoc(endpoint(a, `["v1.0.0"]`, "")), "versions", false},
		{"versions empty", wellKnownDoc(endpoint(a, `[]`, "")), "versions", false},
		{"versions missing", wellKnownDoc(`{"url":"` + a + `"}`), "versions", false},
		{"version not a string", wellKnownDoc(endpoint(a, `[1]`, "")), "versions", false},
		{"priority 1.5", wellKnownDoc(endpoint(a, `["1.0.0"]`, `,"priority":1.5`)), "priority", false},
		{"priority negative", wellKnownDoc(endpoint(a, `["1.0.0"]`, `,"priority":-0.1`)), "priority", false},
		{"priority string", wellKnownDoc(endpoint(a, `["1.0.0"]`, `,"priority":"1"`)), "priority", false},
		{"priority null", wellKnownDoc(endpoint(a, `["1.0.0"]`, `,"priority":null`)), "priority", false},
		{"not JSON", `<html>not json</html>`, "not a JSON object", false},
		{"JSON array", `[]`, "not a JSON object", false},
		{"null", `null`, "not a JSON object", false},
		{"one bad endpoint among good ones", wellKnownDoc(endpoint(a, `["1.0.0"]`, ""), endpoint(a, `["1.0"]`, "")), "endpoint 1: versions", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wkBefore := wk.count()
			doc.set(tc.doc)
			_, err := c.Discover(ctx, tv)
			de := asDiscoveryError(t, err)
			if de.Stage != StageWellKnown || len(de.Attempts) != 1 || de.Attempts[0].Stage != StageWellKnown {
				t.Fatalf("%v: stage %s, %d attempts", err, de.Stage, len(de.Attempts))
			}
			if !strings.Contains(de.Attempts[0].Reason, tc.rule) {
				t.Errorf("reason %q does not name %q", de.Attempts[0].Reason, tc.rule)
			}
			if errors.Is(err, ErrInsecureURL) != tc.policy {
				t.Errorf("errors.Is(ErrInsecureURL) = %v, want %v", !tc.policy, tc.policy)
			}
			if wk.count()-wkBefore != 1 || api.count() != 0 {
				t.Errorf("%d well-known and %d discovery requests, want 1 and 0", wk.count()-wkBefore, api.count())
			}
		})
	}

	// Unknown properties are ignored, at the top and in an endpoint, as is a
	// priority at the bounds.
	doc.set(`{"schemaVersion":1,"future":{"a":[1]},"endpoints":[{"url":"` + a + `","versions":["1.0.0"],"priority":0,"extra":true}]}`)
	if _, err := discoveryClient(t, wkSrv).Discover(ctx, tv); err != nil || api.count() != 1 {
		t.Errorf("unknown properties: %v, %d discovery requests", err, api.count())
	}
}

// Case 24: failed attempts fail over to the next endpoint.
func TestDiscoverFailover(t *testing.T) {
	ctx := context.Background()
	good, goodSrv := served(t, nil)
	good.h = jsonHandler(resultsJSON(goodSrv.URL, otherReleaseID))
	bad, badSrv := served(t, nil)
	b := badSrv.URL
	wrongID := `[{"productReleaseUuid":"%s","servers":[{"rootUrl":"` + b + `","versions":["1.0.0"]}]}]`
	server := func(s string) string {
		return `[{"productReleaseUuid":"` + releaseID.String() + `","servers":[` + s + `]}]`
	}

	for _, tc := range []struct {
		name   string
		h      http.HandlerFunc
		reason string
	}{
		{"503", status(503, "application/json", `{"error":"OBJECT_UNKNOWN"}`), "HTTP 503"},
		{"500 empty", status(500, "", ""), "HTTP 500"},
		{"non-TEA 404 JSON", status(404, "application/json", `{"message":"Not Found"}`), "not a TEA error"},
		{"non-TEA 404 array", status(404, "application/json", `[{"error":"OBJECT_UNKNOWN"}]`), "not a TEA error"},
		{"404 text/html", status(404, "text/html", `{"error":"OBJECT_UNKNOWN"}`), "not a TEA error"},
		{"404 empty", status(404, "", ""), "not a TEA error"},
		{"invalid JSON", jsonHandler(`[{"productReleaseUuid":`), "not a JSON array"},
		{"an object", jsonHandler(`{"productReleaseUuid":"` + releaseID.String() + `"}`), "not a JSON array"},
		{"empty array", jsonHandler(`[]`), "empty array"},
		{"uuid not-a-uuid", jsonHandler(fmt.Sprintf(wrongID, "not-a-uuid")), "not a uuid"},
		{"uuid of 35 characters", jsonHandler(fmt.Sprintf(wrongID, "22222222-2222-4222-8222-22222222222")), "not a uuid"},
		{"uuid missing", jsonHandler(`[{"servers":[{"rootUrl":"` + b + `","versions":["1.0.0"]}]}]`), "productReleaseUuid"},
		{"servers empty", jsonHandler(server(``)), "servers"},
		{"server versions empty", jsonHandler(server(`{"rootUrl":"` + b + `","versions":[]}`)), "versions"},
		{"server version v1", jsonHandler(server(`{"rootUrl":"` + b + `","versions":["v1"]}`)), "versions"},
		{"server priority 2", jsonHandler(server(`{"rootUrl":"` + b + `","versions":["1.0.0"],"priority":2}`)), "priority"},
		{"rootUrl with a query", jsonHandler(server(`{"rootUrl":"` + b + `?a","versions":["1.0.0"]}`)), "rootUrl pattern"},
		{"http rootUrl not under an allowance", jsonHandler(server(`{"rootUrl":"http://127.0.0.1:1/tea","versions":["1.0.0"]}`)), "URL policy"},
		{"rootUrl with a dot segment", jsonHandler(server(`{"rootUrl":"` + b + `/x/..","versions":["1.0.0"]}`)), "URL policy"},
		{"a redirect to http", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://127.0.0.1:1/x", http.StatusFound)
		}, "http URL is not under"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad.h = tc.h
			bad.n.Store(0)
			good.n.Store(0)
			_, wkSrv := served(t, jsonHandler(wellKnownDoc(endpoint(b, `["1.0.0"]`, ""), endpoint(goodSrv.URL, `["1.0.0"]`, ""))))
			rec := &recorder{}
			c := discoveryClient(t, wkSrv, WithTrace(rec.add))
			res, err := c.Discover(ctx, mustTEI(t, discTEI))
			if err != nil {
				t.Fatal(err)
			}
			if len(res) != 1 || res[0].ProductReleaseUUID != otherReleaseID || res[0].DiscoveredAt.RootURL() != goodSrv.URL {
				t.Errorf("results %+v, want the second endpoint's", res)
			}
			if bad.count() != 1 || good.count() != 1 {
				t.Errorf("requests: first %d, second %d; want 1 and 1", bad.count(), good.count())
			}
			f := rec.failed()
			if len(f) != 1 || f[0].Stage != StageAPIDiscovery || f[0].URL != b+"/v1.0.0/discovery" || !strings.Contains(f[0].Reason, tc.reason) {
				t.Errorf("failed attempts %+v, want one at the first endpoint naming %q", f, tc.reason)
			}
		})
	}

	// A TLS failure (a certificate the client does not trust) is a failed
	// attempt too; the untrusted server's handler is never reached.
	untrusted := newCounter(jsonHandler(resultsJSON(goodSrv.URL, releaseID)))
	us := httptest.NewUnstartedServer(untrusted)
	us.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}
	us.Config.ErrorLog = log.New(io.Discard, "", 0) // the expected handshake failures
	us.StartTLS()
	t.Cleanup(us.Close)
	good.n.Store(0)
	_, wkSrv := served(t, jsonHandler(wellKnownDoc(endpoint(us.URL, `["1.0.0"]`, ""), endpoint(goodSrv.URL, `["1.0.0"]`, ""))))
	rec := &recorder{}
	c := discoveryClient(t, wkSrv, WithTrace(rec.add))
	res, err := c.Discover(ctx, mustTEI(t, discTEI))
	if err != nil || len(res) != 1 || res[0].ProductReleaseUUID != otherReleaseID {
		t.Fatalf("TLS failure: %+v %v", res, err)
	}
	if f := rec.failed(); len(f) != 1 || f[0].URL != us.URL+"/v1.0.0/discovery" || !strings.Contains(f[0].Reason, "certificate") {
		t.Errorf("TLS failure attempts %+v", f)
	}
	if untrusted.count() != 0 || good.count() != 1 {
		t.Errorf("TLS failure: untrusted handler %d, second endpoint %d", untrusted.count(), good.count())
	}
	_, err = discoveryClient(t, wkSrv, WithDiscoveryAttempts(2, time.Millisecond)).Discover(ctx, mustTEI(t, discTEI))
	var ce *tls.CertificateVerificationError
	if de := asDiscoveryError(t, err); !errors.As(de.Attempts[0].Err, &ce) {
		t.Errorf("TLS failure Attempt.Err: %v", de.Attempts[0].Err)
	}
}

// selfSigned makes a certificate for 127.0.0.1 that no test client trusts.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "untrusted.example"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Case 24: a uuid in another accepted spelling decodes to the canonical value.
func TestDiscoverUppercaseUUID(t *testing.T) {
	api, apiSrv := served(t, nil)
	api.h = jsonHandler(`[{"productReleaseUuid":"ABCDEF00-2222-4222-8222-222222222222","servers":[{"rootUrl":"` + apiSrv.URL + `","versions":["1.0.0"]}]}]`)
	_, wkSrv := served(t, jsonHandler(wellKnownDoc(endpoint(apiSrv.URL, `["1.0.0"]`, ""))))
	res, err := discoveryClient(t, wkSrv).Discover(context.Background(), mustTEI(t, discTEI))
	if err != nil {
		t.Fatal(err)
	}
	if got := res[0].ProductReleaseUUID.String(); got != "abcdef00-2222-4222-8222-222222222222" {
		t.Errorf("uuid %q, want lowercase", got)
	}
}

// Case 25: answers that end discovery at once, with no failover.
func TestDiscoverNoFailover(t *testing.T) {
	ctx := context.Background()
	second, secondSrv := served(t, nil)
	second.h = jsonHandler(resultsJSON(secondSrv.URL, releaseID))
	first, firstSrv := served(t, nil)
	_, wkSrv := served(t, jsonHandler(wellKnownDoc(endpoint(firstSrv.URL+"/tea", `["1.0.0"]`, ""), endpoint(secondSrv.URL, `["1.0.0"]`, ""))))

	run := func(t *testing.T, h http.HandlerFunc) error {
		t.Helper()
		first.h = h
		first.n.Store(0)
		second.n.Store(0)
		_, err := discoveryClient(t, wkSrv).Discover(ctx, mustTEI(t, discTEI))
		if first.count() != 1 || second.count() != 0 {
			t.Errorf("requests: first %d, second %d; want 1 and 0", first.count(), second.count())
		}
		return err
	}

	t.Run("TEA 404 OBJECT_UNKNOWN", func(t *testing.T) {
		err := run(t, status(404, "application/json; charset=utf-8", `{"error":"OBJECT_UNKNOWN","message":"no such TEI"}`))
		var nr *NotResolvedError
		if !errors.As(err, &nr) || nr.Code != ErrorCodeObjectUnknown || nr.Base.String() != firstSrv.URL+"/tea/v1.0.0" {
			t.Fatalf("%v, want *NotResolvedError OBJECT_UNKNOWN at the first base", err)
		}
		if !errors.Is(err, ErrObjectUnknown) {
			t.Errorf("errors.Is(ErrObjectUnknown) does not hold")
		}
	})
	t.Run("TEA 404 unknown code", func(t *testing.T) {
		code := "FUTURE_CODE" + strings.Repeat("X", 10000)
		err := run(t, status(404, "application/json", `{"error":"`+code+`","extra":1}`))
		var nr *NotResolvedError
		if !errors.As(err, &nr) || nr.Code != ErrorCodeUnknown || nr.RawCode != code[:64] {
			t.Fatalf("%v, want *NotResolvedError with the code cut to 64 bytes", err)
		}
		if errors.Is(err, ErrObjectUnknown) || len(err.Error()) > 200 {
			t.Errorf("unknown code: %q", err)
		}
	})
	for _, tc := range []struct {
		name   string
		h      http.HandlerFunc
		status int
		is     error
	}{
		{"401", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="x"`)
			w.WriteHeader(401)
		}, 401, ErrUnauthorized},
		{"403", status(403, "", ""), 403, ErrForbidden},
		{"400", status(400, "application/json", `{"error":"INVALID_REQUEST"}`), 400, ErrInvalidRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := run(t, tc.h)
			var ae *APIError
			if !errors.As(err, &ae) || ae.Status != tc.status || !errors.Is(err, tc.is) {
				t.Fatalf("%v, want *APIError %d", err, tc.status)
			}
			var de *DiscoveryError
			if errors.As(err, &de) {
				t.Errorf("a stop is not a *DiscoveryError: %v", err)
			}
		})
	}
	t.Run("401 at the well-known stage", func(t *testing.T) {
		wk, wkSrv := served(t, status(401, "", ""))
		_, err := discoveryClient(t, wkSrv).Discover(ctx, mustTEI(t, discTEI))
		if !errors.Is(err, ErrUnauthorized) || wk.count() != 1 {
			t.Errorf("%v after %d requests, want ErrUnauthorized after 1", err, wk.count())
		}
	})
}

// Case 26: the attempt bound, the backoff and cancellation.
func TestDiscoverAttemptBound(t *testing.T) {
	ctx := context.Background()
	tv := mustTEI(t, discTEI)
	var eps []string
	var cs []*counter
	for i := 0; i < 4; i++ {
		c, s := served(t, status(503, "", ""))
		cs = append(cs, c)
		eps = append(eps, endpoint(s.URL, `["1.0.0"]`, ""))
	}
	wk, wkSrv := served(t, jsonHandler(wellKnownDoc(eps...)))

	// Every GET counts, the successful well-known fetch included: 3 attempts
	// are the well-known fetch and the first two endpoints.
	_, err := discoveryClient(t, wkSrv, WithDiscoveryAttempts(3, time.Millisecond)).Discover(ctx, tv)
	de := asDiscoveryError(t, err)
	if de.Stage != StageAPIDiscovery || len(de.Attempts) != 2 {
		t.Fatalf("%v: stage %s, %d attempts", err, de.Stage, len(de.Attempts))
	}
	total := wk.count()
	for i, c := range cs {
		total += c.count()
		if want := int64(map[bool]int{true: 1}[i < 2]); c.count() != want {
			t.Errorf("endpoint %d: %d requests, want %d", i, c.count(), want)
		}
	}
	if total != 3 {
		t.Errorf("%d requests in total, want 3", total)
	}
	for i, a := range de.Attempts {
		if a.URL != strings.TrimSuffix(strings.TrimPrefix(eps[i], `{"url":"`), `","versions":["1.0.0"]}`)+"/v1.0.0/discovery" ||
			a.Reason != "HTTP 503" || !errors.Is(a.Err, ErrServer) || strings.Contains(a.URL, "?") {
			t.Errorf("attempt %d: %+v", i, a)
		}
	}

	// With attempts left over, the candidates are tried again from the
	// first: one endpoint, 4 attempts, 3 discovery requests.
	one, oneSrv := served(t, status(503, "", ""))
	_, wk1 := served(t, jsonHandler(wellKnownDoc(endpoint(oneSrv.URL, `["1.0.0"]`, ""))))
	_, err = discoveryClient(t, wk1).Discover(ctx, tv)
	if de := asDiscoveryError(t, err); len(de.Attempts) != 3 || one.count() != 3 {
		t.Errorf("one endpoint: %d attempts, %d requests, want 3 and 3", len(de.Attempts), one.count())
	}

	// A failing well-known fetch is retried within the bound, with backoff
	// doubling from the first.
	bad, badSrv := served(t, status(502, "", ""))
	rec := &recorder{}
	start := time.Now()
	_, err = discoveryClient(t, badSrv, WithDiscoveryAttempts(3, 40*time.Millisecond), WithTrace(rec.add)).Discover(ctx, tv)
	de = asDiscoveryError(t, err)
	if de.Stage != StageWellKnown || len(de.Attempts) != 3 || bad.count() != 3 {
		t.Errorf("failing well-known: stage %s, %d attempts, %d requests", de.Stage, len(de.Attempts), bad.count())
	}
	var waits []time.Duration
	for _, ev := range rec.events() {
		if ev.Kind == TraceBackoff {
			waits = append(waits, ev.Wait)
		}
	}
	if fmt.Sprint(waits) != "[40ms 80ms]" || time.Since(start) < 120*time.Millisecond {
		t.Errorf("backoffs %v after %v, want [40ms 80ms] and at least 120 ms", waits, time.Since(start))
	}

	// A context cancelled during a backoff ends Discover promptly.
	bad.n.Store(0)
	cctx, cancel := context.WithCancel(ctx)
	time.AfterFunc(100*time.Millisecond, cancel)
	start = time.Now()
	_, err = discoveryClient(t, badSrv, WithDiscoveryAttempts(4, 10*time.Second)).Discover(cctx, tv)
	if !errors.Is(err, context.Canceled) || time.Since(start) > time.Second || bad.count() != 1 {
		t.Errorf("cancel during backoff: %v after %v and %d requests", err, time.Since(start), bad.count())
	}
}

func TestBackoffDelay(t *testing.T) {
	var got []time.Duration
	for i := 0; i < 7; i++ {
		got = append(got, backoffDelay(250*time.Millisecond, i))
	}
	if fmt.Sprint(got) != "[250ms 500ms 1s 2s 4s 4s 4s]" {
		t.Errorf("default backoffs %v", got)
	}
	if d := backoffDelay(3*time.Second, 1); d != 4*time.Second {
		t.Errorf("3 s doubled: %v, want the 4 s cap", d)
	}
	if d := backoffDelay(10*time.Second, 0); d != 4*time.Second {
		t.Errorf("10 s first: %v, want the 4 s cap", d)
	}
}

// stalling returns a handler that, while stall reports true for the request
// number (from 1), sends headers and one byte and then stops (headers) or
// sends nothing (none), until the request or the test ends; otherwise it
// calls h.
func stalling(t *testing.T, mode string, stall func(n int64) bool, h http.HandlerFunc) *counter {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	c := newCounter(nil)
	c.h = func(w http.ResponseWriter, r *http.Request) {
		if !stall(c.count()) {
			h(w, r)
			return
		}
		if mode == "headers" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("["))
			w.(http.Flusher).Flush()
		}
		select {
		case <-r.Context().Done():
		case <-stop:
		}
	}
	return c
}

// Case 26b: AttemptTimeout makes a stalled attempt a failed one.
func TestDiscoverAttemptTimeout(t *testing.T) {
	ctx := context.Background()
	tv := mustTEI(t, discTEI)
	bounded := []Option{WithLimits(Limits{AttemptTimeout: 200 * time.Millisecond}), WithDiscoveryAttempts(4, 10*time.Millisecond)}
	first := func(n int64) bool { return n == 1 }
	always := func(int64) bool { return true }

	for _, mode := range []string{"headers", "none"} {
		t.Run("well-known "+mode, func(t *testing.T) {
			api, apiSrv := served(t, nil)
			api.h = jsonHandler(resultsJSON(apiSrv.URL, releaseID))
			wk := stalling(t, mode, first, jsonHandler(wellKnownDoc(endpoint(apiSrv.URL, `["1.0.0"]`, ""))))
			wkSrv := startTLS(t, wk)
			rec := &recorder{}
			start := time.Now()
			res, err := discoveryClient(t, wkSrv, append(bounded, WithTrace(rec.add))...).Discover(ctx, tv)
			if err != nil || len(res) != 1 {
				t.Fatalf("%v", err)
			}
			if d := time.Since(start); d > time.Second || d < 190*time.Millisecond {
				t.Errorf("succeeded after %v, want within 1 s", d)
			}
			if f := rec.failed(); wk.count() != 2 || len(f) != 1 || f[0].Stage != StageWellKnown || !strings.Contains(f[0].Reason, "time bound") {
				t.Errorf("%d well-known requests, failed attempts %+v", wk.count(), f)
			}
			// With one attempt only, the DiscoveryError carries the cause.
			wk.n.Store(0)
			_, err = discoveryClient(t, wkSrv, append(bounded, WithDiscoveryAttempts(1, time.Millisecond))...).Discover(ctx, tv)
			de := asDiscoveryError(t, err)
			if !errors.Is(de.Attempts[0].Err, ErrTimeout) || !errors.Is(err, ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("Attempt.Err %v, want ErrTimeout", de.Attempts[0].Err)
			}
		})
	}

	discoveryStall := func(t *testing.T, mode string, opts ...Option) {
		t.Helper()
		good, goodSrv := served(t, nil)
		good.h = jsonHandler(resultsJSON(goodSrv.URL, otherReleaseID))
		slow := stalling(t, mode, always, nil)
		slowSrv := startTLS(t, slow)
		_, wkSrv := served(t, jsonHandler(wellKnownDoc(endpoint(slowSrv.URL, `["1.0.0"]`, ""), endpoint(goodSrv.URL, `["1.0.0"]`, ""))))
		rec := &recorder{}
		start := time.Now()
		res, err := discoveryClient(t, wkSrv, append(append(bounded, WithTrace(rec.add)), opts...)...).Discover(ctx, tv)
		if err != nil || len(res) != 1 || res[0].ProductReleaseUUID != otherReleaseID {
			t.Fatalf("%+v %v", res, err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("succeeded after %v, want within 1 s", d)
		}
		if f := rec.failed(); slow.count() != 1 || len(f) != 1 || f[0].Stage != StageAPIDiscovery || !strings.Contains(f[0].Reason, "time bound") {
			t.Errorf("%d stalled requests, failed attempts %+v", slow.count(), f)
		}
	}
	for _, mode := range []string{"headers", "none"} {
		t.Run("discovery "+mode, func(t *testing.T) { discoveryStall(t, mode) })
	}
	// The same with a caller http.Client that has no timeouts of its own
	// (the TLS test client above has none either; this one is plain).
	t.Run("caller http.Client", func(t *testing.T) {
		h := newCounter(nil)
		srv := startHTTP(t, h)
		stop := make(chan struct{})
		t.Cleanup(func() { close(stop) })
		h.h = func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/tea":
				jsonHandler(wellKnownDoc(endpoint(srv.URL+"/slow", `["1.0.0"]`, ""), endpoint(srv.URL+"/good", `["1.0.0"]`, "")))(w, r)
			case "/good/v1.0.0/discovery":
				jsonHandler(resultsJSON(srv.URL+"/good", otherReleaseID))(w, r)
			default:
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
				case <-stop:
				}
			}
		}
		c, err := New(append(bounded, WithHTTPClient(&http.Client{}), WithInsecureHTTPBase(srv.URL), WithWellKnownLocation("example.com", srv.URL))...)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		res, err := c.Discover(ctx, tv)
		if err != nil || res[0].ProductReleaseUUID != otherReleaseID || time.Since(start) > time.Second || h.count() != 3 {
			t.Errorf("%+v %v after %v and %d requests", res, err, time.Since(start), h.count())
		}
	})

	// A caller context that ends during a stalled attempt ends Discover with
	// its error, not ErrTimeout, and no further attempt is made.
	t.Run("caller context", func(t *testing.T) {
		wk := stalling(t, "headers", always, nil)
		wkSrv := startTLS(t, wk)
		for _, attempts := range []int{1, 4} {
			wk.n.Store(0)
			rec := &recorder{}
			cctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			start := time.Now()
			_, err := discoveryClient(t, wkSrv, WithLimits(Limits{AttemptTimeout: 5 * time.Second}),
				WithDiscoveryAttempts(attempts, time.Millisecond), WithTrace(rec.add)).Discover(cctx, tv)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrTimeout) || time.Since(start) > time.Second {
				t.Errorf("attempts %d: %v after %v, want the caller's deadline", attempts, err, time.Since(start))
			}
			var de *DiscoveryError
			if errors.As(err, &de) || len(rec.failed()) != 0 {
				t.Errorf("attempts %d: the caller's context ending is not a failed attempt: %v, %+v", attempts, err, rec.failed())
			}
			time.Sleep(50 * time.Millisecond)
			if wk.count() != 1 {
				t.Errorf("attempts %d: %d well-known requests, want 1", attempts, wk.count())
			}
		}
	})
}

// Case 26c: the results cap refuses a whole answer.
func TestDiscoverResultsCap(t *testing.T) {
	ctx := context.Background()
	tv := mustTEI(t, discTEI)
	ids := func(n int) []uuid.UUID {
		out := make([]uuid.UUID, n)
		for i := range out {
			out[i] = uuid.NewSHA1(uuid.NameSpaceURL, []byte(fmt.Sprint("result-", i)))
		}
		return out
	}
	many, manySrv := served(t, nil)
	many.h = jsonHandler(resultsJSON(manySrv.URL, ids(3)...))
	two, twoSrv := served(t, nil)
	two.h = jsonHandler(resultsJSON(twoSrv.URL, ids(2)...))
	capped := WithLimits(Limits{DiscoveryResults: 2})

	_, wkSrv := served(t, jsonHandler(wellKnownDoc(endpoint(manySrv.URL, `["1.0.0"]`, ""), endpoint(twoSrv.URL, `["1.0.0"]`, ""))))
	rec := &recorder{}
	res, err := discoveryClient(t, wkSrv, capped, WithTrace(rec.add)).Discover(ctx, tv)
	if err != nil || len(res) != 2 || res[0].DiscoveredAt.RootURL() != twoSrv.URL {
		t.Fatalf("%+v %v, want the second endpoint's two results", res, err)
	}
	if f := rec.failed(); many.count() != 1 || len(f) != 1 || !strings.Contains(f[0].Reason, "more than 2 results") {
		t.Errorf("failed attempts %+v", f)
	}

	_, wkOne := served(t, jsonHandler(wellKnownDoc(endpoint(manySrv.URL, `["1.0.0"]`, ""))))
	many.n.Store(0)
	_, err = discoveryClient(t, wkOne, capped, WithDiscoveryAttempts(2, time.Millisecond)).Discover(ctx, tv)
	de := asDiscoveryError(t, err)
	if !errors.Is(err, ErrTooManyResults) || !errors.Is(de.Attempts[0].Err, ErrTooManyResults) || many.count() != 1 {
		t.Errorf("one endpoint, attempts exhausted: %v after %d requests", err, many.count())
	}

	// The default cap is 32: 33 results are refused, 32 accepted.
	many.h = jsonHandler(resultsJSON(manySrv.URL, ids(33)...))
	_, err = discoveryClient(t, wkOne, WithDiscoveryAttempts(2, time.Millisecond)).Discover(ctx, tv)
	if !errors.Is(err, ErrTooManyResults) {
		t.Errorf("33 results with the default cap: %v", err)
	}
	many.h = jsonHandler(resultsJSON(manySrv.URL, ids(32)...))
	if res, err := discoveryClient(t, wkOne).Discover(ctx, tv); err != nil || len(res) != 32 {
		t.Errorf("32 results with the default cap: %d, %v", len(res), err)
	}
}

// Case 11b: byte limits on both discovery stages are failed attempts.
func TestDiscoverByteLimits(t *testing.T) {
	ctx := context.Background()
	tv := mustTEI(t, discTEI)
	api, apiSrv := served(t, nil)
	results := resultsJSON(apiSrv.URL, releaseID)
	api.h = jsonHandler(results)
	doc := wellKnownDoc(endpoint(apiSrv.URL, `["1.0.0"]`, ""))
	pad := func(s string, n int) string { return s + strings.Repeat(" ", n-len(s)) }
	chunked := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body[:10]))
			w.(http.Flusher).Flush() // no Content-Length: chunked
			_, _ = w.Write([]byte(body[10:]))
		}
	}

	for _, tc := range []struct {
		name string
		h    func(string) http.HandlerFunc
	}{{"Content-Length", jsonHandler}, {"chunked", chunked}} {
		t.Run("well-known "+tc.name, func(t *testing.T) {
			wk, wkSrv := served(t, tc.h(pad(doc, 257)))
			lim := WithLimits(Limits{WellKnownBytes: 256})
			_, err := discoveryClient(t, wkSrv, lim, WithDiscoveryAttempts(1, time.Millisecond)).Discover(ctx, tv)
			de := asDiscoveryError(t, err)
			if de.Stage != StageWellKnown || !errors.Is(de.Attempts[0].Err, ErrResponseTooLarge) || !errors.Is(err, ErrResponseTooLarge) || wk.count() != 1 {
				t.Errorf("%v after %d requests", err, wk.count())
			}
			// The same document at exactly the limit is accepted.
			wk.h = tc.h(pad(doc, 256))
			if _, err := discoveryClient(t, wkSrv, lim).Discover(ctx, tv); err != nil {
				t.Errorf("at the limit: %v", err)
			}
		})
		t.Run("discovery "+tc.name, func(t *testing.T) {
			api.h = tc.h(pad(results, 513))
			api.n.Store(0)
			_, wkSrv := served(t, jsonHandler(doc))
			lim := WithLimits(Limits{DiscoveryBytes: 512})
			_, err := discoveryClient(t, wkSrv, lim, WithDiscoveryAttempts(2, time.Millisecond)).Discover(ctx, tv)
			de := asDiscoveryError(t, err)
			if de.Stage != StageAPIDiscovery || !errors.Is(de.Attempts[0].Err, ErrResponseTooLarge) || api.count() != 1 {
				t.Errorf("%v after %d requests", err, api.count())
			}
			api.h = tc.h(pad(results, 512))
			if _, err := discoveryClient(t, wkSrv, lim).Discover(ctx, tv); err != nil {
				t.Errorf("at the limit: %v", err)
			}
		})
	}
}

// Design 3.6: no response-body content and no long input reaches an error
// or an attempt's reason.
func TestDiscoveryErrorsCarryNoBody(t *testing.T) {
	ctx := context.Background()
	const marker = "BODY-MARKER-9f2c"
	long := strings.Repeat("A", 5000)
	api, apiSrv := served(t, nil)
	doc := &guarded[string]{}
	_, wkSrv := served(t, func(w http.ResponseWriter, r *http.Request) { jsonHandler(doc.get())(w, r) })
	good := wellKnownDoc(endpoint(apiSrv.URL, `["1.0.0"]`, ""))

	for _, tc := range []struct{ name, doc, answer string }{
		{"well-known url", wellKnownDoc(endpoint("https://"+marker+long+"/x?"+marker, `["1.0.0"]`, "")), ""},
		{"well-known version", wellKnownDoc(endpoint(apiSrv.URL, `["`+marker+long+`"]`, "")), ""},
		{"well-known priority", wellKnownDoc(endpoint(apiSrv.URL, `["1.0.0"]`, `,"priority":"`+marker+`"`)), ""},
		{"well-known syntax", `{"schemaVersion":1,"endpoints":[` + marker, ""},
		{"discovery uuid", good, `[{"productReleaseUuid":"` + marker + long + `","servers":[]}]`},
		{"discovery rootUrl", good, `[{"productReleaseUuid":"` + releaseID.String() + `","servers":[{"rootUrl":"http://` + marker + long + `","versions":["1.0.0"]}]}]`},
		{"discovery message", good, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc.set(tc.doc)
			if tc.answer != "" {
				api.h = jsonHandler(tc.answer)
			} else {
				api.h = status(503, "application/json", `{"error":"`+marker+`","message":"`+marker+`"}`)
			}
			rec := &recorder{}
			c := discoveryClient(t, wkSrv, WithDiscoveryAttempts(2, time.Millisecond), WithTrace(rec.add))
			_, err := c.Discover(ctx, mustTEI(t, discTEI))
			de := asDiscoveryError(t, err)
			texts := []string{err.Error()}
			for _, a := range de.Attempts {
				texts = append(texts, a.Reason, a.URL)
			}
			for _, ev := range rec.events() {
				texts = append(texts, fmt.Sprintf("%+v", ev))
			}
			for _, s := range texts {
				if strings.Contains(s, marker) {
					t.Errorf("text carries body content: %.120q", s)
				}
				if len(s) > 400 {
					t.Errorf("text of %d bytes: %.120q", len(s), s)
				}
			}
		})
	}
}

// Case 27: results, SelectServer and DiscoverPURL.
func TestDiscoverResultsAndSelectServer(t *testing.T) {
	ctx := context.Background()
	api, apiSrv := served(t, nil)
	api.h = jsonHandler(resultsJSON(apiSrv.URL, releaseID, otherReleaseID))
	wk, wkSrv := served(t, jsonHandler(wellKnownDoc(endpoint(apiSrv.URL, `["1.0.0"]`, ""))))
	c := discoveryClient(t, wkSrv)
	res, err := c.Discover(ctx, mustTEI(t, discTEI))
	if err != nil || len(res) != 2 || res[0].ProductReleaseUUID != releaseID || res[1].ProductReleaseUUID != otherReleaseID {
		t.Fatalf("%+v %v, want both results in array order", res, err)
	}
	if len(res[0].Servers) != 1 || res[0].Servers[0].RootUrl != apiSrv.URL || res[0].Servers[0].Versions[0] != "1.0.0" {
		t.Errorf("servers %+v", res[0].Servers)
	}

	p := func(f float32) *float32 { return &f }
	sel := func(servers ...teaapi.ServerInfo) (APIBase, error) {
		return c.SelectServer(DiscoveryResult{ProductReleaseUUID: releaseID, Servers: servers})
	}
	b, err := sel(
		teaapi.ServerInfo{RootUrl: "https://a.example.com", Versions: []string{"0.2.0"}},
		teaapi.ServerInfo{RootUrl: "https://b.example.com", Versions: []string{"1.0.0"}, Priority: p(0.5)},
		teaapi.ServerInfo{RootUrl: "https://c.example.com/tea", Versions: []string{"0.9.0", "1.0.0+x"}},
		teaapi.ServerInfo{RootUrl: "https://d.example.com", Versions: []string{"1.0.0"}},
	)
	if err != nil || b.RootURL() != "https://c.example.com/tea" || b.Version() != "1.0.0+x" {
		t.Errorf("SelectServer: %v %v, want c with 1.0.0+x", b, err)
	}
	// The /discovery base is not reused unless it is listed.
	r := DiscoveryResult{Servers: []teaapi.ServerInfo{{RootUrl: "https://e.example.com", Versions: []string{"1.0.0"}}}, DiscoveredAt: res[0].DiscoveredAt}
	if b, err := c.SelectServer(r); err != nil || b.RootURL() != "https://e.example.com" {
		t.Errorf("SelectServer used %v %v", b, err)
	}
	for _, tc := range []struct {
		name    string
		servers []teaapi.ServerInfo
		is      error
	}{
		{"http root not under an allowance", []teaapi.ServerInfo{{RootUrl: "http://127.0.0.1:8086/tea", Versions: []string{"1.0.0"}}}, ErrInsecureURL},
		{"http root preferred over https", []teaapi.ServerInfo{
			{RootUrl: "https://a.example.com", Versions: []string{"1.0.0"}, Priority: p(0.2)},
			{RootUrl: "http://a.example.com", Versions: []string{"1.0.0"}},
		}, ErrInsecureURL},
		{"dot segment", []teaapi.ServerInfo{{RootUrl: "https://a.example.com/x/..", Versions: []string{"1.0.0"}}}, ErrInsecureURL},
		{"no supported version", []teaapi.ServerInfo{{RootUrl: "https://a.example.com", Versions: []string{"2.0.0"}}}, ErrInvalidArgument},
		{"no servers", nil, ErrInvalidArgument},
		{"rootUrl pattern", []teaapi.ServerInfo{{RootUrl: "https://a.example.com/", Versions: []string{"1.0.0"}}}, ErrInvalidArgument},
		{"version not SemVer", []teaapi.ServerInfo{{RootUrl: "https://a.example.com", Versions: []string{"1.0"}}}, ErrInvalidArgument},
		{"priority out of range", []teaapi.ServerInfo{{RootUrl: "https://a.example.com", Versions: []string{"1.0.0"}, Priority: p(1.5)}}, ErrInvalidArgument},
	} {
		if b, err := sel(tc.servers...); !errors.Is(err, tc.is) || b.RootURL() != "" {
			t.Errorf("%s: %v %v, want %v", tc.name, b, err, tc.is)
		}
	}
	var pe *URLPolicyError
	if _, err := sel(teaapi.ServerInfo{RootUrl: "http://127.0.0.1:8086/tea", Versions: []string{"1.0.0"}}); !errors.As(err, &pe) {
		t.Errorf("http root: %v, want *URLPolicyError", err)
	}

	// DiscoverPURL sends purl=, not tei=, and makes no well-known request.
	purl := "pkg:maven/org.example/lib@1.2.3?type=jar&classifier=a%2Bb#sub/path"
	wkBefore := wk.count()
	api.n.Store(0)
	base, _ := ParseAPIBase(apiSrv.URL, "1.0.0")
	res, err = c.DiscoverPURL(ctx, base, purl)
	if err != nil || len(res) != 2 || res[0].DiscoveredAt != base {
		t.Fatalf("DiscoverPURL: %+v %v", res, err)
	}
	q := api.lastReq().URL
	if q.Path != "/v1.0.0/discovery" || q.RawQuery != "purl="+url.QueryEscape(purl) || q.Query().Get("purl") != purl || q.Query().Has("tei") {
		t.Errorf("DiscoverPURL request %s", q)
	}
	if wk.count() != wkBefore || api.count() != 1 {
		t.Errorf("DiscoverPURL: %d well-known and %d discovery requests", wk.count()-wkBefore, api.count())
	}
	// A TEA 404 is NotResolved there too.
	api.h = status(404, "application/json", `{"error":"OBJECT_UNKNOWN"}`)
	var nr *NotResolvedError
	if _, err := c.DiscoverPURL(ctx, base, purl); !errors.As(err, &nr) || nr.Base != base {
		t.Errorf("DiscoverPURL TEA 404: %v", err)
	}

	// Local refusals: no request is made.
	api.n.Store(0)
	httpBase, _ := ParseAPIBase(strings.Replace(apiSrv.URL, "https://", "http://", 1), "1.0.0")
	for name, f := range map[string]func() error{
		"not pkg:":      func() error { _, err := c.DiscoverPURL(ctx, base, "maven/org.example/lib"); return err },
		"empty":         func() error { _, err := c.DiscoverPURL(ctx, base, ""); return err },
		"too long":      func() error { _, err := c.DiscoverPURL(ctx, base, "pkg:"+strings.Repeat("a", 2045)); return err },
		"control":       func() error { _, err := c.DiscoverPURL(ctx, base, "pkg:a/b\n"); return err },
		"invalid UTF-8": func() error { _, err := c.DiscoverPURL(ctx, base, "pkg:a/\xff"); return err },
		"zero base":     func() error { _, err := c.DiscoverPURL(ctx, APIBase{}, purl); return err },
		"zero TEI":      func() error { _, err := c.Discover(ctx, tei.TEI{}); return err },
	} {
		if err := f(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v, want ErrInvalidArgument", name, err)
		} else if strings.Contains(err.Error(), "aaaa") {
			t.Errorf("%s: the error repeats the input: %.100q", name, err)
		}
	}
	if _, err := c.DiscoverPURL(ctx, httpBase, purl); !errors.Is(err, ErrInsecureURL) {
		t.Errorf("http base: %v, want ErrInsecureURL", err)
	}
	if api.count() != 0 {
		t.Errorf("refused calls made %d requests", api.count())
	}
	if _, err := c.DiscoverPURL(ctx, base, "pkg:"+strings.Repeat("a", 2044)); errors.Is(err, ErrInvalidArgument) {
		t.Errorf("2048-byte PURL refused: %v", err)
	}
}

// Case 27b: an origin allowance covers servers[] roots under it only.
func TestSelectServerUnderAllowance(t *testing.T) {
	c, err := New(WithInsecureHTTPBase("http://127.0.0.1:8086"))
	if err != nil {
		t.Fatal(err)
	}
	sel := func(root string) (APIBase, error) {
		return c.SelectServer(DiscoveryResult{Servers: []teaapi.ServerInfo{{RootUrl: root, Versions: []string{"1.0.0"}}}})
	}
	if b, err := sel("http://127.0.0.1:8086/tea"); err != nil || b.String() != "http://127.0.0.1:8086/tea/v1.0.0" {
		t.Errorf("under the origin: %v %v", b, err)
	}
	for _, root := range []string{"http://127.0.0.1:8087/tea", "http://localhost:8086/tea", "http://127.0.0.2:8086"} {
		if _, err := sel(root); !errors.Is(err, ErrInsecureURL) {
			t.Errorf("%s: %v, want ErrInsecureURL", root, err)
		}
	}
}

// Case 13b: no credential reaches the well-known location, /discovery on a
// base other than the credential root, or a servers[] root on another host;
// the root itself gets it.
func TestDiscoveryCredentials(t *testing.T) {
	ctx := context.Background()
	const token = "bearer-for-root-only"
	port := func(s *httptest.Server) string { return portOf(t, s) }
	rootH := newCounter(nil)
	rootSrv := startHTTP(t, rootH)
	root := "http://localhost:" + port(rootSrv) + "/tea"
	eH := newCounter(nil)
	eSrv := startHTTP(t, eH)
	eRoot := "http://sub.localhost:" + port(eSrv) + "/tea"
	dH := newCounter(nil)
	dSrv := startHTTP(t, dH)
	dEndpoint := "http://localhost:" + port(dSrv) + "/api"
	release := `{"uuid":"` + releaseID.String() + `","version":"1.0.0","createdDate":"2026-01-15T00:00:00Z","components":[]}`
	rootH.h = func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/discovery") {
			jsonHandler(resultsJSON(root, releaseID))(w, r)
			return
		}
		jsonHandler(release)(w, r)
	}
	eH.h = jsonHandler(release)
	dH.h = jsonHandler(resultsJSON(eRoot, releaseID))
	doc := &guarded[string]{v: wellKnownDoc(endpoint(dEndpoint, `["1.0.0"]`, ""))}
	wkH := newCounter(func(w http.ResponseWriter, r *http.Request) { jsonHandler(doc.get())(w, r) })
	wkSrv := startHTTP(t, wkH)
	wkLoc := "http://127.0.0.1:" + port(wkSrv)

	c, err := New(
		WithHTTPClient(localhostClient()),
		WithInsecureHTTPBase("http://localhost:"+port(rootSrv)),
		WithInsecureHTTPBase("http://sub.localhost:"+port(eSrv)),
		WithInsecureHTTPBase("http://localhost:"+port(dSrv)),
		WithInsecureHTTPBase(wkLoc),
		WithWellKnownLocation("example.com", wkLoc),
		WithBearerToken(root, token),
	)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Discover(ctx, mustTEI(t, discTEI))
	if err != nil {
		t.Fatal(err)
	}
	base, err := c.SelectServer(res[0])
	if err != nil || base.RootURL() != eRoot {
		t.Fatalf("SelectServer: %v %v", base, err)
	}
	a, err := c.API(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetProductRelease(ctx, releaseID); err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]*counter{"well-known": wkH, "discovery on another base": dH, "servers[] root on another host": eH} {
		if h.count() != 1 {
			t.Errorf("%s: %d requests, want 1", name, h.count())
		}
		if got := h.lastReq().Header.Get("Authorization"); got != "" {
			t.Errorf("%s received Authorization %q", name, got)
		}
	}

	// Positive controls: /discovery at the root and an API call under it
	// carry the bearer.
	doc.set(wellKnownDoc(endpoint(root, `["1.0.0"]`, "")))
	res, err = c.Discover(ctx, mustTEI(t, discTEI))
	if err != nil {
		t.Fatal(err)
	}
	if got := rootH.lastReq().Header.Get("Authorization"); got != "Bearer "+token || !strings.HasSuffix(rootH.lastReq().URL.Path, "/discovery") {
		t.Errorf("discovery at the root: Authorization %q", got)
	}
	base, _ = c.SelectServer(res[0])
	a, _ = c.API(base)
	if _, err := a.GetProductRelease(ctx, releaseID); err != nil {
		t.Fatal(err)
	}
	if got := rootH.lastReq().Header.Get("Authorization"); got != "Bearer "+token {
		t.Errorf("API call at the root: Authorization %q", got)
	}
	if got := wkH.lastReq().Header.Get("Authorization"); got != "" || wkH.count() != 2 {
		t.Errorf("well-known (second run) received Authorization %q", got)
	}
}

// Case 39b: trace events of a discovery with one failed attempt.
func TestDiscoveryTrace(t *testing.T) {
	good, goodSrv := served(t, nil)
	good.h = jsonHandler(resultsJSON(goodSrv.URL, releaseID))
	_, badSrv := served(t, status(503, "", ""))
	_, wkSrv := served(t, jsonHandler(wellKnownDoc(endpoint(badSrv.URL+"/tea", `["1.0.0"]`, ""), endpoint(goodSrv.URL, `["1.0.0"]`, ""))))
	rec := &recorder{}
	c := discoveryClient(t, wkSrv, WithDiscoveryAttempts(4, 5*time.Millisecond), WithTrace(rec.add))
	tv := mustTEI(t, discTEI)
	if _, err := c.Discover(context.Background(), tv); err != nil {
		t.Fatal(err)
	}
	wkURL := wkSrv.URL + "/.well-known/tea"
	d1 := badSrv.URL + "/tea/v1.0.0/discovery"
	d2 := goodSrv.URL + "/v1.0.0/discovery"
	want := []TraceEvent{
		{Kind: TraceRequest, Stage: StageWellKnown, Method: "GET", URL: wkURL},
		{Kind: TraceResponse, Stage: StageWellKnown, Method: "GET", URL: wkURL, Status: 200},
		{Kind: TraceRequest, Stage: StageAPIDiscovery, Method: "GET", URL: d1},
		{Kind: TraceResponse, Stage: StageAPIDiscovery, Method: "GET", URL: d1, Status: 503},
		{Kind: TraceAttemptFailed, Stage: StageAPIDiscovery, Method: "GET", URL: d1, Reason: "HTTP 503"},
		{Kind: TraceBackoff, Stage: StageAPIDiscovery, Wait: 5 * time.Millisecond},
		{Kind: TraceRequest, Stage: StageAPIDiscovery, Method: "GET", URL: d2},
		{Kind: TraceResponse, Stage: StageAPIDiscovery, Method: "GET", URL: d2, Status: 200},
	}
	got := rec.events()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("events:\n%v\nwant\n%v", got, want)
	}
	for _, ev := range got {
		s := fmt.Sprintf("%+v", ev)
		for _, bad := range []string{"?", tv.String(), tv.ID(), url.QueryEscape(tv.String()), "tei="} {
			if strings.Contains(s, bad) {
				t.Errorf("event %s contains %q", s, bad)
			}
		}
	}
}
