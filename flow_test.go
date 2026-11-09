package tea

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/oolong-project/tea-client-go/tei"
)

// Made-up identifiers of the flow fixture.
var (
	relA       = uuid.MustParse("5a1e0c3d-1b2a-4c5d-8e6f-7a8b9c0d1e2f")
	relB       = uuid.MustParse("6b2f1d4e-2c3b-4d6e-9f7a-8b9c0d1e2f3a")
	compPinned = uuid.MustParse("7c3a2e5f-3d4c-4e7f-8a8b-9c0d1e2f3a4b")
	crPinned   = uuid.MustParse("8d4b3f6a-4e5d-4f8a-9b9c-0d1e2f3a4b5c")
	compFree   = uuid.MustParse("9e5c4a7b-5f6e-4a9b-8cad-1e2f3a4b5c6d")
	crNewest   = uuid.MustParse("af6d5b8c-6a7f-4bac-9dbe-2f3a4b5c6d7e")
	compThird  = uuid.MustParse("b07e6c9d-7b8a-4cbd-8ecf-3a4b5c6d7e8f")
)

const collectionJSON = `{"uuid":"%s","version":2,"belongsTo":"%s","createdDate":"2026-01-15T00:00:00Z","updateReason":{"type":"INITIAL_RELEASE"},"artifacts":[]}`

func productReleaseJSON(id uuid.UUID, version string, comps string) string {
	return fmt.Sprintf(`{"uuid":"%s","product":"%s","productName":"Sample Product","version":"%s","createdDate":"2026-01-15T00:00:00Z","components":[%s],"latestCollection":`+collectionJSON+`}`,
		id, productID, version, comps, id, "PRODUCT_RELEASE")
}

func componentReleaseJSON(id, comp uuid.UUID) string {
	return fmt.Sprintf(`{"uuid":"%s","component":"%s","version":"2.0.0","createdDate":"2026-01-15T00:00:00Z","latestCollection":`+collectionJSON+`}`,
		id, comp, id, "COMPONENT_RELEASE")
}

const cleJSON = `{"events":[]}`

// flowServer is a TEA server for the flow: a well-known document listing
// <srv>/tea, /discovery, product and component releases. Per-path overrides
// set a status (with a TEA error body when code is set).
type flowServer struct {
	*counter
	url       string
	mu        sync.Mutex
	results   string // the /discovery answer
	releases  map[uuid.UUID]string
	overrides map[string][2]string // path suffix -> status, TEA code
}

func newFlowServer(t *testing.T) *flowServer {
	fs := &flowServer{releases: map[uuid.UUID]string{}, overrides: map[string][2]string{}}
	fs.counter = newCounter(func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		p := strings.TrimPrefix(r.URL.Path, "/tea/v1.0.0")
		if o, ok := fs.overrides[p]; ok {
			var status int
			_, _ = fmt.Sscan(o[0], &status)
			if o[1] != "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = fmt.Fprintf(w, `{"error":%q}`, o[1])
				return
			}
			w.WriteHeader(status)
			return
		}
		switch {
		case r.URL.Path == "/.well-known/tea":
			jsonHandler(`{"schemaVersion":1,"endpoints":[{"url":"`+fs.url+`/tea","versions":["1.0.0"]}]}`)(w, r)
		case p == "/discovery":
			jsonHandler(fs.results)(w, r)
		case strings.HasPrefix(p, "/productRelease/") && strings.HasSuffix(p, "/cle"),
			strings.HasPrefix(p, "/componentRelease/") && strings.HasSuffix(p, "/cle"):
			jsonHandler(cleJSON)(w, r)
		case strings.HasPrefix(p, "/productRelease/"):
			id, err := uuid.Parse(strings.TrimPrefix(p, "/productRelease/"))
			if body, ok := fs.releases[id]; err == nil && ok {
				jsonHandler(body)(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"OBJECT_UNKNOWN"}`))
		case p == "/component/"+compFree.String():
			jsonHandler(`{"uuid":"`+compFree.String()+`","name":"Free Part","identifiers":[]}`)(w, r)
		case p == "/component/"+compFree.String()+"/releases":
			jsonHandler(`{"timestamp":"2026-01-15T00:00:00Z","pageStartIndex":0,"pageSize":1,"totalResults":2,"hasNext":true,"nextPageToken":"t",`+
				`"results":[{"uuid":"`+crNewest.String()+`","component":"`+compFree.String()+`","version":"2.0.0","createdDate":"2026-01-15T00:00:00Z"}]}`)(w, r)
		case p == "/componentRelease/"+crPinned.String():
			jsonHandler(componentReleaseJSON(crPinned, compPinned))(w, r)
		case p == "/componentRelease/"+crNewest.String():
			jsonHandler(componentReleaseJSON(crNewest, compFree))(w, r)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"OBJECT_UNKNOWN"}`))
		}
	})
	srv := startHTTP(t, fs)
	fs.url = srv.URL
	return fs
}

func (fs *flowServer) set(f func()) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f()
}

// result is a /discovery result for release id served at this server.
func (fs *flowServer) result(id uuid.UUID) string {
	return `{"productReleaseUuid":"` + id.String() + `","servers":[{"rootUrl":"` + fs.url + `/tea","versions":["1.0.0"]}]}`
}

// paths returns the request paths seen, under the API base.
func (fs *flowServer) paths() []string {
	var ps []string
	for _, r := range fs.requests() {
		p := strings.TrimPrefix(r.URL.Path, "/tea/v1.0.0")
		if r.URL.RawQuery != "" && !strings.HasSuffix(p, "/discovery") {
			p += "?" + r.URL.RawQuery
		}
		ps = append(ps, p)
	}
	return ps
}

func (fs *flowServer) count(path string) int {
	n := 0
	for _, p := range fs.paths() {
		if p == path {
			n++
		}
	}
	return n
}

func (fs *flowServer) client(t *testing.T, opts ...Option) *Client {
	t.Helper()
	c, err := New(append([]Option{WithInsecureHTTPBase(fs.url), WithWellKnownLocation("example.com", fs.url)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var flowTEI = func() tei.TEI {
	v, err := tei.Parse("tei://example.com/uuid/" + relA.String())
	if err != nil {
		panic(err)
	}
	return v
}()

const twoComponents = `{"uuid":"7c3a2e5f-3d4c-4e7f-8a8b-9c0d1e2f3a4b","release":"8d4b3f6a-4e5d-4f8a-9b9c-0d1e2f3a4b5c"},{"uuid":"9e5c4a7b-5f6e-4a9b-8cad-1e2f3a4b5c6d"}`

// Case 35: one result, the release, its CLE and two components.
func TestFlowOneResult(t *testing.T) {
	fs := newFlowServer(t)
	fs.set(func() {
		fs.results = "[" + fs.result(relA) + "]"
		fs.releases[relA] = productReleaseJSON(relA, "1.0.0", twoComponents)
	})
	res, err := fs.client(t).FullFlow(context.Background(), flowTEI, FlowOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Release.Uuid != relA || res.Release.Version != "1.0.0" || res.ReleaseCLE == nil || res.API.Base().RootURL() != fs.url+"/tea" {
		t.Errorf("release %+v, CLE %v", res.Release, res.ReleaseCLE)
	}
	if len(res.Components) != 2 {
		t.Fatalf("%d components", len(res.Components))
	}
	p, u := res.Components[0], res.Components[1]
	if !p.Pinned || p.Component != nil || p.Release == nil || p.Release.Uuid != crPinned || p.CLE == nil || p.Err != nil {
		t.Errorf("pinned component %+v", p)
	}
	if u.Pinned || u.Component == nil || u.Component.Uuid != compFree || u.Release == nil || u.Release.Uuid != crNewest || u.CLE == nil || u.Err != nil {
		t.Errorf("unpinned component %+v", u)
	}
	want := "/component/" + compFree.String() + "/releases?pageSize=1&sortField=createdDate&sortOrder=desc"
	found := false
	for _, path := range fs.paths() {
		if strings.HasPrefix(path, "/component/"+compFree.String()+"/releases") {
			found = path == want
			if !found {
				t.Errorf("listing %s, want %s", path, want)
			}
		}
	}
	if !found {
		t.Errorf("no listing of the unpinned component's releases in %q", fs.paths())
	}
	if fs.count("/productRelease/"+relA.String()) != 1 {
		t.Errorf("product release read %d times", fs.count("/productRelease/"+relA.String()))
	}

	// SkipCLE: no CLE request at all.
	before := len(fs.paths())
	res, err = fs.client(t).FullFlow(context.Background(), flowTEI, FlowOptions{SkipCLE: true})
	if err != nil || res.ReleaseCLE != nil || res.Components[0].CLE != nil {
		t.Fatalf("SkipCLE: %v", err)
	}
	for _, path := range fs.paths()[before:] {
		if strings.HasSuffix(path, "/cle") {
			t.Errorf("SkipCLE requested %s", path)
		}
	}
}

// Case 36: CLE NOT_IMPLEMENTED is no CLE; one component's failure is its
// own; the product release's failure fails the flow.
func TestFlowFailures(t *testing.T) {
	ctx := context.Background()
	fs := newFlowServer(t)
	fs.set(func() {
		fs.results = "[" + fs.result(relA) + "]"
		fs.releases[relA] = productReleaseJSON(relA, "1.0.0", twoComponents)
		fs.overrides["/productRelease/"+relA.String()+"/cle"] = [2]string{"404", "NOT_IMPLEMENTED"}
		fs.overrides["/componentRelease/"+crPinned.String()+"/cle"] = [2]string{"404", "OBJECT_UNKNOWN"}
		fs.overrides["/componentRelease/"+crNewest.String()] = [2]string{"500", ""}
	})
	c := fs.client(t)
	res, err := c.FullFlow(ctx, flowTEI, FlowOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ReleaseCLE != nil {
		t.Errorf("CLE NOT_IMPLEMENTED: %v, want nil", res.ReleaseCLE)
	}
	if p := res.Components[0]; p.Err != nil || p.Release == nil || p.CLE != nil {
		t.Errorf("pinned component with CLE OBJECT_UNKNOWN: %+v", p)
	}
	if u := res.Components[1]; !errors.Is(u.Err, ErrServer) || u.Release != nil || u.Component == nil {
		t.Errorf("unpinned component with a 500 release: %+v", u)
	}

	// Another CLE error on a component is recorded; on the release it fails
	// the flow.
	fs.set(func() {
		delete(fs.overrides, "/componentRelease/"+crNewest.String())
		fs.overrides["/componentRelease/"+crNewest.String()+"/cle"] = [2]string{"500", ""}
	})
	res, err = c.FullFlow(ctx, flowTEI, FlowOptions{})
	if err != nil || !errors.Is(res.Components[1].Err, ErrServer) || res.Components[1].Release == nil {
		t.Errorf("component CLE 500: %v %+v", err, res.Components[1])
	}
	fs.set(func() { fs.overrides["/productRelease/"+relA.String()+"/cle"] = [2]string{"500", ""} })
	if _, err := c.FullFlow(ctx, flowTEI, FlowOptions{}); !errors.Is(err, ErrServer) {
		t.Errorf("release CLE 500: %v, want ErrServer", err)
	}
	fs.set(func() { delete(fs.overrides, "/productRelease/"+relA.String()+"/cle") })

	// The product release 404: the flow fails.
	fs.set(func() { fs.overrides["/productRelease/"+relA.String()] = [2]string{"404", "OBJECT_UNKNOWN"} })
	if _, err := c.FullFlow(ctx, flowTEI, FlowOptions{}); !errors.Is(err, ErrObjectUnknown) {
		t.Errorf("product release 404: %v, want ErrObjectUnknown", err)
	}
}

// A component with no release, and the caller's context ending the walk.
func TestFlowFromRelease(t *testing.T) {
	ctx := context.Background()
	fs := newFlowServer(t)
	noRelease := newCounter(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tea/v1.0.0/component/" + compThird.String() + "/releases":
			jsonHandler(`{"timestamp":"2026-01-15T00:00:00Z","pageStartIndex":0,"pageSize":1,"totalResults":0,"hasNext":false,"results":[]}`)(w, r)
		case "/tea/v1.0.0/component/" + compThird.String():
			jsonHandler(`{"uuid":"`+compThird.String()+`","name":"Third","identifiers":[]}`)(w, r)
		default:
			fs.ServeHTTP(w, r)
		}
	})
	srv := startHTTP(t, noRelease)
	fs.set(func() {
		fs.releases[relB] = productReleaseJSON(relB, "2.0.0", `{"uuid":"`+compThird.String()+`"},`+twoComponents)
	})
	a := newTestAPI(t, srv.URL, "/tea")
	res, err := a.c.FlowFromRelease(ctx, a, relB, FlowOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if third := res.Components[0]; !errors.Is(third.Err, ErrObjectUnknown) || third.Component == nil || third.Release != nil {
		t.Errorf("component with no release: %+v", third)
	}
	if res.Components[1].Err != nil || res.Components[2].Err != nil {
		t.Errorf("the other components: %v, %v", res.Components[1].Err, res.Components[2].Err)
	}
	if _, err := a.c.FlowFromRelease(ctx, nil, relB, FlowOptions{}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("nil API: %v", err)
	}

	// The caller's context ending during the walk ends the flow with its
	// error: it is cancelled when the first component's answer arrives, and
	// no further component is tried.
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	before := noRelease.count()
	cancelling := newTestAPI(t, srv.URL, "/tea", WithTrace(func(ev TraceEvent) {
		if ev.Kind == TraceResponse && strings.HasSuffix(ev.URL, "/component/"+compThird.String()) {
			cancel()
		}
	}))
	res, err = cancelling.c.FlowFromRelease(cctx, cancelling, relB, FlowOptions{SkipCLE: true})
	if !errors.Is(err, context.Canceled) || res != nil || noRelease.count() != before+2 {
		t.Errorf("cancelled walk: %v after %d requests, want context.Canceled after the release and the first component", err, noRelease.count()-before)
	}
}

// Case 37: several results.
func TestFlowSeveralResults(t *testing.T) {
	ctx := context.Background()
	fs := newFlowServer(t)
	// The second result is served by a second server, so the test sees
	// which server the flow continues with.
	fs2 := newFlowServer(t)
	fs.set(func() {
		fs.results = "[" + fs.result(relA) + "," + fs2.result(relB) + "]"
		fs.releases[relA] = productReleaseJSON(relA, "1.0.0", "")
	})
	fs2.set(func() { fs2.releases[relB] = productReleaseJSON(relB, "2.0.0", twoComponents) })
	c := fs.client(t, WithInsecureHTTPBase(fs2.url))

	_, err := c.FullFlow(ctx, flowTEI, FlowOptions{})
	var ae *AmbiguousError
	if !errors.As(err, &ae) || len(ae.Results) != 2 || ae.Results[0].ProductReleaseUUID != relA || ae.Results[1].ProductReleaseUUID != relB {
		t.Fatalf("Select nil: %v, want *AmbiguousError with both results", err)
	}
	if n := fs.count("/productRelease/"+relA.String()) + fs2.count("/productRelease/"+relB.String()); n != 0 {
		t.Errorf("Select nil: %d product-release requests, want 0", n)
	}

	var seen []Candidate
	res, err := c.FullFlow(ctx, flowTEI, FlowOptions{Select: func(_ context.Context, cands []Candidate) (int, error) {
		seen = cands
		return 1, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0].Release.Uuid != relA || seen[1].Release.Uuid != relB || seen[1].API.Base().RootURL() != fs2.url+"/tea" {
		t.Errorf("candidates %+v", seen)
	}
	if res.API.Base().RootURL() != fs2.url+"/tea" || res.Release.Uuid != relB || len(res.Components) != 2 || res.Components[0].Err != nil {
		t.Errorf("Select 1: continued with %s, release %v", res.API.Base(), res.Release.Uuid)
	}
	// The chosen candidate's release is not read again; its components
	// come from its server.
	if fs2.count("/productRelease/"+relB.String()) != 1 || fs2.count("/componentRelease/"+crPinned.String()) != 1 || fs.count("/componentRelease/"+crPinned.String()) != 0 {
		t.Errorf("requests: second server %q, first server %q", fs2.paths(), fs.paths())
	}

	// A Select error is returned.
	selErr := errors.New("the person declined")
	if _, err := c.FullFlow(ctx, flowTEI, FlowOptions{Select: func(context.Context, []Candidate) (int, error) { return 0, selErr }}); !errors.Is(err, selErr) {
		t.Errorf("Select error: %v", err)
	}
}

// Case 38: more component refs than Limits.FlowComponents.
func TestFlowComponentLimit(t *testing.T) {
	fs := newFlowServer(t)
	three := twoComponents + `,{"uuid":"` + compThird.String() + `"}`
	fs.set(func() {
		fs.results = "[" + fs.result(relA) + "]"
		fs.releases[relA] = productReleaseJSON(relA, "1.0.0", three)
	})
	before := len(fs.paths())
	_, err := fs.client(t, WithLimits(Limits{FlowComponents: 2})).FullFlow(context.Background(), flowTEI, FlowOptions{SkipCLE: true})
	if !errors.Is(err, ErrTooManyComponents) {
		t.Fatalf("3 refs with FlowComponents 2: %v, want ErrTooManyComponents", err)
	}
	for _, p := range fs.paths()[before:] {
		if strings.HasPrefix(p, "/component") {
			t.Errorf("component request %s made before the refusal", p)
		}
	}
	// At the limit: all three walked.
	res, err := fs.client(t, WithLimits(Limits{FlowComponents: 3})).FullFlow(context.Background(), flowTEI, FlowOptions{SkipCLE: true})
	if err != nil || len(res.Components) != 3 {
		t.Errorf("3 refs with FlowComponents 3: %v", err)
	}
}

// Case 38b: the Candidates cap and Select's index.
func TestCandidatesCap(t *testing.T) {
	ctx := context.Background()
	fs := newFlowServer(t)
	relC := uuid.MustParse("c18f7dae-8c9b-4dce-9fd0-4b5c6d7e8f90")
	fs.set(func() {
		for _, id := range []uuid.UUID{relA, relB, relC} {
			fs.releases[id] = productReleaseJSON(id, "1.0.0", "")
		}
	})
	c := fs.client(t, WithLimits(Limits{DiscoveryResults: 2}))
	results := func(ids ...uuid.UUID) []DiscoveryResult {
		var rs []DiscoveryResult
		for _, id := range ids {
			ps, err := c.decodeDiscovery([]byte("[" + fs.result(id) + "]"))
			if err != nil {
				t.Fatal(err)
			}
			rs = append(rs, ps...)
		}
		return rs
	}

	if _, err := c.Candidates(ctx, results(relA, relB, relC)); !errors.Is(err, ErrTooManyResults) || fs.counter.count() != 0 {
		t.Fatalf("3 results with DiscoveryResults 2: %v after %d requests", err, fs.counter.count())
	}
	cands, err := c.Candidates(ctx, results(relA, relB))
	if err != nil || len(cands) != 2 || fs.counter.count() != 2 ||
		fs.count("/productRelease/"+relA.String()) != 1 || fs.count("/productRelease/"+relB.String()) != 1 {
		t.Fatalf("2 results: %v, %d requests %q", err, fs.counter.count(), fs.paths())
	}
	// The default cap is 32.
	many := make([]DiscoveryResult, 33)
	dc := fs.client(t)
	if _, err := dc.Candidates(ctx, many); !errors.Is(err, ErrTooManyResults) || fs.counter.count() != 2 {
		t.Errorf("33 results with the default cap: %v", err)
	}
	// A failing candidate is reported with its index.
	fs.set(func() { fs.overrides["/productRelease/"+relB.String()] = [2]string{"500", ""} })
	if _, err := c.Candidates(ctx, results(relA, relB)); !errors.Is(err, ErrServer) || !strings.Contains(err.Error(), "result 1") {
		t.Errorf("failing candidate: %v", err)
	}
	fs.set(func() { delete(fs.overrides, "/productRelease/"+relB.String()) })

	// A Select index out of range.
	fs.set(func() { fs.results = "[" + fs.result(relA) + "," + fs.result(relB) + "]" })
	for _, i := range []int{5, 2, -1} {
		_, err := c.FullFlow(ctx, flowTEI, FlowOptions{Select: func(context.Context, []Candidate) (int, error) { return i, nil }})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("Select returning %d for 2 candidates: %v, want ErrInvalidArgument", i, err)
		}
	}
}
