//go:build integration

package tea_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	tea "github.com/oolong-project/tea-client-go"
	"github.com/oolong-project/tea-client-go/internal/oolongtest"
	"github.com/oolong-project/tea-client-go/teaapi"
)

// Fixture ids and values: oolong docs/tea-upgrade/fixture-reference.md.
var (
	alphaProduct     = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	release100       = uuid.MustParse("22222222-2222-4222-8222-222222222222")
	release110       = uuid.MustParse("22222222-2222-4222-8222-222222222223")
	componentRelease = uuid.MustParse("44444444-4444-4444-8444-444444444444")
	unknownID        = uuid.MustParse("99999999-9999-4999-8999-999999999999")
)

const fixtureTEI = "tei://localhost/uuid/22222222-2222-4222-8222-222222222222"

// integrationAPI starts (or finds) the oolong server and returns the API at
// its root, built with the options the design names for the suite.
func integrationAPI(t *testing.T, srv *oolongtest.Server, extra ...tea.Option) *tea.API {
	t.Helper()
	opts := append([]tea.Option{
		tea.WithInsecureHTTPBase(srv.URL),
		tea.WithWellKnownLocation("localhost", srv.URL),
	}, extra...)
	c, err := tea.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	base, err := tea.ParseAPIBase(srv.URL, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.API(base)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

// Case 5: pagination and queries.
func TestIntegrationPagination(t *testing.T) {
	a := integrationAPI(t, oolongtest.Start(t))
	ctx := ctx(t)

	var names []string
	for p, err := range a.AllProducts(ctx, tea.ProductQuery{Page: tea.Page{PageSize: 2}}) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, p.Name)
	}
	want := []string{"Alpha Fixture", "Beta Fixture", "Delta Fixture", "Epsilon Fixture", "Gamma Fixture"}
	if len(names) != len(want) {
		t.Fatalf("products %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("products %v, want %v", names, want)
		}
	}

	var versions []string
	for r, err := range a.AllProductReleasesOf(ctx, alphaProduct, tea.ReleasePage{
		Page: tea.Page{PageSize: 2, SortOrder: tea.SortAsc}, SortField: tea.ReleaseSortCreatedDate,
	}) {
		if err != nil {
			t.Fatal(err)
		}
		versions = append(versions, r.Version)
	}
	if len(versions) != 3 || versions[0] != "0.9.0" || versions[1] != "1.0.0" || versions[2] != "1.1.0" {
		t.Fatalf("Alpha releases by createdDate: %v", versions)
	}

	page, err := a.QueryProductReleases(ctx, tea.ReleaseQuery{IDType: teaapi.TEI, IDValue: fixtureTEI})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Results) != 1 || page.Results[0].Uuid != release100 || page.HasNext {
		t.Fatalf("query by TEI: %+v", page)
	}

	first, err := a.QueryProducts(ctx, tea.ProductQuery{Page: tea.Page{PageSize: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if !first.HasNext || first.NextPageToken == nil {
		t.Fatalf("first page has no next token: %+v", first)
	}
	tok := []byte(*first.NextPageToken)
	i := len(tok) / 2
	if tok[i] == 'A' {
		tok[i] = 'B'
	} else {
		tok[i] = 'A'
	}
	_, err = a.QueryProducts(ctx, tea.ProductQuery{Page: tea.Page{PageSize: 2, PageToken: string(tok)}})
	if !errors.Is(err, tea.ErrInvalidPageToken) {
		t.Fatalf("modified page token: %v, want ErrInvalidPageToken", err)
	}
}

// Case 6: collections, CLE, token, unknown ids.
func TestIntegrationCollections(t *testing.T) {
	a := integrationAPI(t, oolongtest.Start(t))
	ctx := ctx(t)

	for _, v := range []int{1, 2} {
		c, err := a.GetProductReleaseCollection(ctx, release100, v)
		if err != nil || c.Version != v {
			t.Errorf("product release collection %d: %+v %v", v, c, err)
		}
		c, err = a.GetComponentReleaseCollection(ctx, componentRelease, v)
		if err != nil || c.Version != v {
			t.Errorf("component release collection %d: %+v %v", v, c, err)
		}
	}
	latest, err := a.GetLatestProductReleaseCollection(ctx, release110)
	if err != nil || latest.Version != 1 || len(latest.Artifacts) != 0 {
		t.Errorf("synthetic latest collection: %+v %v", latest, err)
	}
	if _, err := a.GetProductRelease(ctx, unknownID); !errors.Is(err, tea.ErrObjectUnknown) {
		t.Errorf("unknown product release: %v", err)
	}
	if _, err := a.GetProduct(ctx, unknownID); !errors.Is(err, tea.ErrObjectUnknown) {
		t.Errorf("unknown product: %v", err)
	}
	for name, f := range map[string]func() error{
		"product":         func() error { _, err := a.GetProductCLE(ctx, alphaProduct); return err },
		"product release": func() error { _, err := a.GetProductReleaseCLE(ctx, release100); return err },
		"component": func() error {
			_, err := a.GetComponentCLE(ctx, uuid.MustParse("33333333-3333-4333-8333-333333333333"))
			return err
		},
		"component release": func() error { _, err := a.GetComponentReleaseCLE(ctx, componentRelease); return err },
	} {
		if err := f(); !errors.Is(err, tea.ErrNotImplemented) {
			t.Errorf("%s CLE: %v, want ErrNotImplemented", name, err)
		}
	}
	if _, err := a.RequestToken(ctx, "fixture-id", "fixture-secret"); !errors.Is(err, tea.ErrNotImplemented) {
		t.Errorf("RequestToken: %v, want ErrNotImplemented", err)
	}
}

// headerSpy records the Authorization header of every request it forwards;
// it sits below the client's auth transport.
type headerSpy struct {
	mu   sync.Mutex
	seen []string
}

func (s *headerSpy) RoundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.seen = append(s.seen, r.Header.Get("Authorization"))
	s.mu.Unlock()
	return http.DefaultTransport.RoundTrip(r)
}

// Case 9: a bearer configured for the server is sent, accepted and ignored.
func TestIntegrationBearerIgnored(t *testing.T) {
	srv := oolongtest.Start(t)
	spy := &headerSpy{}
	a := integrationAPI(t, srv, tea.WithBearerToken(srv.URL, "fixture-bearer-token"),
		tea.WithHTTPClient(&http.Client{Transport: spy}))
	r, err := a.GetProductRelease(ctx(t), release100)
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "1.0.0" {
		t.Errorf("release version %q", r.Version)
	}
	spy.mu.Lock()
	defer spy.mu.Unlock()
	if len(spy.seen) == 0 || spy.seen[len(spy.seen)-1] != "Bearer fixture-bearer-token" {
		t.Errorf("the bearer was not sent: %q", spy.seen)
	}
}
