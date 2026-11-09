package tea

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/oolong-project/tea-client-go/teaapi"
)

// Case 19: arguments refused before any request.
func TestLocalRefusals(t *testing.T) {
	h := newCounter(nil)
	srv := startHTTP(t, h)
	a := newTestAPI(t, srv.URL, "")
	ctx := context.Background()
	bad := map[string]func() error{
		"pageSize 101": func() error { return ignore(a.QueryProducts(ctx, ProductQuery{Page: Page{PageSize: 101}})) },
		"pageSize -1":  func() error { return ignore(a.QueryComponents(ctx, ComponentQuery{Page: Page{PageSize: -1}})) },
		"release pageSize 101": func() error {
			return ignore(a.ListProductReleases(ctx, productID, ReleasePage{Page: Page{PageSize: 101}}))
		},
		"collection page -1": func() error {
			return ignore(a.ListComponentReleaseCollections(ctx, compRelID, CollectionPage{Page: Page{PageSize: -1}}))
		},
		"product sort field": func() error { return ignore(a.QueryProducts(ctx, ProductQuery{SortField: "createdDate"})) },
		"release sort field": func() error { return ignore(a.QueryProductReleases(ctx, ReleaseQuery{SortField: "name"})) },
		"list sort field":    func() error { return ignore(a.ListComponentReleases(ctx, compID, ReleasePage{SortField: "Version"})) },
		"collection sort field": func() error {
			return ignore(a.ListProductReleaseCollections(ctx, releaseID, CollectionPage{SortField: "createdDate"}))
		},
		"sort order":            func() error { return ignore(a.QueryProducts(ctx, ProductQuery{Page: Page{SortOrder: "DESC"}})) },
		"id type":               func() error { return ignore(a.QueryProducts(ctx, ProductQuery{IDType: "SWID", IDValue: "x"})) },
		"idValue without type":  func() error { return ignore(a.QueryProductReleases(ctx, ReleaseQuery{IDValue: "x"})) },
		"comp idValue no type":  func() error { return ignore(a.QueryComponentReleases(ctx, ReleaseQuery{IDValue: "x"})) },
		"components idValue":    func() error { return ignore(a.QueryComponents(ctx, ComponentQuery{IDValue: "x"})) },
		"products idValue only": func() error { return ignore(a.QueryProducts(ctx, ProductQuery{IDValue: "x"})) },
	}
	for name, f := range bad {
		if err := f(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v, want ErrInvalidArgument", name, err)
		}
	}
	if h.count() != 0 {
		t.Errorf("%d requests were sent for refused arguments", h.count())
	}
	// The boundaries are accepted.
	for _, size := range []int{0, 1, 100} {
		_ = ignore(a.QueryProducts(ctx, ProductQuery{Page: Page{PageSize: size}}))
	}
	if h.count() != 3 {
		t.Errorf("page sizes 0, 1, 100: %d requests, want 3", h.count())
	}
}

// pager serves pages of products: page i of n has one product; the token
// for page i+1 is tokens[i].
func pager(t *testing.T, n int, tokens []string, forever bool) (*counter, *API) {
	t.Helper()
	h := newCounter(nil)
	h.h = func(w http.ResponseWriter, r *http.Request) {
		got := r.URL.Query().Get("pageToken")
		i := 0
		for j, tk := range tokens {
			if got == tk {
				i = j + 1
			}
		}
		if got != "" && i == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		next := ""
		hasNext := forever || i < n-1
		if hasNext {
			next = tokens[i%len(tokens)]
		}
		page := teaapi.PaginatedProductResponse{HasNext: hasNext, Results: []teaapi.Product{{
			Uuid: uuid.NewSHA1(uuid.NameSpaceURL, []byte(fmt.Sprint(i))), Name: fmt.Sprintf("p%d", i), Identifiers: []teaapi.Identifier{},
		}}}
		if next != "" {
			page.NextPageToken = &next
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page)
	}
	srv := startHTTP(t, h)
	return h, newTestAPI(t, srv.URL, "", WithLimits(Limits{Pages: 4}))
}

// Case 20: iterators.
func TestIterator(t *testing.T) {
	ctx := context.Background()
	tokens := []string{"t1 +/&=?%x", "t2%2F\u00e9"}
	h, a := pager(t, 3, tokens, false)
	var names []string
	for p, err := range a.AllProducts(ctx, ProductQuery{Page: Page{PageSize: 1}}) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, p.Name)
	}
	if fmt.Sprint(names) != "[p0 p1 p2]" || h.count() != 3 {
		t.Fatalf("names %v after %d requests", names, h.count())
	}
	reqs := h.requests()
	for i, tk := range tokens {
		if got := reqs[i+1].URL.Query().Get("pageToken"); got != tk {
			t.Errorf("page %d token %q, want %q verbatim", i+2, got, tk)
		}
		if reqs[i+1].URL.Query().Get("pageSize") != "1" {
			t.Errorf("page %d lost pageSize", i+2)
		}
	}

	// A server that always has a next page stops at Limits.Pages.
	h, a = pager(t, 0, tokens, true)
	n := 0
	var last error
	for _, err := range a.AllProducts(ctx, ProductQuery{}) {
		if err != nil {
			last = err
			break
		}
		n++
	}
	if !errors.Is(last, ErrPageLimit) || n != 4 || h.count() != 4 {
		t.Errorf("endless pages: %v after %d results, %d requests", last, n, h.count())
	}

	// hasNext true without a token.
	srv := startHTTP(t, jsonHandler(`{"hasNext":true,"results":[]}`))
	b := newTestAPI(t, srv.URL, "")
	var ue *UnexpectedResponseError
	for _, err := range b.AllProducts(ctx, ProductQuery{}) {
		last = err
		break
	}
	if !errors.As(last, &ue) {
		t.Errorf("hasNext without nextPageToken: %v", last)
	}
	if _, err := b.QueryProducts(ctx, ProductQuery{}); !errors.As(err, &ue) {
		t.Errorf("QueryProducts, hasNext without nextPageToken: %v", err)
	}

	// Cancelling the context stops the iterator.
	h, a = pager(t, 0, tokens, true)
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	n, last = 0, nil
	for _, err := range a.AllProducts(cctx, ProductQuery{}) {
		if err != nil {
			last = err
			break
		}
		n++
		cancel()
	}
	if !errors.Is(last, context.Canceled) || n != 1 || h.count() != 1 {
		t.Errorf("cancelled: %v after %d results, %d requests", last, n, h.count())
	}

	// Breaking out of the loop stops requests.
	h, a = pager(t, 0, tokens, true)
	for range a.AllProducts(ctx, ProductQuery{}) {
		break
	}
	if h.count() != 1 {
		t.Errorf("break: %d requests", h.count())
	}

	// The other iterators walk their own operations.
	other := newCounter(jsonHandler(`{"hasNext":false,"results":[]}`))
	osrv := startHTTP(t, other)
	o := newTestAPI(t, osrv.URL, "")
	for _, c := range []struct {
		path string
		run  func()
	}{
		{"/v1.0.0/components", func() {
			for range o.AllComponents(ctx, ComponentQuery{}) {
			}
		}},
		{"/v1.0.0/productReleases", func() {
			for range o.AllProductReleases(ctx, ReleaseQuery{}) {
			}
		}},
		{"/v1.0.0/componentReleases", func() {
			for range o.AllComponentReleases(ctx, ReleaseQuery{}) {
			}
		}},
		{"/v1.0.0/product/" + productID.String() + "/releases", func() {
			for range o.AllProductReleasesOf(ctx, productID, ReleasePage{}) {
			}
		}},
		{"/v1.0.0/component/" + compID.String() + "/releases", func() {
			for range o.AllComponentReleasesOf(ctx, compID, ReleasePage{}) {
			}
		}},
		{"/v1.0.0/productRelease/" + releaseID.String() + "/collections", func() {
			for range o.AllProductReleaseCollectionsOf(ctx, releaseID, CollectionPage{}) {
			}
		}},
		{"/v1.0.0/componentRelease/" + compRelID.String() + "/collections", func() {
			for range o.AllComponentReleaseCollectionsOf(ctx, compRelID, CollectionPage{}) {
			}
		}},
	} {
		c.run()
		if got := other.lastReq().URL.Path; got != c.path {
			t.Errorf("iterator requested %s, want %s", got, c.path)
		}
	}
}
