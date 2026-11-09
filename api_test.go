package tea

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/oolong-project/tea-client-go/teaapi"
)

type typedCall struct {
	name   string
	call   func(context.Context, *API) error
	method string
	path   string
	query  url.Values
}

func ignore[T any](_ T, err error) error { return err }

// typedCalls lists every typed call with zero paging, and the request each
// must send (the API root is "/tea").
func typedCalls() []typedCall {
	p, r, c, cr, ar := productID.String(), releaseID.String(), compID.String(), compRelID.String(), artID.String()
	v := "/tea/v1.0.0"
	return []typedCall{
		{"GetProduct", func(ctx context.Context, a *API) error { return ignore(a.GetProduct(ctx, productID)) }, "GET", v + "/product/" + p, nil},
		{"QueryProducts", func(ctx context.Context, a *API) error { return ignore(a.QueryProducts(ctx, ProductQuery{})) }, "GET", v + "/products", nil},
		{"ListProductReleases", func(ctx context.Context, a *API) error {
			return ignore(a.ListProductReleases(ctx, productID, ReleasePage{}))
		}, "GET", v + "/product/" + p + "/releases", nil},
		{"GetProductCLE", func(ctx context.Context, a *API) error { return ignore(a.GetProductCLE(ctx, productID)) }, "GET", v + "/product/" + p + "/cle", nil},
		{"QueryProductReleases", func(ctx context.Context, a *API) error {
			return ignore(a.QueryProductReleases(ctx, ReleaseQuery{}))
		}, "GET", v + "/productReleases", nil},
		{"GetProductRelease", func(ctx context.Context, a *API) error { return ignore(a.GetProductRelease(ctx, releaseID)) }, "GET", v + "/productRelease/" + r, nil},
		{"GetProductReleaseCLE", func(ctx context.Context, a *API) error {
			return ignore(a.GetProductReleaseCLE(ctx, releaseID))
		}, "GET", v + "/productRelease/" + r + "/cle", nil},
		{"ListProductReleaseCollections", func(ctx context.Context, a *API) error {
			return ignore(a.ListProductReleaseCollections(ctx, releaseID, CollectionPage{}))
		}, "GET", v + "/productRelease/" + r + "/collections", nil},
		{"GetLatestProductReleaseCollection", func(ctx context.Context, a *API) error {
			return ignore(a.GetLatestProductReleaseCollection(ctx, releaseID))
		}, "GET", v + "/productRelease/" + r + "/collection/latest", nil},
		{"GetProductReleaseCollection", func(ctx context.Context, a *API) error {
			return ignore(a.GetProductReleaseCollection(ctx, releaseID, 3))
		}, "GET", v + "/productRelease/" + r + "/collection/3", nil},
		{"GetComponent", func(ctx context.Context, a *API) error { return ignore(a.GetComponent(ctx, compID)) }, "GET", v + "/component/" + c, nil},
		{"QueryComponents", func(ctx context.Context, a *API) error { return ignore(a.QueryComponents(ctx, ComponentQuery{})) }, "GET", v + "/components", nil},
		{"ListComponentReleases", func(ctx context.Context, a *API) error {
			return ignore(a.ListComponentReleases(ctx, compID, ReleasePage{}))
		}, "GET", v + "/component/" + c + "/releases", nil},
		{"GetComponentCLE", func(ctx context.Context, a *API) error { return ignore(a.GetComponentCLE(ctx, compID)) }, "GET", v + "/component/" + c + "/cle", nil},
		{"QueryComponentReleases", func(ctx context.Context, a *API) error {
			return ignore(a.QueryComponentReleases(ctx, ReleaseQuery{}))
		}, "GET", v + "/componentReleases", nil},
		{"GetComponentRelease", func(ctx context.Context, a *API) error { return ignore(a.GetComponentRelease(ctx, compRelID)) }, "GET", v + "/componentRelease/" + cr, nil},
		{"GetComponentReleaseCLE", func(ctx context.Context, a *API) error {
			return ignore(a.GetComponentReleaseCLE(ctx, compRelID))
		}, "GET", v + "/componentRelease/" + cr + "/cle", nil},
		{"ListComponentReleaseCollections", func(ctx context.Context, a *API) error {
			return ignore(a.ListComponentReleaseCollections(ctx, compRelID, CollectionPage{}))
		}, "GET", v + "/componentRelease/" + cr + "/collections", nil},
		{"GetLatestComponentReleaseCollection", func(ctx context.Context, a *API) error {
			return ignore(a.GetLatestComponentReleaseCollection(ctx, compRelID))
		}, "GET", v + "/componentRelease/" + cr + "/collection/latest", nil},
		{"GetComponentReleaseCollection", func(ctx context.Context, a *API) error {
			return ignore(a.GetComponentReleaseCollection(ctx, compRelID, 2))
		}, "GET", v + "/componentRelease/" + cr + "/collection/2", nil},
		{"GetLatestArtifact", func(ctx context.Context, a *API) error { return ignore(a.GetLatestArtifact(ctx, artID)) }, "GET", v + "/artifact/" + ar + "/latest", nil},
		{"GetArtifact", func(ctx context.Context, a *API) error { return ignore(a.GetArtifact(ctx, artID, 4)) }, "GET", v + "/artifact/" + ar + "/4", nil},
		{"RequestToken", func(ctx context.Context, a *API) error { return ignore(a.RequestToken(ctx, "id", "secret")) }, "POST", v + "/token", nil},
	}
}

// Case 18: each method sends the spec's path, method and query.
func TestTypedCallRequests(t *testing.T) {
	h := newCounter(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	srv := startHTTP(t, h)
	a := newTestAPI(t, srv.URL, "/tea")
	ctx := context.Background()
	calls := typedCalls()
	if len(calls) != 23 {
		t.Fatalf("%d typed calls in the table, want 23", len(calls))
	}
	for _, c := range calls {
		_ = c.call(ctx, a)
		r := h.lastReq()
		if r.Method != c.method || r.URL.EscapedPath() != c.path || r.URL.RawQuery != "" {
			t.Errorf("%s: %s %s?%s, want %s %s", c.name, r.Method, r.URL.EscapedPath(), r.URL.RawQuery, c.method, c.path)
		}
	}

	// Query parameters, as given.
	tok := "a b&c=d/+%"
	page := Page{PageSize: 10, PageToken: tok, SortOrder: SortDesc}
	want := func(extra ...string) url.Values {
		v := url.Values{"pageSize": {"10"}, "pageToken": {tok}, "sortOrder": {"desc"}}
		for i := 0; i+1 < len(extra); i += 2 {
			v.Set(extra[i], extra[i+1])
		}
		return v
	}
	id := []string{"idType", "TEI", "idValue", "tei://example.com/uuid/x"}
	queries := []typedCall{
		{"QueryProducts", func(ctx context.Context, a *API) error {
			return ignore(a.QueryProducts(ctx, ProductQuery{Page: page, SortField: ProductSortName, IDType: teaapi.TEI, IDValue: id[3]}))
		}, "", "/tea/v1.0.0/products", want(append([]string{"sortField", "name"}, id...)...)},
		{"QueryComponents", func(ctx context.Context, a *API) error {
			return ignore(a.QueryComponents(ctx, ComponentQuery{Page: page, SortField: ComponentSortName, IDType: teaapi.TEI, IDValue: id[3]}))
		}, "", "/tea/v1.0.0/components", want(append([]string{"sortField", "name"}, id...)...)},
		{"QueryProductReleases", func(ctx context.Context, a *API) error {
			return ignore(a.QueryProductReleases(ctx, ReleaseQuery{Page: page, SortField: ReleaseSortReleaseDate, IDType: teaapi.TEI, IDValue: id[3]}))
		}, "", "/tea/v1.0.0/productReleases", want(append([]string{"sortField", "releaseDate"}, id...)...)},
		{"QueryComponentReleases", func(ctx context.Context, a *API) error {
			return ignore(a.QueryComponentReleases(ctx, ReleaseQuery{Page: page, SortField: ReleaseSortVersion, IDType: teaapi.PURL, IDValue: "pkg:generic/x@1"}))
		}, "", "/tea/v1.0.0/componentReleases", want("sortField", "version", "idType", "PURL", "idValue", "pkg:generic/x@1")},
		{"ListProductReleases", func(ctx context.Context, a *API) error {
			return ignore(a.ListProductReleases(ctx, productID, ReleasePage{Page: page, SortField: ReleaseSortCreatedDate}))
		}, "", "/tea/v1.0.0/product/" + productID.String() + "/releases", want("sortField", "createdDate")},
		{"ListComponentReleases", func(ctx context.Context, a *API) error {
			return ignore(a.ListComponentReleases(ctx, compID, ReleasePage{Page: page, SortField: ReleaseSortCreatedDate}))
		}, "", "/tea/v1.0.0/component/" + compID.String() + "/releases", want("sortField", "createdDate")},
		{"ListProductReleaseCollections", func(ctx context.Context, a *API) error {
			return ignore(a.ListProductReleaseCollections(ctx, releaseID, CollectionPage{Page: page, SortField: CollectionSortVersion}))
		}, "", "/tea/v1.0.0/productRelease/" + releaseID.String() + "/collections", want("sortField", "version")},
		{"ListComponentReleaseCollections", func(ctx context.Context, a *API) error {
			return ignore(a.ListComponentReleaseCollections(ctx, compRelID, CollectionPage{Page: page, SortField: CollectionSortVersion}))
		}, "", "/tea/v1.0.0/componentRelease/" + compRelID.String() + "/collections", want("sortField", "version")},
	}
	for _, c := range queries {
		_ = c.call(ctx, a)
		r := h.lastReq()
		if r.URL.EscapedPath() != c.path {
			t.Errorf("%s: path %s", c.name, r.URL.EscapedPath())
		}
		got := r.URL.Query()
		if len(got) != len(c.query) {
			t.Errorf("%s: query %v, want %v", c.name, got, c.query)
		}
		for k, v := range c.query {
			if got.Get(k) != v[0] {
				t.Errorf("%s: %s=%q, want %q", c.name, k, got.Get(k), v[0])
			}
		}
	}

	// A uuid path parameter is lowercase.
	upper := uuid.MustParse(strings.ToUpper(productID.String()))
	_, _ = a.GetProduct(ctx, upper)
	if got := h.lastReq().URL.Path; got != "/tea/v1.0.0/product/"+productID.String() {
		t.Errorf("uuid path %s", got)
	}
}

// Case 16: a 2xx the client cannot use is an *UnexpectedResponseError for
// every typed call, never a panic.
func TestTypedCallUnexpectedJSON(t *testing.T) {
	var body string
	srv := startHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	a := newTestAPI(t, srv.URL, "/tea")
	ctx := context.Background()
	for _, b := range []string{"{", "null", `"a string"`, "", "  \n", "[1,2]", "42", `{"uuid":5}`} {
		body = b
		for _, c := range typedCalls() {
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Errorf("%s with body %q panicked: %v", c.name, b, p)
					}
				}()
				err := c.call(ctx, a)
				var ue *UnexpectedResponseError
				if b == `{"uuid":5}` && (strings.HasSuffix(c.name, "CLE") || strings.HasPrefix(c.name, "Query") || strings.HasPrefix(c.name, "List")) {
					return // no uuid field in this type: an unknown field, ignored (D8)
				}
				if !errors.As(err, &ue) || ue.Status != 200 {
					t.Errorf("%s with body %q: %v, want *UnexpectedResponseError", c.name, b, err)
				}
			}()
		}
	}

	// Uuids in responses.
	body = `{"uuid":"not-a-uuid","name":"p","identifiers":[]}`
	var ue *UnexpectedResponseError
	if _, err := a.GetProduct(ctx, productID); !errors.As(err, &ue) {
		t.Errorf("uuid not-a-uuid: %v", err)
	}
	body = `{"uuid":"ABCDEF00-2222-4222-8222-222222222222","name":"p","identifiers":[]}`
	p, err := a.GetProduct(ctx, productID)
	if err != nil {
		t.Fatalf("uppercase uuid: %v", err)
	}
	h := newCounter(jsonHandler(`{"hasNext":false,"results":[]}`))
	srv2 := startHTTP(t, h)
	b := newTestAPI(t, srv2.URL, "/tea")
	if _, err := b.ListProductReleases(ctx, p.Uuid, ReleasePage{}); err != nil {
		t.Fatal(err)
	}
	if got := h.lastReq().URL.Path; got != "/tea/v1.0.0/product/abcdef00-2222-4222-8222-222222222222/releases" {
		t.Errorf("path built from an uppercase uuid: %s", got)
	}
}

// Case 16 and design 3.6: an undecodable body never reaches the error text,
// not even the bad value a decoder error would quote.
func TestDecodeErrorCarriesNoBody(t *testing.T) {
	const sentinel = "SECRET-BODY-CONTENT-7f3a"
	var body string
	srv := startHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	a := newTestAPI(t, srv.URL, "/tea")
	ctx := context.Background()
	cases := map[string]struct {
		body string
		call func() error
	}{
		"time field": {
			`{"uuid":"` + releaseID.String() + `","version":"1","createdDate":"2026-01-15T00:00:00Z","releaseDate":"` + sentinel + `","components":[],"product":"` + productID.String() + `"}`,
			func() error { return ignore(a.GetProductRelease(ctx, releaseID)) },
		},
		"uuid field": {
			`{"uuid":"` + sentinel + `","name":"p","identifiers":[]}`,
			func() error { return ignore(a.GetProduct(ctx, productID)) },
		},
		"object where a string belongs": {
			`{"uuid":"` + productID.String() + `","name":{"` + sentinel + `":1},"identifiers":[]}`,
			func() error { return ignore(a.GetProduct(ctx, productID)) },
		},
		"syntax": {
			`{"uuid":"` + productID.String() + `","name":"` + sentinel + `" ` + sentinel + `}`,
			func() error { return ignore(a.GetProduct(ctx, productID)) },
		},
	}
	for name, c := range cases {
		body = c.body
		err := c.call()
		var ue *UnexpectedResponseError
		if !errors.As(err, &ue) {
			t.Errorf("%s: %v, want *UnexpectedResponseError", name, err)
			continue
		}
		if strings.Contains(err.Error(), sentinel) || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: error repeats body content: %v", name, err)
		}
		if !strings.Contains(ue.Reason, "teaapi.") {
			t.Errorf("%s: reason %q does not name the type", name, ue.Reason)
		}
	}
}
