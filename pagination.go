package tea

import (
	"context"
	"fmt"
	"iter"

	"github.com/google/uuid"

	"github.com/oolong-project/tea-client-go/teaapi"
)

// SortOrder is the spec's sort-order.
type SortOrder string

// Sort orders. The zero value omits the parameter (server default: asc).
const (
	SortAsc  SortOrder = "asc"
	SortDesc SortOrder = "desc"
)

// Valid reports whether o is empty or one of the constants.
func (o SortOrder) Valid() bool { return o == "" || o == SortAsc || o == SortDesc }

// ProductSortField is the spec's sort-field-product.
type ProductSortField string

// Product sort fields.
const ProductSortName ProductSortField = "name"

// Valid reports whether f is empty or one of the constants.
func (f ProductSortField) Valid() bool { return f == "" || f == ProductSortName }

// ComponentSortField is the spec's sort-field-component.
type ComponentSortField string

// Component sort fields.
const ComponentSortName ComponentSortField = "name"

// Valid reports whether f is empty or one of the constants.
func (f ComponentSortField) Valid() bool { return f == "" || f == ComponentSortName }

// ReleaseSortField is the spec's sort-field-product-release and
// sort-field-component-release (the same set).
type ReleaseSortField string

// Release sort fields.
const (
	ReleaseSortCreatedDate ReleaseSortField = "createdDate"
	ReleaseSortReleaseDate ReleaseSortField = "releaseDate"
	ReleaseSortVersion     ReleaseSortField = "version"
)

// Valid reports whether f is empty or one of the constants.
func (f ReleaseSortField) Valid() bool {
	switch f {
	case "", ReleaseSortCreatedDate, ReleaseSortReleaseDate, ReleaseSortVersion:
		return true
	}
	return false
}

// CollectionSortField is the spec's sort-field-collection.
type CollectionSortField string

// Collection sort fields.
const CollectionSortVersion CollectionSortField = "version"

// Valid reports whether f is empty or one of the constants.
func (f CollectionSortField) Valid() bool { return f == "" || f == CollectionSortVersion }

// Page carries the paging parameters every list operation takes. A zero
// field is omitted from the request (PageSize 0 is the server's default).
// PageToken is passed back verbatim; it is opaque.
type Page struct {
	PageSize  int
	PageToken string
	SortOrder SortOrder
}

// ProductQuery selects products (queryProducts).
type ProductQuery struct {
	Page
	SortField ProductSortField
	IDType    teaapi.IdentifierType
	IDValue   string
}

// ComponentQuery selects components (queryComponents).
type ComponentQuery struct {
	Page
	SortField ComponentSortField
	IDType    teaapi.IdentifierType
	IDValue   string
}

// ReleaseQuery selects product releases or component releases
// (queryProductReleases, queryComponentReleases).
type ReleaseQuery struct {
	Page
	SortField ReleaseSortField
	IDType    teaapi.IdentifierType
	IDValue   string
}

// ReleasePage pages through one parent's releases (listProductReleases,
// listComponentReleases).
type ReleasePage struct {
	Page
	SortField ReleaseSortField
}

// CollectionPage pages through one release's collections
// (listProductReleaseCollections, listComponentReleaseCollections).
type CollectionPage struct {
	Page
	SortField CollectionSortField
}

const maxPageSize = 100

func (p Page) check() error {
	if p.PageSize < 0 || p.PageSize > maxPageSize {
		return fmt.Errorf("%w: page size %d is not 0 or 1..100", ErrInvalidArgument, p.PageSize)
	}
	if !p.SortOrder.Valid() {
		return fmt.Errorf("%w: sort order %q", ErrInvalidArgument, truncateArg(string(p.SortOrder)))
	}
	return nil
}

func checkID(t teaapi.IdentifierType, v string) error {
	if t != "" && !t.Valid() {
		return fmt.Errorf("%w: identifier type %q", ErrInvalidArgument, truncateArg(string(t)))
	}
	if v != "" && t == "" {
		return fmt.Errorf("%w: IDValue without IDType", ErrInvalidArgument)
	}
	return nil
}

func sortFieldErr(f string) error {
	return fmt.Errorf("%w: sort field %q", ErrInvalidArgument, truncateArg(f))
}

// opt returns a pointer to v, or nil for the zero value (parameter omitted).
func opt[T comparable](v T) *T {
	var zero T
	if v == zero {
		return nil
	}
	return &v
}

func optConv[T ~string](s string) *T {
	if s == "" {
		return nil
	}
	v := T(s)
	return &v
}

func (p Page) size() *teaapi.PageSize { return opt(teaapi.PageSize(p.PageSize)) }

func (q ProductQuery) params() (*teaapi.QueryProductsParams, error) {
	if err := q.check(); err != nil {
		return nil, err
	}
	if !q.SortField.Valid() {
		return nil, sortFieldErr(string(q.SortField))
	}
	if err := checkID(q.IDType, q.IDValue); err != nil {
		return nil, err
	}
	return &teaapi.QueryProductsParams{
		IdType: opt(q.IDType), IdValue: opt(q.IDValue), PageSize: q.size(), PageToken: opt(q.PageToken),
		SortField: optConv[teaapi.QueryProductsParamsSortField](string(q.SortField)),
		SortOrder: optConv[teaapi.QueryProductsParamsSortOrder](string(q.SortOrder)),
	}, nil
}

func (q ComponentQuery) params() (*teaapi.QueryComponentsParams, error) {
	if err := q.check(); err != nil {
		return nil, err
	}
	if !q.SortField.Valid() {
		return nil, sortFieldErr(string(q.SortField))
	}
	if err := checkID(q.IDType, q.IDValue); err != nil {
		return nil, err
	}
	return &teaapi.QueryComponentsParams{
		IdType: opt(q.IDType), IdValue: opt(q.IDValue), PageSize: q.size(), PageToken: opt(q.PageToken),
		SortField: optConv[teaapi.QueryComponentsParamsSortField](string(q.SortField)),
		SortOrder: optConv[teaapi.QueryComponentsParamsSortOrder](string(q.SortOrder)),
	}, nil
}

func (q ReleaseQuery) check() error {
	if err := q.Page.check(); err != nil {
		return err
	}
	if !q.SortField.Valid() {
		return sortFieldErr(string(q.SortField))
	}
	return checkID(q.IDType, q.IDValue)
}

func (q ReleaseQuery) productParams() (*teaapi.QueryProductReleasesParams, error) {
	if err := q.check(); err != nil {
		return nil, err
	}
	return &teaapi.QueryProductReleasesParams{
		IdType: opt(q.IDType), IdValue: opt(q.IDValue), PageSize: q.size(), PageToken: opt(q.PageToken),
		SortField: optConv[teaapi.QueryProductReleasesParamsSortField](string(q.SortField)),
		SortOrder: optConv[teaapi.QueryProductReleasesParamsSortOrder](string(q.SortOrder)),
	}, nil
}

func (q ReleaseQuery) componentParams() (*teaapi.QueryComponentReleasesParams, error) {
	if err := q.check(); err != nil {
		return nil, err
	}
	return &teaapi.QueryComponentReleasesParams{
		IdType: opt(q.IDType), IdValue: opt(q.IDValue), PageSize: q.size(), PageToken: opt(q.PageToken),
		SortField: optConv[teaapi.QueryComponentReleasesParamsSortField](string(q.SortField)),
		SortOrder: optConv[teaapi.QueryComponentReleasesParamsSortOrder](string(q.SortOrder)),
	}, nil
}

func (p ReleasePage) check() error {
	if err := p.Page.check(); err != nil {
		return err
	}
	if !p.SortField.Valid() {
		return sortFieldErr(string(p.SortField))
	}
	return nil
}

func (p ReleasePage) productParams() (*teaapi.ListProductReleasesParams, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	return &teaapi.ListProductReleasesParams{
		PageSize: p.size(), PageToken: opt(p.PageToken),
		SortField: optConv[teaapi.ListProductReleasesParamsSortField](string(p.SortField)),
		SortOrder: optConv[teaapi.ListProductReleasesParamsSortOrder](string(p.SortOrder)),
	}, nil
}

func (p ReleasePage) componentParams() (*teaapi.ListComponentReleasesParams, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	return &teaapi.ListComponentReleasesParams{
		PageSize: p.size(), PageToken: opt(p.PageToken),
		SortField: optConv[teaapi.ListComponentReleasesParamsSortField](string(p.SortField)),
		SortOrder: optConv[teaapi.ListComponentReleasesParamsSortOrder](string(p.SortOrder)),
	}, nil
}

func (p CollectionPage) check() error {
	if err := p.Page.check(); err != nil {
		return err
	}
	if !p.SortField.Valid() {
		return sortFieldErr(string(p.SortField))
	}
	return nil
}

func (p CollectionPage) productParams() (*teaapi.ListProductReleaseCollectionsParams, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	return &teaapi.ListProductReleaseCollectionsParams{
		PageSize: p.size(), PageToken: opt(p.PageToken),
		SortField: optConv[teaapi.ListProductReleaseCollectionsParamsSortField](string(p.SortField)),
		SortOrder: optConv[teaapi.ListProductReleaseCollectionsParamsSortOrder](string(p.SortOrder)),
	}, nil
}

func (p CollectionPage) componentParams() (*teaapi.ListComponentReleaseCollectionsParams, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	return &teaapi.ListComponentReleaseCollectionsParams{
		PageSize: p.size(), PageToken: opt(p.PageToken),
		SortField: optConv[teaapi.ListComponentReleaseCollectionsParamsSortField](string(p.SortField)),
		SortOrder: optConv[teaapi.ListComponentReleaseCollectionsParamsSortOrder](string(p.SortOrder)),
	}, nil
}

// paginate yields every result of every page, starting at token. It stops at
// the first error, at hasNext false, or with ErrPageLimit after Limits.Pages
// pages; a cancelled context stops it with the context's error.
func paginate[T any](ctx context.Context, a *API, token string, fetch func(ctx context.Context, token string) ([]T, bool, *string, error)) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		var zero T
		for page := 0; ; page++ {
			if page >= a.c.limits.Pages {
				yield(zero, fmt.Errorf("after %d pages: %w", page, ErrPageLimit))
				return
			}
			if err := ctx.Err(); err != nil {
				yield(zero, err)
				return
			}
			results, hasNext, next, err := fetch(ctx, token)
			if err != nil {
				yield(zero, err)
				return
			}
			for _, r := range results {
				if !yield(r, nil) {
					return
				}
			}
			if !hasNext {
				return
			}
			token = *next // checkPage guarantees a non-empty token
		}
	}
}

// AllProducts iterates over every product the query selects.
func (a *API) AllProducts(ctx context.Context, q ProductQuery) iter.Seq2[teaapi.Product, error] {
	return paginate(ctx, a, q.PageToken, func(ctx context.Context, token string) ([]teaapi.Product, bool, *string, error) {
		q.PageToken = token
		r, err := a.QueryProducts(ctx, q)
		if err != nil {
			return nil, false, nil, err
		}
		return r.Results, r.HasNext, r.NextPageToken, nil
	})
}

// AllComponents iterates over every component the query selects.
func (a *API) AllComponents(ctx context.Context, q ComponentQuery) iter.Seq2[teaapi.Component, error] {
	return paginate(ctx, a, q.PageToken, func(ctx context.Context, token string) ([]teaapi.Component, bool, *string, error) {
		q.PageToken = token
		r, err := a.QueryComponents(ctx, q)
		if err != nil {
			return nil, false, nil, err
		}
		return r.Results, r.HasNext, r.NextPageToken, nil
	})
}

// AllProductReleases iterates over every product release the query selects.
func (a *API) AllProductReleases(ctx context.Context, q ReleaseQuery) iter.Seq2[teaapi.ProductRelease, error] {
	return paginate(ctx, a, q.PageToken, func(ctx context.Context, token string) ([]teaapi.ProductRelease, bool, *string, error) {
		q.PageToken = token
		r, err := a.QueryProductReleases(ctx, q)
		if err != nil {
			return nil, false, nil, err
		}
		return r.Results, r.HasNext, r.NextPageToken, nil
	})
}

// AllComponentReleases iterates over every component release the query selects.
func (a *API) AllComponentReleases(ctx context.Context, q ReleaseQuery) iter.Seq2[teaapi.ComponentRelease, error] {
	return paginate(ctx, a, q.PageToken, func(ctx context.Context, token string) ([]teaapi.ComponentRelease, bool, *string, error) {
		q.PageToken = token
		r, err := a.QueryComponentReleases(ctx, q)
		if err != nil {
			return nil, false, nil, err
		}
		return r.Results, r.HasNext, r.NextPageToken, nil
	})
}

// AllProductReleasesOf iterates over every release of one product.
func (a *API) AllProductReleasesOf(ctx context.Context, id uuid.UUID, p ReleasePage) iter.Seq2[teaapi.ProductRelease, error] {
	return paginate(ctx, a, p.PageToken, func(ctx context.Context, token string) ([]teaapi.ProductRelease, bool, *string, error) {
		p.PageToken = token
		r, err := a.ListProductReleases(ctx, id, p)
		if err != nil {
			return nil, false, nil, err
		}
		return r.Results, r.HasNext, r.NextPageToken, nil
	})
}

// AllComponentReleasesOf iterates over every release of one component.
func (a *API) AllComponentReleasesOf(ctx context.Context, id uuid.UUID, p ReleasePage) iter.Seq2[teaapi.ComponentRelease, error] {
	return paginate(ctx, a, p.PageToken, func(ctx context.Context, token string) ([]teaapi.ComponentRelease, bool, *string, error) {
		p.PageToken = token
		r, err := a.ListComponentReleases(ctx, id, p)
		if err != nil {
			return nil, false, nil, err
		}
		return r.Results, r.HasNext, r.NextPageToken, nil
	})
}

// AllProductReleaseCollectionsOf iterates over every collection of one product release.
func (a *API) AllProductReleaseCollectionsOf(ctx context.Context, id uuid.UUID, p CollectionPage) iter.Seq2[teaapi.Collection, error] {
	return paginate(ctx, a, p.PageToken, func(ctx context.Context, token string) ([]teaapi.Collection, bool, *string, error) {
		p.PageToken = token
		r, err := a.ListProductReleaseCollections(ctx, id, p)
		if err != nil {
			return nil, false, nil, err
		}
		return r.Results, r.HasNext, r.NextPageToken, nil
	})
}

// AllComponentReleaseCollectionsOf iterates over every collection of one component release.
func (a *API) AllComponentReleaseCollectionsOf(ctx context.Context, id uuid.UUID, p CollectionPage) iter.Seq2[teaapi.Collection, error] {
	return paginate(ctx, a, p.PageToken, func(ctx context.Context, token string) ([]teaapi.Collection, bool, *string, error) {
		p.PageToken = token
		r, err := a.ListComponentReleaseCollections(ctx, id, p)
		if err != nil {
			return nil, false, nil, err
		}
		return r.Results, r.HasNext, r.NextPageToken, nil
	})
}
