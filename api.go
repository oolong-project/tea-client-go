package tea

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/oolong-project/tea-client-go/teaapi"
)

// API is the typed TEA API at one APIBase. It is safe for concurrent use.
// Every method returns teaapi types; errors are *APIError (non-2xx),
// *UnexpectedResponseError (a 2xx the client cannot use), *URLPolicyError,
// or wrap ErrResponseTooLarge, ErrTimeout, ErrInvalidArgument or the
// caller's context error.
type API struct {
	c    *Client
	base APIBase
	d    *doer
	raw  *teaapi.Client
	gen  *teaapi.ClientWithResponses
}

func newAPI(c *Client, base APIBase) (*API, error) {
	d := &doer{c: c, base: base.url()}
	server := base.String() + "/"
	raw, err := teaapi.NewClient(server, teaapi.WithHTTPClient(d))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	gen, err := teaapi.NewClientWithResponses(server, teaapi.WithHTTPClient(d))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return &API{c: c, base: base, d: d, raw: raw, gen: gen}, nil
}

// Base returns the API base this API is bound to.
func (a *API) Base() APIBase { return a.base }

// Generated returns the generated client for operations this package does
// not wrap. It sends through the same bounded, auth-aware doer as the typed
// methods: the URL policy, the credential rules and the byte and time limits
// apply. Its requests carry no call kind, so each is classified by its path
// relative to the API base: /artifact/{uuid}/{latest|version}/download as a
// download (Limits.DownloadBytes, IdleTimeout), .../signature as a signature
// (SignatureBytes, IdleTimeout), /discovery as discovery (DiscoveryBytes,
// AttemptTimeout), and everything else as JSON (JSONBytes, CallTimeout).
//
// The generated download operations read the whole body into memory, so a
// download through Generated can hold up to Limits.DownloadBytes (512 MiB by
// default); DownloadArtifact streams and verifies checksums instead.
//
// The auth transport decides every Authorization header, so a header set by
// a request editor is removed off a credential root and replaced on one. In
// particular a token request made through Generated cannot carry HTTP Basic
// credentials; use RequestToken.
func (a *API) Generated() *teaapi.ClientWithResponses { return a.gen }

// call sends one typed JSON request and decodes a 2xx body into T.
func call[T any](ctx context.Context, op string, send func(context.Context) (*http.Response, error)) (*T, error) {
	resp, err := send(withKind(ctx, kindJSON))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	body, err := readBody(resp)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, mapError(op, resp, body)
	}
	v, err := decodeBody[T](op, resp.StatusCode, body)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// readBody reads a body already bounded by the doer and closes it.
func readBody(resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(resp.Body)
}

// decodeBody decodes a 2xx JSON body. A missing body, "null", a value of the
// wrong type, invalid JSON or a uuid that does not decode is an
// *UnexpectedResponseError. Its reason names only the type that failed to
// decode: decoder errors quote body content (a time.ParseError repeats the
// value), and no body content goes into an error (design 3.6).
func decodeBody[T any](op string, status int, body []byte) (*T, error) {
	trimmed := bytes.TrimSpace(body)
	switch {
	case len(trimmed) == 0:
		return nil, unexpected(op, status, "empty body")
	case bytes.Equal(trimmed, []byte("null")):
		return nil, unexpected(op, status, "null body")
	}
	v := new(T)
	if err := json.Unmarshal(trimmed, v); err != nil {
		return nil, unexpected(op, status, fmt.Sprintf("body does not decode as %T", *v))
	}
	return v, nil
}

func checkPage(op string, hasNext bool, next *string) error {
	if hasNext && (next == nil || *next == "") {
		return unexpected(op, http.StatusOK, "hasNext is true without nextPageToken")
	}
	return nil
}

// Products

// GetProduct reads one product.
func (a *API) GetProduct(ctx context.Context, id uuid.UUID) (*teaapi.Product, error) {
	return call[teaapi.Product](ctx, "getting product "+id.String(), func(ctx context.Context) (*http.Response, error) {
		return a.raw.GetProduct(ctx, id)
	})
}

// QueryProducts reads one page of products.
func (a *API) QueryProducts(ctx context.Context, q ProductQuery) (*teaapi.PaginatedProductResponse, error) {
	const op = "querying products"
	p, err := q.params()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	r, err := call[teaapi.PaginatedProductResponse](ctx, op, func(ctx context.Context) (*http.Response, error) {
		return a.raw.QueryProducts(ctx, p)
	})
	if err != nil {
		return nil, err
	}
	return r, checkPage(op, r.HasNext, r.NextPageToken)
}

// ListProductReleases reads one page of a product's releases.
func (a *API) ListProductReleases(ctx context.Context, id uuid.UUID, pg ReleasePage) (*teaapi.PaginatedProductReleaseResponse, error) {
	op := "listing releases of product " + id.String()
	p, err := pg.productParams()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	r, err := call[teaapi.PaginatedProductReleaseResponse](ctx, op, func(ctx context.Context) (*http.Response, error) {
		return a.raw.ListProductReleases(ctx, id, p)
	})
	if err != nil {
		return nil, err
	}
	return r, checkPage(op, r.HasNext, r.NextPageToken)
}

// GetProductCLE reads a product's lifecycle events.
func (a *API) GetProductCLE(ctx context.Context, id uuid.UUID) (*teaapi.Cle, error) {
	return call[teaapi.Cle](ctx, "getting CLE of product "+id.String(), func(ctx context.Context) (*http.Response, error) {
		return a.raw.GetProductCle(ctx, id)
	})
}

// Product releases

// QueryProductReleases reads one page of product releases.
func (a *API) QueryProductReleases(ctx context.Context, q ReleaseQuery) (*teaapi.PaginatedProductReleaseResponse, error) {
	const op = "querying product releases"
	p, err := q.productParams()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	r, err := call[teaapi.PaginatedProductReleaseResponse](ctx, op, func(ctx context.Context) (*http.Response, error) {
		return a.raw.QueryProductReleases(ctx, p)
	})
	if err != nil {
		return nil, err
	}
	return r, checkPage(op, r.HasNext, r.NextPageToken)
}

// GetProductRelease reads one product release with its latest collection.
func (a *API) GetProductRelease(ctx context.Context, id uuid.UUID) (*teaapi.ProductReleaseWithCollection, error) {
	return call[teaapi.ProductReleaseWithCollection](ctx, "getting product release "+id.String(), func(ctx context.Context) (*http.Response, error) {
		return a.raw.GetProductRelease(ctx, id)
	})
}

// GetProductReleaseCLE reads a product release's lifecycle events.
func (a *API) GetProductReleaseCLE(ctx context.Context, id uuid.UUID) (*teaapi.Cle, error) {
	return call[teaapi.Cle](ctx, "getting CLE of product release "+id.String(), func(ctx context.Context) (*http.Response, error) {
		return a.raw.GetProductReleaseCle(ctx, id)
	})
}

// ListProductReleaseCollections reads one page of a product release's collections.
func (a *API) ListProductReleaseCollections(ctx context.Context, id uuid.UUID, pg CollectionPage) (*teaapi.PaginatedCollectionResponse, error) {
	op := "listing collections of product release " + id.String()
	p, err := pg.productParams()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	r, err := call[teaapi.PaginatedCollectionResponse](ctx, op, func(ctx context.Context) (*http.Response, error) {
		return a.raw.ListProductReleaseCollections(ctx, id, p)
	})
	if err != nil {
		return nil, err
	}
	return r, checkPage(op, r.HasNext, r.NextPageToken)
}

// GetLatestProductReleaseCollection reads a product release's latest collection.
func (a *API) GetLatestProductReleaseCollection(ctx context.Context, id uuid.UUID) (*teaapi.Collection, error) {
	return call[teaapi.Collection](ctx, "getting latest collection of product release "+id.String(), func(ctx context.Context) (*http.Response, error) {
		return a.raw.GetLatestProductReleaseCollection(ctx, id)
	})
}

// GetProductReleaseCollection reads one version of a product release's collection.
func (a *API) GetProductReleaseCollection(ctx context.Context, id uuid.UUID, version int) (*teaapi.Collection, error) {
	op := fmt.Sprintf("getting collection %d of product release %s", version, id)
	return call[teaapi.Collection](ctx, op, func(ctx context.Context) (*http.Response, error) {
		return a.raw.GetProductReleaseCollectionByVersion(ctx, id, version)
	})
}

// Components

// GetComponent reads one component.
func (a *API) GetComponent(ctx context.Context, id uuid.UUID) (*teaapi.Component, error) {
	return call[teaapi.Component](ctx, "getting component "+id.String(), func(ctx context.Context) (*http.Response, error) {
		return a.raw.GetComponent(ctx, id)
	})
}

// QueryComponents reads one page of components.
func (a *API) QueryComponents(ctx context.Context, q ComponentQuery) (*teaapi.PaginatedComponentResponse, error) {
	const op = "querying components"
	p, err := q.params()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	r, err := call[teaapi.PaginatedComponentResponse](ctx, op, func(ctx context.Context) (*http.Response, error) {
		return a.raw.QueryComponents(ctx, p)
	})
	if err != nil {
		return nil, err
	}
	return r, checkPage(op, r.HasNext, r.NextPageToken)
}

// ListComponentReleases reads one page of a component's releases.
func (a *API) ListComponentReleases(ctx context.Context, id uuid.UUID, pg ReleasePage) (*teaapi.PaginatedComponentReleaseResponse, error) {
	op := "listing releases of component " + id.String()
	p, err := pg.componentParams()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	r, err := call[teaapi.PaginatedComponentReleaseResponse](ctx, op, func(ctx context.Context) (*http.Response, error) {
		return a.raw.ListComponentReleases(ctx, id, p)
	})
	if err != nil {
		return nil, err
	}
	return r, checkPage(op, r.HasNext, r.NextPageToken)
}

// GetComponentCLE reads a component's lifecycle events.
func (a *API) GetComponentCLE(ctx context.Context, id uuid.UUID) (*teaapi.Cle, error) {
	return call[teaapi.Cle](ctx, "getting CLE of component "+id.String(), func(ctx context.Context) (*http.Response, error) {
		return a.raw.GetComponentCle(ctx, id)
	})
}

// Component releases

// QueryComponentReleases reads one page of component releases.
func (a *API) QueryComponentReleases(ctx context.Context, q ReleaseQuery) (*teaapi.PaginatedComponentReleaseResponse, error) {
	const op = "querying component releases"
	p, err := q.componentParams()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	r, err := call[teaapi.PaginatedComponentReleaseResponse](ctx, op, func(ctx context.Context) (*http.Response, error) {
		return a.raw.QueryComponentReleases(ctx, p)
	})
	if err != nil {
		return nil, err
	}
	return r, checkPage(op, r.HasNext, r.NextPageToken)
}

// GetComponentRelease reads one component release with its latest collection.
func (a *API) GetComponentRelease(ctx context.Context, id uuid.UUID) (*teaapi.ComponentReleaseWithCollection, error) {
	return call[teaapi.ComponentReleaseWithCollection](ctx, "getting component release "+id.String(), func(ctx context.Context) (*http.Response, error) {
		return a.raw.GetComponentRelease(ctx, id)
	})
}

// GetComponentReleaseCLE reads a component release's lifecycle events.
func (a *API) GetComponentReleaseCLE(ctx context.Context, id uuid.UUID) (*teaapi.Cle, error) {
	return call[teaapi.Cle](ctx, "getting CLE of component release "+id.String(), func(ctx context.Context) (*http.Response, error) {
		return a.raw.GetComponentReleaseCle(ctx, id)
	})
}

// ListComponentReleaseCollections reads one page of a component release's collections.
func (a *API) ListComponentReleaseCollections(ctx context.Context, id uuid.UUID, pg CollectionPage) (*teaapi.PaginatedCollectionResponse, error) {
	op := "listing collections of component release " + id.String()
	p, err := pg.componentParams()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	r, err := call[teaapi.PaginatedCollectionResponse](ctx, op, func(ctx context.Context) (*http.Response, error) {
		return a.raw.ListComponentReleaseCollections(ctx, id, p)
	})
	if err != nil {
		return nil, err
	}
	return r, checkPage(op, r.HasNext, r.NextPageToken)
}

// GetLatestComponentReleaseCollection reads a component release's latest collection.
func (a *API) GetLatestComponentReleaseCollection(ctx context.Context, id uuid.UUID) (*teaapi.Collection, error) {
	return call[teaapi.Collection](ctx, "getting latest collection of component release "+id.String(), func(ctx context.Context) (*http.Response, error) {
		return a.raw.GetLatestComponentReleaseCollection(ctx, id)
	})
}

// GetComponentReleaseCollection reads one version of a component release's collection.
func (a *API) GetComponentReleaseCollection(ctx context.Context, id uuid.UUID, version int) (*teaapi.Collection, error) {
	op := fmt.Sprintf("getting collection %d of component release %s", version, id)
	return call[teaapi.Collection](ctx, op, func(ctx context.Context) (*http.Response, error) {
		return a.raw.GetComponentReleaseCollectionByVersion(ctx, id, version)
	})
}

// Artifacts

// GetLatestArtifact reads the latest revision of an artifact's metadata.
func (a *API) GetLatestArtifact(ctx context.Context, id uuid.UUID) (*teaapi.Artifact, error) {
	return call[teaapi.Artifact](ctx, "getting latest artifact "+id.String(), func(ctx context.Context) (*http.Response, error) {
		return a.raw.GetLatestArtifact(ctx, id)
	})
}

// GetArtifact reads one revision of an artifact's metadata.
func (a *API) GetArtifact(ctx context.Context, id uuid.UUID, version int) (*teaapi.Artifact, error) {
	op := fmt.Sprintf("getting artifact %s version %d", id, version)
	return call[teaapi.Artifact](ctx, op, func(ctx context.Context) (*http.Response, error) {
		return a.raw.GetArtifactByVersion(ctx, id, version)
	})
}
