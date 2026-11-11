package tea

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/oolong-project/tea-client-go/teaapi"
	"github.com/oolong-project/tea-client-go/tei"
)

// FlowOptions adjusts FullFlow and FlowFromRelease.
type FlowOptions struct {
	// Select chooses among several discovery results. It is given every
	// candidate (each with its selected server and product release) and
	// returns the index of the one to continue with. nil: several results
	// are an *AmbiguousError. The library never prompts; a caller that
	// asks a person does it here or after an *AmbiguousError.
	Select func(ctx context.Context, cands []Candidate) (int, error)
	// SkipCLE skips every lifecycle (CLE) request.
	SkipCLE bool
}

// Candidate is one discovery result with the API of its selected server
// and its product release, as Candidates loads it.
type Candidate struct {
	Result  DiscoveryResult
	API     *API
	Release *teaapi.ProductReleaseWithCollection
}

// AmbiguousError is a discovery with several results and no
// FlowOptions.Select. Results are in the server's order; Candidates loads
// them for a choice.
type AmbiguousError struct {
	Results []DiscoveryResult
}

func (e *AmbiguousError) Error() string {
	return fmt.Sprintf("tea: discovery returned %d results and no selector was given", len(e.Results))
}

// FlowResult is a product release with its lifecycle and components.
type FlowResult struct {
	// API is the API the release was read from.
	API *API
	// Release is the product release; its LatestCollection carries the
	// artifacts and their formats (the flow downloads nothing).
	Release *teaapi.ProductReleaseWithCollection
	// ReleaseCLE is nil when the server answers NOT_IMPLEMENTED or
	// OBJECT_UNKNOWN for it, or with SkipCLE.
	ReleaseCLE *teaapi.Cle
	// Components follow the release's component refs, in order.
	Components []FlowComponent
}

// FlowComponent is one component ref of a product release, resolved.
type FlowComponent struct {
	Ref teaapi.ComponentRef
	// Pinned is true when Ref.Release names the component release.
	Pinned bool
	// Component is fetched for an unpinned ref only.
	Component *teaapi.Component
	// Release is the pinned component release, or for an unpinned ref the
	// newest by createdDate.
	Release *teaapi.ComponentReleaseWithCollection
	// CLE is the component release's lifecycle; nil when NOT_IMPLEMENTED or
	// OBJECT_UNKNOWN, or with SkipCLE.
	CLE *teaapi.Cle
	// Err is this component's failure; the walk continues with the others.
	Err error
}

// FullFlow resolves t and reads its product release with its lifecycle and
// components (the CLI's full_tea_flow): Discover; with one result the
// server SelectServer picks and FlowFromRelease. With several results and
// no o.Select it returns *AmbiguousError (and reads no product release);
// with o.Select it loads Candidates (at most Limits.DiscoveryResults
// product-release requests), lets Select choose (an index out of range
// wraps ErrInvalidArgument) and continues with the chosen candidate's API
// and release. Discovery errors are returned as Discover gives them.
func (c *Client) FullFlow(ctx context.Context, t tei.TEI, o FlowOptions) (*FlowResult, error) {
	results, err := c.Discover(ctx, t)
	if err != nil {
		return nil, err
	}
	switch {
	case len(results) == 0:
		return nil, fmt.Errorf("full flow: %w: discovery returned no result", ErrInvalidArgument)
	case len(results) == 1:
		base, err := c.SelectServer(results[0])
		if err != nil {
			return nil, err
		}
		a, err := c.API(base)
		if err != nil {
			return nil, fmt.Errorf("full flow: %w", err)
		}
		return c.flow(ctx, a, results[0].ProductReleaseUUID, nil, o)
	case o.Select == nil:
		return nil, &AmbiguousError{Results: results}
	}
	cands, err := c.Candidates(ctx, results)
	if err != nil {
		return nil, err
	}
	i, err := o.Select(ctx, cands)
	if err != nil {
		return nil, fmt.Errorf("full flow: selecting a candidate: %w", err)
	}
	if i < 0 || i >= len(cands) {
		return nil, fmt.Errorf("full flow: %w: Select returned %d for %d candidates", ErrInvalidArgument, i, len(cands))
	}
	return c.flow(ctx, cands[i].API, cands[i].Result.ProductReleaseUUID, cands[i].Release, o)
}

// Candidates loads, for each discovery result, the server SelectServer
// picks, its API and the product release there: one product-release
// request per result, in order. More than Limits.DiscoveryResults results
// (a caller may pass results it did not get from Discover) is
// ErrTooManyResults before any request. The first failure (a refused
// server, a failed request) is returned, naming the result's index.
func (c *Client) Candidates(ctx context.Context, results []DiscoveryResult) ([]Candidate, error) {
	const op = "loading candidates"
	if len(results) > c.limits.DiscoveryResults {
		return nil, fmt.Errorf("%s: %w: %d results, at most %d", op, ErrTooManyResults, len(results), c.limits.DiscoveryResults)
	}
	cands := make([]Candidate, 0, len(results))
	for i, r := range results {
		base, err := c.SelectServer(r)
		if err != nil {
			return nil, fmt.Errorf("%s: result %d: %w", op, i, err)
		}
		a, err := c.API(base)
		if err != nil {
			return nil, fmt.Errorf("%s: result %d: %w", op, i, err)
		}
		rel, err := a.GetProductRelease(ctx, r.ProductReleaseUUID)
		if err != nil {
			return nil, fmt.Errorf("%s: result %d: %w", op, i, err)
		}
		cands = append(cands, Candidate{Result: r, API: a, Release: rel})
	}
	return cands, nil
}

// FlowFromRelease reads product release release at a with its lifecycle
// and components. The release's CLE is nil when the server answers
// NOT_IMPLEMENTED or OBJECT_UNKNOWN; another CLE error (a failure to obtain
// an access token, ErrNoAccessToken, included), or any error on the release
// itself, is returned. More component refs than
// Limits.FlowComponents is ErrTooManyComponents before any component
// request (never a silent truncation). For each ref, in order: a pinned ref
// reads that component release; an unpinned one reads the component and
// its newest release (ListComponentReleases sorted by createdDate
// descending, page size 1; a component with no release fails with an error
// wrapping ErrObjectUnknown), then that release. Then the component
// release's CLE, as for the product release. A component's failure is
// recorded in its Err and the walk continues; the caller's context ending
// ends the walk with ctx.Err().
func (c *Client) FlowFromRelease(ctx context.Context, a *API, release uuid.UUID, o FlowOptions) (*FlowResult, error) {
	if a == nil {
		return nil, fmt.Errorf("full flow: %w: nil API", ErrInvalidArgument)
	}
	return c.flow(ctx, a, release, nil, o)
}

// flow is FlowFromRelease with the product release already read (rel) or
// not (nil).
func (c *Client) flow(ctx context.Context, a *API, release uuid.UUID, rel *teaapi.ProductReleaseWithCollection, o FlowOptions) (*FlowResult, error) {
	if rel == nil {
		var err error
		if rel, err = a.GetProductRelease(ctx, release); err != nil {
			return nil, err
		}
	}
	res := &FlowResult{API: a, Release: rel}
	if !o.SkipCLE {
		cle, err := optionalCLE(a.GetProductReleaseCLE(ctx, rel.Uuid))
		if err != nil {
			return nil, err
		}
		res.ReleaseCLE = cle
	}
	if len(rel.Components) > c.limits.FlowComponents {
		return nil, fmt.Errorf("full flow: product release %s: %w: %d component refs, at most %d",
			rel.Uuid, ErrTooManyComponents, len(rel.Components), c.limits.FlowComponents)
	}
	res.Components = make([]FlowComponent, 0, len(rel.Components))
	for _, ref := range rel.Components {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("full flow: %w", err)
		}
		res.Components = append(res.Components, a.flowComponent(ctx, ref, o))
	}
	return res, nil
}

// flowComponent resolves one component ref; failures go into Err.
func (a *API) flowComponent(ctx context.Context, ref teaapi.ComponentRef, o FlowOptions) FlowComponent {
	fc := FlowComponent{Ref: ref, Pinned: ref.Release != nil}
	relID := uuid.Nil
	if fc.Pinned {
		relID = *ref.Release
	} else {
		comp, err := a.GetComponent(ctx, ref.Uuid)
		if err != nil {
			fc.Err = err
			return fc
		}
		fc.Component = comp
		page, err := a.ListComponentReleases(ctx, ref.Uuid, ReleasePage{
			Page:      Page{PageSize: 1, SortOrder: SortDesc},
			SortField: ReleaseSortCreatedDate,
		})
		if err != nil {
			fc.Err = err
			return fc
		}
		if len(page.Results) == 0 {
			fc.Err = fmt.Errorf("listing releases of component %s: %w: the component lists no release", ref.Uuid, ErrObjectUnknown)
			return fc
		}
		relID = page.Results[0].Uuid
	}
	cr, err := a.GetComponentRelease(ctx, relID)
	if err != nil {
		fc.Err = err
		return fc
	}
	fc.Release = cr
	if !o.SkipCLE {
		fc.CLE, fc.Err = optionalCLE(a.GetComponentReleaseCLE(ctx, cr.Uuid))
	}
	return fc
}

// optionalCLE turns NOT_IMPLEMENTED and OBJECT_UNKNOWN into no CLE. A
// failure to obtain an access token is returned: it says nothing about the
// release (a 404 from /token wraps ErrNotImplemented too).
func optionalCLE(cle *teaapi.Cle, err error) (*teaapi.Cle, error) {
	if errors.Is(err, ErrNoAccessToken) {
		return cle, err
	}
	if errors.Is(err, ErrNotImplemented) || errors.Is(err, ErrObjectUnknown) {
		return nil, nil
	}
	return cle, err
}
