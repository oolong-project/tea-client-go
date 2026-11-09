//go:build live

package tea_test

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	tea "github.com/oolong-project/tea-client-go"
	"github.com/oolong-project/tea-client-go/teaapi"
	"github.com/oolong-project/tea-client-go/tei"
)

// The live suite runs against the public ReARM demo only with the build tag
// live and TEA_LIVE=1, so the default go test ./... never reaches the
// network: TEA_LIVE=1 go test -tags live -run Live ./...
const liveTEI = "tei://demo.rearmhq.com/uuid/b9f115fb-6688-4a3f-a262-3acc04e1fc9e"

func liveOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("TEA_LIVE") != "1" {
		t.Skip("live test: set TEA_LIVE=1 (and -tags live) to run it against the public demo")
	}
}

// Case 1: discovery with default options (https only, anonymous). Only the
// structure is asserted, not which release the demo returns.
func TestLiveDiscover(t *testing.T) {
	liveOnly(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c, err := tea.New()
	if err != nil {
		t.Fatal(err)
	}
	tv, err := tei.Parse(liveTEI)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Discover(ctx, tv)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) == 0 || len(res) > 32 {
		t.Fatalf("%d results, want 1 to Limits.DiscoveryResults (32)", len(res))
	}
	for i, r := range res {
		if r.ProductReleaseUUID == uuid.Nil || len(r.Servers) == 0 {
			t.Errorf("result %d: uuid %s, %d servers", i, r.ProductReleaseUUID, len(r.Servers))
			continue
		}
		base, err := c.SelectServer(r)
		if err != nil {
			t.Errorf("result %d: SelectServer: %v", i, err)
			continue
		}
		if !strings.HasPrefix(base.RootURL(), "https://") || base.Version() != "1.0.0" {
			t.Errorf("result %d: selected %s version %s, want an https base with 1.0.0", i, base.RootURL(), base.Version())
		}
	}
}

// liveTyped reports whether err is one of the client's typed errors.
func liveTyped(err error) bool {
	var (
		ae *tea.APIError
		ue *tea.UnexpectedResponseError
		pe *tea.URLPolicyError
	)
	return errors.As(err, &ae) || errors.As(err, &ue) || errors.As(err, &pe) ||
		errors.Is(err, tea.ErrTimeout) || errors.Is(err, tea.ErrResponseTooLarge) || errors.Is(err, tea.ErrObjectUnknown)
}

// liveFlow runs Discover and FullFlow (Select chooses 0 and records the
// candidate) and returns the flow and the discovery result it is for.
func liveFlow(t *testing.T, ctx context.Context, c *tea.Client) (*tea.FlowResult, tea.DiscoveryResult) {
	t.Helper()
	tv, err := tei.Parse(liveTEI)
	if err != nil {
		t.Fatal(err)
	}
	results, err := c.Discover(ctx, tv)
	if err != nil {
		t.Fatal(err)
	}
	var chosen *tea.Candidate
	res, err := c.FullFlow(ctx, tv, tea.FlowOptions{Select: func(_ context.Context, cands []tea.Candidate) (int, error) {
		chosen = &cands[0]
		return 0, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if chosen != nil {
		return res, chosen.Result
	}
	if len(results) != 1 {
		t.Fatalf("Select was not called, but discovery returned %d results", len(results))
	}
	return res, results[0]
}

// Cases 2 to 4: the full flow, a verified download and an unknown product,
// with default options. Only structure and the API's contracts are
// asserted, not the demo's data.
func TestLiveFlowAndDownload(t *testing.T) {
	liveOnly(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c, err := tea.New()
	if err != nil {
		t.Fatal(err)
	}
	res, result := liveFlow(t, ctx, c)

	// Case 2.
	r := res.Release
	if r.Uuid != result.ProductReleaseUUID {
		t.Errorf("release %s fetched for discovery result %s", r.Uuid, result.ProductReleaseUUID)
	}
	if r.Version == "" || r.LatestCollection.Version < 1 {
		t.Errorf("release version %q, latest collection version %d", r.Version, r.LatestCollection.Version)
	}
	for i, comp := range res.Components {
		if comp.Release == nil && (comp.Err == nil || !liveTyped(comp.Err)) {
			t.Errorf("component %d: no release and error %v (want a typed error)", i, comp.Err)
		}
		if comp.Err != nil && !liveTyped(comp.Err) {
			t.Errorf("component %d: untyped error %v", i, comp.Err)
		}
	}

	// Case 3: the first format with a supported strong checksum, within a
	// 64 MiB cap, product release first, then the components.
	t.Run("download", func(t *testing.T) {
		type candidate struct {
			api *tea.API
			art teaapi.Artifact
			f   teaapi.ArtifactFormat
		}
		var cands []candidate
		add := func(arts []teaapi.Artifact) {
			for _, art := range arts {
				for _, f := range art.Formats {
					if f.Checksums == nil {
						continue
					}
					for _, s := range *f.Checksums {
						if s.AlgType != teaapi.SHA1 && s.AlgType != teaapi.BLAKE3 && s.AlgType.Valid() {
							cands = append(cands, candidate{res.API, art, f})
							break
						}
					}
				}
			}
		}
		add(r.LatestCollection.Artifacts)
		for _, comp := range res.Components {
			if comp.Release != nil {
				add(comp.Release.LatestCollection.Artifacts)
			}
		}
		for _, cd := range cands {
			dr, err := cd.api.DownloadArtifact(ctx, tea.ArtifactRef{UUID: cd.art.Uuid, Version: cd.art.Version}, cd.f, io.Discard, tea.DownloadOptions{MaxBytes: 64 << 20})
			if errors.Is(err, tea.ErrResponseTooLarge) {
				continue
			}
			if err != nil {
				t.Fatalf("artifact %s version %d (%s): %v", cd.art.Uuid, cd.art.Version, cd.f.MediaType, err)
			}
			if dr.Bytes == 0 || len(dr.Verified) == 0 {
				t.Errorf("download %+v", dr)
			}
			t.Logf("verified %d bytes of %s version %d (%s) with %v", dr.Bytes, cd.art.Uuid, cd.art.Version, cd.f.MediaType, dr.Verified)
			return
		}
		t.Skipf("none of %d formats with a supported checksum is within the 64 MiB cap", len(cands))
	})

	// Case 4.
	if _, err := res.API.GetProduct(ctx, uuid.MustParse("99999999-9999-4999-8999-999999999999")); !errors.Is(err, tea.ErrObjectUnknown) {
		t.Errorf("unknown product: %v, want ErrObjectUnknown", err)
	}
}
