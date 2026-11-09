package tea

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"iter"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/oolong-project/tea-client-go/teaapi"
)

// gitBlobID is the git object id of a blob: sha1("blob <len>\0" + bytes).
func gitBlobID(b []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(b))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// Case 1: the pinned files are byte copies of upstream, and the generator
// is not in go.mod.
func TestSpecPin(t *testing.T) {
	for path, want := range map[string]string{
		"spec/openapi.yaml":               "c96baa3e102c195895643fab81ae468ee54b8182",
		"spec/tea-well-known.schema.json": "b0804f1ae79c8ec72adea6d5c12e8f75f6036729",
		"spec/LICENSE":                    "0808751c23d827d483dc3673d6e3f49514e49d1f",
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := gitBlobID(b); got != want {
			t.Errorf("%s: blob %s, want %s", path, got, want)
		}
	}
	if got := gitBlobID([]byte("")); got != "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" {
		t.Fatalf("gitBlobID of empty blob = %s", got)
	}
}

func TestGoModHasNoToolLine(t *testing.T) {
	f, err := os.Open("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "tool" || strings.HasPrefix(line, "tool ") || strings.HasPrefix(line, "tool(") {
			t.Errorf("go.mod has a tool line %q; the generator belongs in tools.mod", line)
		}
	}
	tools, err := os.ReadFile("tools.mod")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tools), "tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen") {
		t.Error("tools.mod does not pin the generator")
	}
}

// Case 2: every one of the 28 operations has a method on the generated
// client interface (compile-time).
var (
	_ = teaapi.ClientInterface.Discover
	_ = teaapi.ClientInterface.QueryProducts
	_ = teaapi.ClientInterface.GetProduct
	_ = teaapi.ClientInterface.ListProductReleases
	_ = teaapi.ClientInterface.GetProductCle
	_ = teaapi.ClientInterface.QueryProductReleases
	_ = teaapi.ClientInterface.GetProductRelease
	_ = teaapi.ClientInterface.GetProductReleaseCle
	_ = teaapi.ClientInterface.ListProductReleaseCollections
	_ = teaapi.ClientInterface.GetLatestProductReleaseCollection
	_ = teaapi.ClientInterface.GetProductReleaseCollectionByVersion
	_ = teaapi.ClientInterface.QueryComponents
	_ = teaapi.ClientInterface.GetComponent
	_ = teaapi.ClientInterface.ListComponentReleases
	_ = teaapi.ClientInterface.GetComponentCle
	_ = teaapi.ClientInterface.QueryComponentReleases
	_ = teaapi.ClientInterface.GetComponentRelease
	_ = teaapi.ClientInterface.GetComponentReleaseCle
	_ = teaapi.ClientInterface.ListComponentReleaseCollections
	_ = teaapi.ClientInterface.GetLatestComponentReleaseCollection
	_ = teaapi.ClientInterface.GetComponentReleaseCollectionByVersion
	_ = teaapi.ClientInterface.GetLatestArtifact
	_ = teaapi.ClientInterface.DownloadLatestArtifact
	_ = teaapi.ClientInterface.DownloadLatestArtifactSignature
	_ = teaapi.ClientInterface.GetArtifactByVersion
	_ = teaapi.ClientInterface.DownloadArtifactByVersion
	_ = teaapi.ClientInterface.DownloadArtifactSignatureByVersion
	_ = teaapi.ClientInterface.RequestTokenWithBody
	_ = teaapi.ClientInterface.RequestTokenWithFormdataBody
)

// Case 2: the tea.API wrapper set of 3.5 built by this task (the download
// helpers of 3.8 are added with the downloads).
var (
	_ func(*API) APIBase                                                                                     = (*API).Base
	_ func(*API, context.Context, uuid.UUID) (*teaapi.Product, error)                                        = (*API).GetProduct
	_ func(*API, context.Context, ProductQuery) (*teaapi.PaginatedProductResponse, error)                    = (*API).QueryProducts
	_ func(*API, context.Context, uuid.UUID, ReleasePage) (*teaapi.PaginatedProductReleaseResponse, error)   = (*API).ListProductReleases
	_ func(*API, context.Context, uuid.UUID) (*teaapi.Cle, error)                                            = (*API).GetProductCLE
	_ func(*API, context.Context, ReleaseQuery) (*teaapi.PaginatedProductReleaseResponse, error)             = (*API).QueryProductReleases
	_ func(*API, context.Context, uuid.UUID) (*teaapi.ProductReleaseWithCollection, error)                   = (*API).GetProductRelease
	_ func(*API, context.Context, uuid.UUID) (*teaapi.Cle, error)                                            = (*API).GetProductReleaseCLE
	_ func(*API, context.Context, uuid.UUID, CollectionPage) (*teaapi.PaginatedCollectionResponse, error)    = (*API).ListProductReleaseCollections
	_ func(*API, context.Context, uuid.UUID) (*teaapi.Collection, error)                                     = (*API).GetLatestProductReleaseCollection
	_ func(*API, context.Context, uuid.UUID, int) (*teaapi.Collection, error)                                = (*API).GetProductReleaseCollection
	_ func(*API, context.Context, uuid.UUID) (*teaapi.Component, error)                                      = (*API).GetComponent
	_ func(*API, context.Context, ComponentQuery) (*teaapi.PaginatedComponentResponse, error)                = (*API).QueryComponents
	_ func(*API, context.Context, uuid.UUID, ReleasePage) (*teaapi.PaginatedComponentReleaseResponse, error) = (*API).ListComponentReleases
	_ func(*API, context.Context, uuid.UUID) (*teaapi.Cle, error)                                            = (*API).GetComponentCLE
	_ func(*API, context.Context, ReleaseQuery) (*teaapi.PaginatedComponentReleaseResponse, error)           = (*API).QueryComponentReleases
	_ func(*API, context.Context, uuid.UUID) (*teaapi.ComponentReleaseWithCollection, error)                 = (*API).GetComponentRelease
	_ func(*API, context.Context, uuid.UUID) (*teaapi.Cle, error)                                            = (*API).GetComponentReleaseCLE
	_ func(*API, context.Context, uuid.UUID, CollectionPage) (*teaapi.PaginatedCollectionResponse, error)    = (*API).ListComponentReleaseCollections
	_ func(*API, context.Context, uuid.UUID) (*teaapi.Collection, error)                                     = (*API).GetLatestComponentReleaseCollection
	_ func(*API, context.Context, uuid.UUID, int) (*teaapi.Collection, error)                                = (*API).GetComponentReleaseCollection
	_ func(*API, context.Context, uuid.UUID) (*teaapi.Artifact, error)                                       = (*API).GetLatestArtifact
	_ func(*API, context.Context, uuid.UUID, int) (*teaapi.Artifact, error)                                  = (*API).GetArtifact
	_ func(*API, context.Context, string, string) (*teaapi.TokenResponse, error)                             = (*API).RequestToken
	_ func(*API) *teaapi.ClientWithResponses                                                                 = (*API).Generated
	_ func(*API, context.Context, ProductQuery) iter.Seq2[teaapi.Product, error]                             = (*API).AllProducts
	_ func(*API, context.Context, ComponentQuery) iter.Seq2[teaapi.Component, error]                         = (*API).AllComponents
	_ func(*API, context.Context, ReleaseQuery) iter.Seq2[teaapi.ProductRelease, error]                      = (*API).AllProductReleases
	_ func(*API, context.Context, ReleaseQuery) iter.Seq2[teaapi.ComponentRelease, error]                    = (*API).AllComponentReleases
	_ func(*API, context.Context, uuid.UUID, ReleasePage) iter.Seq2[teaapi.ProductRelease, error]            = (*API).AllProductReleasesOf
	_ func(*API, context.Context, uuid.UUID, ReleasePage) iter.Seq2[teaapi.ComponentRelease, error]          = (*API).AllComponentReleasesOf
	_ func(*API, context.Context, uuid.UUID, CollectionPage) iter.Seq2[teaapi.Collection, error]             = (*API).AllProductReleaseCollectionsOf
	_ func(*API, context.Context, uuid.UUID, CollectionPage) iter.Seq2[teaapi.Collection, error]             = (*API).AllComponentReleaseCollectionsOf
)
