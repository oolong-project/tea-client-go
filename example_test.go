package tea_test

import (
	"context"
	"fmt"
	"log"

	"github.com/google/uuid"

	tea "github.com/oolong-project/tea-client-go"
	"github.com/oolong-project/tea-client-go/tei"
)

// Examples have no Output line: go test compiles them but does not run
// them, so they never reach the network.

func Example() {
	ctx := context.Background()
	c, err := tea.New()
	if err != nil {
		log.Fatal(err)
	}
	base, err := tea.ParseAPIBase("https://demo.rearmhq.com/tea", "1.0.0")
	if err != nil {
		log.Fatal(err)
	}
	api, err := c.API(base)
	if err != nil {
		log.Fatal(err)
	}
	release, err := api.GetProductRelease(ctx, uuid.MustParse("b9f115fb-6688-4a3f-a262-3acc04e1fc9e"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(release.Version, release.LatestCollection.Version)
}

func ExampleAPI_AllProducts() {
	ctx := context.Background()
	c, err := tea.New()
	if err != nil {
		log.Fatal(err)
	}
	base, err := tea.ParseAPIBase("https://demo.rearmhq.com/tea", "1.0.0")
	if err != nil {
		log.Fatal(err)
	}
	api, err := c.API(base)
	if err != nil {
		log.Fatal(err)
	}
	for p, err := range api.AllProducts(ctx, tea.ProductQuery{Page: tea.Page{PageSize: 50}}) {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(p.Uuid, p.Name)
	}
}

func ExampleWithInsecureHTTPBase() {
	// A local server over plain http: the allowance covers the origin and
	// every path under it, and nothing else.
	c, err := tea.New(
		tea.WithInsecureHTTPBase("http://localhost:8086"),
		tea.WithWellKnownLocation("localhost", "http://localhost:8086"),
		tea.WithBearerToken("http://localhost:8086/tea", "a-token"),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = c
}

func ExampleClient_Discover() {
	ctx := context.Background()
	c, err := tea.New()
	if err != nil {
		log.Fatal(err)
	}
	t, err := tei.Parse("tei://demo.rearmhq.com/uuid/b9f115fb-6688-4a3f-a262-3acc04e1fc9e")
	if err != nil {
		log.Fatal(err)
	}
	results, err := c.Discover(ctx, t) // every result, in the server's order
	if err != nil {
		log.Fatal(err)
	}
	base, err := c.SelectServer(results[0]) // a servers[] root, not the /discovery base
	if err != nil {
		log.Fatal(err)
	}
	api, err := c.API(base)
	if err != nil {
		log.Fatal(err)
	}
	release, err := api.GetProductRelease(ctx, results[0].ProductReleaseUUID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(release.Version)
}

func ExampleClient_FullFlow() {
	ctx := context.Background()
	c, err := tea.New()
	if err != nil {
		log.Fatal(err)
	}
	t, err := tei.Parse("tei://demo.rearmhq.com/uuid/b9f115fb-6688-4a3f-a262-3acc04e1fc9e")
	if err != nil {
		log.Fatal(err)
	}
	res, err := c.FullFlow(ctx, t, tea.FlowOptions{})
	if err != nil {
		log.Fatal(err) // *tea.AmbiguousError when discovery returned several results
	}
	fmt.Println(*res.Release.ProductName, res.Release.Version)
	for _, comp := range res.Components {
		if comp.Err != nil {
			fmt.Println("component", comp.Ref.Uuid, "failed:", comp.Err)
			continue
		}
		fmt.Println("component release", comp.Release.Uuid, comp.Release.Version)
	}
}

func ExampleAPI_DownloadArtifactToFile() {
	ctx := context.Background()
	c, err := tea.New()
	if err != nil {
		log.Fatal(err)
	}
	base, err := tea.ParseAPIBase("https://demo.rearmhq.com/tea", "1.0.0")
	if err != nil {
		log.Fatal(err)
	}
	api, err := c.API(base)
	if err != nil {
		log.Fatal(err)
	}
	release, err := api.GetProductRelease(ctx, uuid.MustParse("b9f115fb-6688-4a3f-a262-3acc04e1fc9e"))
	if err != nil {
		log.Fatal(err)
	}
	for _, art := range release.LatestCollection.Artifacts {
		for _, f := range art.Formats {
			// Written to a temporary file, verified against the format's
			// checksums, then renamed into place; nothing is left on failure.
			res, err := api.DownloadArtifactToFile(ctx, tea.ArtifactRef{UUID: art.Uuid, Version: art.Version}, f, "sbom.json", tea.DownloadOptions{})
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(res.Bytes, res.Verified)
			return
		}
	}
}

func ExampleWithAPIKey() {
	// The key is exchanged for a token only when the server asks for one
	// (a 401 with a Bearer challenge under the root), and the token is sent
	// under that root only.
	c, err := tea.New(tea.WithAPIKey("https://tea.example.com/tea", "key-id", "key-secret"))
	if err != nil {
		log.Fatal(err)
	}
	_ = c
}
