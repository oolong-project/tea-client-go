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
