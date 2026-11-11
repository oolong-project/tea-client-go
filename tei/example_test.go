package tei_test

import (
	"fmt"
	"log"

	"github.com/oolong-project/tea-client-go/tei"
)

func ExampleParse() {
	t, err := tei.Parse("tei://demo.rearmhq.com/uuid/b9f115fb-6688-4a3f-a262-3acc04e1fc9e")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(t.Domain(), t.Type(), t.ID())
	// Output: demo.rearmhq.com uuid b9f115fb-6688-4a3f-a262-3acc04e1fc9e
}

func ExampleParseCompat() {
	t, legacy, err := tei.ParseCompat("urn:tei:uuid:products.example.com:d4d9f54a-abcf-11ee-ac79-1a52914d44b1")
	if err != nil {
		log.Fatal(err)
	}
	if legacy {
		fmt.Println("warning: legacy urn:tei: form; use", t)
	}
	// Output: warning: legacy urn:tei: form; use tei://products.example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1
}
