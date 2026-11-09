//go:build live

package tea_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	tea "github.com/oolong-project/tea-client-go"
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
