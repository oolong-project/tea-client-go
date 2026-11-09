package tea

import (
	"context"
	"errors"
	"net/http"
	"runtime/debug"
	"strings"
	"testing"
)

// Case 8: option values New refuses.
func TestNewRefusesOptions(t *testing.T) {
	cases := map[string]Option{
		"https allowance":         WithInsecureHTTPBase("https://example.com"),
		"relative allowance":      WithInsecureHTTPBase("/tea"),
		"host-less allowance":     WithInsecureHTTPBase("http:///tea"),
		"userinfo allowance":      WithInsecureHTTPBase("http://user:pw@example.com"),
		"query allowance":         WithInsecureHTTPBase("http://example.com/tea?x=1"),
		"empty query allowance":   WithInsecureHTTPBase("http://example.com/tea?"),
		"fragment allowance":      WithInsecureHTTPBase("http://example.com/tea#f"),
		"trailing slash":          WithInsecureHTTPBase("http://example.com/tea/"),
		"origin trailing slash":   WithInsecureHTTPBase("http://example.com/"),
		"dot segment":             WithInsecureHTTPBase("http://example.com/a/../b"),
		"encoded dot segment":     WithInsecureHTTPBase("http://example.com/a/%2E%2e/b"),
		"single dot segment":      WithInsecureHTTPBase("http://example.com/a/./b"),
		"nil http client":         WithHTTPClient(nil),
		"empty user agent":        WithUserAgent(""),
		"negative limit":          WithLimits(Limits{JSONBytes: -1}),
		"zero attempts":           WithDiscoveryAttempts(0, 0),
		"bad well-known domain":   WithWellKnownLocation("exa_mple.com", "https://example.com"),
		"bad well-known location": WithWellKnownLocation("example.com", "https://example.com/x/"),
		"empty bearer":            WithBearerToken("https://example.com/tea", ""),
		"nil trace":               WithTrace(nil),
	}
	for name, opt := range cases {
		if _, err := New(opt); !errors.Is(err, ErrInvalidOption) {
			t.Errorf("%s: New = %v, want ErrInvalidOption", name, err)
		}
	}

	// A bearer on an http root needs an allowance covering it.
	if _, err := New(WithBearerToken("http://127.0.0.1:8080/tea", "tok")); !errors.Is(err, ErrInvalidOption) {
		t.Errorf("http bearer root without allowance: %v", err)
	}
	if _, err := New(WithInsecureHTTPBase("http://127.0.0.1:8081"), WithBearerToken("http://127.0.0.1:8080/tea", "tok")); !errors.Is(err, ErrInvalidOption) {
		t.Errorf("http bearer root under another port's allowance: %v", err)
	}
	if _, err := New(WithInsecureHTTPBase("http://127.0.0.1:8080/teapot"), WithBearerToken("http://127.0.0.1:8080/tea", "tok")); !errors.Is(err, ErrInvalidOption) {
		t.Errorf("http bearer root beside the allowance path: %v", err)
	}
	if _, err := New(WithBearerToken("http://127.0.0.1:8080/tea", "tok"), WithInsecureHTTPBase("http://127.0.0.1:8080")); err != nil {
		t.Errorf("http bearer root under an allowance (any option order): %v", err)
	}
	if _, err := New(WithWellKnownLocation("localhost", "http://127.0.0.1:8080")); !errors.Is(err, ErrInvalidOption) {
		t.Errorf("http well-known location without allowance: %v", err)
	}
	// The secret never appears in an option error.
	_, err := New(WithBearerToken("http://127.0.0.1:8080/tea", "s3cr3t-token-value"))
	if err == nil || strings.Contains(err.Error(), "s3cr3t-token-value") {
		t.Errorf("option error leaks the token: %v", err)
	}

	// Accepted forms.
	for name, opt := range map[string]Option{
		"origin":        WithInsecureHTTPBase("http://127.0.0.1:8080"),
		"path":          WithInsecureHTTPBase("http://127.0.0.1:8080/tea"),
		"https bearer":  WithBearerToken("https://example.com/tea", "tok"),
		"limits":        WithLimits(Limits{JSONBytes: 10, CallTimeout: -1}),
		"attempts":      WithDiscoveryAttempts(3, 0),
		"https wk":      WithWellKnownLocation("Example.com", "https://example.com:8443"),
		"user agent":    WithUserAgent("x/1"),
		"trace":         WithTrace(func(TraceEvent) {}),
		"caller client": WithHTTPClient(&http.Client{}),
	} {
		if _, err := New(opt); err != nil {
			t.Errorf("%s: New = %v", name, err)
		}
	}
}

// Case 40: the User-Agent header.
func TestUserAgent(t *testing.T) {
	h := newCounter(jsonHandler(`{"uuid":"` + productID.String() + `","name":"p","identifiers":[]}`))
	srv := startHTTP(t, h)
	a := newTestAPI(t, srv.URL, "/tea")
	if _, err := a.GetProduct(context.Background(), productID); err != nil {
		t.Fatal(err)
	}
	if got := h.lastReq().Header.Get("User-Agent"); got != "tea-client-go/devel" {
		t.Errorf("default User-Agent = %q", got)
	}

	b := newTestAPI(t, srv.URL, "/tea", WithUserAgent("x/1"))
	if _, err := b.GetProduct(context.Background(), productID); err != nil {
		t.Fatal(err)
	}
	if got := h.lastReq().Header.Get("User-Agent"); got != "x/1" {
		t.Errorf("WithUserAgent: User-Agent = %q", got)
	}
}

func TestModuleVersion(t *testing.T) {
	dep := func(v string, repl *debug.Module) *debug.BuildInfo {
		return &debug.BuildInfo{
			Main: debug.Module{Path: "example.com/app", Version: "v9.9.9"},
			Deps: []*debug.Module{{Path: "example.com/other", Version: "v1.0.0"}, {Path: modulePath, Version: v, Replace: repl}},
		}
	}
	cases := []struct {
		name string
		bi   *debug.BuildInfo
		ok   bool
		want string
	}{
		{"dependency", dep("v0.3.1", nil), true, "v0.3.1"},
		{"replaced with version", dep("v0.3.1", &debug.Module{Path: "example.com/fork", Version: "v0.3.2"}), true, "v0.3.2"},
		{"replaced with directory", dep("v0.3.1", &debug.Module{Path: "../fork"}), true, "v0.3.1"},
		{"main module devel", &debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "(devel)"}}, true, "devel"},
		{"main module tagged", &debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "v0.4.0"}}, true, "v0.4.0"},
		{"not found", &debug.BuildInfo{Main: debug.Module{Path: "example.com/app"}}, true, "devel"},
		{"no build info", nil, false, "devel"},
	}
	for _, c := range cases {
		if got := moduleVersion(c.bi, c.ok); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
