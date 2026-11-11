package tea

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// No refusal, error or trace event repeats userinfo, a query or a fragment
// of a URL, nor a secret in a URL that does not parse.

// leaks reports the first of secrets that s holds.
func leaks(s string, secrets ...string) (string, bool) {
	for _, x := range secrets {
		if strings.Contains(s, x) {
			return x, true
		}
	}
	return "", false
}

// T-27: every option that takes a URL, and ParseAPIBase.
func TestRefusedURLArgumentsAreNotRepeated(t *testing.T) {
	bad := []string{
		"https://alice:s3cr3t-pw@example.com/tea",
		"https://alice:s3cr3t-pw@example.com/tea/",
		"https://alice:s3cr3t-pw@example.com/tea?x=1",
		"https://alice:s3cr3t-pw@example.com/tea/%zz",
		"https://s3cr3t-token@example.com/tea",
		"alice:s3cr3t-pw@example.com/tea",
		"https:///alice:s3cr3t-pw@example.com/tea",
		"https://example.com/tea?sig=s3cr3t-sig",
		"https://example.com/tea#s3cr3t-frag",
		"https://example.com/%zz/s3cr3t-path",
	}
	type refusal struct {
		name string
		err  error
		want error
	}
	refuse := func(raw string) []refusal {
		var out []refusal
		for name, opt := range map[string]Option{
			"WithAPIKey":            WithAPIKey(raw, "id", "secret"),
			"WithPreemptiveAPIKey":  WithPreemptiveAPIKey(raw, "id", "secret"),
			"WithBearerToken":       WithBearerToken(raw, "token"),
			"WithInsecureHTTPBase":  WithInsecureHTTPBase(raw),
			"WithWellKnownLocation": WithWellKnownLocation("example.com", raw),
		} {
			_, err := New(opt)
			out = append(out, refusal{name, err, ErrInvalidOption})
		}
		_, err := ParseAPIBase(raw, "1.0.0")
		return append(out, refusal{"ParseAPIBase", err, nil})
	}
	for _, raw := range bad {
		for _, r := range refuse(raw) {
			if r.err == nil || (r.want != nil && !errors.Is(r.err, r.want)) {
				t.Errorf("%s(%q): %v, want a refusal", r.name, raw, r.err)
				continue
			}
			if r.want == nil && !errors.Is(r.err, ErrInvalidArgument) && !errors.Is(r.err, ErrInsecureURL) {
				t.Errorf("%s(%q): %v, want ErrInvalidArgument", r.name, raw, r.err)
			}
			for _, s := range []string{r.err.Error(), fmt.Sprintf("%+v", r.err)} {
				if x, ok := leaks(s, "s3cr3t", "alice"); ok {
					t.Errorf("%s(%q): %q holds %q", r.name, raw, s, x)
				}
			}
		}
	}
	// Swapped arguments: the token where the root belongs.
	_, err := New(WithBearerToken("s3cr3t-token-value", "https://example.com/tea"))
	if !errors.Is(err, ErrInvalidOption) || strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("swapped WithBearerToken: %v", err)
	}
	// A URL with nothing secret is still named.
	for _, r := range refuse("https://example.com/tea/") {
		if r.err == nil || !strings.Contains(r.err.Error(), `"https://example.com/tea/"`) {
			t.Errorf("%s: %v, want the URL named", r.name, r.err)
		}
	}
}

// T-28: the WithWellKnownLocation domain: neither userinfo nor a query or a
// fragment is repeated.
func TestRefusedWellKnownDomainIsNotRepeated(t *testing.T) {
	for _, domain := range []string{
		"alice:s3cr3t-pw@example.com",
		"https://example.com/tea?sig=s3cr3t-sig",
		"example.com#s3cr3t-frag",
	} {
		_, err := New(WithWellKnownLocation(domain, "https://example.com"))
		if !errors.Is(err, ErrInvalidOption) {
			t.Errorf("%q: %v, want ErrInvalidOption", domain, err)
			continue
		}
		if x, ok := leaks(err.Error(), "s3cr3t", "alice"); ok {
			t.Errorf("%q: %q holds %q", domain, err, x)
		}
	}
	_, err := New(WithWellKnownLocation("exa mple.com", "https://example.com"))
	if err == nil || !strings.Contains(err.Error(), `"exa mple.com"`) {
		t.Errorf("a plain bad domain: %v, want it named", err)
	}
}

// T-29: a redirect whose Location does not parse: net/http would quote the
// header value in its own error; the transport refuses it first.
func TestUnparsableRedirectLocationIsNotRepeated(t *testing.T) {
	g := newRig(t, modeFilter)
	second := newCounter(nil)
	secondURL := g.server("localhost", second)
	loc := "http://bob:s3cr3t-loc@" + strings.TrimPrefix(secondURL, "http://") + "/%zz"
	redirect := func(w http.ResponseWriter) {
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusFound)
	}
	g.r.set(func(s *tokenRoot) {
		s.hook = func(w http.ResponseWriter, r *http.Request) bool {
			redirect(w)
			return true
		}
	})
	check := func(what string, texts ...string) {
		t.Helper()
		for _, s := range texts {
			if x, ok := leaks(s, "s3cr3t", "bob"); ok {
				t.Errorf("%s: %q holds %q", what, s, x)
			}
		}
	}

	// (a) an API call.
	c := g.client()
	_, err := g.api(c, g.r.root).GetProductRelease(ctxBG, releaseID)
	var pe *URLPolicyError
	if !errors.As(err, &pe) {
		t.Errorf("(a) API call: %v (%T), want *URLPolicyError", err, err)
	}
	check("(a)", err.Error(), fmt.Sprintf("%+v", err))

	// (b) a /discovery attempt, with a trace observer.
	base, _ := ParseAPIBase(g.r.root, "1.0.0")
	_, err = c.DiscoverPURL(ctxBG, base, "pkg:generic/widget")
	var de *DiscoveryError
	if !errors.As(err, &de) || !errors.As(err, &pe) {
		t.Fatalf("(b) discovery: %v (%T), want a *DiscoveryError of *URLPolicyError attempts", err, err)
	}
	check("(b)", err.Error(), fmt.Sprintf("%+v", err))
	for _, a := range de.Attempts {
		check("(b) attempt", a.URL, a.Reason, a.Err.Error())
	}
	for _, ev := range g.rec.events() {
		check("(b) trace", fmt.Sprintf("%+v", ev))
	}

	// (c) /token, through RequestToken and through the preemptive option.
	_, err = g.api(c, g.r.root).RequestToken(ctxBG, rigKeyID, rigSecret)
	var ue *UnexpectedResponseError
	if !errors.As(err, &ue) || !strings.Contains(err.Error(), "redirect from /token refused") {
		t.Errorf("(c) RequestToken: %v, want *UnexpectedResponseError redirect from /token refused", err)
	}
	check("(c)", err.Error())
	_, a := g.preemptive()
	_, err = a.GetProductRelease(ctxBG, releaseID)
	if !errors.As(err, &ue) || !errors.Is(err, ErrNoAccessToken) {
		t.Errorf("(c) preemptive: %v, want *UnexpectedResponseError and ErrNoAccessToken", err)
	}
	check("(c) preemptive", err.Error())
	if second.count() != 0 {
		t.Errorf("the second server saw %d requests", second.count())
	}
}

// T-30: userinfo in a parsable URL from a server: a redirect from
// /discovery, a servers[].rootUrl, an external artifact url.
func TestServerURLUserinfoIsNotRepeated(t *testing.T) {
	g := newRig(t, modeFilter)
	target := newCounter(nil)
	targetURL := g.server("localhost", target)
	withUser := "http://bob:s3cr3t-ui@" + strings.TrimPrefix(targetURL, "http://")
	mode := &guarded[string]{v: "redirect"}
	g.r.set(func(s *tokenRoot) {
		s.hook = func(w http.ResponseWriter, r *http.Request) bool {
			switch {
			case strings.HasSuffix(r.URL.Path, "/discovery") && mode.get() == "redirect":
				http.Redirect(w, r, withUser+"/tea/v1.0.0/discovery", http.StatusFound)
				return true
			case strings.HasSuffix(r.URL.Path, "/discovery"):
				jsonHandler(resultsJSON(withUser+"/tea", releaseID))(w, r)
				return true
			}
			return false
		}
	})
	c := g.client()
	check := func(what string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: no error", what)
			return
		}
		texts := []string{err.Error(), fmt.Sprintf("%+v", err)}
		var de *DiscoveryError
		if errors.As(err, &de) {
			for _, a := range de.Attempts {
				texts = append(texts, a.URL, a.Reason, a.Err.Error())
			}
		}
		for _, ev := range g.rec.events() {
			texts = append(texts, fmt.Sprintf("%+v", ev))
		}
		for _, s := range texts {
			if x, ok := leaks(s, "s3cr3t", "bob"); ok {
				t.Errorf("%s: %q holds %q", what, s, x)
			}
		}
	}
	base, _ := ParseAPIBase(g.r.root, "1.0.0")
	_, err := c.DiscoverPURL(ctxBG, base, "pkg:generic/widget")
	check("redirect from /discovery", err)
	mode.set("servers")
	_, err = c.DiscoverPURL(ctxBG, base, "pkg:generic/widget")
	check("servers[].rootUrl", err)
	body := []byte(fixtureJSON)
	ext := fmtOf(mtJSON, sha256Sum(body))
	ext.Url = strPtr(withUser + "/files/widget.json")
	_, err = g.api(c, g.r.root).DownloadArtifact(ctxBG, ref3, ext, io.Discard, DownloadOptions{})
	check("external artifact url", err)
	if target.count() != 0 {
		t.Errorf("the userinfo target saw %d requests", target.count())
	}
}
