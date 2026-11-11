package tea

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// What hand-made mutants of the API-key discovery change left alive: the
// texts of the two token failures, a waiter that leaves,
// every redirect status, the Location refusal's URL and cause and the body it
// closes, an anonymous request under the root, the build metadata of an API's
// version, the wording of the refusals, and the roots two credentials share.

// closeTracker is a response body that records its Close.
type closeTracker struct{ closed atomic.Bool }

func (c *closeTracker) Read([]byte) (int, error) { return 0, io.EOF }
func (c *closeTracker) Close() error             { c.closed.Store(true); return nil }

// answerWith is a RoundTripper that answers every request with one response.
type answerWith func(*http.Request) *http.Response

func (f answerWith) RoundTrip(r *http.Request) (*http.Response, error) { return f(r), nil }

func TestTokenFailureTextsNameTheCauseAndWhen(t *testing.T) {
	t.Run("up front", func(t *testing.T) {
		g := newRig(t, modeFilter)
		g.r.set(func(s *tokenRoot) { s.fail = tokenInvalidClient })
		_, a := g.preemptive()
		_, err := a.GetProductRelease(ctxBG, releaseID)
		if g.note(err) == nil || !errors.Is(err, ErrNoAccessToken) {
			t.Fatalf("err = %v, want ErrNoAccessToken", err)
		}
		if !strings.Contains(err.Error(), "obtaining an access token: ") || strings.Contains(err.Error(), "after HTTP 401") {
			t.Errorf("err = %q, want the up-front wording", err)
		}
		if !strings.Contains(err.Error(), "invalid_client") {
			t.Errorf("err = %q, want the cause named", err)
		}
	})
	t.Run("after a 401", func(t *testing.T) {
		g := newRig(t, modeChallenge)
		g.r.set(func(s *tokenRoot) { s.fail = tokenInvalidClient })
		c := g.client(WithAPIKey(g.r.root, rigKeyID, rigSecret))
		_, err := g.api(c, g.r.root).GetProductRelease(ctxBG, releaseID)
		if g.note(err) == nil || !errors.Is(err, ErrNoAccessToken) {
			t.Fatalf("err = %v, want ErrNoAccessToken", err)
		}
		if !strings.Contains(err.Error(), "obtaining an access token after HTTP 401: ") {
			t.Errorf("err = %q, want the after-401 wording", err)
		}
		if !strings.Contains(err.Error(), "invalid_client") {
			t.Errorf("err = %q, want the cause named", err)
		}
	})
}

// A caller waiting for another's token request that gives up gets its own
// context's error as a failure to obtain a token, and sends no request.
func TestPreemptiveWaiterThatLeavesSendsNothing(t *testing.T) {
	g := newRig(t, modeFilter)
	hold, entered := make(chan struct{}), make(chan struct{}, 4)
	g.r.set(func(s *tokenRoot) { s.hold, s.entered = hold, entered })
	_, a := g.preemptive()
	first := make(chan error, 1)
	go func() {
		_, err := a.GetProductRelease(ctxBG, releaseID)
		first <- err
	}()
	<-entered
	mark := g.r.mark()
	ctx, cancel := context.WithTimeout(ctxBG, 50*time.Millisecond)
	defer cancel()
	_, err := a.GetProductRelease(ctx, releaseID)
	if g.note(err) == nil || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrNoAccessToken) {
		t.Errorf("the waiter: %v, want its context's error as ErrNoAccessToken", err)
	}
	if st := g.r.steps(mark); len(st) != 0 {
		t.Errorf("the waiter caused requests: %v", st)
	}
	close(hold)
	if err := <-first; g.note(err) != nil {
		t.Fatal(err)
	}
}

// Every redirect status is read before net/http does: a Location that does not
// parse is refused with the request's redacted URL and ErrInsecureURL, and the
// answer's body is closed.
func TestUnparsableLocationIsRefusedForEveryRedirectStatus(t *testing.T) {
	const bad = "http://s3cr3t-loc@[::1"
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			g := newRig(t, modeFilter)
			g.r.set(func(s *tokenRoot) {
				s.hook = func(w http.ResponseWriter, r *http.Request) bool {
					if r.URL.Path != "/tea/v1.0.0/boom" {
						return false
					}
					w.Header().Set("Location", bad)
					w.WriteHeader(code)
					return true
				}
			})
			a := g.api(g.client(), g.r.root)
			req, err := http.NewRequestWithContext(ctxBG, http.MethodGet, g.r.root+"/v1.0.0/boom?sig=s3cr3t-q", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := a.d.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatalf("a %d with an unparsable Location was handed back", code)
			}
			var pe *URLPolicyError
			if !errors.As(err, &pe) || !errors.Is(err, ErrInsecureURL) {
				t.Fatalf("err = %v, want a *URLPolicyError wrapping ErrInsecureURL", err)
			}
			if strings.Contains(pe.URL, "s3cr3t") || strings.Contains(err.Error(), "s3cr3t") || !strings.Contains(err.Error(), "redirect Location does not parse") {
				t.Errorf("err = %q (URL %q), want the redacted URL and the reason", err, pe.URL)
			}
		})
	}
}

func TestUnparsableLocationAnswerIsClosed(t *testing.T) {
	body := &closeTracker{}
	hc := &http.Client{Transport: answerWith(func(r *http.Request) *http.Response {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"http://[::1"}}, Body: body, Request: r}
	})}
	c, err := New(WithHTTPClient(hc), WithInsecureHTTPBase("http://localhost:1"))
	if err != nil {
		t.Fatal(err)
	}
	base, err := ParseAPIBase("http://localhost:1/tea", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.API(base)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(ctxBG, http.MethodGet, "http://localhost:1/tea/v1.0.0/boom", nil)
	if _, err := a.d.Do(req); err == nil {
		t.Fatal("an unparsable Location was handed back")
	}
	if !body.closed.Load() {
		t.Error("the refused answer's body was not closed")
	}
}

// An anonymous request under the root (an external artifact URL that happens to
// be under it) never causes a token request and carries no token.
func TestPreemptiveAnonymousDownloadUnderTheRootCausesNoTokenRequest(t *testing.T) {
	g := newRig(t, modeFilter)
	g.r.set(func(s *tokenRoot) {
		s.hook = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == "/tea/files/widget.json" {
				_, _ = w.Write([]byte(fixtureJSON))
				return true
			}
			return false
		}
	})
	_, a := g.preemptive()
	ext := fmtOf(mtJSON, sha256Sum([]byte(fixtureJSON)))
	ext.Url = strPtr(g.r.root + "/files/widget.json")
	mark := g.r.mark()
	if _, err := a.DownloadArtifact(ctxBG, ref3, ext, io.Discard, DownloadOptions{}); g.note(err) != nil {
		t.Fatal(err)
	}
	wantSteps(t, "anonymous download under R", g.r.steps(mark), []string{"GET /tea/files/widget.json -"})
	if g.r.tokens() != 0 {
		t.Errorf("%d token requests, want none", g.r.tokens())
	}
}

// The token request goes to <root>/v<version>/token with the version of the API
// that made the request, build metadata and all.
func TestTokenEndpointKeepsTheAPIsVersionVerbatim(t *testing.T) {
	g := newRig(t, modeFilter)
	var paths guarded[[]string]
	g.r.set(func(s *tokenRoot) {
		s.hook = func(w http.ResponseWriter, r *http.Request) bool {
			if !strings.HasPrefix(r.URL.Path, "/tea/v1.0.0+build.7/") {
				return false
			}
			paths.set(append(paths.get(), r.Method+" "+r.URL.Path))
			switch {
			case strings.HasSuffix(r.URL.Path, "/token"):
				jsonHandler(`{"access_token":"issued-access-token-1","token_type":"Bearer","expires_in":3600}`)(w, r)
			default:
				jsonHandler(productReleaseJSON(releaseID, "1.0.0", ""))(w, r)
			}
			return true
		}
	})
	c := g.client(WithPreemptiveAPIKey(g.r.root, rigKeyID, rigSecret))
	base, err := ParseAPIBase(g.r.root, "1.0.0+build.7")
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.API(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetProductRelease(ctxBG, releaseID); g.note(err) != nil {
		t.Fatal(err)
	}
	got := paths.get()
	if len(got) != 2 || got[0] != "POST /tea/v1.0.0+build.7/token" || !strings.HasPrefix(got[1], "GET /tea/v1.0.0+build.7/productRelease/") {
		t.Errorf("requests = %v, want the token request at the API's own version first", got)
	}
}

// The wording of what New refuses and why it names no secret.
func TestOptionRefusalWording(t *testing.T) {
	refusal := func(opt Option) string {
		_, err := New(opt)
		if err == nil {
			t.Fatalf("%v accepted", opt)
		}
		return err.Error()
	}
	long := strings.Repeat("x", 300)
	cases := []struct {
		name string
		opt  Option
		want string
		not  string
	}{
		{"preemptive names itself", WithPreemptiveAPIKey("https://example.com/tea/", "id", "secret"), "WithPreemptiveAPIKey: ", ""},
		{"a domain with a slash", WithWellKnownLocation("exa/mple.com", "https://example.com/tea"), "WithWellKnownLocation: the domain is not a TEI domain name", "exa/mple"},
		{"a domain with a question mark", WithWellKnownLocation("exa?mple.com", "https://example.com/tea"), "WithWellKnownLocation: the domain is not a TEI domain name", "exa?mple"},
		{"a long domain is cut", WithWellKnownLocation(long+"_", "https://example.com/tea"), "is not a TEI domain name", strings.Repeat("x", 200)},
		{"an at sign in the path", WithInsecureHTTPBase("https://example.com/p@th"), "WithInsecureHTTPBase: the URL is not an http URL", "p@th"},
		{"no host name", WithInsecureHTTPBase("https://:8080/tea"), "WithInsecureHTTPBase: the URL has no host", ":8080"},
		{"another scheme", WithInsecureHTTPBase("ftp://example.com/tea"), "WithInsecureHTTPBase: the URL is not an absolute http or https URL", "ftp://example.com"},
		{"an https URL is named", WithInsecureHTTPBase("https://example.com/tea"), `WithInsecureHTTPBase: "https://example.com/tea" is not an http URL`, ""},
		{"a long URL is cut", WithInsecureHTTPBase("https://example.com/" + long), "is not an http URL", strings.Repeat("x", 200)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := refusal(c.opt)
			if !strings.Contains(got, c.want) {
				t.Errorf("%q does not contain %q", got, c.want)
			}
			if c.not != "" && strings.Contains(got, c.not) {
				t.Errorf("%q contains %q", got, c.not)
			}
		})
	}
	// A long root is cut in the refusals of New that name it.
	longRoot := "http://localhost:7001/" + long
	for name, opts := range map[string][]Option{
		"a credential root over http":     {WithAPIKey(longRoot, "id", "secret")},
		"a well-known location over http": {WithWellKnownLocation("example.com", longRoot)},
		"a preemptive root shared":        {WithInsecureHTTPBase("http://localhost:7001"), WithPreemptiveAPIKey(longRoot, "a", "s"), WithAPIKey(longRoot, "b", "s")},
	} {
		_, err := New(opts...)
		if err == nil || strings.Contains(err.Error(), strings.Repeat("x", 200)) {
			t.Errorf("%s: %v, want a refusal that cuts the URL", name, err)
		}
	}
	_, err := ParseAPIBase("https://alice:s3cr3t-pw@example.com/tea", "1.0.0")
	if err == nil || !strings.Contains(err.Error(), "the root URL does not match the rootUrl pattern") || strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("ParseAPIBase with userinfo: %v", err)
	}
}

// Two credentials are one root only when scheme, host, port and path all agree.
func TestPreemptiveRootsThatDifferAreNotTheSameRoot(t *testing.T) {
	allow := []Option{WithInsecureHTTPBase("http://localhost:7001"), WithInsecureHTTPBase("http://localhost:7002"), WithInsecureHTTPBase("http://127.0.0.1:7001")}
	for name, other := range map[string]Option{
		"another scheme": WithAPIKey("https://localhost:7001/tea", "id2", "secret2"),
		"another host":   WithAPIKey("http://127.0.0.1:7001/tea", "id2", "secret2"),
		"another port":   WithAPIKey("http://localhost:7002/tea", "id2", "secret2"),
		"another path":   WithAPIKey("http://localhost:7001/tea/sub", "id2", "secret2"),
	} {
		t.Run(name, func(t *testing.T) {
			opts := append([]Option{WithPreemptiveAPIKey("http://localhost:7001/tea", "id", "secret"), other}, allow...)
			if _, err := New(opts...); err != nil {
				t.Errorf("New refused two roots that differ: %v", err)
			}
		})
	}
	// The refusal is one text per credential that shares its root, however many others do.
	_, err := New(append([]Option{
		WithPreemptiveAPIKey("http://localhost:7001/tea", "a", "s"),
		WithPreemptiveAPIKey("http://localhost:7001/tea", "b", "s"),
		WithPreemptiveAPIKey("http://localhost:7001/tea", "c", "s"),
	}, allow...)...)
	if err == nil {
		t.Fatal("three credentials of one root accepted")
	}
	if n := strings.Count(err.Error(), "is also the root of another credential"); n != 3 {
		t.Errorf("%d refusals, want one per credential (3): %v", n, err)
	}
}
