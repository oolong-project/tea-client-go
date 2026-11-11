package tea

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// WithPreemptiveAPIKey, the token endpoint at the key's root, the shared
// token request and the bounds after a 401.

// preemptive is a rig client with WithPreemptiveAPIKey bound to R, and its
// API at R.
func (g *rig) preemptive(opts ...Option) (*Client, *API) {
	g.t.Helper()
	c := g.client(append([]Option{WithPreemptiveAPIKey(g.r.root, rigKeyID, rigSecret)}, opts...)...)
	return c, g.api(c, g.r.root)
}

// T-11: what New refuses and accepts with the option.
func TestPreemptiveAPIKeyOption(t *testing.T) {
	const secret = "option-s3cret-value"
	const root = "https://example.com/tea"
	refused := map[string][]Option{
		"empty id":                          {WithPreemptiveAPIKey(root, "", secret)},
		"empty secret":                      {WithPreemptiveAPIKey(root, "id", "")},
		"root ending in /":                  {WithPreemptiveAPIKey(root+"/", "id", secret)},
		"http root":                         {WithPreemptiveAPIKey("http://example.com/tea", "id", secret)},
		"bearer, then":                      {WithBearerToken(root, "tok"), WithPreemptiveAPIKey(root, "id", secret)},
		"then bearer":                       {WithPreemptiveAPIKey(root, "id", secret), WithBearerToken(root, "tok")},
		"api key, then":                     {WithAPIKey(root, "id2", "other-secret"), WithPreemptiveAPIKey(root, "id", secret)},
		"then api key":                      {WithPreemptiveAPIKey(root, "id", secret), WithAPIKey(root, "id2", "other-secret")},
		"two preemptive":                    {WithPreemptiveAPIKey(root, "id", secret), WithPreemptiveAPIKey(root, "id2", "other-secret")},
		"same root written otherwise":       {WithPreemptiveAPIKey(root, "id", secret), WithBearerToken("https://EXAMPLE.com:443/tea", "tok")},
		"same root written otherwise, then": {WithAPIKey("https://EXAMPLE.com:443/tea", "id2", "other-secret"), WithPreemptiveAPIKey(root, "id", secret)},
	}
	for name, opts := range refused {
		_, err := New(opts...)
		if !errors.Is(err, ErrInvalidOption) {
			t.Errorf("%s: %v, want ErrInvalidOption", name, err)
		} else if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "other-secret") {
			t.Errorf("%s: the error holds a secret: %v", name, err)
		}
	}
	accepted := map[string][]Option{
		"https root":                 {WithPreemptiveAPIKey(root, "id", secret)},
		"http under allowance":       {WithInsecureHTTPBase("http://example.com"), WithPreemptiveAPIKey("http://example.com/tea", "id", secret)},
		"nested roots":               {WithPreemptiveAPIKey(root, "id", secret), WithBearerToken(root+"/sub", "tok")},
		"v0.0.0 options on one root": {WithBearerToken(root, "tok"), WithAPIKey(root, "id", secret)},
	}
	for name, opts := range accepted {
		if _, err := New(opts...); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// T-12: New makes no request.
func TestPreemptiveAPIKeyNewIsQuiet(t *testing.T) {
	g := newRig(t, modeFilter)
	g.preemptive()
	if g.r.mark() != 0 {
		t.Errorf("the server saw %d requests", g.r.mark())
	}
}

// T-13: the token is obtained before the first request and sent on every
// request; one token request.
func TestPreemptiveAPIKeyFilter(t *testing.T) {
	g := newRig(t, modeFilter)
	_, a := g.preemptive()
	for i := 0; i < 3; i++ {
		pr, err := a.GetProductRelease(ctxBG, releaseID)
		if g.note(err) != nil || len(pr.Components) != 2 {
			t.Fatalf("call %d: %v", i+1, err)
		}
	}
	wantSteps(t, "R", g.r.steps(0), []string{postToken, getRel("1"), getRel("1"), getRel("1")})
}

// T-14: concurrent first calls share one token request.
func TestPreemptiveAPIKeyConcurrentFirstCalls(t *testing.T) {
	g := newRig(t, modeFilter)
	g.r.set(func(s *tokenRoot) { s.delay = 100 * time.Millisecond })
	_, a := g.preemptive()
	var wg sync.WaitGroup
	errs := make([]error, 16)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = a.GetProductRelease(ctxBG, releaseID)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if g.note(err) != nil {
			t.Error(err)
		}
	}
	if g.r.tokens() != 1 {
		t.Errorf("%d token requests, want 1", g.r.tokens())
	}
	for _, st := range g.r.steps(0)[1:] {
		if st != getRel("1") {
			t.Errorf("request %q, want every GET with token 1", st)
		}
	}
}

// T-15: with the option, /discovery carries the token from the first
// attempt, so a filtering server returns the authenticated view. Paired
// with T-10 (TestDiscoverAPIKeyFilterDefault) on the same fixture.
func TestPreemptiveAPIKeyDiscovery(t *testing.T) {
	g, _, wk, wkOpt := discoveryRig(t, modeFilter)
	c, _ := g.preemptive(wkOpt)
	res, err := c.Discover(ctxBG, mustTEI(t, discTEI))
	if g.note(err) != nil || len(res) != 2 {
		t.Fatalf("Discover: %v, %d results, want 2", err, len(res))
	}
	base, err := c.SelectServer(res[1])
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.API(base)
	if err != nil {
		t.Fatal(err)
	}
	pr, err := a.GetProductRelease(ctxBG, res[1].ProductReleaseUUID)
	if g.note(err) != nil || len(pr.Components) != 2 {
		t.Fatalf("GetProductRelease: %v", err)
	}
	wantSteps(t, "R", g.r.steps(0), []string{postToken, getDisc("1"), getRel("1")})
	if wk.count() != 1 || wk.lastReq().Header.Get("Authorization") != "" {
		t.Error("the well-known host received Authorization")
	}
}

// T-16: off the root (another host, /teapot, a redirect off the origin, an
// external artifact url) nothing carries a credential or causes a token
// request; with the cache empty and with a token held.
func TestPreemptiveAPIKeyOffRoot(t *testing.T) {
	for _, held := range []bool{false, true} {
		name := "cache empty"
		if held {
			name = "token held"
		}
		t.Run(name, func(t *testing.T) {
			g := newRig(t, modeFilter)
			other := newCounter(jsonHandler(productReleaseJSON(releaseID, "1.0.0", "")))
			otherRoot := g.server("sub.localhost", other) + "/tea"
			portTarget := newCounter(jsonHandler(productReleaseJSON(releaseID, "1.0.0", "")))
			portURL := g.server("localhost", portTarget)
			hostTarget := newCounter(jsonHandler(productReleaseJSON(releaseID, "1.0.0", "")))
			hostURL := g.server("sub.localhost", hostTarget)
			redirect := &guarded[string]{}
			g.r.set(func(s *tokenRoot) {
				s.hook = func(w http.ResponseWriter, r *http.Request) bool {
					switch {
					case strings.HasPrefix(r.URL.Path, "/teapot/"):
						jsonHandler(productReleaseJSON(releaseID, "1.0.0", ""))(w, r)
						return true
					case strings.HasPrefix(r.URL.Path, rv+"/productRelease/") && redirect.get() != "":
						to := strings.SplitN(redirect.get(), " ", 2)
						code := http.StatusFound
						if to[0] == "307" {
							code = http.StatusTemporaryRedirect
						}
						http.Redirect(w, r, to[1]+r.URL.Path, code)
						return true
					case r.URL.Path == "/tea/files/widget.json":
						_, _ = w.Write([]byte(fixtureJSON))
						return true
					}
					return false
				}
			})
			c, a := g.preemptive()
			if held {
				if _, err := a.GetProductRelease(ctxBG, releaseID); g.note(err) != nil {
					t.Fatal(err)
				}
			}
			start := g.r.tokens()
			for _, root := range []string{otherRoot, "http://localhost:" + g.r.port + "/teapot"} {
				mark := g.r.mark()
				if _, err := g.api(c, root).GetProductRelease(ctxBG, releaseID); g.note(err) != nil {
					t.Fatalf("%s: %v", root, err)
				}
				for _, st := range g.r.steps(mark) {
					if !strings.HasSuffix(st, " -") {
						t.Errorf("%s: R saw %q", root, st)
					}
				}
			}
			if other.count() != 1 || other.lastReq().Header.Get("Authorization") != "" {
				t.Errorf("servers[] root on another host: %d requests, Authorization %q", other.count(), other.lastReq().Header.Get("Authorization"))
			}
			if g.r.tokens() != start {
				t.Errorf("an API off the root caused %d token requests", g.r.tokens()-start)
			}
			for _, to := range []struct {
				code, url string
				h         *counter
			}{{"302", portURL, portTarget}, {"307", portURL, portTarget}, {"302", hostURL, hostTarget}, {"307", hostURL, hostTarget}} {
				redirect.set(to.code + " " + to.url)
				before := to.h.count()
				if _, err := a.GetProductRelease(ctxBG, releaseID); g.note(err) != nil {
					t.Fatalf("redirect %s to %s: %v", to.code, to.url, err)
				}
				if to.h.count() != before+1 || to.h.lastReq().Header.Get("Authorization") != "" {
					t.Errorf("redirect %s to %s: the target received Authorization %q", to.code, to.url, to.h.lastReq().Header.Get("Authorization"))
				}
			}
			redirect.set("")
			if want := 1; g.r.tokens() != want {
				t.Errorf("%d token requests in all, want %d (the request under R only)", g.r.tokens(), want)
			}
			body := []byte(fixtureJSON)
			ext := fmtOf(mtJSON, sha256Sum(body))
			ext.Url = strPtr(g.r.root + "/files/widget.json")
			mark := g.r.mark()
			if _, err := a.DownloadArtifact(ctxBG, ref3, ext, io.Discard, DownloadOptions{}); g.note(err) != nil {
				t.Fatal(err)
			}
			wantSteps(t, "external url under R", g.r.steps(mark), []string{"GET /tea/files/widget.json -"})
			if g.r.tokens() != 1 {
				t.Errorf("the external url caused a token request")
			}
		})
	}
}

// T-17: the token endpoint is <root>/v<version>/token, whatever API under
// the root makes the request; an API above the key's root gets none.
func TestAPIKeyTokenEndpointIsTheRoots(t *testing.T) {
	for _, preemptive := range []bool{true, false} {
		name := "WithAPIKey"
		mode := modeChallenge
		if preemptive {
			name, mode = "WithPreemptiveAPIKey", modeFilter
		}
		t.Run(name, func(t *testing.T) {
			g := newRig(t, mode)
			key := WithAPIKey
			if preemptive {
				key = WithPreemptiveAPIKey
			}
			c := g.client(key(g.r.root, rigKeyID, rigSecret))
			if _, err := g.api(c, g.r.root+"/sub").GetProductRelease(ctxBG, releaseID); g.note(err) != nil {
				t.Fatal(err)
			}
			want := []string{postToken, "GET /tea/sub/v1.0.0/productRelease/{id} 1"}
			if !preemptive {
				want = append([]string{"GET /tea/sub/v1.0.0/productRelease/{id} -"}, want...)
			}
			wantSteps(t, "sub API", g.r.steps(0), want)

			// (c) the key's root deeper than the API base.
			deep := g.client(key(g.r.root+"/v1.0.0/productRelease", rigKeyID, rigSecret))
			mark, tokens := g.r.mark(), g.r.tokens()
			_, err := g.api(deep, g.r.root).GetProductRelease(ctxBG, releaseID)
			if !errors.Is(g.note(err), ErrInvalidArgument) || g.r.tokens() != tokens {
				t.Errorf("key root below the API base: %v, %d token requests", err, g.r.tokens()-tokens)
			}
			if preemptive && g.r.mark() != mark {
				t.Errorf("key root below the API base: the resource request was sent: %q", g.r.steps(mark))
			}
		})
	}
}

// T-18: a redirect from /token: no request reaches its target and the
// resource request is not sent.
func TestPreemptiveAPIKeyTokenRedirect(t *testing.T) {
	g := newRig(t, modeFilter)
	target := newCounter(nil)
	targetURL := g.server("localhost", target)
	g.r.set(func(s *tokenRoot) { s.fail, s.tokenTo = tokenRedirect, targetURL+"/tea/v1.0.0/token" })
	_, a := g.preemptive()
	_, err := a.GetProductRelease(ctxBG, releaseID)
	var ue *UnexpectedResponseError
	if !errors.As(g.note(err), &ue) || ue.Status != http.StatusTemporaryRedirect || !errors.Is(err, ErrNoAccessToken) {
		t.Errorf("%v, want *UnexpectedResponseError 307 and ErrNoAccessToken", err)
	}
	if target.count() != 0 {
		t.Errorf("the redirect target saw %d requests", target.count())
	}
	wantSteps(t, "R", g.r.steps(0), []string{postToken})
}

// T-19: a refused token request is not cached: each call tries once, and
// no resource request is sent.
func TestPreemptiveAPIKeyTokenRefused(t *testing.T) {
	g := newRig(t, modeFilter)
	g.r.set(func(s *tokenRoot) { s.fail = tokenInvalidClient })
	_, a := g.preemptive()
	for i := 0; i < 2; i++ {
		_, err := a.GetProductRelease(ctxBG, releaseID)
		var te *TokenError
		if !errors.Is(g.note(err), ErrNoAccessToken) || !errors.As(err, &te) {
			t.Errorf("call %d: %v, want ErrNoAccessToken and *TokenError", i+1, err)
		}
	}
	wantSteps(t, "R", g.r.steps(0), []string{postToken, postToken})
}

// testClock is a clock the token cache reads (Client.now).
type testClock struct{ g guarded[time.Time] }

func (k *testClock) now() time.Time          { return k.g.get() }
func (k *testClock) advance(d time.Duration) { k.g.set(k.g.get().Add(d)) }
func newTestClock() *testClock {
	k := &testClock{}
	k.g.set(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	return k
}

// T-20: expiry is honoured; with the option no request leaves without a
// token, without it the expired token is followed by an anonymous request.
func TestAPIKeyTokenExpiry(t *testing.T) {
	for _, preemptive := range []bool{true, false} {
		name := "WithAPIKey"
		if preemptive {
			name = "WithPreemptiveAPIKey"
		}
		t.Run(name, func(t *testing.T) {
			g := newRig(t, modeChallenge)
			key := WithAPIKey
			if preemptive {
				key = WithPreemptiveAPIKey
			}
			c := g.client(key(g.r.root, rigKeyID, rigSecret))
			clk := newTestClock()
			c.now = clk.now
			a := g.api(c, g.r.root)
			call := func() {
				t.Helper()
				if _, err := a.GetProductRelease(ctxBG, releaseID); g.note(err) != nil {
					t.Fatal(err)
				}
			}
			call()
			call()
			clk.advance(3600*time.Second - tokenLeeway)
			call()
			want := []string{postToken, getRel("1"), getRel("1"), postToken, getRel("2")}
			if !preemptive {
				want = []string{getRel("-"), postToken, getRel("1"), getRel("1"), getRel("-"), postToken, getRel("2")}
			}
			wantSteps(t, name, g.r.steps(0), want)
		})
	}
}

// T-21: a token that is not cacheable is still sent on the request it was
// obtained for.
func TestPreemptiveAPIKeyUncachedToken(t *testing.T) {
	g := newRig(t, modeChallenge)
	g.r.set(func(s *tokenRoot) { s.expires = "30" })
	_, a := g.preemptive()
	for i := 0; i < 2; i++ {
		if _, err := a.GetProductRelease(ctxBG, releaseID); g.note(err) != nil {
			t.Fatal(err)
		}
	}
	wantSteps(t, "R", g.r.steps(0), []string{postToken, getRel("1"), postToken, getRel("2")})
}

// T-22: a 401 on a cached token: one fresh token, one retry; a 401 on the
// retry is returned, and the token it carried is dropped, so the next call
// does not send it again.
func TestPreemptiveAPIKeyRefreshOnce(t *testing.T) {
	g := newRig(t, modeChallenge)
	_, a := g.preemptive()
	if _, err := a.GetProductRelease(ctxBG, releaseID); g.note(err) != nil {
		t.Fatal(err)
	}
	g.r.set(func(s *tokenRoot) { s.valid = "rotated-elsewhere" })
	mark := g.r.mark()
	if _, err := a.GetProductRelease(ctxBG, releaseID); g.note(err) != nil {
		t.Fatal(err)
	}
	wantSteps(t, "rotated", g.r.steps(mark), []string{getRel("1"), postToken, getRel("2")})

	g.r.set(func(s *tokenRoot) { s.refuseAll = true })
	mark = g.r.mark()
	_, err := a.GetProductRelease(ctxBG, releaseID)
	if !errors.Is(g.note(err), ErrUnauthorized) {
		t.Errorf("%v, want ErrUnauthorized", err)
	}
	wantSteps(t, "refused", g.r.steps(mark), []string{getRel("2"), postToken, getRel("3")})

	mark = g.r.mark()
	_, err = a.GetProductRelease(ctxBG, releaseID)
	if !errors.Is(g.note(err), ErrUnauthorized) {
		t.Errorf("%v, want ErrUnauthorized", err)
	}
	wantSteps(t, "after the refused retry", g.r.steps(mark), []string{postToken, getRel("4")})
}

// T-23: a token obtained for the request and refused is reported at once,
// not refreshed: one token request and one GET per call.
func TestPreemptiveAPIKeyFreshTokenRefused(t *testing.T) {
	g := newRig(t, modeChallenge)
	g.r.set(func(s *tokenRoot) { s.refuseAll = true })
	_, a := g.preemptive()
	for i := 1; i <= 5; i++ {
		mark := g.r.mark()
		_, err := a.GetProductRelease(ctxBG, releaseID)
		if !errors.Is(g.note(err), ErrUnauthorized) {
			t.Errorf("call %d: %v, want ErrUnauthorized", i, err)
		}
		n := string(rune('0' + i))
		wantSteps(t, "call", g.r.steps(mark), []string{postToken, getRel(n)})
	}
	if g.r.tokens() != 5 {
		t.Errorf("%d token requests, want 5", g.r.tokens())
	}
}

// T-24: concurrent 401s on the same stale token share one token request.
func TestAPIKeyConcurrentRefresh(t *testing.T) {
	for _, preemptive := range []bool{true, false} {
		name := "WithAPIKey"
		if preemptive {
			name = "WithPreemptiveAPIKey"
		}
		t.Run(name, func(t *testing.T) {
			g := newRig(t, modeChallenge)
			key := WithAPIKey
			if preemptive {
				key = WithPreemptiveAPIKey
			}
			a := g.api(g.client(key(g.r.root, rigKeyID, rigSecret)), g.r.root)
			if _, err := a.GetProductRelease(ctxBG, releaseID); g.note(err) != nil {
				t.Fatal(err)
			}
			g.r.set(func(s *tokenRoot) { s.valid, s.delay = "rotated-elsewhere", 50*time.Millisecond })
			tokens := g.r.tokens()
			var wg sync.WaitGroup
			errs := make([]error, 16)
			for i := range errs {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, errs[i] = a.GetProductRelease(ctxBG, releaseID)
				}()
			}
			wg.Wait()
			for _, err := range errs {
				if g.note(err) != nil {
					t.Error(err)
				}
			}
			if g.r.tokens() != tokens+1 {
				t.Errorf("%d token requests, want 1", g.r.tokens()-tokens)
			}
		})
	}
}

// T-25: waiting for a token request in flight: (a) a waiter leaves on its
// own context; (b) when the requester's context ends, a live waiter makes
// its own token request.
func TestPreemptiveAPIKeyTurnTaking(t *testing.T) {
	t.Run("waiter leaves", func(t *testing.T) {
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
		ctx, cancel := context.WithTimeout(ctxBG, 50*time.Millisecond)
		defer cancel()
		_, err := a.GetProductRelease(ctx, releaseID)
		if !errors.Is(g.note(err), context.DeadlineExceeded) {
			t.Errorf("the waiter: %v, want its context's error", err)
		}
		select {
		case err := <-first:
			t.Fatalf("the first caller returned while /token stalled: %v", err)
		default:
		}
		close(hold)
		if err := <-first; g.note(err) != nil {
			t.Fatal(err)
		}
		if g.r.tokens() != 1 {
			t.Errorf("%d token requests, want 1", g.r.tokens())
		}
	})
	t.Run("requester leaves", func(t *testing.T) {
		g := newRig(t, modeFilter)
		hold, entered := make(chan struct{}), make(chan struct{}, 4)
		g.r.set(func(s *tokenRoot) { s.hold, s.entered = hold, entered })
		_, a := g.preemptive()
		ctx, cancel := context.WithCancel(ctxBG)
		first, second := make(chan error, 1), make(chan error, 1)
		go func() {
			_, err := a.GetProductRelease(ctx, releaseID)
			first <- err
		}()
		<-entered
		go func() {
			_, err := a.GetProductRelease(ctxBG, releaseID)
			second <- err
		}()
		time.Sleep(50 * time.Millisecond) // the second caller is waiting
		cancel()
		if err := <-first; !errors.Is(g.note(err), context.Canceled) {
			t.Errorf("the requester: %v, want its context's error", err)
		}
		close(hold)
		if err := <-second; g.note(err) != nil {
			t.Fatalf("the waiter: %v", err)
		}
		if g.r.tokens() != 2 {
			t.Errorf("%d token requests, want 2", g.r.tokens())
		}
	})
}

// T-26: a token failure during the flow is returned, never read as "no
// CLE" (a 404 from /token wraps ErrNotImplemented).
func TestFlowTokenFailureIsNotNoCLE(t *testing.T) {
	// Tokens are not cacheable, so each request makes its own token
	// request; the first failAfter of them work.
	for name, failAfter := range map[string]int{"product release CLE": 1, "component release CLE": 3} {
		t.Run(name, func(t *testing.T) {
			g := newRig(t, modeChallenge)
			g.r.set(func(s *tokenRoot) { s.expires, s.fail, s.failAfter = "30", tokenNotImplemented, failAfter })
			c, a := g.preemptive()
			res, err := c.FlowFromRelease(ctxBG, a, releaseID, FlowOptions{})
			g.note(err)
			if failAfter == 1 {
				if !errors.Is(err, ErrNoAccessToken) || res != nil {
					t.Errorf("%v (result %v), want ErrNoAccessToken", err, res)
				}
				return
			}
			if err != nil || res.ReleaseCLE == nil || len(res.Components) == 0 {
				t.Fatalf("%v, result %+v", err, res)
			}
			fc := res.Components[0]
			g.note(fc.Err)
			if fc.Release == nil || fc.CLE != nil || !errors.Is(fc.Err, ErrNoAccessToken) {
				t.Errorf("component %+v, want its release read and Err matching ErrNoAccessToken", fc)
			}
		})
	}
	t.Run("WithAPIKey, 401 on the CLE", func(t *testing.T) {
		g := newRig(t, modeFilter)
		g.r.set(func(s *tokenRoot) {
			s.fail = tokenNotImplemented
			s.hook = func(w http.ResponseWriter, r *http.Request) bool {
				if strings.HasSuffix(r.URL.Path, "/cle") {
					challenge(w)
					return true
				}
				return false
			}
		})
		c := g.client(WithAPIKey(g.r.root, rigKeyID, rigSecret))
		res, err := c.FlowFromRelease(ctxBG, g.api(c, g.r.root), releaseID, FlowOptions{})
		if !errors.Is(g.note(err), ErrNoAccessToken) || !errors.Is(err, ErrNotImplemented) || res != nil {
			t.Errorf("%v (result %v), want ErrNoAccessToken", err, res)
		}
	})
}
