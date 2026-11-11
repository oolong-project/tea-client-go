package tea

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// API keys on discovery: a /discovery request is made by the candidate's
// API, so an API-key credential acts on it as on an API call, and only
// under its root.

// discoveryRig is a rig whose well-known host (on 127.0.0.1) lists the
// endpoints in doc.
func discoveryRig(t *testing.T, mode rootMode) (*rig, *guarded[string], *counter, Option) {
	t.Helper()
	g := newRig(t, mode)
	doc := &guarded[string]{v: wellKnownDoc(endpoint(g.r.root, `["1.0.0"]`, ""))}
	wk, wkOpt := g.wellKnown(doc)
	return g, doc, wk, wkOpt
}

func wantSteps(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s: requests\n  %q\nwant\n  %q", what, got, want)
	}
}

// T-1: Discover recovers a 401 on /discovery under the key's root.
func TestDiscoverAPIKeyRecoversChallenge(t *testing.T) {
	g, _, wk, wkOpt := discoveryRig(t, modeChallenge)
	c := g.client(wkOpt, WithAPIKey(g.r.root, rigKeyID, rigSecret))
	res, err := c.Discover(ctxBG, mustTEI(t, discTEI))
	if g.note(err) != nil || len(res) != 2 {
		t.Fatalf("Discover: %v, %d results", err, len(res))
	}
	wantSteps(t, "R", g.r.steps(0), []string{getDisc("-"), postToken, getDisc("1")})
	if g.r.tokens() != 1 {
		t.Errorf("%d token requests", g.r.tokens())
	}
	if wk.count() != 1 || wk.lastReq().Header.Get("Authorization") != "" {
		t.Errorf("well-known: %d requests, Authorization %q", wk.count(), wk.lastReq().Header.Get("Authorization"))
	}
}

// T-2: DiscoverPURL at R's base recovers it the same way.
func TestDiscoverPURLAPIKeyRecoversChallenge(t *testing.T) {
	g := newRig(t, modeChallenge)
	c := g.client(WithAPIKey(g.r.root, rigKeyID, rigSecret))
	base, err := ParseAPIBase(g.r.root, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.DiscoverPURL(ctxBG, base, "pkg:generic/widget@1.0.0")
	if g.note(err) != nil || len(res) != 2 {
		t.Fatalf("DiscoverPURL: %v, %d results", err, len(res))
	}
	wantSteps(t, "R", g.r.steps(0), []string{getDisc("-"), postToken, getDisc("1")})
}

// T-3: an endpoint that answers 401 Bearer but is not under the key's root
// (another host, another port, a path that only starts with the root's
// text) causes no token request and gets no credential.
func TestDiscoverAPIKeyChallengeOffRoot(t *testing.T) {
	g, doc, _, wkOpt := discoveryRig(t, modeChallenge)
	challenger := func() (*counter, http.Handler) {
		h := newCounter(func(w http.ResponseWriter, r *http.Request) { challenge(w) })
		return h, h
	}
	otherHost, hh := challenger()
	otherHostURL := g.server("sub.localhost", hh) + "/tea"
	otherPort, ph := challenger()
	otherPortURL := g.server("localhost", ph) + "/tea"
	teapot, _ := challenger()
	g.r.set(func(s *tokenRoot) {
		s.hook = func(w http.ResponseWriter, r *http.Request) bool {
			if strings.HasPrefix(r.URL.Path, "/teapot/") {
				teapot.ServeHTTP(w, r)
				return true
			}
			return false
		}
	})
	c := g.client(wkOpt, WithAPIKey(g.r.root, rigKeyID, rigSecret))
	for name, tc := range map[string]struct {
		url string
		h   *counter
	}{
		"another host":          {otherHostURL, otherHost},
		"another port":          {otherPortURL, otherPort},
		"/teapot on R's origin": {"http://localhost:" + g.r.port + "/teapot", teapot},
	} {
		doc.set(wellKnownDoc(endpoint(tc.url, `["1.0.0"]`, "")))
		before := tc.h.count()
		_, err := c.Discover(ctxBG, mustTEI(t, discTEI))
		g.note(err)
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized || !errors.Is(err, ErrUnauthorized) {
			t.Errorf("%s: %v, want *APIError 401", name, err)
		}
		if g.r.tokens() != 0 {
			t.Errorf("%s: %d token requests at R", name, g.r.tokens())
		}
		reqs := tc.h.requests()[before:]
		if len(reqs) != 1 || reqs[0].Method != http.MethodGet || reqs[0].Header.Get("Authorization") != "" {
			t.Errorf("%s: the endpoint saw %d requests (want one GET without Authorization)", name, len(reqs))
		}
	}
}

// T-4: (a) R's /discovery redirected to another origin that answers 401
// Bearer; (b) an endpoint outside the root redirected into R's /discovery,
// which answers 401 Bearer. Neither causes a token request.
func TestDiscoverAPIKeyChallengeAcrossRedirect(t *testing.T) {
	g, doc, _, wkOpt := discoveryRig(t, modeChallenge)
	target := newCounter(func(w http.ResponseWriter, r *http.Request) { challenge(w) })
	targetURL := g.server("sub.localhost", target)
	outside := newCounter(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, g.r.root+"/v1.0.0/discovery?"+r.URL.RawQuery, http.StatusFound)
	})
	outsideURL := g.server("sub.localhost", outside) + "/tea"
	c := g.client(wkOpt, WithAPIKey(g.r.root, rigKeyID, rigSecret))

	// (a), with token 1 held from a first run.
	if _, err := c.Discover(ctxBG, mustTEI(t, discTEI)); g.note(err) != nil {
		t.Fatal(err)
	}
	g.r.set(func(s *tokenRoot) {
		s.hook = func(w http.ResponseWriter, r *http.Request) bool {
			if strings.HasSuffix(r.URL.Path, "/discovery") {
				http.Redirect(w, r, targetURL+"/tea/v1.0.0/discovery", http.StatusFound)
				return true
			}
			return false
		}
	})
	_, err := c.Discover(ctxBG, mustTEI(t, discTEI))
	g.note(err)
	if !errors.Is(err, ErrUnauthorized) || g.r.tokens() != 1 {
		t.Errorf("(a): %v, %d token requests in all, want ErrUnauthorized and 1", err, g.r.tokens())
	}
	if target.count() != 1 || target.lastReq().Header.Get("Authorization") != "" {
		t.Errorf("(a): the redirect target saw %d requests, Authorization %q", target.count(), target.lastReq().Header.Get("Authorization"))
	}

	// (b), on a fresh client: nothing held.
	g.r.set(func(s *tokenRoot) { s.hook = nil })
	doc.set(wellKnownDoc(endpoint(outsideURL, `["1.0.0"]`, "")))
	c = g.client(wkOpt, WithAPIKey(g.r.root, rigKeyID, rigSecret))
	mark := g.r.mark()
	_, err = c.Discover(ctxBG, mustTEI(t, discTEI))
	g.note(err)
	if !errors.Is(err, ErrUnauthorized) || g.r.tokens() != 1 {
		t.Errorf("(b): %v, %d token requests in all, want ErrUnauthorized and 1", err, g.r.tokens())
	}
	wantSteps(t, "(b) R", g.r.steps(mark), []string{getDisc("-")})
}

// T-5: a server that refuses every token: one token request, one retry,
// and the 401 after it stops discovery (no failover).
func TestDiscoverAPIKeyRefusedTokenStops(t *testing.T) {
	g, doc, _, wkOpt := discoveryRig(t, modeChallenge)
	second := newCounter(nil)
	secondURL := g.server("sub.localhost", second) + "/tea"
	doc.set(wellKnownDoc(endpoint(g.r.root, `["1.0.0"]`, `,"priority":1`), endpoint(secondURL, `["1.0.0"]`, `,"priority":0.5`)))
	g.r.set(func(s *tokenRoot) { s.refuseAll = true })
	c := g.client(wkOpt, WithAPIKey(g.r.root, rigKeyID, rigSecret))
	_, err := c.Discover(ctxBG, mustTEI(t, discTEI))
	g.note(err)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
		t.Errorf("%v, want *APIError 401", err)
	}
	wantSteps(t, "R", g.r.steps(0), []string{getDisc("-"), postToken, getDisc("1")})
	if second.count() != 0 {
		t.Errorf("the second endpoint saw %d requests", second.count())
	}
}

// T-6: a failed token request stops discovery with ErrNoAccessToken, after
// one token request, without failover.
func TestDiscoverAPIKeyTokenFailureStops(t *testing.T) {
	for name, fail := range map[string]tokenFailure{"invalid_client": tokenInvalidClient, "404": tokenNotImplemented, "307": tokenRedirect} {
		t.Run(name, func(t *testing.T) {
			g, doc, _, wkOpt := discoveryRig(t, modeChallenge)
			second := newCounter(nil)
			secondURL := g.server("sub.localhost", second) + "/tea"
			redirected := newCounter(nil)
			redirectedURL := g.server("localhost", redirected)
			doc.set(wellKnownDoc(endpoint(g.r.root, `["1.0.0"]`, `,"priority":1`), endpoint(secondURL, `["1.0.0"]`, `,"priority":0.5`)))
			g.r.set(func(s *tokenRoot) { s.fail, s.tokenTo = fail, redirectedURL+"/tea/v1.0.0/token" })
			c := g.client(wkOpt, WithAPIKey(g.r.root, rigKeyID, rigSecret))
			_, err := c.Discover(ctxBG, mustTEI(t, discTEI))
			g.note(err)
			var de *DiscoveryError
			if errors.As(err, &de) || !errors.Is(err, ErrNoAccessToken) {
				t.Fatalf("%v (%T), want an ErrNoAccessToken that is not a *DiscoveryError", err, err)
			}
			var te *TokenError
			var ue *UnexpectedResponseError
			switch fail {
			case tokenInvalidClient:
				if !errors.As(err, &te) || te.Code != "invalid_client" {
					t.Errorf("%v, want *TokenError invalid_client", err)
				}
			case tokenNotImplemented:
				if !errors.Is(err, ErrNotImplemented) {
					t.Errorf("%v, want ErrNotImplemented", err)
				}
			case tokenRedirect:
				if !errors.As(err, &ue) || ue.Status != http.StatusTemporaryRedirect {
					t.Errorf("%v, want *UnexpectedResponseError 307", err)
				}
			}
			if g.r.tokens() != 1 || second.count() != 0 || redirected.count() != 0 {
				t.Errorf("%d token requests, second endpoint %d, redirect target %d requests", g.r.tokens(), second.count(), redirected.count())
			}
		})
	}
}

// T-7: a 403 with a Bearer challenge, and a 401 with a Basic challenge, on
// /discovery cause no token request.
func TestDiscoverAPIKeyNoRecovery(t *testing.T) {
	g, _, _, wkOpt := discoveryRig(t, modeChallenge)
	status := &guarded[int]{v: http.StatusForbidden}
	g.r.set(func(s *tokenRoot) {
		s.hook = func(w http.ResponseWriter, r *http.Request) bool {
			if !strings.HasSuffix(r.URL.Path, "/discovery") {
				return false
			}
			if status.get() == http.StatusForbidden {
				w.Header().Set("WWW-Authenticate", `Bearer realm="tea", error="insufficient_scope"`)
				w.WriteHeader(http.StatusForbidden)
				return true
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="tea"`)
			w.WriteHeader(http.StatusUnauthorized)
			return true
		}
	})
	c := g.client(wkOpt, WithAPIKey(g.r.root, rigKeyID, rigSecret))
	_, err := c.Discover(ctxBG, mustTEI(t, discTEI))
	if !errors.Is(g.note(err), ErrForbidden) {
		t.Errorf("403 Bearer: %v, want ErrForbidden", err)
	}
	status.set(http.StatusUnauthorized)
	_, err = c.Discover(ctxBG, mustTEI(t, discTEI))
	if !errors.Is(g.note(err), ErrUnauthorized) {
		t.Errorf("401 Basic: %v, want ErrUnauthorized", err)
	}
	if g.r.tokens() != 0 {
		t.Errorf("%d token requests", g.r.tokens())
	}
}

// T-8: the token obtained in one attempt serves the next: a 503 after the
// recovery is a failed attempt, and the next attempt carries token 1.
func TestDiscoverAPIKeyTokenServesNextAttempt(t *testing.T) {
	g, _, _, wkOpt := discoveryRig(t, modeChallenge)
	failed := &guarded[bool]{}
	g.r.set(func(s *tokenRoot) {
		s.hook = func(w http.ResponseWriter, r *http.Request) bool {
			if strings.HasSuffix(r.URL.Path, "/discovery") && r.Header.Get("Authorization") != "" && !failed.get() {
				failed.set(true)
				w.WriteHeader(http.StatusServiceUnavailable)
				return true
			}
			return false
		}
	})
	c := g.client(wkOpt, WithAPIKey(g.r.root, rigKeyID, rigSecret))
	res, err := c.Discover(ctxBG, mustTEI(t, discTEI))
	if g.note(err) != nil || len(res) != 2 {
		t.Fatalf("Discover: %v, %d results", err, len(res))
	}
	wantSteps(t, "R", g.r.steps(0), []string{getDisc("-"), postToken, getDisc("1"), getDisc("1")})
}

// T-9: a well-known URL under the key's root never causes a token request;
// it carries a token only once one is held.
func TestDiscoverAPIKeyWellKnownUnderRoot(t *testing.T) {
	g := newRig(t, modeChallenge)
	wkAnswers := &guarded[bool]{}
	g.r.set(func(s *tokenRoot) {
		s.hook = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != "/tea/.well-known/tea" {
				return false
			}
			if !wkAnswers.get() {
				challenge(w)
				return true
			}
			jsonHandler(wellKnownDoc(endpoint(g.r.root, `["1.0.0"]`, "")))(w, r)
			return true
		}
	})
	wkOpt := WithWellKnownLocation("example.com", g.r.root)
	_, err := g.client(wkOpt, WithAPIKey(g.r.root, rigKeyID, rigSecret)).Discover(ctxBG, mustTEI(t, discTEI))
	var ae *APIError
	if !errors.As(g.note(err), &ae) || ae.Status != http.StatusUnauthorized || g.r.tokens() != 0 {
		t.Errorf("well-known 401 Bearer: %v, %d token requests; want *APIError 401 and none", err, g.r.tokens())
	}

	wkAnswers.set(true)
	c := g.client(wkOpt, WithPreemptiveAPIKey(g.r.root, rigKeyID, rigSecret))
	mark := g.r.mark()
	for i := 0; i < 2; i++ {
		if _, err := c.Discover(ctxBG, mustTEI(t, discTEI)); g.note(err) != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
	wk := "GET /tea/.well-known/tea "
	wantSteps(t, "preemptive", g.r.steps(mark), []string{wk + "-", postToken, getDisc("1"), wk + "1", getDisc("1")})
}

// T-10: without the preemptive option a filtering server is never asked
// for a token: the caller gets the anonymous view.
func TestDiscoverAPIKeyFilterDefault(t *testing.T) {
	g, _, wk, wkOpt := discoveryRig(t, modeFilter)
	c := g.client(wkOpt, WithAPIKey(g.r.root, rigKeyID, rigSecret))
	res, err := c.Discover(ctxBG, mustTEI(t, discTEI))
	if g.note(err) != nil || len(res) != 1 {
		t.Fatalf("Discover: %v, %d results, want 1", err, len(res))
	}
	base, err := c.SelectServer(res[0])
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.API(base)
	if err != nil {
		t.Fatal(err)
	}
	pr, err := a.GetProductRelease(ctxBG, res[0].ProductReleaseUUID)
	if g.note(err) != nil || len(pr.Components) != 1 {
		t.Fatalf("GetProductRelease: %v", err)
	}
	wantSteps(t, "R", g.r.steps(0), []string{getDisc("-"), getRel("-")})
	if wk.lastReq().Header.Get("Authorization") != "" {
		t.Error("the well-known host received Authorization")
	}
}
