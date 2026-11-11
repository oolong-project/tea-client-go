package tea

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// The edges of where a credential goes and what a failed token request matches: a token
// obtained for one root is never sent to the root of another credential, a failed token
// request matches its own cause and ErrNoAccessToken and nothing else, what a refused
// retry leaves in the cache, a 401 under a bearer root, the first of equal roots, and two
// refusal wordings.

// T-1: a redirect from the root of one credential into the root of another. The token that
// was obtained for the first (up front, or after the challenge) is not the second's: the
// second root receives no Authorization from the redirect.
func TestTokenOfOneRootIsNotSentToTheRootOfAnotherCredential(t *testing.T) {
	for _, preemptive := range []bool{true, false} {
		name, mode, key := "WithAPIKey", modeChallenge, WithAPIKey
		if preemptive {
			name, mode, key = "WithPreemptiveAPIKey", modeFilter, WithPreemptiveAPIKey
		}
		t.Run(name, func(t *testing.T) {
			g := newRig(t, mode)
			s := newTokenRoot(t, modeChallenge)
			g.allow = append(g.allow, WithInsecureHTTPBase("http://localhost:"+s.port))
			g.r.set(func(r *tokenRoot) {
				r.hook = func(w http.ResponseWriter, q *http.Request) bool {
					if strings.Contains(q.URL.Path, "/productRelease/") && q.Header.Get("Authorization") != "" {
						http.Redirect(w, q, s.root+strings.TrimPrefix(q.URL.Path, "/tea"), http.StatusFound)
						return true
					}
					return false
				}
			})
			c := g.client(key(g.r.root, rigKeyID, rigSecret), WithAPIKey(s.root, rigKeyID, rigSecret))
			_, err := g.api(c, g.r.root).GetProductRelease(ctxBG, releaseID)
			g.note(err)
			steps := s.steps(0)
			if len(steps) == 0 {
				t.Fatal("the redirect did not reach the second root: the test shows nothing")
			}
			for i, st := range steps {
				if strings.HasSuffix(st, " ?") {
					t.Errorf("step %d at the second root carried a token that is not its own: %q", i+1, steps)
				}
			}
			if !strings.HasSuffix(steps[0], " -") {
				t.Errorf("the first request at the second root carried an Authorization: %q", steps[0])
			}
		})
	}
}

// T-2: the error of a failed token request is ErrNoAccessToken and whatever its cause
// chain holds, and no other sentinel: a caller testing for a missing object, an
// unimplemented operation or a timeout is not told yes whatever the cause.
func TestFailedTokenRequestMatchesItsCauseChainOnly(t *testing.T) {
	others := map[string]error{
		"ErrObjectUnknown": ErrObjectUnknown, "ErrNotImplemented": ErrNotImplemented, "ErrTimeout": ErrTimeout,
		"ErrRedirectLimit": ErrRedirectLimit, "ErrInsecureURL": ErrInsecureURL, "ErrInvalidArgument": ErrInvalidArgument,
		"ErrResponseTooLarge": ErrResponseTooLarge,
	}
	for _, c := range []struct {
		name string
		fail tokenFailure
		also error // in the cause chain
	}{
		{"invalid_client", tokenInvalidClient, nil},
		{"NOT_IMPLEMENTED", tokenNotImplemented, ErrNotImplemented},
	} {
		for _, preemptive := range []bool{true, false} {
			name, mode, key := "WithAPIKey", modeChallenge, WithAPIKey
			if preemptive {
				name, mode, key = "WithPreemptiveAPIKey", modeFilter, WithPreemptiveAPIKey
			}
			t.Run(c.name+" "+name, func(t *testing.T) {
				g := newRig(t, mode)
				g.r.set(func(s *tokenRoot) { s.fail = c.fail })
				a := g.api(g.client(key(g.r.root, rigKeyID, rigSecret)), g.r.root)
				_, err := a.GetProductRelease(ctxBG, releaseID)
				if !errors.Is(g.note(err), ErrNoAccessToken) {
					t.Fatalf("%v, want ErrNoAccessToken", err)
				}
				if c.also != nil && !errors.Is(err, c.also) {
					t.Errorf("%v does not match its cause %v", err, c.also)
				}
				for n, other := range others {
					if other != c.also && errors.Is(err, other) {
						t.Errorf("%v matches %s", err, n)
					}
				}
			})
		}
	}
}

// T-3: a 401 on the retry that carries no Bearer challenge is returned, and the token the
// retry carried stays in the cache: the next call sends it again, with no token request.
func TestRetryRefusedWithoutChallengeKeepsTheToken(t *testing.T) {
	g := newRig(t, modeChallenge)
	refuse := &guarded[bool]{}
	refuse.set(true)
	g.r.set(func(s *tokenRoot) {
		s.hook = func(w http.ResponseWriter, q *http.Request) bool {
			if refuse.get() && strings.Contains(q.URL.Path, "/productRelease/") && q.Header.Get("Authorization") != "" {
				w.WriteHeader(http.StatusUnauthorized)
				return true
			}
			return false
		}
	})
	a := g.api(g.client(WithAPIKey(g.r.root, rigKeyID, rigSecret)), g.r.root)
	if _, err := a.GetProductRelease(ctxBG, releaseID); !errors.Is(g.note(err), ErrUnauthorized) {
		t.Fatalf("the retry refused without a challenge: %v, want ErrUnauthorized", err)
	}
	if g.r.tokens() != 1 {
		t.Fatalf("%d token requests after the first call, want 1", g.r.tokens())
	}
	refuse.set(false)
	mark := g.r.mark()
	if _, err := a.GetProductRelease(ctxBG, releaseID); g.note(err) != nil {
		t.Fatalf("the next call: %v", err)
	}
	if g.r.tokens() != 1 {
		t.Errorf("the next call asked for a new token (%d token requests): the token was dropped", g.r.tokens())
	}
	wantSteps(t, "the next call", g.r.steps(mark), []string{"GET /tea/v1.0.0/productRelease/{id} 1"})
}

// T-4: a Bearer challenge under a root that holds a bearer token is returned as
// ErrUnauthorized; there is no key to ask a token with and no token request is made.
func TestBearerRootChallengeIsReturned(t *testing.T) {
	g := newRig(t, modeChallenge)
	a := g.api(g.client(WithBearerToken(g.r.root, "held-token")), g.r.root)
	_, err := a.GetProductRelease(ctxBG, releaseID)
	if !errors.Is(g.note(err), ErrUnauthorized) {
		t.Errorf("%v, want ErrUnauthorized", err)
	}
	if g.r.tokens() != 0 {
		t.Errorf("%d token requests under a bearer root", g.r.tokens())
	}
	wantSteps(t, "bearer root", g.r.steps(0), []string{"GET /tea/v1.0.0/productRelease/{id} ?"})
}

// Among equal roots the first configured credential is the one that is used.
func TestFirstConfiguredOfEqualRootsIsUsed(t *testing.T) {
	g := newRig(t, modeChallenge)
	bearerFirst := g.api(g.client(WithBearerToken(g.r.root, "held-token"), WithAPIKey(g.r.root, rigKeyID, rigSecret)), g.r.root)
	_, err := bearerFirst.GetProductRelease(ctxBG, releaseID)
	if !errors.Is(g.note(err), ErrUnauthorized) || g.r.tokens() != 0 {
		t.Errorf("bearer first: %v, %d token requests, want ErrUnauthorized and none", err, g.r.tokens())
	}
	keyFirst := g.api(g.client(WithAPIKey(g.r.root, rigKeyID, rigSecret), WithBearerToken(g.r.root, "held-token")), g.r.root)
	if _, err := keyFirst.GetProductRelease(ctxBG, releaseID); g.note(err) != nil || g.r.tokens() != 1 {
		t.Errorf("key first: %v, %d token requests, want success and 1", err, g.r.tokens())
	}
}

// Two refusal wordings: the root URL ParseAPIBase quotes, and the option a refused key
// names.
func TestRefusalWordingOfRootAndKey(t *testing.T) {
	_, err := ParseAPIBase("https://example.com/tea/", "1.0.0")
	if err == nil || !strings.Contains(err.Error(), `root URL "https://example.com/tea/" does not match the rootUrl pattern`) {
		t.Errorf("ParseAPIBase with a trailing slash: %v", err)
	}
	_, err = ParseAPIBase("ftp://example.com/tea", "1.0.0")
	if err == nil || !strings.Contains(err.Error(), "the root URL does not match the rootUrl pattern") {
		t.Errorf("ParseAPIBase with another scheme: %v", err)
	}
	for name, opt := range map[string]Option{
		"WithAPIKey":           WithAPIKey("https://example.com/tea", "", "secret"),
		"WithPreemptiveAPIKey": WithPreemptiveAPIKey("https://example.com/tea", "id", ""),
	} {
		_, err := New(opt)
		if err == nil || !errors.Is(err, ErrInvalidOption) || !strings.HasSuffix(err.Error(), name+": empty key id or secret") {
			t.Errorf("%s: %v, want a refusal that names %s", name, err, name)
		}
	}
}
