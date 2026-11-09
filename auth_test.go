package tea

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oolong-project/tea-client-go/teaapi"
)

// redirector answers /r?code=<status>&to=<url> with that redirect and
// anything else with a product.
func redirector(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/r") {
		code := http.StatusFound
		if r.URL.Query().Get("code") == "307" {
			code = http.StatusTemporaryRedirect
		}
		http.Redirect(w, r, r.URL.Query().Get("to"), code)
		return
	}
	jsonHandler(productJSON())(w, r)
}

func setAuth(value string) teaapi.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", value)
		return nil
	}
}

// Case 12: anonymous by default.
func TestAnonymousSendsNoAuthorization(t *testing.T) {
	ctx := context.Background()
	h := newCounter(redirector)
	srv := startHTTP(t, h)
	a := newTestAPI(t, srv.URL, "/tea")
	if _, err := a.GetProduct(ctx, productID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Generated().GetProductWithResponse(ctx, productID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.QueryProducts(ctx, ProductQuery{IDType: teaapi.TEI, IDValue: "tei://example.com/uuid/x"}); err != nil {
		t.Fatal(err)
	}
	to := url.QueryEscape(srv.URL + "/tea/v1.0.0/product/" + productID.String())
	if _, err := a.Generated().GetProductWithResponse(ctx, productID, rewriteTo(t, srv.URL+"/tea/v1.0.0/r?to="+to)); err != nil {
		t.Fatal(err)
	}
	reqs := h.requests()
	if len(reqs) != 5 {
		t.Fatalf("%d requests, want 5", len(reqs))
	}
	for _, r := range reqs {
		if v, ok := r.Header["Authorization"]; ok {
			t.Errorf("%s carries Authorization %q", r.URL.Path, v)
		}
	}
}

// authFixture: two plain-http servers addressed as localhost, 127.0.0.1 and
// sub.localhost, all allowed, and a bearer bound to http://localhost:PORT/tea.
type authFixture struct {
	a, b         *counter
	port, port2  string
	root         string
	opts         []Option
	t            *testing.T
	bearer       string
	insecureOpts []Option
}

func newAuthFixture(t *testing.T) *authFixture {
	f := &authFixture{t: t, a: newCounter(redirector), b: newCounter(redirector), bearer: "bearer-token-value-1"}
	sa, sb := startHTTP(t, f.a), startHTTP(t, f.b)
	f.port, f.port2 = portOf(t, sa), portOf(t, sb)
	f.root = "http://localhost:" + f.port + "/tea"
	for _, host := range []string{"localhost", "sub.localhost", "127.0.0.1"} {
		for _, p := range []string{f.port, f.port2} {
			f.insecureOpts = append(f.insecureOpts, WithInsecureHTTPBase("http://"+host+":"+p))
		}
	}
	f.opts = append([]Option{WithHTTPClient(localhostClient()), WithBearerToken(f.root, f.bearer)}, f.insecureOpts...)
	return f
}

func (f *authFixture) api(root string, extra ...Option) *API {
	f.t.Helper()
	c, err := New(append(append([]Option{}, f.opts...), extra...)...)
	if err != nil {
		f.t.Fatal(err)
	}
	base, err := ParseAPIBase(root, "1.0.0")
	if err != nil {
		f.t.Fatal(err)
	}
	a, err := c.API(base)
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}

// Case 13a: the bearer is bound to its root.
func TestBearerBoundToRoot(t *testing.T) {
	ctx := context.Background()
	f := newAuthFixture(t)
	want := "Bearer " + f.bearer

	if _, err := f.api(f.root).GetProduct(ctx, productID); err != nil {
		t.Fatal(err)
	}
	if got := f.a.lastReq().Header.Get("Authorization"); got != want {
		t.Fatalf("under the root: Authorization %q", got)
	}

	outside := map[string]*counter{
		"http://localhost:" + f.port + "/teapot":      f.a,
		"http://localhost:" + f.port2 + "/tea":        f.b,
		"http://sub.localhost:" + f.port2 + "/tea":    f.b,
		"http://sub.localhost:" + f.port + "/tea":     f.a,
		"http://127.0.0.1:" + f.port + "/tea":         f.a,
		"http://localhost:" + f.port + "/other/thing": f.a,
	}
	for root, srv := range outside {
		before := srv.count()
		if _, err := f.api(root).GetProduct(ctx, productID); err != nil {
			t.Fatalf("%s: %v", root, err)
		}
		if srv.count() != before+1 {
			t.Fatalf("%s: request did not arrive", root)
		}
		if v, ok := srv.lastReq().Header["Authorization"]; ok {
			t.Errorf("%s: Authorization %q sent outside the root", root, v)
		}
	}

	// 302 and 307 from the root to another port or a subdomain: the first
	// hop carries the bearer, the target sees no Authorization, even when a
	// request editor set one (Go copies an Authorization header set on the
	// request to such targets; the auth transport removes it).
	api := f.api(f.root)
	for _, code := range []string{"302", "307"} {
		for _, target := range []string{
			"http://localhost:" + f.port2 + "/tea/v1.0.0/product/" + productID.String(),
			"http://sub.localhost:" + f.port2 + "/tea/v1.0.0/product/" + productID.String(),
		} {
			for _, editor := range []bool{false, true} {
				beforeA, beforeB := f.a.count(), f.b.count()
				from := f.root + "/v1.0.0/r?code=" + code + "&to=" + url.QueryEscape(target)
				eds := []teaapi.RequestEditorFn{rewriteTo(t, from)}
				if editor {
					eds = append(eds, setAuth("Basic c2VjcmV0OnNlY3JldA=="))
				}
				if _, err := api.Generated().GetProductWithResponse(ctx, productID, eds...); err != nil {
					t.Fatalf("%s to %s: %v", code, target, err)
				}
				if f.a.count() != beforeA+1 || f.b.count() != beforeB+1 {
					t.Fatalf("%s to %s: redirect not followed", code, target)
				}
				if got := f.a.lastReq().Header.Get("Authorization"); got != want {
					t.Errorf("%s first hop: Authorization %q, want the bearer", code, got)
				}
				if v, ok := f.b.lastReq().Header["Authorization"]; ok {
					t.Errorf("%s to %s (editor %v): target saw Authorization %q", code, target, editor, v)
				}
			}
		}
	}

	// A header set by a Generated() request editor: removed outside the
	// root, replaced by the configured bearer under it.
	if _, err := f.api("http://localhost:"+f.port2+"/tea").Generated().GetProductWithResponse(ctx, productID, setAuth("Bearer caller-set")); err != nil {
		t.Fatal(err)
	}
	if v, ok := f.b.lastReq().Header["Authorization"]; ok {
		t.Errorf("editor header outside the root reached the server: %q", v)
	}
	if _, err := api.Generated().GetProductWithResponse(ctx, productID, setAuth("Bearer caller-set")); err != nil {
		t.Fatal(err)
	}
	if got := f.a.lastReq().Header.Values("Authorization"); len(got) != 1 || got[0] != want {
		t.Errorf("editor header under the root: %q, want only the configured bearer", got)
	}
}

// tokenServer answers /token by mode and records requests.
type tokenServer struct {
	*counter
	mode string // "ok", "mac", "404", "404-empty", "invalid_client", "redirect"
	to   string
	code int
	body string
}

func newTokenServer() *tokenServer {
	ts := &tokenServer{mode: "ok"}
	ts.counter = newCounter(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ts.body = string(b)
		switch ts.mode {
		case "ok":
			jsonHandler(`{"access_token":"issued-token-1","token_type":"Bearer","expires_in":3600}`)(w, r)
		case "mac":
			jsonHandler(`{"access_token":"issued-token-1","token_type":"mac"}`)(w, r)
		case "404":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"NOT_IMPLEMENTED"}`))
		case "404-empty":
			w.WriteHeader(http.StatusNotFound)
		case "invalid_client":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"bad\u0007 client"}`))
		case "redirect":
			http.Redirect(w, r, ts.to, ts.code)
		}
	})
	return ts
}

// Case 14a: the token request.
func TestRequestToken(t *testing.T) {
	const keyID, secret = "a:b@c", "p:q%"
	ctx := context.Background()
	f := newAuthFixture(t)
	ts := newTokenServer()
	second := newCounter(nil)
	sa, sb := startHTTP(t, ts), startHTTP(t, second)
	port, port2 := portOf(t, sa), portOf(t, sb)
	root := "http://localhost:" + port + "/tea"
	opts := []Option{WithHTTPClient(localhostClient()), WithBearerToken(root, "bearer-token-value-2")}
	for _, h := range []string{"localhost", "sub.localhost"} {
		for _, p := range []string{port, port2} {
			opts = append(opts, WithInsecureHTTPBase("http://"+h+":"+p))
		}
	}
	f.opts = opts
	api := f.api(root)

	tr, err := api.RequestToken(ctx, keyID, secret)
	if err != nil {
		t.Fatal(err)
	}
	if tr.AccessToken != "issued-token-1" || ts.count() != 1 {
		t.Fatalf("token %q after %d requests", tr.AccessToken, ts.count())
	}
	r := ts.lastReq()
	wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("a%3Ab%40c:p%3Aq%25"))
	if r.Method != http.MethodPost || r.URL.Path != "/tea/v1.0.0/token" || ts.body != "grant_type=client_credentials" ||
		r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("request %s %s body %q type %q", r.Method, r.URL.Path, ts.body, r.Header.Get("Content-Type"))
	}
	if got := r.Header.Values("Authorization"); len(got) != 1 || got[0] != wantBasic {
		t.Errorf("Authorization %q, want Basic credentials (not the bearer)", got)
	}

	var errs []error
	ts.mode = "mac"
	_, err = api.RequestToken(ctx, keyID, secret)
	var ue *UnexpectedResponseError
	if !errors.As(err, &ue) {
		t.Errorf("token_type mac: %v", err)
	}
	errs = append(errs, err)
	for _, m := range []string{"404", "404-empty"} {
		ts.mode = m
		_, err = api.RequestToken(ctx, keyID, secret)
		if !errors.Is(err, ErrNotImplemented) {
			t.Errorf("%s: %v, want ErrNotImplemented", m, err)
		}
		errs = append(errs, err)
	}
	ts.mode = "invalid_client"
	_, err = api.RequestToken(ctx, keyID, secret)
	var te *TokenError
	if !errors.As(err, &te) || te.Code != teaapi.InvalidClient || strings.ContainsRune(te.Description, 7) {
		t.Errorf("token error: %v", err)
	}
	errs = append(errs, err)

	// Redirects: 307 to the same host on another port, 302 to a subdomain.
	for _, c := range []struct {
		code int
		to   string
	}{
		{http.StatusTemporaryRedirect, "http://localhost:" + port2 + "/tea/v1.0.0/token"},
		{http.StatusFound, "http://sub.localhost:" + port2 + "/tea/v1.0.0/token"},
		{http.StatusTemporaryRedirect, "http://localhost:" + port + "/tea/v1.0.0/token2"},
	} {
		ts.mode, ts.to, ts.code = "redirect", c.to, c.code
		before := ts.count()
		_, err = api.RequestToken(ctx, keyID, secret)
		if !errors.As(err, &ue) || ue.Status != c.code || !strings.Contains(ue.Reason, "redirect from /token refused") {
			t.Errorf("%d to %s: %v", c.code, c.to, err)
		}
		if ts.count() != before+1 {
			t.Errorf("%d to %s: the redirect was followed (%d requests)", c.code, c.to, ts.count()-before)
		}
		if strings.Contains(err.Error(), c.to) || strings.Contains(err.Error(), "token2") {
			t.Errorf("error echoes the Location: %v", err)
		}
		errs = append(errs, err)
	}
	if second.count() != 0 {
		t.Errorf("the redirect target received %d requests", second.count())
	}

	for _, e := range errs {
		for _, s := range []string{keyID, secret, url.QueryEscape(keyID), url.QueryEscape(secret), wantBasic[6:], "bearer-token-value-2"} {
			if e != nil && strings.Contains(e.Error(), s) {
				t.Errorf("error %q contains a credential", e)
			}
		}
	}
}

// keyServer is a TEA root that needs a token: /token issues
// "issued-access-token-<n>" for the right Basic credentials, and a product
// GET succeeds only with the token the server currently accepts.
type keyServer struct {
	*counter
	tokens   atomic.Int64 // tokens issued
	valid    guarded[string]
	mode     guarded[string] // "", "always-invalid", "403", "basic-challenge", "redirect:<url>"
	tokenTo  guarded[string] // when set, /token answers 307 to it
	expires  guarded[string] // expires_in of issued tokens; "" is 3600
	basic    string
	tokReqs  guarded[int]
	resource guarded[[]string] // Authorization of each product request
}

func newKeyServer(keyID, secret string) *keyServer {
	ks := &keyServer{basic: "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(keyID)+":"+url.QueryEscape(secret)))}
	ks.counter = newCounter(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			ks.tokReqs.set(ks.tokReqs.get() + 1)
			if to := ks.tokenTo.get(); to != "" {
				http.Redirect(w, r, to, http.StatusTemporaryRedirect)
				return
			}
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != ks.basic {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			tok := "issued-access-token-" + strconv.FormatInt(ks.tokens.Add(1), 10)
			ks.valid.set(tok)
			exp := ks.expires.get()
			if exp == "" {
				exp = "3600"
			}
			jsonHandler(`{"access_token":"`+tok+`","token_type":"Bearer","expires_in":`+exp+`}`)(w, r)
			return
		}
		got := r.Header.Get("Authorization")
		ks.resource.set(append(ks.resource.get(), got))
		switch mode := ks.mode.get(); {
		case mode == "403":
			// A Bearer challenge on a 403 (RFC 6750 insufficient_scope): it
			// still must not trigger a token request.
			w.Header().Set("WWW-Authenticate", `Bearer realm="x", error="insufficient_scope"`)
			w.WriteHeader(http.StatusForbidden)
		case strings.HasPrefix(mode, "redirect:"):
			http.Redirect(w, r, strings.TrimPrefix(mode, "redirect:"), http.StatusFound)
		case mode == "basic-challenge":
			w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
			w.WriteHeader(http.StatusUnauthorized)
		case got == "":
			w.Header().Set("WWW-Authenticate", `Bearer realm="x"`)
			w.WriteHeader(http.StatusUnauthorized)
		case mode == "always-invalid" || got != "Bearer "+ks.valid.get():
			w.Header().Set("WWW-Authenticate", `Bearer realm="x", error="invalid_token"`)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			jsonHandler(productJSON())(w, r)
		}
	})
	return ks
}

// Case 14b: WithAPIKey's recovery.
func TestAPIKeyRecovery(t *testing.T) {
	const keyID, secret = "key:id@1", "s3cret%value"
	ctx := context.Background()
	ks := newKeyServer(keyID, secret)
	second := newCounter(nil)
	sa, sb := startHTTP(t, ks), startHTTP(t, second)
	root := sa.URL + "/tea"
	var events []TraceEvent
	var errs []error
	newAPI := func(rootPath string, keyRoot string) *API {
		return newTestAPI(t, sa.URL, rootPath, WithInsecureHTTPBase(sb.URL), WithAPIKey(keyRoot, keyID, secret),
			WithTrace(func(ev TraceEvent) { events = append(events, ev) }))
	}
	a := newAPI("/tea", root)
	tokens := func() int { return ks.tokReqs.get() }
	resources := func() []string { return ks.resource.get() }

	// First request: 401 Bearer challenge, exactly one token request, one
	// retry with the token.
	if _, err := a.GetProduct(ctx, productID); err != nil {
		t.Fatal(err)
	}
	if tokens() != 1 || !slices.Equal(resources(), []string{"", "Bearer issued-access-token-1"}) {
		t.Fatalf("first request: %d token requests, product requests carried %q", tokens(), resources())
	}
	if r := ks.requests()[1]; r.Method != http.MethodPost || r.URL.Path != "/tea/v1.0.0/token" || r.Header.Get("Authorization") != ks.basic {
		t.Errorf("token request %s %s", r.Method, r.URL.Path)
	}
	// The cached token is sent up front; no token request.
	if _, err := a.GetProduct(ctx, productID); err != nil || tokens() != 1 || resources()[2] != "Bearer issued-access-token-1" {
		t.Fatalf("cached token: %v, %d token requests, %q", err, tokens(), resources())
	}

	// invalid_token on the cached token (the server moved on): one refresh,
	// one retry.
	ks.valid.set("rotated-elsewhere")
	if _, err := a.GetProduct(ctx, productID); err != nil {
		t.Fatal(err)
	}
	if tokens() != 2 || !slices.Equal(resources()[3:], []string{"Bearer issued-access-token-1", "Bearer issued-access-token-2"}) {
		t.Fatalf("refresh: %d token requests, %q", tokens(), resources()[3:])
	}

	// invalid_token again after the refresh: returned as ErrUnauthorized,
	// one token request, no loop.
	ks.mode.set("always-invalid")
	before, beforeRes := tokens(), len(resources())
	_, err := a.GetProduct(ctx, productID)
	if !errors.Is(err, ErrUnauthorized) || tokens() != before+1 || len(resources()) != beforeRes+2 {
		t.Errorf("second invalid_token: %v, %d token requests, %d product requests", err, tokens()-before, len(resources())-beforeRes)
	}
	errs = append(errs, err)
	// The same on a fresh client: two token requests in total.
	fresh := newAPI("/tea", root)
	before = tokens()
	_, err = fresh.GetProduct(ctx, productID)
	if !errors.Is(err, ErrUnauthorized) || tokens() != before+1 {
		t.Errorf("fresh client, always invalid: %v, %d token requests", err, tokens()-before)
	}
	errs = append(errs, err)
	_, err = fresh.GetProduct(ctx, productID)
	if !errors.Is(err, ErrUnauthorized) || tokens() != before+2 {
		t.Errorf("fresh client, cached token invalid: %v, %d token requests in total, want 2", err, tokens()-before)
	}
	errs = append(errs, err)

	// 403: no token request.
	ks.mode.set("403")
	before, beforeRes = tokens(), len(resources())
	_, err = a.GetProduct(ctx, productID)
	if !errors.Is(err, ErrForbidden) || tokens() != before || len(resources()) != beforeRes+1 {
		t.Errorf("403: %v, %d token requests", err, tokens()-before)
	}
	errs = append(errs, err)
	// A 401 whose challenge is not Bearer: no token request.
	ks.mode.set("basic-challenge")
	_, err = newAPI("/tea", root).GetProduct(ctx, productID)
	if !errors.Is(err, ErrUnauthorized) || tokens() != before {
		t.Errorf("Basic challenge: %v, %d token requests", err, tokens()-before)
	}
	errs = append(errs, err)
	ks.mode.set("")

	// A request under the root redirected off it, where a Bearer challenge
	// answers: the 401 is not from the root, so no token request.
	challenger := newCounter(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="elsewhere"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	sc := startHTTP(t, challenger)
	ks.mode.set("redirect:" + sc.URL + "/tea/v1.0.0/product/" + productID.String())
	offRoot := newTestAPI(t, sa.URL, "/tea", WithInsecureHTTPBase(sc.URL), WithAPIKey(root, keyID, secret))
	_, err = offRoot.GetProduct(ctx, productID)
	if !errors.Is(err, ErrUnauthorized) || tokens() != before || challenger.count() != 1 {
		t.Errorf("401 from off the root after a redirect: %v, %d token requests, %d off-root requests", err, tokens()-before, challenger.count())
	}
	if v, ok := challenger.lastReq().Header["Authorization"]; ok {
		t.Errorf("off-root redirect target received Authorization %q", v)
	}
	errs = append(errs, err)
	ks.mode.set("")

	// Not a GET (a request editor makes it HEAD): no recovery.
	head := func(_ context.Context, r *http.Request) error { r.Method = http.MethodHead; return nil }
	if resp, err := newAPI("/tea", root).Generated().GetProductWithResponse(ctx, productID, head); err != nil || resp.StatusCode() != http.StatusUnauthorized || tokens() != before {
		t.Errorf("HEAD: %v, %d token requests", err, tokens()-before)
	}
	// A request outside the key's root: no token sent, no recovery.
	other := newTestAPI(t, sa.URL, "/other", WithAPIKey(root, keyID, secret))
	beforeRes = len(resources())
	if _, err := other.GetProduct(ctx, productID); !errors.Is(err, ErrUnauthorized) || tokens() != before || resources()[beforeRes] != "" {
		t.Errorf("outside the root: %v, %d token requests", err, tokens()-before)
	}
	// An API whose base is not under the key's root (the root is deeper):
	// the recovery is refused with no token request.
	deep := newAPI("/tea", root+"/v1.0.0/product")
	_, err = deep.GetProduct(ctx, productID)
	if !errors.Is(err, ErrInvalidArgument) || tokens() != before {
		t.Errorf("API base outside the root: %v, %d token requests", err, tokens()-before)
	}
	errs = append(errs, err)

	// An external artifact url under the key's root answered 401 Bearer:
	// an anonymous request never triggers a token request.
	body := []byte(fixtureJSON)
	ext := fmtOf(mtJSON, sha256Sum(body))
	ext.Url = strPtr(root + "/files/widget.json")
	before, beforeRes = tokens(), len(resources())
	_, err = newAPI("/tea", root).DownloadArtifact(ctx, ref3, ext, io.Discard, DownloadOptions{})
	if !errors.Is(err, ErrUnauthorized) || tokens() != before || len(resources()) != beforeRes+1 || resources()[beforeRes] != "" {
		t.Errorf("anonymous external url under the root: %v, %d token requests, %d requests", err, tokens()-before, len(resources())-beforeRes)
	}
	errs = append(errs, err)

	// The automatic token request answered 307 to another port: the call
	// fails and the target receives nothing.
	ks.tokenTo.set(sb.URL + "/tea/v1.0.0/token")
	before, beforeRes = tokens(), len(resources())
	_, err = newAPI("/tea", root).GetProduct(ctx, productID)
	var ue *UnexpectedResponseError
	if !errors.As(err, &ue) || ue.Status != http.StatusTemporaryRedirect || tokens() != before+1 || len(resources()) != beforeRes+1 {
		t.Errorf("token 307: %v, %d token requests, %d product requests", err, tokens()-before, len(resources())-beforeRes)
	}
	if second.count() != 0 {
		t.Errorf("the redirect target received %d requests", second.count())
	}
	errs = append(errs, err)
	ks.tokenTo.set("")

	secrets := []string{keyID, secret, url.QueryEscape(keyID), url.QueryEscape(secret), ks.basic[len("Basic "):], "issued-access-token"}
	for _, e := range errs {
		for _, s := range secrets {
			if e != nil && strings.Contains(e.Error(), s) {
				t.Errorf("error %q contains %q", e, s)
			}
		}
	}
	if len(events) == 0 {
		t.Fatal("no trace events")
	}
	for _, ev := range events {
		for _, s := range secrets {
			if strings.Contains(fmt.Sprintf("%+v", ev), s) {
				t.Errorf("trace event %+v contains %q", ev, s)
			}
		}
	}
}

// The token cache: expires_in minus 30 s; none given, no expiry.
func TestAPIKeyTokenCache(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	n := func(v int) *int { return &v }
	k := &apiKey{}
	k.store("t1", n(3600), now)
	if k.cached(now.Add(3569*time.Second)) != "t1" || k.cached(now.Add(3570*time.Second)) != "" {
		t.Error("expires_in 3600: the token must be used until 3570 s and not after")
	}
	k.store("t2", n(30), now)
	if k.cached(now) != "" {
		t.Error("expires_in 30: nothing left after the 30 s leeway, the token must not be cached")
	}
	// expires_in is server-supplied: values whose seconds overflow a
	// time.Duration are saturated, not wrapped (a wrap made them negative,
	// so the token was not cached); a negative one is not cached.
	for _, v := range []int{math.MaxInt, int(math.MaxInt64/int64(time.Second)) + 1} {
		k.store("big", n(v), now)
		if k.cached(now.Add(100*365*24*time.Hour)) != "big" {
			t.Errorf("expires_in %d: the token must be cached for a very long time", v)
		}
	}
	k.store("neg", n(-5), now)
	if k.cached(now) != "" {
		t.Error("expires_in -5: the token must not be cached")
	}
	k.store("t3", nil, now)
	if k.cached(now.Add(1000*time.Hour)) != "t3" {
		t.Error("no expires_in: the token must be kept")
	}
	k.drop("other")
	if k.cached(now) != "t3" {
		t.Error("drop of another token must keep the cached one")
	}
	k.drop("t3")
	if k.cached(now) != "" {
		t.Error("drop of the cached token must forget it")
	}
}

// WithAPIKey's option checks; the secret never appears in the error.
func TestWithAPIKeyOption(t *testing.T) {
	const secret = "option-secret-value"
	for name, opts := range map[string][]Option{
		"empty id":     {WithAPIKey("https://example.com/tea", "", secret)},
		"empty secret": {WithAPIKey("https://example.com/tea", "id", "")},
		"bad root":     {WithAPIKey("https://example.com/tea/", "id", secret)},
		"http root":    {WithAPIKey("http://example.com/tea", "id", secret)},
	} {
		_, err := New(opts...)
		if !errors.Is(err, ErrInvalidOption) {
			t.Errorf("%s: %v, want ErrInvalidOption", name, err)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the error contains the secret: %v", name, err)
		}
	}
	if _, err := New(WithInsecureHTTPBase("http://example.com"), WithAPIKey("http://example.com/tea", "id", secret)); err != nil {
		t.Errorf("http root under an allowance: %v", err)
	}
}

// A token whose expires_in leaves nothing after the 30 s leeway is used for
// the retry that obtained it but not cached, so the next request starts a
// new recovery (T-5 of OOL-6 test run 1).
func TestAPIKeyUncachedToken(t *testing.T) {
	const keyID, secret = "uncached-id", "uncached-secret"
	ctx := context.Background()
	ks := newKeyServer(keyID, secret)
	ks.expires.set("30")
	sa := startHTTP(t, ks)
	a := newTestAPI(t, sa.URL, "/tea", WithAPIKey(sa.URL+"/tea", keyID, secret))
	for i := 1; i <= 2; i++ {
		if _, err := a.GetProduct(ctx, productID); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	want := []string{"", "Bearer issued-access-token-1", "", "Bearer issued-access-token-2"}
	if got := ks.resource.get(); ks.tokReqs.get() != 2 || !slices.Equal(got, want) {
		t.Errorf("%d token requests, product requests carried %q, want %q", ks.tokReqs.get(), got, want)
	}
}
