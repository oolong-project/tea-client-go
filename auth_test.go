package tea

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

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
