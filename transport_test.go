package tea

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/oolong-project/tea-client-go/teaapi"
)

func productJSON() string {
	return `{"uuid":"` + productID.String() + `","name":"Sample Product","identifiers":[]}`
}

// paddedProduct is a valid product JSON body of exactly n bytes.
func paddedProduct(n int) string {
	s := productJSON()
	return s + strings.Repeat(" ", n-len(s))
}

// rewriteTo is a Generated() request editor that sends the request to target.
func rewriteTo(t *testing.T, target string) teaapi.RequestEditorFn {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	return func(_ context.Context, req *http.Request) error {
		req.URL = u
		req.Host = u.Host
		return nil
	}
}

func isPolicy(err error, sentinel error) bool {
	var pe *URLPolicyError
	return errors.As(err, &pe) && errors.Is(err, sentinel)
}

// Case 9a: an allowance covers what is under its base.
func TestAllowanceCoversPathsUnderBase(t *testing.T) {
	h := newCounter(jsonHandler(productJSON()))
	srv := startHTTP(t, h)
	other := newCounter(jsonHandler(productJSON()))
	otherSrv := startHTTP(t, other)
	port, otherPort := portOf(t, srv), portOf(t, otherSrv)
	ctx := context.Background()

	c, err := New(WithInsecureHTTPBase(srv.URL + "/tea"))
	if err != nil {
		t.Fatal(err)
	}
	base, err := ParseAPIBase(srv.URL+"/tea", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.API(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetProduct(ctx, productID); err != nil {
		t.Fatalf("request under the base: %v", err)
	}
	if got := h.lastReq().URL.Path; got != "/tea/v1.0.0/product/"+productID.String() {
		t.Fatalf("path %q", got)
	}
	if _, err := a.Generated().GetProductWithResponse(ctx, productID, rewriteTo(t, srv.URL+"/tea")); err != nil {
		t.Fatalf("request to the base itself: %v", err)
	}
	if got := h.lastReq().URL.Path; got != "/tea" {
		t.Fatalf("base itself: path %q", got)
	}

	before := h.count()
	refused := []string{
		"http://127.0.0.1:" + port + "/teapot/v1.0.0/product/" + productID.String(),
		"http://127.0.0.1:" + port + "/other",
		"http://127.0.0.1:" + otherPort + "/tea/v1.0.0/product/" + productID.String(),
		"http://localhost:" + port + "/tea/v1.0.0/product/" + productID.String(),
	}
	for _, target := range refused {
		_, err := a.Generated().GetProductWithResponse(ctx, productID, rewriteTo(t, target))
		if !isPolicy(err, ErrInsecureURL) {
			t.Errorf("%s: err = %v, want *URLPolicyError wrapping ErrInsecureURL", target, err)
		}
	}
	for _, root := range []string{
		"http://127.0.0.1:" + port + "/teapot",
		"http://127.0.0.1:" + otherPort + "/tea",
		"http://localhost:" + port + "/tea",
	} {
		b, err := ParseAPIBase(root, "1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.API(b); !isPolicy(err, ErrInsecureURL) {
			t.Errorf("API(%s) = %v, want ErrInsecureURL", root, err)
		}
	}
	if h.count() != before || other.count() != 0 {
		t.Errorf("refused requests reached a server: %d, %d", h.count()-before, other.count())
	}

	for _, root := range []string{
		"http://127.0.0.1:" + port + "/tea/../admin",
		"http://127.0.0.1:" + port + "/tea/%2e%2e/admin",
		"https://example.com/a/./b",
	} {
		if _, err := ParseAPIBase(root, "1.0.0"); !isPolicy(err, ErrInsecureURL) {
			t.Errorf("ParseAPIBase(%s) = %v, want *URLPolicyError wrapping ErrInsecureURL", root, err)
		}
	}

	// The origin form covers every path on the origin, and nothing else.
	o := newTestAPI(t, srv.URL, "/anything")
	if _, err := o.GetProduct(ctx, productID); err != nil {
		t.Fatalf("origin allowance: %v", err)
	}
	if got := h.lastReq().URL.Path; got != "/anything/v1.0.0/product/"+productID.String() {
		t.Fatalf("origin allowance path %q", got)
	}
	_, err = o.Generated().GetProductWithResponse(ctx, productID, rewriteTo(t, "http://127.0.0.1:"+otherPort+"/x"))
	if !isPolicy(err, ErrInsecureURL) || other.count() != 0 {
		t.Errorf("origin allowance, other port: %v (requests %d)", err, other.count())
	}
}

func TestUnderHelper(t *testing.T) {
	mustBase := func(s string) baseURL {
		b, err := parseBase(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	mustURL := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	cases := []struct {
		base, u string
		want    bool
	}{
		{"http://H", "http://H:80/x", true},
		{"http://H:80", "http://h/x", true},
		{"http://h:80/tea", "http://H/tea", true},
		{"http://h/tea", "http://h/tea/v1.0.0/x", true},
		{"http://h/tea", "http://h/teapot", false},
		{"http://h/tea", "http://h/", false},
		{"http://h", "http://h", true},
		{"http://h", "http://h:81/", false},
		{"http://h", "https://h:80/", false},
		{"http://h", "http://g/", false},
	}
	for _, c := range cases {
		if got := under(mustURL(c.u), mustBase(c.base)); got != c.want {
			t.Errorf("under(%s, %s) = %v, want %v", c.u, c.base, got, c.want)
		}
	}
}

// Case 10: redirects.
func TestRedirects(t *testing.T) {
	ctx := context.Background()
	plain := newCounter(jsonHandler(productJSON()))
	plainSrv := startHTTP(t, plain)

	var target string
	tlsSrv := startTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/loop/"):
			var n int
			fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/loop/"), "%d", &n)
			http.Redirect(w, r, fmt.Sprintf("/loop/%d", n+1), http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/tea/"):
			http.Redirect(w, r, target, http.StatusFound)
		default:
			jsonHandler(productJSON())(w, r)
		}
	}))
	api := func(opts ...Option) *API {
		return newTestAPI(t, tlsSrv.URL, "/tea", append([]Option{WithHTTPClient(tlsSrv.Client())}, opts...)...)
	}

	// https to http is refused without an allowance.
	target = plainSrv.URL + "/tea/v1.0.0/product/" + productID.String()
	if _, err := api().GetProduct(ctx, productID); !isPolicy(err, ErrInsecureURL) || plain.count() != 0 {
		t.Errorf("https to http: %v (requests %d)", err, plain.count())
	}
	// ... allowed when the target is under an allowance, refused when not.
	if _, err := api(WithInsecureHTTPBase(plainSrv.URL+"/other")).GetProduct(ctx, productID); !isPolicy(err, ErrInsecureURL) || plain.count() != 0 {
		t.Errorf("http target beside the allowance: %v (requests %d)", err, plain.count())
	}
	if _, err := api(WithInsecureHTTPBase(plainSrv.URL+"/tea")).GetProduct(ctx, productID); err != nil || plain.count() != 1 {
		t.Errorf("http target under an allowance: %v (requests %d)", err, plain.count())
	}

	// A userinfo target is refused.
	target = strings.Replace(tlsSrv.URL, "https://", "https://user:pw@", 1) + "/final"
	_, err := api().GetProduct(ctx, productID)
	if !isPolicy(err, ErrInsecureURL) || strings.Contains(err.Error(), "pw@") {
		t.Errorf("userinfo target: %v", err)
	}

	// The redirect limit: 5 redirects are followed, the 6th is refused.
	loop := newTestAPI(t, tlsSrv.URL, "/loop/0", WithHTTPClient(tlsSrv.Client()))
	_, err = loop.Generated().GetProductWithResponse(ctx, productID, rewriteTo(t, tlsSrv.URL+"/loop/0"))
	if !isPolicy(err, ErrRedirectLimit) {
		t.Errorf("redirect loop: %v, want ErrRedirectLimit", err)
	}
	tr := newCounter(nil)
	traced := newTestAPI(t, tlsSrv.URL, "/tea", WithHTTPClient(tlsSrv.Client()), WithTrace(func(ev TraceEvent) {
		if ev.Kind == TraceRequest {
			tr.n.Add(1)
		}
	}))
	_, err = traced.Generated().GetProductWithResponse(ctx, productID, rewriteTo(t, tlsSrv.URL+"/loop/0"))
	if !errors.Is(err, ErrRedirectLimit) || tr.count() != 6 {
		t.Errorf("redirect loop: %v after %d requests, want ErrRedirectLimit after 6 (1 + 5 redirects)", err, tr.count())
	}
}

// Case 11a: byte limits on typed JSON calls.
func TestJSONByteLimit(t *testing.T) {
	const limit = 1024
	ctx := context.Background()
	var body string
	var chunked, gz bool
	var sawGzip bool
	srv := startHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case gz:
			sawGzip = strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write([]byte(body))
			_ = zw.Close()
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", fmt.Sprint(buf.Len()))
			_, _ = w.Write(buf.Bytes())
		case chunked:
			_, _ = w.Write([]byte(body[:10]))
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte(body[10:]))
		default:
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			_, _ = w.Write([]byte(body))
		}
	}))
	a := newTestAPI(t, srv.URL, "", WithLimits(Limits{JSONBytes: limit}))

	for _, mode := range []string{"content-length", "chunked", "gzip"} {
		chunked, gz = mode == "chunked", mode == "gzip"
		body = paddedProduct(limit)
		if _, err := a.GetProduct(ctx, productID); err != nil {
			t.Errorf("%s: body of exactly the limit: %v", mode, err)
		}
		body = paddedProduct(limit + 1)
		if _, err := a.GetProduct(ctx, productID); !errors.Is(err, ErrResponseTooLarge) {
			t.Errorf("%s: body one byte over: %v, want ErrResponseTooLarge", mode, err)
		}
	}
	body = paddedProduct(64 * limit)
	if _, err := a.GetProduct(ctx, productID); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("gzip bomb: %v, want ErrResponseTooLarge", err)
	}
	if !sawGzip {
		t.Error("the transport did not negotiate gzip; the gzip case tested nothing")
	}

	// A non-2xx body over ErrorBodyBytes is cut, and still classified.
	errSrv := startHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		status := http.StatusNotFound
		if strings.Contains(r.URL.Path, "/component/") {
			status = http.StatusInternalServerError
		}
		w.WriteHeader(status)
		if strings.Contains(r.URL.Path, "/productRelease/") {
			// The TEA error object starts after ErrorBodyBytes: only a body
			// that is not cut would classify it.
			_, _ = w.Write([]byte(strings.Repeat(" ", 8192) + `{"error":"OBJECT_UNKNOWN"}`))
			return
		}
		_, _ = w.Write([]byte(`{"error":"OBJECT_UNKNOWN"}` + strings.Repeat(" ", 256<<10)))
	}))
	e := newTestAPI(t, errSrv.URL, "", WithLimits(Limits{ErrorBodyBytes: 4096}))
	_, err := e.GetProduct(ctx, productID)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !errors.Is(err, ErrObjectUnknown) || errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("large 404: %v, want *APIError OBJECT_UNKNOWN", err)
	}
	if _, err := e.GetComponent(ctx, compID); !errors.Is(err, ErrServer) {
		t.Errorf("large 500: %v, want ErrServer", err)
	}
	// The body is cut at ErrorBodyBytes: an error object beyond it is not read.
	_, err = e.GetProductRelease(ctx, releaseID)
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound || apiErr.TEA || errors.Is(err, ErrObjectUnknown) {
		t.Errorf("TEA error after ErrorBodyBytes of padding: %#v, want a non-TEA 404 (body cut)", err)
	}
}

// Case 11c: Generated() is bounded, and the kind comes from the path.
func TestGeneratedIsBounded(t *testing.T) {
	ctx := context.Background()
	var size int
	srv := startHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/download") {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(bytes.Repeat([]byte("x"), size))
			return
		}
		jsonHandler(paddedProduct(size))(w, r)
	}))
	a := newTestAPI(t, srv.URL, "/tea", WithLimits(Limits{JSONBytes: 1024, DownloadBytes: 1024}))
	g := a.Generated()

	size = 1025
	if _, err := g.GetProductWithResponse(ctx, productID); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("Generated GetProduct over JSONBytes: %v", err)
	}
	if _, err := g.DownloadArtifactByVersionWithResponse(ctx, artID, 1, nil); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("Generated download over DownloadBytes: %v", err)
	}
	size = 512
	r, err := g.DownloadArtifactByVersionWithResponse(ctx, artID, 1, nil)
	if err != nil || len(r.Body) != 512 {
		t.Errorf("Generated download under the limit: %v", err)
	}

	// Classification by path: 2 KiB is over JSONBytes and under DownloadBytes.
	b := newTestAPI(t, srv.URL, "/tea", WithLimits(Limits{JSONBytes: 1024, DownloadBytes: 4096}))
	size = 2048
	if _, err := b.Generated().GetProductWithResponse(ctx, productID); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("2 KiB on a JSON path: %v, want ErrResponseTooLarge", err)
	}
	r, err = b.Generated().DownloadArtifactByVersionWithResponse(ctx, artID, 1, nil)
	if err != nil || len(r.Body) != 2048 {
		t.Errorf("2 KiB on a download path: %v", err)
	}
	if r, err := b.Generated().DownloadLatestArtifactWithResponse(ctx, artID, nil); err != nil || len(r.Body) != 2048 {
		t.Errorf("2 KiB on the latest download path: %v", err)
	}
}

func TestClassify(t *testing.T) {
	d := &doer{base: &url.URL{Scheme: "https", Host: "example.com", Path: "/tea/v1.0.0"}}
	for path, want := range map[string]callKind{
		"/tea/v1.0.0/artifact/" + artID.String() + "/latest/download":  kindDownload,
		"/tea/v1.0.0/artifact/" + artID.String() + "/3/download":       kindDownload,
		"/tea/v1.0.0/artifact/" + artID.String() + "/latest/signature": kindSignature,
		"/tea/v1.0.0/artifact/" + artID.String() + "/3/signature":      kindSignature,
		"/tea/v1.0.0/discovery":                                    kindDiscovery,
		"/tea/v1.0.0/artifact/" + artID.String() + "/3":            kindJSON,
		"/tea/v1.0.0/product/" + productID.String():                kindJSON,
		"/other/v1.0.0/artifact/" + artID.String() + "/3/download": kindJSON,
		"/tea/v1.0.0/token":                                        kindJSON,
	} {
		if got := d.classify(&url.URL{Scheme: "https", Host: "example.com", Path: path}); got != want {
			t.Errorf("classify(%s) = %d, want %d", path, got, want)
		}
	}
}

// stallServer answers per mode: "headers" sends headers and one body byte,
// then stalls; "none" never sends headers; "after1k" sends 1 KiB then
// stalls; "trickle" sends one byte every 100 ms for 1.5 s.
func stallServer(t *testing.T, mode *guarded[string]) string {
	t.Helper()
	stop := make(chan struct{})
	srv := startHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wait := func() {
			select {
			case <-r.Context().Done():
			case <-stop:
			}
		}
		switch mode.get() {
		case "none":
			wait()
		case "headers":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{"))
			w.(http.Flusher).Flush()
			wait()
		case "after1k":
			_, _ = w.Write(bytes.Repeat([]byte("x"), 1024))
			w.(http.Flusher).Flush()
			wait()
		case "trickle":
			for i := 0; i < 15; i++ {
				_, _ = w.Write([]byte("x"))
				w.(http.Flusher).Flush()
				select {
				case <-time.After(100 * time.Millisecond):
				case <-r.Context().Done():
					return
				}
			}
		}
	}))
	t.Cleanup(func() { close(stop) })
	return srv.URL
}

// Case 11d: time bounds.
func TestCallTimeout(t *testing.T) {
	mode := &guarded[string]{v: "headers"}
	srvURL := stallServer(t, mode)
	bounded := WithLimits(Limits{CallTimeout: 200 * time.Millisecond})

	check := func(name string, f func() error) {
		t.Helper()
		start := time.Now()
		err := f()
		if !errors.Is(err, ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: %v, want ErrTimeout", name, err)
		}
		if d := time.Since(start); d > time.Second || d < 150*time.Millisecond {
			t.Errorf("%s: returned after %v", name, d)
		}
	}
	for _, m := range []string{"headers", "none"} {
		mode.set(m)
		a := newTestAPI(t, srvURL, "", bounded)
		check(m+" typed", func() error { _, err := a.GetProduct(ctxTimeout(t, 5*time.Second), productID); return err })
		check(m+" generated", func() error {
			_, err := a.Generated().GetProductWithResponse(ctxTimeout(t, 5*time.Second), productID)
			return err
		})
		own := newTestAPI(t, srvURL, "", bounded, WithHTTPClient(&http.Client{}))
		check(m+" caller http.Client", func() error { _, err := own.GetProduct(ctxTimeout(t, 5*time.Second), productID); return err })
	}

	// The caller's earlier deadline wins, and is not reported as ErrTimeout.
	mode.set("headers")
	a := newTestAPI(t, srvURL, "", bounded)
	start := time.Now()
	_, err := a.GetProduct(ctxTimeout(t, 100*time.Millisecond), productID)
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrTimeout) || time.Since(start) > 190*time.Millisecond {
		t.Errorf("caller deadline 100 ms: %v after %v", err, time.Since(start))
	}

	// A negative CallTimeout leaves only the caller's context.
	off := newTestAPI(t, srvURL, "", WithLimits(Limits{CallTimeout: -1}))
	start = time.Now()
	_, err = off.GetProduct(ctxTimeout(t, 300*time.Millisecond), productID)
	if d := time.Since(start); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrTimeout) || d < 290*time.Millisecond || d > time.Second {
		t.Errorf("CallTimeout disabled: %v after %v", err, d)
	}
}

func TestIdleTimeoutGenerated(t *testing.T) {
	mode := &guarded[string]{v: "after1k"}
	srvURL := stallServer(t, mode)
	// CallTimeout is short too, to show a download is not under it.
	a := newTestAPI(t, srvURL, "/tea", WithLimits(Limits{IdleTimeout: 200 * time.Millisecond, CallTimeout: 200 * time.Millisecond}))

	start := time.Now()
	_, err := a.Generated().DownloadArtifactByVersionWithResponse(ctxTimeout(t, 5*time.Second), artID, 1, nil)
	if d := time.Since(start); !errors.Is(err, ErrTimeout) || d > time.Second {
		t.Errorf("stalled download: %v after %v, want ErrTimeout within 1 s", err, d)
	}

	mode.set("trickle")
	start = time.Now()
	r, err := a.Generated().DownloadArtifactByVersionWithResponse(context.Background(), artID, 1, nil)
	if err != nil || len(r.Body) != 15 {
		t.Errorf("trickling download: %v", err)
	}
	if d := time.Since(start); d < 1400*time.Millisecond {
		t.Errorf("trickling download finished after %v; it should take about 1.5 s", d)
	}
}
