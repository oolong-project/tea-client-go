package tea

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Fixed, made-up identifiers used across the tests.
var (
	productID = uuid.MustParse("0b6f1c2e-6d5a-4c47-9a8e-2f1d3c4b5a60")
	releaseID = uuid.MustParse("1c7a2d3f-7e6b-4d58-8b9f-3a2e4d5c6b71")
	compID    = uuid.MustParse("2d8b3e4a-8f7c-4e69-9cad-4b3f5e6d7c82")
	compRelID = uuid.MustParse("3e9c4f5b-9a8d-4f7a-8dbe-5c4a6f7e8d93")
	artID     = uuid.MustParse("4fad5a6c-ab9e-4a8b-9ecf-6d5b7a8f9ea4")
)

// counter is a handler that counts its requests and records the last one.
type counter struct {
	n    atomic.Int64
	mu   sync.Mutex
	last *http.Request
	all  []*http.Request
	h    http.HandlerFunc
}

func (c *counter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.n.Add(1)
	c.mu.Lock()
	c.last = r.Clone(context.Background())
	c.all = append(c.all, c.last)
	c.mu.Unlock()
	if c.h != nil {
		c.h(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *counter) count() int64 { return c.n.Load() }

func (c *counter) lastReq() *http.Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

func (c *counter) requests() []*http.Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*http.Request(nil), c.all...)
}

func newCounter(h http.HandlerFunc) *counter { return &counter{h: h} }

// jsonHandler answers 200 with body as application/json.
func jsonHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

// startHTTP starts a plain-http test server and closes it at the end.
func startHTTP(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

// startTLS starts an https test server and closes it at the end.
func startTLS(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	return s
}

// newTestAPI builds a client allowing srvURL over http (when it is http),
// and an API at srvURL+rootPath, version 1.0.0.
func newTestAPI(t *testing.T, srvURL, rootPath string, opts ...Option) *API {
	t.Helper()
	all := opts
	if strings.HasPrefix(srvURL, "http://") {
		all = append([]Option{WithInsecureHTTPBase(srvURL)}, opts...)
	}
	c, err := New(all...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	base, err := ParseAPIBase(srvURL+rootPath, "1.0.0")
	if err != nil {
		t.Fatalf("ParseAPIBase: %v", err)
	}
	a, err := c.API(base)
	if err != nil {
		t.Fatalf("API: %v", err)
	}
	return a
}

// localhostClient returns an http.Client whose dialer maps localhost and
// every *.localhost name to 127.0.0.1, so tests can address test servers by
// distinct host names.
func localhostClient() *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if host == "localhost" || strings.HasSuffix(host, ".localhost") {
				addr = net.JoinHostPort("127.0.0.1", port)
			}
			return d.DialContext(ctx, network, addr)
		},
	}
	return &http.Client{Transport: tr}
}

// portOf returns the port of a test server.
func portOf(t *testing.T, s *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(s.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func ctxTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// guarded is a value shared between a test and its handlers.
type guarded[T any] struct {
	mu sync.Mutex
	v  T
}

func (g *guarded[T]) get() T {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.v
}

func (g *guarded[T]) set(v T) {
	g.mu.Lock()
	g.v = v
	g.mu.Unlock()
}
