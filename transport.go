package tea

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// callKind is the kind of a request, which selects its byte limit, its time
// bound and its trace stage (architecture D3). It travels on the request
// context, so redirect hops carry it too.
type callKind int

const (
	kindUnset callKind = iota
	kindWellKnown
	kindDiscovery
	kindJSON
	kindToken
	kindDownload
	kindSignature
)

type kindKey struct{}

func withKind(ctx context.Context, k callKind) context.Context {
	return context.WithValue(ctx, kindKey{}, k)
}

func kindFrom(ctx context.Context) callKind {
	k, _ := ctx.Value(kindKey{}).(callKind)
	return k
}

func (k callKind) stage() Stage {
	switch k {
	case kindWellKnown:
		return StageWellKnown
	case kindDiscovery:
		return StageAPIDiscovery
	case kindToken:
		return StageToken
	case kindDownload, kindSignature:
		return StageDownload
	}
	return StageAPI
}

func (l Limits) bytesFor(k callKind) int64 {
	switch k {
	case kindWellKnown:
		return l.WellKnownBytes
	case kindDiscovery:
		return l.DiscoveryBytes
	case kindToken:
		return l.ErrorBodyBytes
	case kindDownload:
		return l.DownloadBytes
	case kindSignature:
		return l.SignatureBytes
	}
	return l.JSONBytes
}

// timeBound returns the bound for a kind and whether it is an idle bound
// (reset on every byte) rather than a whole-request bound.
func (l Limits) timeBound(k callKind) (d time.Duration, idle bool) {
	switch k {
	case kindWellKnown, kindDiscovery:
		return l.AttemptTimeout, false
	case kindDownload, kindSignature:
		return l.IdleTimeout, true
	}
	return l.CallTimeout, false
}

// doer is the bounded, auth-aware teaapi.HttpRequestDoer. One exists per
// API, so a request without a kind (any Generated() call) can be classified
// by its path relative to the API base.
type doer struct {
	c    *Client
	base *url.URL // the API base (root + "/v" + version); nil outside an API
}

// classify gives the kind of a Generated() request from its path, against
// the specification's templates.
func (d *doer) classify(u *url.URL) callKind {
	if d.base == nil {
		return kindJSON
	}
	bp := strings.TrimSuffix(d.base.EscapedPath(), "/")
	p := u.EscapedPath()
	if !strings.EqualFold(u.Host, d.base.Host) || !strings.HasPrefix(p, bp+"/") {
		return kindJSON
	}
	segs := strings.Split(p[len(bp)+1:], "/")
	switch {
	case len(segs) == 1 && segs[0] == "discovery":
		return kindDiscovery
	case len(segs) == 4 && segs[0] == "artifact" && segs[3] == "download":
		return kindDownload
	case len(segs) == 4 && segs[0] == "artifact" && segs[3] == "signature":
		return kindSignature
	}
	return kindJSON
}

// Do sends req with the URL policy, the byte limit and the time bound of its
// kind applied.
func (d *doer) Do(req *http.Request) (*http.Response, error) {
	parent := req.Context()
	k := kindFrom(parent)
	if k == kindUnset {
		k = d.classify(req.URL)
		parent = withKind(parent, k)
	}
	if err := d.c.checkURL(req.URL); err != nil {
		return nil, err
	}
	bound, idle := d.c.limits.timeBound(k)

	var rctx context.Context
	var cancel context.CancelCauseFunc
	var timer *time.Timer
	switch {
	case bound > 0 && !idle:
		tctx, tcancel := context.WithTimeoutCause(parent, bound, ErrTimeout)
		rctx, cancel = tctx, func(error) { tcancel() }
	default:
		rctx, cancel = context.WithCancelCause(parent)
		if bound > 0 {
			timer = time.AfterFunc(bound, func() { cancel(ErrTimeout) })
		}
	}
	finish := func() {
		if timer != nil {
			timer.Stop()
		}
		cancel(context.Canceled)
	}

	redacted := redact(req.URL)
	resp, err := d.c.hc.Do(req.WithContext(rctx))
	if err != nil {
		err = boundError(parent, rctx, redacted, err)
		finish()
		return nil, err
	}

	body := &boundedBody{
		rc: resp.Body, parent: parent, rctx: rctx, finish: finish,
		timer: timer, idle: bound, url: redacted,
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		body.limit, body.strict = d.c.limits.bytesFor(k), true
		if resp.ContentLength > body.limit {
			_ = resp.Body.Close()
			finish()
			return nil, fmt.Errorf("%s %s: Content-Length %d: %w", req.Method, redacted, resp.ContentLength, ErrResponseTooLarge)
		}
	} else {
		body.limit = d.c.limits.ErrorBodyBytes
	}
	resp.Body = body
	return resp, nil
}

// timeoutError is a library time bound that fired; it wraps ErrTimeout only.
type timeoutError struct{ url string }

func (e *timeoutError) Error() string { return e.url + ": " + ErrTimeout.Error() }
func (e *timeoutError) Unwrap() error { return ErrTimeout }

// boundError classifies an error of a bounded request: the caller's context
// ending wins (its ctx.Err() is returned, wrapped); otherwise the library's
// bound firing is ErrTimeout; otherwise the error is returned with the URL
// in a *url.Error redacted.
func boundError(parent, rctx context.Context, redacted string, err error) error {
	if perr := parent.Err(); perr != nil {
		return fmt.Errorf("%s: %w", redacted, perr)
	}
	if errors.Is(context.Cause(rctx), ErrTimeout) {
		return &timeoutError{url: redacted}
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		ue.URL = redacted
	}
	return err
}

// boundedBody enforces the byte limit and the idle bound on a response body
// and releases the request's context when the body is done.
type boundedBody struct {
	rc     io.ReadCloser
	limit  int64
	strict bool // 2xx: past the limit is ErrResponseTooLarge; else the body is cut
	n      int64

	parent, rctx context.Context
	finish       func()
	timer        *time.Timer
	idle         time.Duration
	url          string

	once sync.Once
	err  error
}

func (b *boundedBody) done() { b.once.Do(b.finish) }

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if max := b.limit - b.n + 1; int64(len(p)) > max {
		p = p[:max]
	}
	k, err := b.rc.Read(p)
	if k > 0 && b.timer != nil {
		b.timer.Reset(b.idle)
	}
	b.n += int64(k)
	if b.n > b.limit {
		k -= int(b.n - b.limit)
		b.n = b.limit
		if b.strict {
			b.err = fmt.Errorf("%s: more than %d bytes: %w", b.url, b.limit, ErrResponseTooLarge)
		} else {
			b.err = io.EOF
		}
		b.done()
		return k, b.err
	}
	if err != nil {
		if err != io.EOF {
			err = boundError(b.parent, b.rctx, b.url, err)
		}
		b.err = err
		b.done()
	}
	return k, err
}

func (b *boundedBody) Close() error {
	err := b.rc.Close()
	b.done()
	return err
}

// checkRedirect is the library's CheckRedirect: a kindToken request follows
// no redirect at all; otherwise at most Limits.Redirects, each target passing
// the URL policy. Credentials are the auth transport's decision on every hop.
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if kindFrom(req.Context()) == kindToken {
		return http.ErrUseLastResponse
	}
	if len(via) > c.limits.Redirects {
		return &URLPolicyError{URL: redact(req.URL), Reason: fmt.Sprintf("more than %d redirects", c.limits.Redirects), err: ErrRedirectLimit}
	}
	return c.checkURL(req.URL)
}

// authTransport is the only place an Authorization header is decided
// (architecture D5). On every hop, redirects included, it removes any
// Authorization header from a request that is not under a configured
// credential root and sets the root's credential on a request under one. A
// kindToken request is left as the token code built it (it follows no
// redirect, so it has one hop). It also sets the User-Agent, checks the URL
// policy as a backstop and reports trace events.
type authTransport struct {
	c    *Client
	next http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.c.checkURL(req.URL); err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	k := kindFrom(req.Context())
	r := req.Clone(req.Context())
	r.Header.Set("User-Agent", t.c.ua)
	if k != kindToken {
		r.Header.Del("Authorization")
		if cr := t.c.credentialFor(r.URL); cr != nil {
			r.Header.Set("Authorization", "Bearer "+cr.token)
		}
	}
	ev := TraceEvent{Stage: k.stage(), Method: r.Method, URL: redact(r.URL)}
	ev.Kind = TraceRequest
	t.c.traceEvent(ev)
	resp, err := t.next.RoundTrip(r)
	if err == nil {
		ev.Kind, ev.Status = TraceResponse, resp.StatusCode
		t.c.traceEvent(ev)
	}
	return resp, err
}

// credentialFor returns the credential whose root u is under; the longest
// root wins when several match.
func (c *Client) credentialFor(u *url.URL) *credential {
	var best *credential
	for i := range c.opts.creds {
		cr := &c.opts.creds[i]
		if under(u, cr.root) && (best == nil || len(cr.root.path) > len(best.root.path)) {
			best = cr
		}
	}
	return best
}
