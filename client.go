package tea

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/oolong-project/tea-client-go/tei"
)

// Limits bounds what the client reads and how long it waits. The zero value
// of a field means its default. For the three durations, a negative value
// disables that bound and leaves only the caller's context; a byte or count
// limit must not be negative.
type Limits struct {
	WellKnownBytes   int64 // .well-known/tea; default 64 KiB
	DiscoveryBytes   int64 // /discovery; default 1 MiB
	DiscoveryResults int   // results in one /discovery answer and given to Candidates; default 32
	JSONBytes        int64 // every other JSON response; default 16 MiB
	ErrorBodyBytes   int64 // non-2xx bodies (read to classify, then discarded) and /token; default 64 KiB
	DownloadBytes    int64 // artifact content; default 512 MiB
	SignatureBytes   int64 // signature content; default 16 MiB
	Redirects        int   // per request; default 5
	Pages            int   // per iterator; default 1000
	FlowComponents   int   // component refs walked by the flow helper; default 1000

	// AttemptTimeout bounds each discovery attempt (one well-known GET or one
	// /discovery GET, headers and body); default 15 s.
	AttemptTimeout time.Duration
	// CallTimeout bounds each non-download request (typed JSON calls,
	// /token, Generated() calls classified as JSON), headers and body;
	// default 30 s.
	CallTimeout time.Duration
	// IdleTimeout bounds downloads and signatures: the longest wait for the
	// response headers or for the next body byte. A download that keeps
	// sending is never cut off. Default 30 s.
	IdleTimeout time.Duration
}

// Default limits (architecture 3.4).
const (
	defaultWellKnownBytes   = 64 << 10
	defaultDiscoveryBytes   = 1 << 20
	defaultDiscoveryResults = 32
	defaultJSONBytes        = 16 << 20
	defaultErrorBodyBytes   = 64 << 10
	defaultDownloadBytes    = 512 << 20
	defaultSignatureBytes   = 16 << 20
	defaultRedirects        = 5
	defaultPages            = 1000
	defaultFlowComponents   = 1000
	defaultAttemptTimeout   = 15 * time.Second
	defaultCallTimeout      = 30 * time.Second
	defaultIdleTimeout      = 30 * time.Second
	defaultAttempts         = 4
	defaultFirstBackoff     = 250 * time.Millisecond
)

func (l Limits) validate() error {
	for name, v := range map[string]int64{
		"WellKnownBytes": l.WellKnownBytes, "DiscoveryBytes": l.DiscoveryBytes,
		"DiscoveryResults": int64(l.DiscoveryResults), "JSONBytes": l.JSONBytes,
		"ErrorBodyBytes": l.ErrorBodyBytes, "DownloadBytes": l.DownloadBytes,
		"SignatureBytes": l.SignatureBytes, "Redirects": int64(l.Redirects),
		"Pages": int64(l.Pages), "FlowComponents": int64(l.FlowComponents),
	} {
		if v < 0 {
			return fmt.Errorf("Limits.%s is negative", name)
		}
	}
	return nil
}

func orDefault[T int | int64 | time.Duration](v, d T) T {
	if v == 0 {
		return d
	}
	return v
}

func (l Limits) withDefaults() Limits {
	l.WellKnownBytes = orDefault(l.WellKnownBytes, defaultWellKnownBytes)
	l.DiscoveryBytes = orDefault(l.DiscoveryBytes, defaultDiscoveryBytes)
	l.DiscoveryResults = orDefault(l.DiscoveryResults, defaultDiscoveryResults)
	l.JSONBytes = orDefault(l.JSONBytes, defaultJSONBytes)
	l.ErrorBodyBytes = orDefault(l.ErrorBodyBytes, defaultErrorBodyBytes)
	l.DownloadBytes = orDefault(l.DownloadBytes, defaultDownloadBytes)
	l.SignatureBytes = orDefault(l.SignatureBytes, defaultSignatureBytes)
	l.Redirects = orDefault(l.Redirects, defaultRedirects)
	l.Pages = orDefault(l.Pages, defaultPages)
	l.FlowComponents = orDefault(l.FlowComponents, defaultFlowComponents)
	l.AttemptTimeout = orDefault(l.AttemptTimeout, defaultAttemptTimeout)
	l.CallTimeout = orDefault(l.CallTimeout, defaultCallTimeout)
	l.IdleTimeout = orDefault(l.IdleTimeout, defaultIdleTimeout)
	return l
}

// TraceKind is the kind of a TraceEvent.
type TraceKind string

// Trace event kinds.
const (
	TraceRequest       TraceKind = "request"
	TraceResponse      TraceKind = "response"
	TraceAttemptFailed TraceKind = "attempt-failed"
	TraceBackoff       TraceKind = "backoff"
)

// Stage names the part of the protocol a request or an attempt belongs to.
type Stage string

// Stages.
const (
	StageWellKnown    Stage = "well-known"
	StageAPIDiscovery Stage = "api-discovery"
	StageAPI          Stage = "api"
	StageDownload     Stage = "download"
	StageToken        Stage = "token"
)

// TraceEvent is what a WithTrace observer receives. It never carries a
// header, a body, a query string or a credential.
type TraceEvent struct {
	Kind   TraceKind
	Stage  Stage
	Method string
	URL    string        // scheme, host, port and path only: never query, fragment or userinfo
	Status int           // TraceResponse
	Reason string        // TraceAttemptFailed: same text as the Attempt in a discovery error
	Wait   time.Duration // TraceBackoff
}

// credential is one configured credential: a bearer token, or an API key
// (key set) whose access token is obtained on a Bearer challenge.
type credential struct {
	root  baseURL
	token string
	key   *apiKey
}

type options struct {
	hc           *http.Client
	userAgent    string
	insecure     []baseURL
	wellKnown    map[string]baseURL // lowercased domain -> base
	creds        []credential
	limits       Limits
	attempts     int
	firstBackoff time.Duration
	trace        func(TraceEvent)
	errs         []error
}

func (o *options) fail(format string, args ...any) {
	o.errs = append(o.errs, fmt.Errorf("%w: "+format, append([]any{ErrInvalidOption}, args...)...))
}

// Option configures a Client.
type Option func(*options)

// WithHTTPClient makes the client send through hc. The library copies hc and
// sets its own CheckRedirect (redirect limit and URL policy) and wraps its
// Transport (nil means http.DefaultTransport) in the auth transport. A
// transport passed here therefore sits below the auth transport and sees
// Authorization headers: use WithTrace for debug output, not a transport
// that dumps headers. hc.Timeout, if set, applies on top of the library's
// own time bounds.
func WithHTTPClient(hc *http.Client) Option {
	return func(o *options) {
		if hc == nil {
			o.fail("WithHTTPClient(nil)")
			return
		}
		o.hc = hc
	}
}

// WithUserAgent replaces the default User-Agent "tea-client-go/<version>".
func WithUserAgent(ua string) Option {
	return func(o *options) {
		if ua == "" || strings.ContainsAny(ua, "\r\n") {
			o.fail("WithUserAgent: empty or multi-line value")
			return
		}
		o.userAgent = ua
	}
}

// WithInsecureHTTPBase allows plain http for URLs under rawURL: same host
// and port, and a path equal to rawURL's path or below it by whole segments.
// rawURL is an absolute http URL without userinfo, query, fragment, trailing
// "/" or dot segment. Repeatable. There is no global switch, and nothing a
// server sends adds or widens an allowance.
func WithInsecureHTTPBase(rawURL string) Option {
	return func(o *options) {
		b, err := parseBase(rawURL)
		if err != nil {
			o.fail("WithInsecureHTTPBase: %v", err)
			return
		}
		if b.scheme != "http" {
			o.fail("WithInsecureHTTPBase: %s is not an http URL", urlSubject(rawURL, "the URL"))
			return
		}
		o.insecure = append(o.insecure, b)
	}
}

// WithWellKnownLocation makes discovery fetch <location>/.well-known/tea for
// TEIs of domain, instead of https://<domain>/.well-known/tea. An http
// location also needs a WithInsecureHTTPBase allowance covering it.
func WithWellKnownLocation(domain, location string) Option {
	return func(o *options) {
		if _, err := tei.Parse("tei://" + domain + "/uuid/x"); err != nil {
			o.fail("WithWellKnownLocation: %s is not a TEI domain name", domainSubject(domain))
			return
		}
		b, err := parseBase(location)
		if err != nil {
			o.fail("WithWellKnownLocation: %v", err)
			return
		}
		if o.wellKnown == nil {
			o.wellKnown = map[string]baseURL{}
		}
		o.wellKnown[strings.ToLower(domain)] = b
	}
}

// domainSubject names a WithWellKnownLocation domain argument in the text
// of its refusal: quoted and cut at 128 bytes only when it holds none of
// "@", "/", "?" and "#" (a domain name has none of them), so a URL passed
// there by mistake is not repeated with its userinfo, query or fragment.
func domainSubject(domain string) string {
	if strings.ContainsAny(domain, "@/?#") {
		return "the domain"
	}
	return fmt.Sprintf("%q", truncateArg(domain))
}

// WithBearerToken sends "Authorization: Bearer <token>" on requests under
// rootURL (an API root, as in servers[].rootUrl), and on no other request.
// An http rootURL must be under a WithInsecureHTTPBase allowance.
func WithBearerToken(rootURL, token string) Option {
	return func(o *options) {
		b, err := parseBase(rootURL)
		if err != nil {
			o.fail("WithBearerToken: %v", err)
			return
		}
		if token == "" || strings.ContainsAny(token, "\r\n\x00") {
			o.fail("WithBearerToken: empty token or token with control characters")
			return
		}
		o.creds = append(o.creds, credential{root: b, token: token})
	}
}

// WithAPIKey configures an API key (key id and secret) for rootURL (an API
// root, as in servers[].rootUrl). No token is requested up front: clients
// do not probe /token. When a GET under rootURL (an API call, or a
// /discovery request of Discover or DiscoverPURL) is answered 401 with a
// Bearer challenge from a URL under rootURL, the client requests a token
// from <rootURL>/v<version>/token, where version is that of the API that
// made the request (whose base must be under rootURL), with the
// client_credentials grant and HTTP Basic credentials, following no
// redirect; it caches the token (until expires_in minus 30 s, when given)
// and retries the request once with it. A 401 on a request that carried
// the cached token drops it, and the client obtains a fresh one and retries
// once. There is never more than one recovery per request, and none on a
// 403. Concurrent requests share one token request. A failure to obtain the
// token matches ErrNoAccessToken. The token is sent on requests under
// rootURL and nowhere else, like a WithBearerToken token. An http rootURL
// must be under a WithInsecureHTTPBase allowance. The key id, the secret
// and the token never appear in an error or a trace event.
//
// When several credentials cover a URL, the one with the longest root
// applies (the first configured among equal roots).
//
// For a server that answers an anonymous caller with less instead of a
// 401, use WithPreemptiveAPIKey.
func WithAPIKey(rootURL, keyID, secret string) Option {
	return withKey("WithAPIKey", rootURL, keyID, secret, tokenOnChallenge)
}

// WithPreemptiveAPIKey is WithAPIKey for a server that answers an anonymous
// caller with less instead of a 401 (a filtered listing, only the public
// results of a discovery): the client does not wait for a challenge. Before
// an API sends a request to a URL under rootURL (a typed call, a Generated()
// call, a download from the server, a /discovery request of Discover or
// DiscoverPURL), the client makes sure it holds an access token, requesting
// one from <rootURL>/v<version>/token when it holds none (none obtained
// yet, expired, or dropped after a 401), and sends it on that request.
// Concurrent requests share one token request. When the token cannot be
// obtained the request is not sent and the error matches ErrNoAccessToken.
//
// A .well-known/tea request and a redirect hop never cause a token request
// and carry the token only when one is already held; an external artifact
// or signature URL never carries it.
//
// This departs from the specification's description of /token ("Clients do
// not probe this endpoint to discover whether authentication is required"):
// use it for a root you know to require your key. Against a server without
// /token every request under rootURL fails (ErrNoAccessToken, wrapping
// ErrNotImplemented), where WithAPIKey would go on without a credential.
//
// Everything else is as WithAPIKey: where the key and the token are sent,
// the cache, one fresh token and one retry after a 401 on a cached token,
// nothing on a 403. A 401 on a request whose token was obtained for it is
// returned as it is. New refuses a rootURL that is also the root of another
// credential.
func WithPreemptiveAPIKey(rootURL, keyID, secret string) Option {
	return withKey("WithPreemptiveAPIKey", rootURL, keyID, secret, tokenUpFront)
}

func withKey(name, rootURL, keyID, secret string, timing tokenTiming) Option {
	return func(o *options) {
		b, err := parseBase(rootURL)
		if err != nil {
			o.fail("%s: %v", name, err)
			return
		}
		if keyID == "" || secret == "" {
			o.fail("%s: empty key id or secret", name)
			return
		}
		o.creds = append(o.creds, credential{root: b, key: &apiKey{id: keyID, secret: secret, timing: timing}})
	}
}

// WithLimits sets the limits; zero fields keep their defaults.
func WithLimits(l Limits) Option {
	return func(o *options) {
		if err := l.validate(); err != nil {
			o.fail("WithLimits: %v", err)
			return
		}
		o.limits = l
	}
}

// WithDiscoveryAttempts sets the total number of discovery attempts across
// the well-known and /discovery stages (default 4) and the first backoff
// (default 250 ms, doubling, capped at 4 s). Every request counts, the
// successful well-known fetch included, so Discover needs at least 2;
// DiscoverPURL makes no well-known request. A zero firstBackoff keeps the
// default.
func WithDiscoveryAttempts(n int, firstBackoff time.Duration) Option {
	return func(o *options) {
		if n < 1 || firstBackoff < 0 {
			o.fail("WithDiscoveryAttempts: attempts must be at least 1 and backoff not negative")
			return
		}
		o.attempts = n
		o.firstBackoff = firstBackoff
	}
}

// WithTrace registers an observer called synchronously, in request order,
// for every request the client makes (redirects included), every response,
// and each failed discovery attempt and backoff. Events never carry headers,
// bodies, query strings or credentials. A panic in f is not recovered.
func WithTrace(f func(TraceEvent)) Option {
	return func(o *options) {
		if f == nil {
			o.fail("WithTrace(nil)")
			return
		}
		o.trace = f
	}
}

// Client is a TEA client. It is safe for concurrent use.
type Client struct {
	opts   options
	limits Limits
	hc     *http.Client // the library's copy: CheckRedirect and auth transport set
	ua     string
	now    func() time.Time // the clock of the token cache; nil is time.Now (a test seam)
}

// clock is the time the token cache is read and filled at.
func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// New builds a Client. It refuses an option value it cannot parse
// (ErrInvalidOption), including an http credential root or well-known
// location that no WithInsecureHTTPBase allowance covers.
func New(opts ...Option) (*Client, error) {
	c := &Client{}
	for _, opt := range opts {
		if opt != nil {
			opt(&c.opts)
		}
	}
	for _, cr := range c.opts.creds {
		if cr.root.scheme == "http" && !c.allowed(cr.root) {
			c.opts.fail("credential root %s is http and not under a WithInsecureHTTPBase allowance", urlSubject(cr.root.raw, "the URL"))
		}
	}
	for i, cr := range c.opts.creds {
		if cr.key == nil || cr.key.timing != tokenUpFront {
			continue
		}
		for j, other := range c.opts.creds {
			if j != i && sameRoot(cr.root, other.root) {
				c.opts.fail("WithPreemptiveAPIKey: root %s is also the root of another credential", urlSubject(cr.root.raw, "the URL"))
				break
			}
		}
	}
	for _, wk := range c.opts.wellKnown {
		if wk.scheme == "http" && !c.allowed(wk) {
			c.opts.fail("well-known location %s is http and not under a WithInsecureHTTPBase allowance", urlSubject(wk.raw, "the URL"))
		}
	}
	if len(c.opts.errs) > 0 {
		return nil, errors.Join(c.opts.errs...)
	}
	c.limits = c.opts.limits.withDefaults()
	if c.opts.attempts == 0 {
		c.opts.attempts = defaultAttempts
	}
	if c.opts.firstBackoff == 0 {
		c.opts.firstBackoff = defaultFirstBackoff
	}
	c.ua = c.opts.userAgent
	if c.ua == "" {
		c.ua = defaultUserAgent()
	}

	var hc http.Client
	if c.opts.hc != nil {
		hc = *c.opts.hc
	} else {
		hc = http.Client{Transport: defaultTransport()}
	}
	next := hc.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	hc.Transport = &authTransport{c: c, next: next}
	hc.CheckRedirect = c.checkRedirect
	c.hc = &hc
	return c, nil
}

// allowed reports whether a configured base is itself under an allowance.
func (c *Client) allowed(b baseURL) bool {
	for _, a := range c.opts.insecure {
		if b.scheme == a.scheme && b.host == a.host && b.port == a.port &&
			(b.path == a.path || strings.HasPrefix(b.path, a.path+"/")) {
			return true
		}
	}
	return false
}

// defaultTransport is a clone of http.DefaultTransport with handshake and
// header timeouts, a second line under the context-based bounds.
func defaultTransport() http.RoundTripper {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		}
	}
	t = t.Clone()
	t.TLSHandshakeTimeout = 10 * time.Second
	t.ResponseHeaderTimeout = 30 * time.Second
	return t
}

const modulePath = "github.com/oolong-project/tea-client-go"

var (
	userAgentOnce sync.Once
	userAgent     string
)

func defaultUserAgent() string {
	userAgentOnce.Do(func() {
		bi, ok := debug.ReadBuildInfo()
		userAgent = "tea-client-go/" + moduleVersion(bi, ok)
	})
	return userAgent
}

// moduleVersion finds this module's version in build info: its Deps entry
// (the replacement's version when replaced with a version), or Main.Version
// when it is the main module. Empty, "(devel)" or no build info is "devel".
func moduleVersion(bi *debug.BuildInfo, ok bool) string {
	if !ok || bi == nil {
		return "devel"
	}
	v := ""
	if bi.Main.Path == modulePath {
		v = bi.Main.Version
	}
	for _, d := range bi.Deps {
		if d == nil || d.Path != modulePath {
			continue
		}
		v = d.Version
		if d.Replace != nil && d.Replace.Version != "" {
			v = d.Replace.Version
		}
	}
	if v == "" || v == "(devel)" {
		return "devel"
	}
	return v
}

// API returns the typed API bound to base. An http base must be under a
// WithInsecureHTTPBase allowance (*URLPolicyError otherwise).
func (c *Client) API(base APIBase) (*API, error) {
	if base.root == nil {
		return nil, fmt.Errorf("%w: zero APIBase", ErrInvalidArgument)
	}
	u := base.url()
	if u == nil {
		return nil, fmt.Errorf("%w: API base does not parse", ErrInvalidArgument)
	}
	if err := c.checkURL(u); err != nil {
		return nil, err
	}
	return newAPI(c, base)
}

func (c *Client) traceEvent(ev TraceEvent) {
	if c.opts.trace != nil {
		c.opts.trace(ev)
	}
}
