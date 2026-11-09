package tea

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oolong-project/tea-client-go/teaapi"
)

const (
	mtJSON = "application/vnd.cyclonedx+json"
	mtXML  = "application/vnd.cyclonedx+xml"
)

// sha256Sum is the SHA-256 checksum of b (the algorithm itself is checked by
// the known-answer vectors of case 28).
func sha256Sum(b []byte) teaapi.Checksum {
	h := sha256.Sum256(b)
	return teaapi.Checksum{AlgType: teaapi.SHA256, AlgValue: hex.EncodeToString(h[:])}
}

// fmtOf is an artifact format with the given media type and checksums.
func fmtOf(mt string, sums ...teaapi.Checksum) teaapi.ArtifactFormat {
	return teaapi.ArtifactFormat{MediaType: mt, Checksums: &sums}
}

func strPtr(s string) *string { return &s }

// serveBytes answers 200 with body as the given media type.
func serveBytes(mt string, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", mt)
		_, _ = w.Write(body)
	}
}

var ref3 = ArtifactRef{UUID: artID, Version: 3}

// Case 30 (= 13c): where the bytes come from, and that no credential goes
// to an external URL.
func TestDownloadSource(t *testing.T) {
	ctx := context.Background()
	body := []byte(fixtureJSON)
	api := newCounter(serveBytes(mtJSON+"; charset=utf-8", body))
	ext := newCounter(serveBytes(mtJSON, body))
	sa, sb := startHTTP(t, api), startHTTP(t, ext)
	root := sa.URL + "/tea"
	const bearer = "download-bearer-1"
	a := newTestAPI(t, sa.URL, "/tea", WithInsecureHTTPBase(sb.URL), WithBearerToken(root, bearer))
	f := fmtOf(mtJSON, sha256Sum(body))

	// Without url: the versioned endpoint with mediaType, the bearer sent
	// (the API is under the root).
	var out bytes.Buffer
	res, err := a.DownloadArtifact(ctx, ref3, f, &out, DownloadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r := api.lastReq()
	if r.URL.Path != "/tea/v1.0.0/artifact/"+artID.String()+"/3/download" || r.URL.Query().Get("mediaType") != mtJSON ||
		!strings.Contains(r.URL.RawQuery, "mediaType=application%2Fvnd.cyclonedx%2Bjson") {
		t.Errorf("server download request %s?%s", r.URL.Path, r.URL.RawQuery)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+bearer {
		t.Errorf("server download: Authorization %q, want the bearer", got)
	}
	if !bytes.Equal(out.Bytes(), body) || res.Bytes != int64(len(body)) || res.Source != DownloadSourceServer ||
		res.MediaType != mtJSON || !slices.Equal(res.Verified, []teaapi.ChecksumType{teaapi.SHA256}) {
		t.Errorf("server download result %+v", res)
	}

	// With url: fetched from that URL only, without Authorization.
	before := api.count()
	fe := f
	fe.Url = strPtr(sb.URL + "/files/widget.json?sig=presigned")
	out.Reset()
	res, err = a.DownloadArtifact(ctx, ref3, fe, &out, DownloadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if api.count() != before || ext.count() != 1 || ext.lastReq().URL.Path != "/files/widget.json" {
		t.Errorf("external download: API requests %d, external %d", api.count()-before, ext.count())
	}
	if v, ok := ext.lastReq().Header["Authorization"]; ok {
		t.Errorf("external URL received Authorization %q", v)
	}
	if res.Source != DownloadSourceExternal || !bytes.Equal(out.Bytes(), body) {
		t.Errorf("external download result %+v", res)
	}

	// An external url that happens to be under the credential root still
	// gets no credential (3.8 step 1: no credential to an external url).
	fu := f
	fu.Url = strPtr(root + "/files/widget.json")
	if _, err := a.DownloadArtifact(ctx, ref3, fu, io.Discard, DownloadOptions{}); err != nil {
		t.Fatal(err)
	}
	if r := api.lastReq(); r.URL.Path != "/tea/files/widget.json" {
		t.Errorf("external url under the root: request to %s", r.URL.Path)
	} else if v, ok := r.Header["Authorization"]; ok {
		t.Errorf("external url under the root received Authorization %q", v)
	}

	// A 302 from the API to another origin: followed, without the header.
	redir := newCounter(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sb.URL+"/files/widget.json", http.StatusFound)
	})
	sr := startHTTP(t, redir)
	ar := newTestAPI(t, sr.URL, "/tea", WithInsecureHTTPBase(sb.URL), WithBearerToken(sr.URL+"/tea", bearer))
	before = ext.count()
	if _, err := ar.DownloadArtifact(ctx, ref3, f, io.Discard, DownloadOptions{}); err != nil {
		t.Fatal(err)
	}
	if redir.count() != 1 || ext.count() != before+1 {
		t.Fatalf("302: %d API requests, %d to the target", redir.count(), ext.count()-before)
	}
	if got := redir.lastReq().Header.Get("Authorization"); got != "Bearer "+bearer {
		t.Errorf("302 first hop: Authorization %q, want the bearer", got)
	}
	if v, ok := ext.lastReq().Header["Authorization"]; ok {
		t.Errorf("302 target received Authorization %q", v)
	}

	// An http external URL not under an allowance: refused, no request.
	other := newCounter(serveBytes(mtJSON, body))
	so := startHTTP(t, other)
	fh := f
	fh.Url = strPtr(so.URL + "/widget.json")
	_, err = a.DownloadArtifact(ctx, ref3, fh, io.Discard, DownloadOptions{})
	var pe *URLPolicyError
	if !errors.As(err, &pe) || !errors.Is(err, ErrInsecureURL) || other.count() != 0 {
		t.Errorf("http external URL: %v, %d requests", err, other.count())
	}
	// A relative external url is refused before any request.
	fr := f
	fr.Url = strPtr("/files/widget.json")
	before = api.count()
	if _, err := a.DownloadArtifact(ctx, ref3, fr, io.Discard, DownloadOptions{}); !isUnexpected(err) || api.count() != before {
		t.Errorf("relative external URL: %v", err)
	}
}

func isUnexpected(err error) bool {
	var ue *UnexpectedResponseError
	return errors.As(err, &ue)
}

// Checks made before any request: arguments and the format's checksums.
func TestDownloadRefusedBeforeRequest(t *testing.T) {
	ctx := context.Background()
	body := []byte(fixtureJSON)
	h := newCounter(serveBytes(mtJSON, body))
	srv := startHTTP(t, h)
	a := newTestAPI(t, srv.URL, "/tea")
	good := fmtOf(mtJSON, sha256Sum(body))
	noMT := good
	noMT.MediaType = ""

	for name, f := range map[string]func() error{
		"version 0": func() error {
			_, err := a.DownloadArtifact(ctx, ArtifactRef{UUID: artID}, good, io.Discard, DownloadOptions{})
			return err
		},
		"no media type": func() error { _, err := a.DownloadArtifact(ctx, ref3, noMT, io.Discard, DownloadOptions{}); return err },
		"nil writer":    func() error { _, err := a.DownloadArtifact(ctx, ref3, good, nil, DownloadOptions{}); return err },
		"negative MaxBytes": func() error {
			_, err := a.DownloadArtifact(ctx, ref3, good, io.Discard, DownloadOptions{MaxBytes: -1})
			return err
		},
		"empty path": func() error { _, err := a.DownloadArtifactToFile(ctx, ref3, good, "", DownloadOptions{}); return err },
		"signature version 0": func() error {
			_, err := a.DownloadSignature(ctx, ArtifactRef{UUID: artID}, good, io.Discard, DownloadOptions{})
			return err
		},
	} {
		if err := f(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v, want ErrInvalidArgument", name, err)
		}
	}
	for name, f := range map[string]teaapi.ArtifactFormat{
		"no checksums": {MediaType: mtJSON},
		"SHA-1 only":   fmtOf(mtJSON, sum(teaapi.SHA1, strings.Repeat("a", 40))),
		"BLAKE3 only":  fmtOf(mtJSON, sum(teaapi.BLAKE3, strings.Repeat("a", 64))),
	} {
		if _, err := a.DownloadArtifact(ctx, ref3, f, io.Discard, DownloadOptions{}); !errors.Is(err, ErrNoUsableChecksum) {
			t.Errorf("%s: %v, want ErrNoUsableChecksum", name, err)
		}
	}
	upper := fmtOf(mtJSON, sum(teaapi.SHA256, strings.ToUpper(sha256Sum(body).AlgValue)))
	if _, err := a.DownloadArtifact(ctx, ref3, upper, io.Discard, DownloadOptions{}); !isUnexpected(err) {
		t.Errorf("uppercase SHA-256: %v, want *UnexpectedResponseError", err)
	}
	if h.count() != 0 {
		t.Errorf("%d requests made; every case is refused before any request", h.count())
	}
	// The control: the same API downloads the good format.
	if _, err := a.DownloadArtifact(ctx, ref3, good, io.Discard, DownloadOptions{}); err != nil || h.count() != 1 {
		t.Errorf("control: %v after %d requests", err, h.count())
	}
}

// Case 31: byte bounds and content coding.
func TestDownloadBounds(t *testing.T) {
	ctx := context.Background()
	body := bytes.Repeat([]byte("0123456789abcdef"), 128) // 2048 bytes
	f := fmtOf(mtJSON, sha256Sum(body))
	mode := &guarded[string]{}
	var acceptEncoding guarded[string]
	h := newCounter(func(w http.ResponseWriter, r *http.Request) {
		acceptEncoding.set(r.Header.Get("Accept-Encoding"))
		w.Header().Set("Content-Type", mtJSON)
		switch mode.get() {
		case "length-then-stall": // Content-Length, no body until the client leaves
			w.Header().Set("Content-Length", "2048")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case "chunked":
			for i := 0; i < len(body); i += 256 {
				_, _ = w.Write(body[i : i+256])
				w.(http.Flusher).Flush()
			}
		case "gzip", "gzip-always":
			if mode.get() == "gzip" && !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				_, _ = w.Write(body)
				return
			}
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = zw.Write(body)
			_ = zw.Close()
		case "br":
			w.Header().Set("Content-Encoding", "br")
			_, _ = w.Write(body)
		case "identity":
			w.Header().Set("Content-Encoding", "identity")
			_, _ = w.Write(body)
		default:
			_, _ = w.Write(body) // with Content-Length
		}
	})
	srv := startHTTP(t, h)
	a := newTestAPI(t, srv.URL, "/tea")

	// Content-Length over MaxBytes: refused at once, nothing written. The
	// server sends no body, so a client that read it would wait for the
	// idle bound (the control below).
	mode.set("length-then-stall")
	var out bytes.Buffer
	start := time.Now()
	_, err := a.DownloadArtifact(ctxTimeout(t, 10*time.Second), ref3, f, &out, DownloadOptions{MaxBytes: 1024})
	if d := time.Since(start); !errors.Is(err, ErrResponseTooLarge) || out.Len() != 0 || d > time.Second {
		t.Errorf("Content-Length 2048 over MaxBytes 1024: %v, %d bytes written, after %v", err, out.Len(), d)
	}
	slow := newTestAPI(t, srv.URL, "/tea", WithLimits(Limits{IdleTimeout: 300 * time.Millisecond}))
	if _, err := slow.DownloadArtifact(ctxTimeout(t, 10*time.Second), ref3, f, io.Discard, DownloadOptions{MaxBytes: 4096}); !errors.Is(err, ErrTimeout) {
		t.Errorf("control, Content-Length 2048 under MaxBytes 4096: %v, want the idle bound to fire", err)
	}

	// A chunked body over the limit stops with ErrResponseTooLarge after at
	// most the limit; a body of exactly the limit passes.
	mode.set("chunked")
	out.Reset()
	if _, err := a.DownloadArtifact(ctx, ref3, f, &out, DownloadOptions{MaxBytes: 2047}); !errors.Is(err, ErrResponseTooLarge) || out.Len() > 2047 {
		t.Errorf("chunked 2048 over MaxBytes 2047: %v, %d bytes written", err, out.Len())
	}
	if res, err := a.DownloadArtifact(ctx, ref3, f, io.Discard, DownloadOptions{MaxBytes: 2048}); err != nil || res.Bytes != 2048 {
		t.Errorf("chunked 2048 at MaxBytes 2048: %+v %v", res, err)
	}

	// Limits.DownloadBytes is the default; MaxBytes overrides it either way.
	mode.set("")
	small := newTestAPI(t, srv.URL, "/tea", WithLimits(Limits{DownloadBytes: 1024}))
	if _, err := small.DownloadArtifact(ctx, ref3, f, io.Discard, DownloadOptions{}); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("DownloadBytes 1024: %v, want ErrResponseTooLarge", err)
	}
	if _, err := small.DownloadArtifact(ctx, ref3, f, io.Discard, DownloadOptions{MaxBytes: 4096}); err != nil {
		t.Errorf("DownloadBytes 1024 with MaxBytes 4096: %v", err)
	}
	if _, err := a.DownloadArtifact(ctx, ref3, f, io.Discard, DownloadOptions{MaxBytes: 1024}); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("default DownloadBytes with MaxBytes 1024: %v, want ErrResponseTooLarge", err)
	}

	// gzip negotiated by the transport: verified against the uncompressed
	// bytes.
	mode.set("gzip")
	out.Reset()
	res, err := a.DownloadArtifact(ctx, ref3, f, &out, DownloadOptions{})
	if err != nil || !bytes.Equal(out.Bytes(), body) || res.Bytes != 2048 || !strings.Contains(acceptEncoding.get(), "gzip") {
		t.Errorf("gzip: %v, %d bytes, Accept-Encoding %q", err, out.Len(), acceptEncoding.get())
	}
	// gzip the transport did not ask for (a caller transport with
	// compression off): the coding stays, and the bytes are refused.
	mode.set("gzip-always")
	raw := newTestAPI(t, srv.URL, "/tea", WithHTTPClient(&http.Client{Transport: &http.Transport{DisableCompression: true}}))
	if _, err := raw.DownloadArtifact(ctx, ref3, f, io.Discard, DownloadOptions{}); !errors.Is(err, ErrUnsupportedContentEncoding) {
		t.Errorf("gzip not removed by the transport: %v, want ErrUnsupportedContentEncoding", err)
	}
	mode.set("br")
	if _, err := a.DownloadArtifact(ctx, ref3, f, io.Discard, DownloadOptions{}); !errors.Is(err, ErrUnsupportedContentEncoding) {
		t.Errorf("br: %v, want ErrUnsupportedContentEncoding", err)
	}
	mode.set("identity")
	if _, err := a.DownloadArtifact(ctx, ref3, f, io.Discard, DownloadOptions{}); err != nil {
		t.Errorf("identity: %v", err)
	}
}

// Case 31b: the idle bound on the wrapped downloads.
func TestDownloadIdleTimeout(t *testing.T) {
	mode := &guarded[string]{}
	srvURL := stallServer(t, mode)
	// CallTimeout is short too, to show a download is not under it.
	a := newTestAPI(t, srvURL, "/tea", WithLimits(Limits{IdleTimeout: 200 * time.Millisecond, CallTimeout: 200 * time.Millisecond}))
	trickled := []byte(strings.Repeat("x", 15))
	f := fmtOf(mtJSON, sha256Sum(trickled))
	f1k := fmtOf(mtJSON, sha256Sum(bytes.Repeat([]byte("x"), 1024)))

	within := func(name string, d time.Duration, err error) {
		t.Helper()
		if !errors.Is(err, ErrTimeout) || d > time.Second {
			t.Errorf("%s: %v after %v, want ErrTimeout within 1 s", name, err, d)
		}
	}
	for _, m := range []string{"after1k", "none"} {
		mode.set(m)
		start := time.Now()
		_, err := a.DownloadArtifact(ctxTimeout(t, 5*time.Second), ref3, f1k, io.Discard, DownloadOptions{})
		within("DownloadArtifact "+m, time.Since(start), err)

		dir := t.TempDir()
		start = time.Now()
		_, err = a.DownloadArtifactToFile(ctxTimeout(t, 5*time.Second), ref3, f1k, filepath.Join(dir, "out.json"), DownloadOptions{})
		within("DownloadArtifactToFile "+m, time.Since(start), err)
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("DownloadArtifactToFile %s left %d files", m, len(entries))
		}

		start = time.Now()
		_, err = a.DownloadSignature(ctxTimeout(t, 5*time.Second), ref3, f1k, io.Discard, DownloadOptions{})
		within("DownloadSignature "+m, time.Since(start), err)
	}

	// One byte every 100 ms for 1.5 s, longer than the bound in total.
	mode.set("trickle")
	start := time.Now()
	res, err := a.DownloadArtifact(context.Background(), ref3, f, io.Discard, DownloadOptions{})
	if err != nil || res.Bytes != 15 || !slices.Equal(res.Verified, []teaapi.ChecksumType{teaapi.SHA256}) {
		t.Errorf("trickling download: %+v %v", res, err)
	}
	if d := time.Since(start); d < 1400*time.Millisecond {
		t.Errorf("trickling download finished after %v; it should take about 1.5 s", d)
	}
	n, err := a.DownloadSignature(context.Background(), ref3, f, io.Discard, DownloadOptions{})
	if err != nil || n != 15 {
		t.Errorf("trickling signature: %d %v", n, err)
	}
}

// Case 32: DownloadArtifactToFile writes only verified bytes, in place.
func TestDownloadArtifactToFile(t *testing.T) {
	ctx := context.Background()
	body := []byte(fixtureJSON)
	h := newCounter(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="../../evil"`)
		serveBytes(mtJSON, body)(w, r)
	})
	srv := startHTTP(t, h)
	a := newTestAPI(t, srv.URL, "/tea")
	top := t.TempDir()
	dir := filepath.Join(top, "a", "b")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(target, []byte("previous content"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A mismatch: the target keeps its content, no temporary file is left.
	bad := fmtOf(mtJSON, sum(teaapi.SHA256, flipped(sha256Sum(body).AlgValue)))
	if _, err := a.DownloadArtifactToFile(ctx, ref3, bad, target, DownloadOptions{}); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "previous content" {
		t.Errorf("target changed after a mismatch: %q", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("%d entries in the directory after a mismatch, want only the target", len(entries))
	}

	// Success: the bytes, mode 0600, nothing else written anywhere.
	res, err := a.DownloadArtifactToFile(ctx, ref3, fmtOf(mtJSON, sha256Sum(body)), target, DownloadOptions{})
	if err != nil || res.Bytes != int64(len(body)) {
		t.Fatalf("download: %+v %v", res, err)
	}
	got, _ := os.ReadFile(target)
	st, _ := os.Stat(target)
	if !bytes.Equal(got, body) || st.Mode().Perm() != 0o600 {
		t.Errorf("target %q mode %v", got, st.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("%d entries in the directory, want only the target", len(entries))
	}
	for _, p := range []string{filepath.Join(top, "evil"), filepath.Join(top, "a", "evil"), filepath.Join(dir, "evil")} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists: Content-Disposition was used", p)
		}
	}
	if top, _ := os.ReadDir(top); len(top) != 1 {
		t.Errorf("%d entries at the top of the temp directory, want only a/", len(top))
	}
}

// Case 33: signatures.
func TestDownloadSignature(t *testing.T) {
	ctx := context.Background()
	sig := []byte("fixture-detached-signature-v1\n")
	notFound := &guarded[bool]{}
	big := &guarded[bool]{}
	api := newCounter(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case notFound.get():
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"SIGNATURE_NOT_FOUND"}`))
		case big.get():
			_, _ = w.Write(bytes.Repeat([]byte("s"), 2048))
		default:
			_, _ = w.Write(sig)
		}
	})
	ext := newCounter(serveBytes("application/pgp-signature", sig))
	sa, sb := startHTTP(t, api), startHTTP(t, ext)
	a := newTestAPI(t, sa.URL, "/tea", WithInsecureHTTPBase(sb.URL), WithBearerToken(sa.URL+"/tea", "sig-bearer"))
	f := fmtOf(mtXML, sha256Sum([]byte("content")))

	// Without signatureUrl: the versioned signature endpoint.
	var out bytes.Buffer
	n, err := a.DownloadSignature(ctx, ref3, f, &out, DownloadOptions{})
	r := api.lastReq()
	if err != nil || n != int64(len(sig)) || !bytes.Equal(out.Bytes(), sig) ||
		r.URL.Path != "/tea/v1.0.0/artifact/"+artID.String()+"/3/signature/download" || r.URL.Query().Get("mediaType") != mtXML {
		t.Errorf("server signature: %d %v, request %s?%s", n, err, r.URL.Path, r.URL.RawQuery)
	}

	// With signatureUrl: that URL only, no credential.
	fs := f
	fs.SignatureUrl = strPtr(sb.URL + "/sigs/widget.xml.asc")
	before := api.count()
	out.Reset()
	if n, err := a.DownloadSignature(ctx, ref3, fs, &out, DownloadOptions{}); err != nil || n != int64(len(sig)) {
		t.Errorf("external signature: %d %v", n, err)
	}
	if api.count() != before || ext.count() != 1 || ext.lastReq().URL.Path != "/sigs/widget.xml.asc" {
		t.Errorf("external signature: %d API requests, %d external", api.count()-before, ext.count())
	}
	if v, ok := ext.lastReq().Header["Authorization"]; ok {
		t.Errorf("signatureUrl received Authorization %q", v)
	}

	// 404 SIGNATURE_NOT_FOUND.
	notFound.set(true)
	if _, err := a.DownloadSignature(ctx, ref3, f, io.Discard, DownloadOptions{}); !errors.Is(err, ErrSignatureNotFound) {
		t.Errorf("404: %v, want ErrSignatureNotFound", err)
	}
	notFound.set(false)

	// Over SignatureBytes: refused; at the limit or with MaxBytes above it:
	// accepted.
	big.set(true)
	small := newTestAPI(t, sa.URL, "/tea", WithLimits(Limits{SignatureBytes: 2047, DownloadBytes: 1 << 20}))
	if _, err := small.DownloadSignature(ctx, ref3, f, io.Discard, DownloadOptions{}); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("2048 over SignatureBytes 2047: %v, want ErrResponseTooLarge", err)
	}
	at := newTestAPI(t, sa.URL, "/tea", WithLimits(Limits{SignatureBytes: 2048}))
	if n, err := at.DownloadSignature(ctx, ref3, f, io.Discard, DownloadOptions{}); err != nil || n != 2048 {
		t.Errorf("2048 at SignatureBytes 2048: %d %v", n, err)
	}
	if n, err := small.DownloadSignature(ctx, ref3, f, io.Discard, DownloadOptions{MaxBytes: 4096}); err != nil || n != 2048 {
		t.Errorf("SignatureBytes 2047 with MaxBytes 4096: %d %v", n, err)
	}
}

// Case 34: 406, other statuses, and DownloadLatestArtifact.
func TestDownloadStatusAndLatest(t *testing.T) {
	ctx := context.Background()
	body := []byte(fixtureJSON)
	xml := []byte("<?xml version=\"1.0\"?><bom name=\"oolong-fixture-widget\"/>\n")
	status := &guarded[int]{}
	plain406 := &guarded[bool]{}
	latest := `{"uuid":"` + artID.String() + `","version":7,"type":"BOM","createdDate":"2026-01-15T00:00:00Z","formats":[` +
		`{"mediaType":"` + mtJSON + `","checksums":[{"algType":"SHA-256","algValue":"` + sha256Sum(body).AlgValue + `"}]},` +
		`{"mediaType":"` + mtXML + `","checksums":[{"algType":"SHA-256","algValue":"` + sha256Sum(xml).AlgValue + `"}]}]}`
	h := newCounter(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/latest"):
			jsonHandler(latest)(w, r)
		case status.get() == http.StatusNotAcceptable && plain406.get():
			w.WriteHeader(http.StatusNotAcceptable)
		case status.get() == http.StatusNotAcceptable:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotAcceptable)
			_, _ = w.Write([]byte(`{"error":"NO_ACCEPTABLE_FORMAT"}`))
		case status.get() != 0:
			w.WriteHeader(status.get())
		case r.URL.Query().Get("mediaType") == mtXML:
			_, _ = w.Write(xml)
		default:
			_, _ = w.Write(body)
		}
	})
	srv := startHTTP(t, h)
	a := newTestAPI(t, srv.URL, "/tea")
	f := fmtOf(mtJSON, sha256Sum(body))

	status.set(http.StatusNotAcceptable)
	if _, err := a.DownloadArtifact(ctx, ref3, f, io.Discard, DownloadOptions{}); !errors.Is(err, ErrNoAcceptableFormat) {
		t.Errorf("406 NO_ACCEPTABLE_FORMAT: %v", err)
	}
	plain406.set(true)
	if _, err := a.DownloadArtifact(ctx, ref3, f, io.Discard, DownloadOptions{}); !errors.Is(err, ErrNoAcceptableFormat) {
		t.Errorf("406 without a TEA body: %v, want ErrNoAcceptableFormat", err)
	}
	status.set(http.StatusInternalServerError)
	if _, err := a.DownloadArtifact(ctx, ref3, f, io.Discard, DownloadOptions{}); !errors.Is(err, ErrServer) {
		t.Errorf("500: %v, want ErrServer", err)
	}
	status.set(http.StatusPartialContent)
	if _, err := a.DownloadArtifact(ctx, ref3, f, io.Discard, DownloadOptions{}); !isUnexpected(err) {
		t.Errorf("206: %v, want *UnexpectedResponseError", err)
	}
	status.set(0)

	// DownloadLatestArtifact: the /latest metadata, then the versioned
	// endpoint of that revision; the format chosen by media type, type and
	// subtype case-insensitively.
	before := len(h.requests())
	var out bytes.Buffer
	res, err := a.DownloadLatestArtifact(ctx, artID, "Application/VND.cyclonedx+XML", &out, DownloadOptions{})
	if err != nil || !bytes.Equal(out.Bytes(), xml) || res.Source != DownloadSourceServer {
		t.Fatalf("latest: %+v %v", res, err)
	}
	reqs := h.requests()[before:]
	base := "/tea/v1.0.0/artifact/" + artID.String()
	if len(reqs) != 2 || reqs[0].URL.Path != base+"/latest" || reqs[1].URL.Path != base+"/7/download" ||
		reqs[1].URL.Query().Get("mediaType") != mtXML {
		for _, r := range reqs {
			t.Logf("request %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		t.Errorf("latest: %d requests, want /latest then /7/download for the XML format", len(reqs))
	}
	// A media type the revision does not have: no download.
	before = len(h.requests())
	_, err = a.DownloadLatestArtifact(ctx, artID, "application/spdx+json", io.Discard, DownloadOptions{})
	if !errors.Is(err, ErrNoAcceptableFormat) || len(h.requests()) != before+1 {
		t.Errorf("unknown media type: %v after %d requests, want ErrNoAcceptableFormat after the metadata only", err, len(h.requests())-before)
	}
	// Parameters compare exactly.
	if sameMediaType(mtJSON+"; version=1.6", mtJSON+"; version=1.5") || !sameMediaType(mtJSON+";version=1.6", "APPLICATION/vnd.cyclonedx+json; version=1.6") {
		t.Error("sameMediaType: parameters must compare exactly, type and subtype case-insensitively")
	}
}
