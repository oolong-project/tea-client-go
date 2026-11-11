package tea

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/oolong-project/tea-client-go/teaapi"
)

// ArtifactRef names one revision of an artifact: the checksums a download
// verifies are those of this revision.
type ArtifactRef struct {
	UUID    uuid.UUID
	Version int
}

// DownloadOptions adjusts one download.
type DownloadOptions struct {
	// MaxBytes overrides the byte limit for this call: Limits.DownloadBytes
	// for artifact content, Limits.SignatureBytes for a signature. Zero
	// keeps the limit; negative is refused.
	MaxBytes int64
	// AllowSHA1Only accepts a format whose only supported checksum is
	// SHA-1. Off by default: such a format fails with ErrNoUsableChecksum.
	AllowSHA1Only bool
}

// DownloadSource says where the bytes of a download came from.
type DownloadSource string

// Download sources.
const (
	// DownloadSourceServer: the TEA server's versioned download endpoint
	// (redirects it answered with included).
	DownloadSourceServer DownloadSource = "server"
	// DownloadSourceExternal: the format's external url.
	DownloadSourceExternal DownloadSource = "external"
)

// DownloadResult describes a verified download.
type DownloadResult struct {
	// Bytes is the number of bytes written.
	Bytes int64
	// MediaType is the media type (type/subtype, lowercase, no parameters)
	// of the response's Content-Type, "" when absent or unparsable.
	MediaType string
	// Source is where the bytes came from.
	Source DownloadSource
	// Verified are the checksum algorithms verified, in the order first
	// listed in the format.
	Verified []teaapi.ChecksumType
}

// DownloadArtifact streams the content of format f of artifact revision ref
// to w and verifies it against f's checksums while streaming.
//
// The bytes come from f.Url when it is set (an external location: it must
// pass the URL policy, and no credential is sent to it on any hop), else
// from <base>/artifact/<uuid>/<version>/download?mediaType=<f.MediaType>,
// the versioned endpoint, so the bytes are those of the revision whose
// checksums f carries. Redirects follow the client's rules; the
// Authorization header is decided on every hop. Content-Disposition is
// ignored. Only 200 is accepted: a 406 wraps ErrNoAcceptableFormat, other
// statuses are *APIError or *UnexpectedResponseError. A Content-Encoding
// the transport did not remove (it decodes only the gzip it asked for) is
// ErrUnsupportedContentEncoding.
//
// The checksums are checked before the request: an algValue that is not
// lowercase hex of its algorithm's length is *UnexpectedResponseError, and
// without a supported checksum other than SHA-1 (SHA-1 counts only with
// o.AllowSHA1Only) the call fails with ErrNoUsableChecksum and makes no
// request; BLAKE3 and unknown algorithms are not supported and are ignored.
// After the body, every supported checksum listed must match, else
// *ChecksumError. More than o.MaxBytes (default Limits.DownloadBytes) is
// ErrResponseTooLarge. No response headers, or no next body byte, for
// Limits.IdleTimeout fails the call with an error wrapping ErrTimeout; a
// download that keeps sending is never cut off. There is no other time limit
// than ctx.
//
// When it returns an error, DownloadArtifact may already have written bytes
// to w: the caller must discard them. DownloadArtifactToFile does that.
func (a *API) DownloadArtifact(ctx context.Context, ref ArtifactRef, f teaapi.ArtifactFormat, w io.Writer, o DownloadOptions) (DownloadResult, error) {
	op := fmt.Sprintf("downloading artifact %s version %d", ref.UUID, ref.Version)
	if w == nil {
		return DownloadResult{}, fmt.Errorf("%s: %w: nil writer", op, ErrInvalidArgument)
	}
	var sums []teaapi.Checksum
	if f.Checksums != nil {
		sums = *f.Checksums
	}
	plan, err := planChecksums(op, sums, o)
	if err != nil {
		return DownloadResult{}, err
	}
	resp, src, err := a.fetch(ctx, op, kindDownload, ref, f, f.Url, o)
	if err != nil {
		return DownloadResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	n, err := io.Copy(io.MultiWriter(append([]io.Writer{w}, plan.writers()...)...), resp.Body)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("%s: %w", op, err)
	}
	verified, err := plan.check()
	if err != nil {
		return DownloadResult{}, fmt.Errorf("%s: %w", op, err)
	}
	return DownloadResult{Bytes: n, MediaType: mediaTypeOf(resp), Source: src, Verified: verified}, nil
}

// DownloadArtifactToFile downloads like DownloadArtifact into a temporary
// file (mode 0600) created in path's directory, verifies it, syncs it and
// renames it over path. On any error the temporary file is removed and
// path is not touched. The library never derives a file name from the
// server (Content-Disposition is ignored).
func (a *API) DownloadArtifactToFile(ctx context.Context, ref ArtifactRef, f teaapi.ArtifactFormat, path string, o DownloadOptions) (res DownloadResult, err error) {
	op := fmt.Sprintf("downloading artifact %s version %d to a file", ref.UUID, ref.Version)
	if path == "" {
		return DownloadResult{}, fmt.Errorf("%s: %w: empty path", op, ErrInvalidArgument)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tea-*")
	if err != nil {
		return DownloadResult{}, fmt.Errorf("%s: %w", op, err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return DownloadResult{}, fmt.Errorf("%s: %w", op, err)
	}
	if res, err = a.DownloadArtifact(ctx, ref, f, tmp, o); err != nil {
		return DownloadResult{}, err
	}
	if err = tmp.Sync(); err != nil {
		return DownloadResult{}, fmt.Errorf("%s: %w", op, err)
	}
	if err = tmp.Close(); err != nil {
		return DownloadResult{}, fmt.Errorf("%s: %w", op, err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return DownloadResult{}, fmt.Errorf("%s: %w", op, err)
	}
	return res, nil
}

// DownloadLatestArtifact reads the latest revision of artifact id
// (GetLatestArtifact), picks its format whose media type is mediaType
// (type and subtype compared case-insensitively, parameters exactly; none
// is an error wrapping ErrNoAcceptableFormat, with no download), and
// downloads that revision with DownloadArtifact. It does not use the
// latest download endpoint: the latest revision can change between reading
// the checksums and fetching the bytes.
func (a *API) DownloadLatestArtifact(ctx context.Context, id uuid.UUID, mediaType string, w io.Writer, o DownloadOptions) (DownloadResult, error) {
	op := "downloading the latest revision of artifact " + id.String()
	art, err := a.GetLatestArtifact(ctx, id)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("%s: %w", op, err)
	}
	for _, f := range art.Formats {
		if sameMediaType(f.MediaType, mediaType) {
			return a.DownloadArtifact(ctx, ArtifactRef{UUID: id, Version: art.Version}, f, w, o)
		}
	}
	return DownloadResult{}, fmt.Errorf("%s: %w: revision %d has no format %q", op, ErrNoAcceptableFormat, art.Version, truncateArg(mediaType))
}

// DownloadSignature streams the detached signature of format f of artifact
// revision ref to w and returns the number of bytes written. It uses
// f.SignatureUrl when set (external: no credential on any hop), else
// <base>/artifact/<uuid>/<version>/signature/download?mediaType=<f.MediaType>.
// The URL, redirect, status and content-coding rules of DownloadArtifact
// apply; more than o.MaxBytes (default Limits.SignatureBytes) is
// ErrResponseTooLarge, and Limits.IdleTimeout applies. A 404
// SIGNATURE_NOT_FOUND wraps ErrSignatureNotFound. The bytes are not
// verified: the specification defines no signature technology. On error,
// bytes already written to w must be discarded.
func (a *API) DownloadSignature(ctx context.Context, ref ArtifactRef, f teaapi.ArtifactFormat, w io.Writer, o DownloadOptions) (int64, error) {
	op := fmt.Sprintf("downloading the signature of artifact %s version %d", ref.UUID, ref.Version)
	if w == nil {
		return 0, fmt.Errorf("%s: %w: nil writer", op, ErrInvalidArgument)
	}
	resp, _, err := a.fetch(ctx, op, kindSignature, ref, f, f.SignatureUrl, o)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return n, fmt.Errorf("%s: %w", op, err)
	}
	return n, nil
}

// fetch sends the GET for a download (k is kindDownload or kindSignature)
// and returns a 200 response whose body is bounded, or an error.
func (a *API) fetch(ctx context.Context, op string, k callKind, ref ArtifactRef, f teaapi.ArtifactFormat, external *string, o DownloadOptions) (*http.Response, DownloadSource, error) {
	if o.MaxBytes < 0 {
		return nil, "", fmt.Errorf("%s: %w: negative MaxBytes", op, ErrInvalidArgument)
	}
	ctx = withMaxBytes(withKind(ctx, k), o.MaxBytes)
	var (
		resp *http.Response
		src  DownloadSource
		err  error
	)
	if external != nil {
		src = DownloadSourceExternal
		u, perr := url.Parse(*external)
		if perr != nil || !u.IsAbs() {
			return nil, "", unexpected(op, http.StatusOK, "the format's external URL is not an absolute URL")
		}
		req, rerr := http.NewRequestWithContext(withAnonymous(ctx), http.MethodGet, u.String(), nil)
		if rerr != nil {
			return nil, "", unexpected(op, http.StatusOK, "the format's external URL does not make a request")
		}
		resp, err = a.d.Do(req)
	} else {
		src = DownloadSourceServer
		if ref.UUID == uuid.Nil || ref.Version < 1 {
			return nil, "", fmt.Errorf("%s: %w: artifact uuid and a version of at least 1 are needed", op, ErrInvalidArgument)
		}
		if f.MediaType == "" {
			return nil, "", fmt.Errorf("%s: %w: the format has no mediaType", op, ErrInvalidArgument)
		}
		mt := f.MediaType
		if k == kindSignature {
			resp, err = a.raw.DownloadArtifactSignatureByVersion(ctx, ref.UUID, ref.Version, &teaapi.DownloadArtifactSignatureByVersionParams{MediaType: &mt})
		} else {
			resp, err = a.raw.DownloadArtifactByVersion(ctx, ref.UUID, ref.Version, &teaapi.DownloadArtifactByVersionParams{MediaType: &mt})
		}
	}
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", op, err)
	}
	if err := checkDownloadResponse(op, resp); err != nil {
		_ = resp.Body.Close()
		return nil, "", err
	}
	return resp, src, nil
}

// checkDownloadResponse accepts 200 with no remaining content coding.
func checkDownloadResponse(op string, resp *http.Response) error {
	switch s := resp.StatusCode; {
	case s == http.StatusOK:
	case s >= 400:
		body, _ := readBody(resp) // classify on what was read; the status counts either way
		e := mapError(op, resp, body)
		if s == http.StatusNotAcceptable && !errors.Is(e, ErrNoAcceptableFormat) {
			return fmt.Errorf("%w: %w", ErrNoAcceptableFormat, e)
		}
		return e
	default:
		return unexpected(op, s, "only 200 carries artifact bytes")
	}
	switch ce := strings.TrimSpace(resp.Header.Get("Content-Encoding")); {
	case ce == "" || strings.EqualFold(ce, "identity"):
	default:
		return fmt.Errorf("%s: %w: the response keeps a content coding the transport did not remove", op, ErrUnsupportedContentEncoding)
	}
	return nil
}

// mediaTypeOf is the response's media type without parameters.
func mediaTypeOf(resp *http.Response) string {
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return ""
	}
	return mt
}

// sameMediaType compares two media types as the specification's mediaType
// selection does: type and subtype case-insensitively, parameters exactly.
func sameMediaType(a, b string) bool {
	at, ap, _ := strings.Cut(a, ";")
	bt, bp, _ := strings.Cut(b, ";")
	return strings.EqualFold(strings.TrimSpace(at), strings.TrimSpace(bt)) && strings.TrimSpace(ap) == strings.TrimSpace(bp)
}
