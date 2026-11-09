package tea

import (
	"crypto/sha1" // SHA-1 is a TEA checksum type; alone it counts only with AllowSHA1Only
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net/http"

	"golang.org/x/crypto/blake2b"

	"github.com/oolong-project/tea-client-go/teaapi"
)

// Checksum verification errors.
var (
	// ErrChecksumMismatch: a listed checksum did not match the bytes
	// (*ChecksumError wraps it).
	ErrChecksumMismatch = errors.New("tea: checksum mismatch")
	// ErrNoUsableChecksum: the format lists no checksum this client can
	// verify with a strong algorithm (SHA-1 only counts with
	// DownloadOptions.AllowSHA1Only; BLAKE3 and unknown algorithms are not
	// supported), or no checksum at all.
	ErrNoUsableChecksum = errors.New("tea: no usable checksum")
	// ErrUnsupportedContentEncoding: a response kept a Content-Encoding other
	// than identity, so its bytes are not the bytes the checksums cover.
	ErrUnsupportedContentEncoding = errors.New("tea: unsupported content encoding")
)

// ChecksumError is a listed checksum that did not match. Expected and
// Actual are lowercase hex digests of Alg's length.
type ChecksumError struct {
	Alg      teaapi.ChecksumType
	Expected string
	Actual   string
}

func (e *ChecksumError) Error() string {
	return fmt.Sprintf("tea: checksum mismatch: %s: expected %s, got %s", e.Alg, e.Expected, e.Actual)
}

// Unwrap returns ErrChecksumMismatch.
func (e *ChecksumError) Unwrap() error { return ErrChecksumMismatch }

// hexLength is the digest length in hex characters of every checksum type
// of the specification (checksum.algValue).
var hexLength = map[teaapi.ChecksumType]int{
	teaapi.SHA1:       40,
	teaapi.SHA256:     64,
	teaapi.SHA384:     96,
	teaapi.SHA512:     128,
	teaapi.SHA3256:    64,
	teaapi.SHA3384:    96,
	teaapi.SHA3512:    128,
	teaapi.BLAKE2b256: 64,
	teaapi.BLAKE2b384: 96,
	teaapi.BLAKE2b512: 128,
	teaapi.BLAKE3:     64,
}

// newHash returns a hash for a supported algorithm, nil for BLAKE3 (no
// implementation in the standard library or golang.org/x/crypto) and for
// unknown algorithms.
func newHash(alg teaapi.ChecksumType) hash.Hash {
	switch alg {
	case teaapi.SHA1:
		return sha1.New()
	case teaapi.SHA256:
		return sha256.New()
	case teaapi.SHA384:
		return sha512.New384()
	case teaapi.SHA512:
		return sha512.New()
	case teaapi.SHA3256:
		return sha3.New256()
	case teaapi.SHA3384:
		return sha3.New384()
	case teaapi.SHA3512:
		return sha3.New512()
	case teaapi.BLAKE2b256:
		h, _ := blake2b.New256(nil) // fails only for a key over 64 bytes
		return h
	case teaapi.BLAKE2b384:
		h, _ := blake2b.New384(nil)
		return h
	case teaapi.BLAKE2b512:
		h, _ := blake2b.New512(nil)
		return h
	}
	return nil
}

func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !('0' <= s[i] && s[i] <= '9' || 'a' <= s[i] && s[i] <= 'f') {
			return false
		}
	}
	return true
}

// checksumPlan is the verification a format's checksums call for.
type checksumPlan struct {
	sums    []teaapi.Checksum // the supported ones, in the order listed
	algs    []teaapi.ChecksumType
	hashers map[teaapi.ChecksumType]hash.Hash
}

// planChecksums checks a format's checksums before any byte is read
// (architecture 3.8 step 5): every algValue of a specification algorithm is
// lowercase hex of that algorithm's length (else *UnexpectedResponseError:
// the metadata, served with 200, is refused); unknown algorithms are
// ignored; at least one supported algorithm other than SHA-1 is listed, or
// with AllowSHA1Only at least SHA-1 (else ErrNoUsableChecksum).
func planChecksums(op string, sums []teaapi.Checksum, o DownloadOptions) (*checksumPlan, error) {
	p := &checksumPlan{hashers: map[teaapi.ChecksumType]hash.Hash{}}
	strong, weak := false, false
	for i, s := range sums {
		n, known := hexLength[s.AlgType]
		if !known {
			continue
		}
		if len(s.AlgValue) != n || !lowerHex(s.AlgValue) {
			return nil, unexpected(op, http.StatusOK, fmt.Sprintf("checksum %d: algValue is not %d lowercase hex characters for %s", i, n, s.AlgType))
		}
		h := newHash(s.AlgType)
		if h == nil {
			continue // BLAKE3: unsupported
		}
		if s.AlgType == teaapi.SHA1 {
			weak = true
		} else {
			strong = true
		}
		if _, ok := p.hashers[s.AlgType]; !ok {
			p.hashers[s.AlgType] = h
			p.algs = append(p.algs, s.AlgType)
		}
		p.sums = append(p.sums, s)
	}
	if !strong && !(weak && o.AllowSHA1Only) {
		reason := "no supported checksum other than SHA-1 (AllowSHA1Only is off)"
		if !weak {
			reason = "no supported checksum (SHA-2, SHA-3, BLAKE2b or, with AllowSHA1Only, SHA-1)"
		}
		return nil, fmt.Errorf("%s: %w: %s", op, ErrNoUsableChecksum, reason)
	}
	return p, nil
}

func (p *checksumPlan) writers() []io.Writer {
	ws := make([]io.Writer, 0, len(p.algs))
	for _, a := range p.algs {
		ws = append(ws, p.hashers[a])
	}
	return ws
}

// check compares every supported checksum with the bytes hashed; the first
// mismatch is a *ChecksumError, whatever else matched.
func (p *checksumPlan) check() ([]teaapi.ChecksumType, error) {
	actual := map[teaapi.ChecksumType]string{}
	for _, a := range p.algs {
		actual[a] = hex.EncodeToString(p.hashers[a].Sum(nil))
	}
	for _, s := range p.sums {
		if actual[s.AlgType] != s.AlgValue {
			return nil, &ChecksumError{Alg: s.AlgType, Expected: s.AlgValue, Actual: actual[s.AlgType]}
		}
	}
	return append([]teaapi.ChecksumType(nil), p.algs...), nil
}

// VerifyChecksums reads r to the end and verifies it against sums with the
// rules of DownloadArtifact: every listed checksum of a supported algorithm
// must match (*ChecksumError otherwise), at least one of them other than
// SHA-1 (or SHA-1 with o.AllowSHA1Only), else ErrNoUsableChecksum; an
// algValue that is not lowercase hex of its algorithm's length is refused
// (*UnexpectedResponseError). With o.MaxBytes > 0, reading stops with
// ErrResponseTooLarge past that many bytes. It returns the algorithms
// verified, in the order first listed.
func VerifyChecksums(r io.Reader, sums []teaapi.Checksum, o DownloadOptions) ([]teaapi.ChecksumType, error) {
	const op = "verifying checksums"
	if o.MaxBytes < 0 {
		return nil, fmt.Errorf("%s: %w: negative MaxBytes", op, ErrInvalidArgument)
	}
	p, err := planChecksums(op, sums, o)
	if err != nil {
		return nil, err
	}
	src := r
	if o.MaxBytes > 0 && o.MaxBytes < math.MaxInt64 {
		// One byte past the cap shows the input is longer. At
		// math.MaxInt64 there is no room for that byte (MaxBytes+1 would
		// overflow and read nothing), and no input can be longer anyway.
		src = io.LimitReader(r, o.MaxBytes+1)
	}
	n, err := io.Copy(io.MultiWriter(p.writers()...), src)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if o.MaxBytes > 0 && n > o.MaxBytes {
		return nil, fmt.Errorf("%s: more than %d bytes: %w", op, o.MaxBytes, ErrResponseTooLarge)
	}
	return p.check()
}
