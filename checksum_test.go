package tea

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/oolong-project/tea-client-go/teaapi"
)

// fixtureJSON is the 137-byte JSON artifact of oolong's TEA 1.0 fixtures
// (docs/tea-upgrade/fixture-reference.md).
const fixtureJSON = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"oolong-fixture-widget"}}}` + "\n"

// Known-answer vectors. They were computed with Python's hashlib (an
// implementation independent of the Go code under test); the "abc" values
// are the published test vectors of each algorithm, and the fixture's
// SHA-256 and SHA-1 are those of the fixture reference.
var knownAnswers = map[string][]teaapi.Checksum{
	"abc": {
		{AlgType: teaapi.SHA1, AlgValue: "a9993e364706816aba3e25717850c26c9cd0d89d"},
		{AlgType: teaapi.SHA256, AlgValue: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{AlgType: teaapi.SHA384, AlgValue: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
		{AlgType: teaapi.SHA512, AlgValue: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
		{AlgType: teaapi.SHA3256, AlgValue: "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
		{AlgType: teaapi.SHA3384, AlgValue: "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"},
		{AlgType: teaapi.SHA3512, AlgValue: "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"},
		{AlgType: teaapi.BLAKE2b256, AlgValue: "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"},
		{AlgType: teaapi.BLAKE2b384, AlgValue: "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4"},
		{AlgType: teaapi.BLAKE2b512, AlgValue: "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"},
	},
	fixtureJSON: {
		{AlgType: teaapi.SHA1, AlgValue: "a9ac7d6e8b5aae33125cd3c3d58c9bb5e3924e35"},
		{AlgType: teaapi.SHA256, AlgValue: "8c5170df0ae7a47f77b2f0b1f03c04500343aa2a26863098d2f133b9350d0f98"},
		{AlgType: teaapi.SHA384, AlgValue: "c33ea1576d977795733a64246a611a76925f5a565d5eb815b3403b700ef4ed9868250653d85531d5a4efe9a69469c0f2"},
		{AlgType: teaapi.SHA512, AlgValue: "a771bb45b9e15bc62c12902966ebae800460fa6766fe6a208c227e221c9d975e2efda4d4e5238734fc60e511dcc42a84aded966236cfde701e66acc70289d819"},
		{AlgType: teaapi.SHA3256, AlgValue: "4609fd7f23d4c2b213477a29df26481df99505ee3b9fd2f3f8e8fd9de2c48749"},
		{AlgType: teaapi.SHA3384, AlgValue: "19a9d5495daefbd326819b3c9693c0b590e36cc9862477e0d064fd1d32f8ee0d8e730e6656832afd21c14ae2e28c7b37"},
		{AlgType: teaapi.SHA3512, AlgValue: "53c5f563dab45e0984ab5b9e8cef458078ca487bfa15b46989a00dff2f24f773d44a812151336802f9c6c49598167734411bc9de9c47acd4e986e337db201c56"},
		{AlgType: teaapi.BLAKE2b256, AlgValue: "76f761f14c95f312552590782f6b2115f617f396d974696d5cb61e05c4bbb82a"},
		{AlgType: teaapi.BLAKE2b384, AlgValue: "f0f63067e41ce301e61626deba2f6dc3293c86b8b68a9cc21a5bca91e1ef95a61cb56ee5046b5f103197cdf6da7b7953"},
		{AlgType: teaapi.BLAKE2b512, AlgValue: "05caafb5d28ab561ab4937f783e665db9e5030f89d98f135e64e959fb11f34d1b4e358b8faf288af6d06dfaab359921e222ad293bfb553b58addc0d0f04f8e18"},
	},
}

// sum is a checksum literal for the tests.
func sum(alg teaapi.ChecksumType, v string) teaapi.Checksum {
	return teaapi.Checksum{AlgType: alg, AlgValue: v}
}

// flipped returns v with its first hex digit changed.
func flipped(v string) string {
	if v[0] == '0' {
		return "1" + v[1:]
	}
	return "0" + v[1:]
}

// Case 28: known-answer vectors for every supported algorithm, each alone
// (SHA-1 with AllowSHA1Only) and all together; each one wrong is a
// mismatch naming it; BLAKE3 only is ErrNoUsableChecksum.
func TestChecksumKnownAnswers(t *testing.T) {
	for data, sums := range knownAnswers {
		name := data
		if len(name) > 8 {
			name = "fixture"
		}
		if len(sums) != 10 {
			t.Fatalf("%s: %d vectors, want one per supported algorithm (10)", name, len(sums))
		}
		for _, s := range sums {
			got, err := VerifyChecksums(strings.NewReader(data), []teaapi.Checksum{s}, DownloadOptions{AllowSHA1Only: true})
			if err != nil || !slices.Equal(got, []teaapi.ChecksumType{s.AlgType}) {
				t.Errorf("%s %s: %v %v", name, s.AlgType, got, err)
			}
			_, err = VerifyChecksums(strings.NewReader(data), []teaapi.Checksum{sum(s.AlgType, flipped(s.AlgValue))}, DownloadOptions{AllowSHA1Only: true})
			var ce *ChecksumError
			if !errors.As(err, &ce) || ce.Alg != s.AlgType || ce.Actual != s.AlgValue {
				t.Errorf("%s %s with a wrong value: %v, want *ChecksumError with the actual digest", name, s.AlgType, err)
			}
		}
		got, err := VerifyChecksums(strings.NewReader(data), sums, DownloadOptions{})
		want := make([]teaapi.ChecksumType, 0, len(sums))
		for _, s := range sums {
			want = append(want, s.AlgType)
		}
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%s all algorithms: %v %v", name, got, err)
		}
	}

	blake3 := sum(teaapi.BLAKE3, strings.Repeat("ab", 32))
	if _, err := VerifyChecksums(strings.NewReader("abc"), []teaapi.Checksum{blake3}, DownloadOptions{AllowSHA1Only: true}); !errors.Is(err, ErrNoUsableChecksum) {
		t.Errorf("BLAKE3 only: %v, want ErrNoUsableChecksum", err)
	}
}

// Case 29: the rules of 3.8 step 5.
func TestChecksumRules(t *testing.T) {
	abc := knownAnswers["abc"]
	sha1, sha256, sha512 := abc[0], abc[1], abc[3]
	verify := func(sums []teaapi.Checksum, o DownloadOptions) ([]teaapi.ChecksumType, error) {
		return VerifyChecksums(strings.NewReader("abc"), sums, o)
	}

	// One of two listed checksums wrong: *ChecksumError naming it, whatever
	// else matched, in either order.
	bad := sum(teaapi.SHA512, flipped(sha512.AlgValue))
	for _, sums := range [][]teaapi.Checksum{{sha256, bad}, {bad, sha256}} {
		_, err := verify(sums, DownloadOptions{})
		var ce *ChecksumError
		if !errors.As(err, &ce) || !errors.Is(err, ErrChecksumMismatch) || ce.Alg != teaapi.SHA512 ||
			ce.Expected != bad.AlgValue || ce.Actual != sha512.AlgValue || !strings.Contains(err.Error(), "SHA-512") {
			t.Errorf("%v: %v, want *ChecksumError for SHA-512", sums, err)
		}
	}
	// Two entries of one algorithm with different values: one mismatches.
	if _, err := verify([]teaapi.Checksum{sha256, sum(teaapi.SHA256, flipped(sha256.AlgValue))}, DownloadOptions{}); !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("two SHA-256 values: %v, want a mismatch", err)
	}

	// SHA-1 only: refused, unless AllowSHA1Only; a wrong SHA-1 still fails
	// with it.
	if _, err := verify([]teaapi.Checksum{sha1}, DownloadOptions{}); !errors.Is(err, ErrNoUsableChecksum) {
		t.Errorf("SHA-1 only: %v, want ErrNoUsableChecksum", err)
	}
	if got, err := verify([]teaapi.Checksum{sha1}, DownloadOptions{AllowSHA1Only: true}); err != nil || !slices.Equal(got, []teaapi.ChecksumType{teaapi.SHA1}) {
		t.Errorf("SHA-1 only with AllowSHA1Only: %v %v", got, err)
	}
	if _, err := verify([]teaapi.Checksum{sum(teaapi.SHA1, flipped(sha1.AlgValue))}, DownloadOptions{AllowSHA1Only: true}); !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("wrong SHA-1 with AllowSHA1Only: %v, want a mismatch", err)
	}
	// SHA-1 next to a strong one: both verified, a wrong SHA-1 fails.
	if got, err := verify([]teaapi.Checksum{sha1, sha256}, DownloadOptions{}); err != nil || !slices.Equal(got, []teaapi.ChecksumType{teaapi.SHA1, teaapi.SHA256}) {
		t.Errorf("SHA-1 and SHA-256: %v %v", got, err)
	}
	if _, err := verify([]teaapi.Checksum{sum(teaapi.SHA1, flipped(sha1.AlgValue)), sha256}, DownloadOptions{}); !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("wrong SHA-1 next to SHA-256: %v, want a mismatch", err)
	}
	// SHA-1 and BLAKE3: BLAKE3 does not count, so this is SHA-1 only.
	blake3 := sum(teaapi.BLAKE3, strings.Repeat("ab", 32))
	if _, err := verify([]teaapi.Checksum{sha1, blake3}, DownloadOptions{}); !errors.Is(err, ErrNoUsableChecksum) {
		t.Errorf("SHA-1 and BLAKE3: %v, want ErrNoUsableChecksum", err)
	}

	// No checksums: refused, even with AllowSHA1Only.
	for _, sums := range [][]teaapi.Checksum{nil, {}} {
		if _, err := verify(sums, DownloadOptions{AllowSHA1Only: true}); !errors.Is(err, ErrNoUsableChecksum) {
			t.Errorf("no checksums: %v, want ErrNoUsableChecksum", err)
		}
	}

	// algValue uppercase, wrong length, not hex: the metadata is refused,
	// also next to a matching checksum, and also for BLAKE3 (a
	// specification algorithm, unsupported here).
	for _, c := range []teaapi.Checksum{
		sum(teaapi.SHA256, strings.ToUpper(sha256.AlgValue)),
		sum(teaapi.SHA256, sha256.AlgValue[:63]),
		sum(teaapi.SHA256, sha256.AlgValue+"0"),
		sum(teaapi.SHA256, sha512.AlgValue),
		sum(teaapi.SHA256, "g"+sha256.AlgValue[1:]),
		sum(teaapi.SHA1, ""),
		sum(teaapi.BLAKE3, strings.Repeat("ab", 31)),
	} {
		_, err := verify([]teaapi.Checksum{sha512, c}, DownloadOptions{AllowSHA1Only: true})
		var ue *UnexpectedResponseError
		if !errors.As(err, &ue) || !strings.Contains(ue.Reason, "lowercase hex") {
			t.Errorf("%s %q: %v, want *UnexpectedResponseError", c.AlgType, c.AlgValue, err)
		}
		if c.AlgValue != "" && strings.Contains(err.Error(), c.AlgValue) {
			t.Errorf("the refusal echoes the value: %v", err)
		}
	}

	// Unknown algType: ignored when a supported one matches; alone it is no
	// usable checksum; its value is not checked.
	unknown := sum("SHA-1024", "XYZ")
	if got, err := verify([]teaapi.Checksum{unknown, sha256}, DownloadOptions{}); err != nil || !slices.Equal(got, []teaapi.ChecksumType{teaapi.SHA256}) {
		t.Errorf("unknown and SHA-256: %v %v", got, err)
	}
	if _, err := verify([]teaapi.Checksum{unknown}, DownloadOptions{AllowSHA1Only: true}); !errors.Is(err, ErrNoUsableChecksum) {
		t.Errorf("unknown only: %v, want ErrNoUsableChecksum", err)
	}

	// MaxBytes on VerifyChecksums: three bytes pass with 3 and fail with 2.
	if _, err := verify([]teaapi.Checksum{sha256}, DownloadOptions{MaxBytes: 3}); err != nil {
		t.Errorf("MaxBytes 3: %v", err)
	}
	if _, err := verify([]teaapi.Checksum{sha256}, DownloadOptions{MaxBytes: 2}); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("MaxBytes 2: %v, want ErrResponseTooLarge", err)
	}
	if _, err := VerifyChecksums(bytes.NewReader(nil), []teaapi.Checksum{sha256}, DownloadOptions{MaxBytes: -1}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("MaxBytes -1: %v, want ErrInvalidArgument", err)
	}
}
