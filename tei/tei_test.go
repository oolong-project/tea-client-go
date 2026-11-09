package tei

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// Case 3: accepted TEIs, kept byte-for-byte.
func TestParseAccepted(t *testing.T) {
	cases := []struct {
		in     string
		domain string
		typ    Type
		id     string
		known  bool
	}{
		{"tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1", "example.com", TypeUUID, "d4d9f54a-abcf-11ee-ac79-1a52914d44b1", true},
		{"tei://example.com/purl/cGtnOm1hdmVuL2NvbW1vbnMtaW8vY29tbW9ucy1pb0AyLjIyLjA", "example.com", TypePURL, "cGtnOm1hdmVuL2NvbW1vbnMtaW8vY29tbW9ucy1pb0AyLjIyLjA", true},
		{"tei://example.com/hash/SHA-256:fd44efd601f651c8865acf0dfeacb0df19a2b50ec69ead0262096fd2f67197b9", "example.com", TypeHash, "SHA-256:fd44efd601f651c8865acf0dfeacb0df19a2b50ec69ead0262096fd2f67197b9", true},
		{"tei://example.com/eanupc/1234567890128", "example.com", TypeEANUPC, "1234567890128", true},
		{"tei://example.com/gtin/0234567890129", "example.com", TypeGTIN, "0234567890129", true},
		{"tei://example.com/asin/B07FZ8S74R", "example.com", TypeASIN, "B07FZ8S74R", true},
		{"tei://example.com/udi/00123456789012", "example.com", TypeUDI, "00123456789012", true},
		{"tei://demo.rearmhq.com/uuid/b9f115fb-6688-4a3f-a262-3acc04e1fc9e", "demo.rearmhq.com", TypeUUID, "b9f115fb-6688-4a3f-a262-3acc04e1fc9e", true},
		{"tei://localhost/uuid/22222222-2222-4222-8222-222222222222", "localhost", TypeUUID, "22222222-2222-4222-8222-222222222222", true},
		{"tei://example.com/foo2/x", "example.com", Type("foo2"), "x", false},
		{"tei://Example.com/uuid/x", "Example.com", TypeUUID, "x", true},
		{"tei://example.com/uuid/D4D9F54A-ABCF-11EE-AC79-1A52914D44B1", "example.com", TypeUUID, "D4D9F54A-ABCF-11EE-AC79-1A52914D44B1", true},
		{"tei://example.com/hash/SHA-256%3Aabc", "example.com", TypeHash, "SHA-256%3Aabc", true},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if got.String() != c.in || got.Domain() != c.domain || got.Type() != c.typ || got.ID() != c.id {
			t.Errorf("Parse(%q) = %q %q %q %q", c.in, got.String(), got.Domain(), got.Type(), got.ID())
		}
		if got.Type().Known() != c.known {
			t.Errorf("Parse(%q).Type().Known() = %v, want %v", c.in, got.Type().Known(), c.known)
		}
	}
}

// Case 4: refusals, each with the rule named and at most 64 input bytes echoed.
func TestParseRefused(t *testing.T) {
	long := "tei://example.com/uuid/" + strings.Repeat("a", 2049-len("tei://example.com/uuid/"))
	label64 := strings.Repeat("a", 64)
	domain254 := strings.Repeat(strings.Repeat("a", 62)+".", 4) + "abcdefghij"
	domain254 = domain254[len(domain254)-254:]
	if domain254[0] == '.' {
		domain254 = "b" + domain254[1:]
	}
	cases := []struct {
		name, in, rule string
	}{
		{"uppercase scheme", "TEI://example.com/uuid/x", "does not start with tei://"},
		{"single slash", "tei:/x", "does not start with tei://"},
		{"empty domain", "tei:///uuid/x", "empty domain"},
		{"port", "tei://example.com:443/uuid/x", "outside [A-Za-z0-9-]"},
		{"userinfo", "tei://user@example.com/uuid/x", "outside [A-Za-z0-9-]"},
		{"ipv4", "tei://192.168.0.1/uuid/x", "IPv4 literal"},
		{"ipv6", "tei://[::1]/uuid/x", "outside [A-Za-z0-9-]"},
		{"label 64", "tei://" + label64 + ".com/uuid/x", "label longer than 63"},
		{"domain 254", "tei://" + domain254 + "/uuid/x", "longer than 253"},
		{"trailing dot", "tei://example.com./uuid/x", "trailing dot"},
		{"underscore", "tei://ex_ample.com/uuid/x", "outside [A-Za-z0-9-]"},
		{"non-ASCII domain", "tei://b\xc3\xbccher.example/uuid/x", "non-ASCII"},
		{"type Uuid", "tei://example.com/Uuid/x", "lowercase letter"},
		{"type 1abc", "tei://example.com/1abc/x", "lowercase letter"},
		{"missing id", "tei://example.com/uuid/", "empty id"},
		{"missing id part", "tei://example.com/uuid", "not exactly domain/type/id"},
		{"fourth segment", "tei://example.com/uuid/x/y", "not exactly domain/type/id"},
		{"encoded slash upper", "tei://example.com/uuid/a%2Fb", "encoded slash"},
		{"encoded slash lower", "tei://example.com/uuid/a%2fb", "encoded slash"},
		{"bad escape", "tei://example.com/uuid/a%G1", "malformed percent escape"},
		{"trailing percent", "tei://example.com/uuid/a%", "malformed percent escape"},
		{"query", "tei://example.com/uuid/a?b", "contains ? or #"},
		{"fragment", "tei://example.com/uuid/a#b", "contains ? or #"},
		{"space", "tei://example.com/uuid/a b", "space"},
		{"control", "tei://example.com/uuid/a\x01b", "control"},
		{"too long", long, "longer than 2048"},
	}
	for _, c := range cases {
		_, err := Parse(c.in)
		if !errors.Is(err, ErrSyntax) {
			t.Errorf("%s: Parse(%q) error = %v, want ErrSyntax", c.name, c.in, err)
			continue
		}
		var se *SyntaxError
		if !errors.As(err, &se) || !strings.Contains(se.Rule, c.rule) {
			t.Errorf("%s: rule = %v, want it to contain %q", c.name, err, c.rule)
		}
		if len(se.Input) > len(c.in) {
			t.Errorf("%s: echoed input longer than input", c.name)
		}
		if len(c.in) > 64 && strings.Contains(err.Error(), c.in[:65]) {
			t.Errorf("%s: error echoes more than 64 input bytes: %v", c.name, err)
		}
	}
	if len(long) != 2049 {
		t.Fatalf("test setup: long TEI is %d bytes", len(long))
	}
	if len(domain254) != 254 {
		t.Fatalf("test setup: domain is %d bytes", len(domain254))
	}
}

// Case 5: the legacy form is refused by Parse with ErrLegacyForm.
func TestParseLegacyForm(t *testing.T) {
	_, err := Parse("urn:tei:uuid:example.com:x")
	if !errors.Is(err, ErrLegacyForm) {
		t.Fatalf("Parse(urn:tei:...) = %v, want ErrLegacyForm", err)
	}
	if !strings.Contains(err.Error(), "ParseLegacyURN") && !strings.Contains(ErrLegacyForm.Error(), "ParseLegacyURN") {
		t.Fatalf("legacy error does not point at ParseLegacyURN: %v", err)
	}
}

// Case 6: ParseLegacyURN with the examples from the ReARM CLI's help.
func TestParseLegacyURN(t *testing.T) {
	const hexValue = "fd44efd601f651c8865acf0dfeacb0df19a2b50ec69ead0262096fd2f67197b9"
	u, err := ParseLegacyURN("urn:tei:uuid:products.example.com:d4d9f54a-abcf-11ee-ac79-1a52914d44b")
	if err != nil || u.String() != "tei://products.example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b" {
		t.Fatalf("uuid: %q %v", u.String(), err)
	}

	const purl = "pkg:pypi/cyclonedx-python-lib@8.4.0"
	p, err := ParseLegacyURN("urn:tei:purl:cyclonedx.org:" + purl)
	if err != nil {
		t.Fatalf("purl: %v", err)
	}
	want := "tei://cyclonedx.org/purl/" + base64.RawURLEncoding.EncodeToString([]byte(purl))
	if p.String() != want || strings.Contains(p.String(), "=") {
		t.Fatalf("purl: got %q, want %q", p.String(), want)
	}
	if got, err := p.PURL(); err != nil || got != purl {
		t.Fatalf("PURL() = %q, %v", got, err)
	}

	h, err := ParseLegacyURN("urn:tei:hash:localhost:SHA256:" + hexValue)
	if err != nil || h.String() != "tei://localhost/hash/SHA-256:"+hexValue {
		t.Fatalf("hash: %q %v", h.String(), err)
	}
	if h2, err := ParseLegacyURN("urn:tei:hash:localhost:SHA3-256:" + hexValue); err != nil || h2.ID() != "SHA3-256:"+hexValue {
		t.Fatalf("hash with checksum-type spelling: %q %v", h2.ID(), err)
	}

	for _, s := range []string{"urn:tei:swid:example.com:x", "urn:tei:gs1:example.com:x"} {
		if _, err := ParseLegacyURN(s); !errors.Is(err, ErrLegacyTypeUnsupported) {
			t.Errorf("ParseLegacyURN(%q) = %v, want ErrLegacyTypeUnsupported", s, err)
		}
	}
	if _, err := ParseLegacyURN("urn:tei:hash:example.com:MD5:" + hexValue[:32]); !errors.Is(err, ErrSyntax) {
		t.Errorf("MD5 hash: %v, want ErrSyntax", err)
	}

	if tt, legacy, err := ParseCompat("urn:tei:uuid:example.com:x"); err != nil || !legacy || tt.String() != "tei://example.com/uuid/x" {
		t.Errorf("ParseCompat legacy: %q %v %v", tt.String(), legacy, err)
	}
	if tt, legacy, err := ParseCompat("tei://example.com/uuid/x"); err != nil || legacy || tt.String() != "tei://example.com/uuid/x" {
		t.Errorf("ParseCompat tei: %q %v %v", tt.String(), legacy, err)
	}
}

func TestPURLWrongType(t *testing.T) {
	u, err := Parse("tei://example.com/uuid/x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.PURL(); err == nil {
		t.Fatal("PURL on a uuid TEI succeeded")
	}
}

// Case 7: fuzzers. No panic; an accepted value round-trips and re-parses equal.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1",
		"tei://example.com/purl/cGtnOm1hdmVuL2NvbW1vbnMtaW8vY29tbW9ucy1pb0AyLjIyLjA",
		"tei://localhost/hash/SHA-256%3Aabc",
		"urn:tei:uuid:example.com:x",
		"tei://a/b/%2f",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := Parse(s)
		if err != nil {
			if len(err.Error()) > 200+maxEcho*4 {
				t.Fatalf("error message too long: %d", len(err.Error()))
			}
			return
		}
		if v.String() != s {
			t.Fatalf("String() = %q, input %q", v.String(), s)
		}
		again, err := Parse(v.String())
		if err != nil || again != v {
			t.Fatalf("re-parse: %v %v", again, err)
		}
	})
}

func FuzzParseLegacyURN(f *testing.F) {
	for _, s := range []string{
		"urn:tei:uuid:products.example.com:d4d9f54a-abcf-11ee-ac79-1a52914d44b",
		"urn:tei:purl:cyclonedx.org:pkg:pypi/cyclonedx-python-lib@8.4.0",
		"urn:tei:hash:localhost:SHA256:fd44",
		"urn:tei:swid:example.com:x",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseLegacyURN(s)
		if err != nil {
			return
		}
		again, err := Parse(v.String())
		if err != nil || again != v {
			t.Fatalf("re-parse of %q: %v %v", v.String(), again, err)
		}
	})
}
