// Package tei parses Transparency Exchange Identifiers (TEIs) as defined by
// the TEA discovery specification ("TEI syntax", discovery/readme.md of
// CycloneDX/transparency-exchange-api at the commit spec/SPEC_PIN.md names).
//
// A TEI has the form tei://<domain-name>/<type>/<id>. Parse keeps the TEI
// exactly as written: it validates, but it never rewrites, decodes or
// normalises. Unknown but well-formed types are accepted, since the type
// registry is open.
//
// The legacy form urn:tei:<type>:<domain>:<id> used by older drafts is not a
// TEI. Parse refuses it with ErrLegacyForm; ParseLegacyURN converts it
// explicitly, as a migration aid.
package tei

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Type is the type part of a TEI. The constants are the types of the TEI
// registry at the pinned specification commit; other well-formed values are
// accepted and reported as unknown by Known.
type Type string

// Registered TEI types (tei-types/ at the pinned specification commit).
const (
	TypeUUID   Type = "uuid"
	TypePURL   Type = "purl"
	TypeHash   Type = "hash"
	TypeEANUPC Type = "eanupc"
	TypeGTIN   Type = "gtin"
	TypeASIN   Type = "asin"
	TypeUDI    Type = "udi"
)

// Known reports whether t is one of the registered types above.
func (t Type) Known() bool {
	switch t {
	case TypeUUID, TypePURL, TypeHash, TypeEANUPC, TypeGTIN, TypeASIN, TypeUDI:
		return true
	}
	return false
}

// TEI is a parsed Transparency Exchange Identifier. The zero value is not a
// valid TEI; obtain one from Parse, ParseLegacyURN or ParseCompat.
type TEI struct {
	raw    string
	domain string
	typ    Type
	id     string
}

// String returns the TEI exactly as it was parsed.
func (t TEI) String() string { return t.raw }

// Domain returns the domain name as written (case kept). DNS is
// case-insensitive, so callers building a URL lowercase it.
func (t TEI) Domain() string { return t.domain }

// Type returns the TEI type.
func (t TEI) Type() Type { return t.typ }

// ID returns the id part as written, still percent-encoded.
func (t TEI) ID() string { return t.id }

// PURL decodes the id of a purl TEI: the PURL, Base64URL-encoded without
// padding. It fails for any other type and for an id that does not decode.
func (t TEI) PURL() (string, error) {
	if t.typ != TypePURL {
		return "", fmt.Errorf("tei: PURL called on a TEI of type %q", truncate(string(t.typ)))
	}
	b, err := base64.RawURLEncoding.DecodeString(t.id)
	if err != nil {
		return "", &SyntaxError{Rule: "purl id is not unpadded Base64URL", Input: truncate(t.id)}
	}
	return string(b), nil
}

// Errors returned by this package. Parse failures are *SyntaxError values
// that wrap ErrSyntax (or ErrLegacyForm for a urn:tei: input).
var (
	ErrSyntax                = errors.New("tei: invalid syntax")
	ErrLegacyForm            = errors.New("tei: legacy urn:tei: form; use tei://<domain>/<type>/<id> or tei.ParseLegacyURN")
	ErrLegacyTypeUnsupported = errors.New("tei: legacy type has no TEI v1.0.0 registry entry")
)

// maxEcho is the most input bytes an error message ever repeats.
const maxEcho = 64

// SyntaxError reports which rule an input broke. Input is truncated to 64
// bytes, so an error never repeats more of an untrusted string than that.
type SyntaxError struct {
	Rule  string
	Input string
	err   error
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("tei: %s: %q", e.Rule, truncate(e.Input))
}

// Unwrap returns ErrSyntax, or the more specific sentinel the error carries.
func (e *SyntaxError) Unwrap() error {
	if e.err != nil {
		return e.err
	}
	return ErrSyntax
}

func truncate(s string) string {
	if len(s) > maxEcho {
		return s[:maxEcho]
	}
	return s
}

func syntaxErr(rule, input string) error { return &SyntaxError{Rule: rule, Input: truncate(input)} }

const (
	prefix       = "tei://"
	legacyPrefix = "urn:tei:"
	maxLen       = 2048
	maxTypeLen   = 32
	maxDomainLen = 253
	maxLabelLen  = 63
)

// Parse parses s as a TEI. The rules, in order: at most 2048 bytes of
// printable ASCII without spaces; the exact prefix tei://; exactly three
// parts (domain, type, id) and no ? or #; a DNS domain name without port,
// userinfo, IP literal or trailing dot; a type matching [a-z][a-z0-9]* of at
// most 32 characters; an id of RFC 3986 pchar characters with well-formed
// percent escapes and no encoded slash.
func Parse(s string) (TEI, error) {
	if len(s) > maxLen {
		return TEI{}, syntaxErr("longer than 2048 bytes", s)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f {
			return TEI{}, syntaxErr("non-ASCII, control or space character", s)
		}
	}
	if !strings.HasPrefix(s, prefix) {
		if strings.HasPrefix(strings.ToLower(s), legacyPrefix) {
			return TEI{}, &SyntaxError{Rule: "legacy urn:tei: form", Input: truncate(s), err: ErrLegacyForm}
		}
		return TEI{}, syntaxErr("does not start with tei://", s)
	}
	if strings.ContainsAny(s, "?#") {
		return TEI{}, syntaxErr("contains ? or #", s)
	}
	parts := strings.Split(s[len(prefix):], "/")
	if len(parts) != 3 {
		return TEI{}, syntaxErr("not exactly domain/type/id", s)
	}
	domain, typ, id := parts[0], parts[1], parts[2]
	if rule := checkDomain(domain); rule != "" {
		return TEI{}, syntaxErr(rule, s)
	}
	if rule := checkType(typ); rule != "" {
		return TEI{}, syntaxErr(rule, s)
	}
	if rule := checkID(id); rule != "" {
		return TEI{}, syntaxErr(rule, s)
	}
	return TEI{raw: s, domain: domain, typ: Type(typ), id: id}, nil
}

func checkDomain(d string) string {
	switch {
	case d == "":
		return "empty domain"
	case len(d) > maxDomainLen:
		return "domain longer than 253 characters"
	case strings.HasSuffix(d, "."):
		return "domain has a trailing dot"
	}
	allNumeric := true
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return "domain has an empty label"
		}
		if len(label) > maxLabelLen {
			return "domain label longer than 63 characters"
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "domain label starts or ends with -"
		}
		numeric := true
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
				numeric = false
			default:
				return "domain has a character outside [A-Za-z0-9-] (port, userinfo or IP literal)"
			}
		}
		if !numeric {
			allNumeric = false
		}
	}
	if allNumeric {
		return "domain is an IPv4 literal"
	}
	return ""
}

func checkType(t string) string {
	if t == "" {
		return "empty type"
	}
	if len(t) > maxTypeLen {
		return "type longer than 32 characters"
	}
	if t[0] < 'a' || t[0] > 'z' {
		return "type does not start with a lowercase letter"
	}
	for i := 1; i < len(t); i++ {
		c := t[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return "type has a character outside [a-z0-9]"
		}
	}
	return ""
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func checkID(id string) string {
	if id == "" {
		return "empty id"
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-._~!$&'()*+,;=:@", c) >= 0:
		case c == '%':
			if i+2 >= len(id) || !isHex(id[i+1]) || !isHex(id[i+2]) {
				return "id has a malformed percent escape"
			}
			if id[i+1] == '2' && (id[i+2] == 'F' || id[i+2] == 'f') {
				return "id has an encoded slash (%2F)"
			}
			i += 2
		default:
			return "id has a character outside RFC 3986 pchar"
		}
	}
	return ""
}

// legacyHashAlgs maps the legacy spellings the old CLI accepted to the
// checksum-type spelling of the specification.
var legacyHashAlgs = map[string]string{
	"SHA1":   "SHA-1",
	"SHA256": "SHA-256",
	"SHA384": "SHA-384",
	"SHA512": "SHA-512",
}

// checksumTypes is the spec's closed checksum-type set.
var checksumTypes = map[string]bool{
	"SHA-1": true, "SHA-256": true, "SHA-384": true, "SHA-512": true,
	"SHA3-256": true, "SHA3-384": true, "SHA3-512": true,
	"BLAKE2b-256": true, "BLAKE2b-384": true, "BLAKE2b-512": true, "BLAKE3": true,
}

// ParseLegacyURN converts urn:tei:<type>:<domain>:<id> (the form older ReARM
// CLI versions accepted; <id> is everything after the domain, colons
// included) into tei://<domain>/<type>/<id'> and parses the result with Parse.
// uuid, eanupc, gtin, asin and udi ids are kept; a purl id is the raw PURL,
// Base64URL-encoded without padding; a hash id is <alg>:<hex> with SHA1,
// SHA256, SHA384 or SHA512 mapped to the checksum-type spelling. Other types
// (swid, gs1, ...) give ErrLegacyTypeUnsupported.
//
// The conversion is a migration aid, not identity: the result may differ from
// the TEI a publisher prints, and then discovery answers OBJECT_UNKNOWN.
func ParseLegacyURN(s string) (TEI, error) {
	if len(s) > maxLen {
		return TEI{}, syntaxErr("longer than 2048 bytes", s)
	}
	if !strings.HasPrefix(s, legacyPrefix) {
		return TEI{}, syntaxErr("does not start with urn:tei:", s)
	}
	parts := strings.SplitN(s[len(legacyPrefix):], ":", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return TEI{}, syntaxErr("not urn:tei:<type>:<domain>:<id>", s)
	}
	typ, domain, id := parts[0], parts[1], parts[2]
	switch Type(typ) {
	case TypeUUID, TypeEANUPC, TypeGTIN, TypeASIN, TypeUDI:
	case TypePURL:
		id = base64.RawURLEncoding.EncodeToString([]byte(id))
	case TypeHash:
		alg, hexValue, ok := strings.Cut(id, ":")
		if !ok {
			return TEI{}, syntaxErr("legacy hash id is not <alg>:<hex>", s)
		}
		if mapped, found := legacyHashAlgs[alg]; found {
			alg = mapped
		} else if !checksumTypes[alg] {
			return TEI{}, syntaxErr("legacy hash algorithm is not a checksum-type", s)
		}
		id = alg + ":" + hexValue
	default:
		return TEI{}, &SyntaxError{Rule: "legacy type " + truncate(typ) + " has no registry entry", Input: truncate(s), err: ErrLegacyTypeUnsupported}
	}
	return Parse(prefix + domain + "/" + typ + "/" + id)
}

// ParseCompat accepts both forms: a tei:// TEI first, then a legacy urn:tei:
// string through ParseLegacyURN, reporting legacy so a caller can warn.
func ParseCompat(s string) (t TEI, legacy bool, err error) {
	if strings.HasPrefix(s, legacyPrefix) {
		t, err = ParseLegacyURN(s)
		return t, true, err
	}
	t, err = Parse(s)
	return t, false, err
}
