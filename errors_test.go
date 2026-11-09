package tea

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

// errorServer answers every request with status, content type and body.
func errorServer(t *testing.T, status *int, ctype, body *string, header http.Header) *API {
	t.Helper()
	srv := startHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range header {
			w.Header()[k] = v
		}
		if *ctype != "" {
			w.Header().Set("Content-Type", *ctype)
		}
		w.WriteHeader(*status)
		_, _ = w.Write([]byte(*body))
	}))
	return newTestAPI(t, srv.URL, "")
}

// Case 15: error mapping.
func TestErrorMapping(t *testing.T) {
	ctx := context.Background()
	status, ctype, body := 404, "application/json; charset=utf-8", ""
	hdr := http.Header{}
	a := errorServer(t, &status, &ctype, &body, hdr)

	for code, sentinel := range map[ErrorCode]error{
		ErrorCodeObjectUnknown:      ErrObjectUnknown,
		ErrorCodeNotImplemented:     ErrNotImplemented,
		ErrorCodeNoAcceptableFormat: ErrNoAcceptableFormat,
		ErrorCodeSignatureNotFound:  ErrSignatureNotFound,
		ErrorCodeInvalidRequest:     ErrInvalidRequest,
		ErrorCodeInvalidPageToken:   ErrInvalidPageToken,
	} {
		body = `{"error":"` + string(code) + `","message":"m","extra":{"x":[1,2]}}`
		_, err := a.GetProduct(ctx, productID)
		var ae *APIError
		if !errors.As(err, &ae) || !ae.TEA || ae.Code != code || ae.Message != "m" || ae.Status != 404 {
			t.Errorf("%s: %#v", code, err)
		}
		if !errors.Is(err, sentinel) {
			t.Errorf("%s: errors.Is(err, its sentinel) is false", code)
		}
		for _, other := range []error{ErrObjectUnknown, ErrNotImplemented, ErrNoAcceptableFormat, ErrSignatureNotFound, ErrInvalidRequest, ErrInvalidPageToken} {
			if other != sentinel && errors.Is(err, other) {
				t.Errorf("%s also matches %v", code, other)
			}
		}
	}

	body = `{"error":"FUTURE_CODE"}`
	_, err := a.GetProduct(ctx, productID)
	var ae *APIError
	if !errors.As(err, &ae) || !ae.TEA || ae.Code != ErrorCodeUnknown || ae.RawCode != "FUTURE_CODE" {
		t.Errorf("unknown code: %#v", err)
	}
	body = `{"error":"` + strings.Repeat("Z", 500) + `"}`
	if _, err := a.GetProduct(ctx, productID); !errors.As(err, &ae) || len(ae.RawCode) != 64 {
		t.Errorf("long unknown code kept %d bytes", len(ae.RawCode))
	}

	for name, c := range map[string][2]string{
		"Nest body":   {"application/json", `{"message":"Not Found","error":404}`},
		"no error":    {"application/json", `{"message":"Not Found"}`},
		"array":       {"application/json", `[{"error":"OBJECT_UNKNOWN"}]`},
		"html":        {"text/html", `{"error":"OBJECT_UNKNOWN"}`},
		"empty":       {"", ""},
		"bad json":    {"application/json", `{"error":`},
		"json-ish ct": {"application/problem+json", `{"error":"OBJECT_UNKNOWN"}`},
	} {
		ctype, body = c[0], c[1]
		_, err := a.GetProduct(ctx, productID)
		if !errors.As(err, &ae) || ae.TEA || ae.Status != 404 || errors.Is(err, ErrObjectUnknown) {
			t.Errorf("%s: %#v, want a non-TEA 404", name, err)
		}
	}

	status, ctype, body = 401, "", ""
	hdr.Set("WWW-Authenticate", `Bearer realm="tea", error="invalid_token", error_description="expired"`)
	_, err = a.GetProduct(ctx, productID)
	if !errors.As(err, &ae) || !errors.Is(err, ErrUnauthorized) || ae.Challenge == nil ||
		ae.Challenge.Scheme != "Bearer" || ae.Challenge.Error != "invalid_token" {
		t.Errorf("401 challenge: %#v (%#v)", err, ae.Challenge)
	}
	hdr.Del("WWW-Authenticate")

	status = 403
	if _, err := a.GetProduct(ctx, productID); !errors.Is(err, ErrForbidden) {
		t.Errorf("403: %v", err)
	}
	for _, s := range []int{500, 502, 503, 599} {
		status = s
		if _, err := a.GetProduct(ctx, productID); !errors.Is(err, ErrServer) {
			t.Errorf("%d: %v, want ErrServer", s, err)
		}
	}
	status = 404
	if _, err := a.GetProduct(ctx, productID); errors.Is(err, ErrServer) || errors.Is(err, ErrUnauthorized) {
		t.Errorf("404 matches a status sentinel: %v", err)
	}

	// A long message with control characters is cut to 200 bytes without them.
	status, ctype = 400, "application/json"
	body = `{"error":"INVALID_REQUEST","message":"` + strings.Repeat(`a\u0000b\u001b[31mc\n`, 1000) + `"}`
	_, err = a.GetProduct(ctx, productID)
	if !errors.As(err, &ae) || len(ae.Message) > 200 || len(ae.Message) < 150 || !utf8.ValidString(ae.Message) {
		t.Fatalf("message %q (%d bytes)", ae.Message, len(ae.Message))
	}
	for _, r := range ae.Message {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("message keeps control character %U", r)
		}
	}
	if len(err.Error()) > 400 {
		t.Errorf("error string is %d bytes", len(err.Error()))
	}
}

func TestParseChallenge(t *testing.T) {
	cases := map[string]Challenge{
		`Bearer`:                       {Scheme: "Bearer"},
		`Bearer realm="x"`:             {Scheme: "Bearer"},
		`Bearer error="invalid_token"`: {Scheme: "Bearer", Error: "invalid_token"},
		`Bearer realm="a, b", error=invalid_token`:     {Scheme: "Bearer", Error: "invalid_token"},
		`Basic realm="x", Bearer error="insufficient"`: {Scheme: "Basic"},
		`Bearer realm="q\"uote", error="e"`:            {Scheme: "Bearer", Error: "e"},
	}
	for in, want := range cases {
		got := parseChallenge([]string{in})
		if got == nil || *got != want {
			t.Errorf("parseChallenge(%s) = %#v, want %#v", in, got, want)
		}
	}
	if parseChallenge(nil) != nil {
		t.Error("no header gave a challenge")
	}
}
