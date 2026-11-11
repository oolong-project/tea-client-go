package tea

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"
)

// ErrorCode is the error code of a TEA error-response body. The six codes of
// the specification's unknown-error-type are known; any other code received
// maps to ErrorCodeUnknown and is kept, truncated, in APIError.RawCode.
type ErrorCode string

// Error codes of the TEA specification (unknown-error-type).
const (
	ErrorCodeUnknown            ErrorCode = ""
	ErrorCodeObjectUnknown      ErrorCode = "OBJECT_UNKNOWN"
	ErrorCodeNotImplemented     ErrorCode = "NOT_IMPLEMENTED"
	ErrorCodeNoAcceptableFormat ErrorCode = "NO_ACCEPTABLE_FORMAT"
	ErrorCodeSignatureNotFound  ErrorCode = "SIGNATURE_NOT_FOUND"
	ErrorCodeInvalidRequest     ErrorCode = "INVALID_REQUEST"
	ErrorCodeInvalidPageToken   ErrorCode = "INVALID_PAGE_TOKEN"
)

func parseErrorCode(s string) ErrorCode {
	switch c := ErrorCode(s); c {
	case ErrorCodeObjectUnknown, ErrorCodeNotImplemented, ErrorCodeNoAcceptableFormat,
		ErrorCodeSignatureNotFound, ErrorCodeInvalidRequest, ErrorCodeInvalidPageToken:
		return c
	}
	return ErrorCodeUnknown
}

// Sentinels an *APIError matches with errors.Is.
var (
	ErrObjectUnknown      = errors.New("tea: object unknown")
	ErrNotImplemented     = errors.New("tea: not implemented")
	ErrSignatureNotFound  = errors.New("tea: signature not found")
	ErrNoAcceptableFormat = errors.New("tea: no acceptable format")
	ErrInvalidRequest     = errors.New("tea: invalid request")
	ErrInvalidPageToken   = errors.New("tea: invalid page token")
	ErrUnauthorized       = errors.New("tea: unauthorized (HTTP 401)")
	ErrForbidden          = errors.New("tea: forbidden (HTTP 403)")
	ErrServer             = errors.New("tea: server error (HTTP 5xx)")
)

// Sentinels for failures the client itself detects.
var (
	// ErrResponseTooLarge: a response body was larger than the limit for its
	// kind of call (Limits), by Content-Length or while reading.
	ErrResponseTooLarge = errors.New("tea: response body exceeds the limit")
	// ErrInvalidArgument: a caller-supplied argument was refused before any request.
	ErrInvalidArgument = errors.New("tea: invalid argument")
	// ErrInvalidOption: New was given an option value it cannot use.
	ErrInvalidOption = errors.New("tea: invalid option")
	// ErrPageLimit: an iterator stopped after Limits.Pages pages.
	ErrPageLimit = errors.New("tea: page limit reached")
	// ErrTooManyComponents: a release has more component refs than Limits.FlowComponents.
	ErrTooManyComponents = errors.New("tea: too many components")
	// ErrTooManyResults: a discovery answer, or the results given to
	// Candidates, exceeded Limits.DiscoveryResults.
	ErrTooManyResults = errors.New("tea: too many discovery results")
	// ErrTimeout: one of the library's own time bounds (Limits.AttemptTimeout,
	// CallTimeout or IdleTimeout) fired while the caller's context was live.
	ErrTimeout = errors.New("tea: time bound exceeded")
	// ErrInsecureURL: a URL was refused by the URL policy (https only, plus
	// http under a WithInsecureHTTPBase allowance; no userinfo, no dot segments).
	ErrInsecureURL = errors.New("tea: URL refused by policy")
	// ErrRedirectLimit: more redirects than Limits.Redirects.
	ErrRedirectLimit = errors.New("tea: too many redirects")
)

const (
	maxMessageBytes = 200
	maxCodeBytes    = 64
)

// Challenge is a parsed WWW-Authenticate challenge of a 401 response.
type Challenge struct {
	Scheme string // as received, e.g. "Bearer"
	Error  string // the error parameter, e.g. "invalid_token"; "" when absent
}

// APIError is a non-2xx answer from a TEA server.
type APIError struct {
	Operation string
	Status    int
	// TEA is true when the body was a TEA error-response: Content-Type
	// application/json and a JSON object with a string "error" property.
	TEA bool
	// Code is the error code when TEA, ErrorCodeUnknown for an unknown code.
	Code ErrorCode
	// RawCode is the code as received when it is unknown, sanitised and
	// truncated to 64 bytes.
	RawCode string
	// Message is the server's message, control characters removed and
	// truncated to 200 bytes. No other part of a body reaches an error.
	Message string
	// Challenge is the parsed WWW-Authenticate header of a 401, if any.
	Challenge *Challenge
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: HTTP %d", e.Operation, e.Status)
	switch {
	case e.TEA && e.Code != ErrorCodeUnknown:
		b.WriteString(" " + string(e.Code))
	case e.TEA:
		fmt.Fprintf(&b, " unknown error code %q", e.RawCode)
	}
	if e.Message != "" {
		fmt.Fprintf(&b, ": %q", e.Message)
	}
	return b.String()
}

// Is matches the sentinels: the six code sentinels by TEA code,
// ErrUnauthorized by status 401, ErrForbidden by 403 and ErrServer by 5xx.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrObjectUnknown:
		return e.TEA && e.Code == ErrorCodeObjectUnknown
	case ErrNotImplemented:
		return e.TEA && e.Code == ErrorCodeNotImplemented
	case ErrSignatureNotFound:
		return e.TEA && e.Code == ErrorCodeSignatureNotFound
	case ErrNoAcceptableFormat:
		return e.TEA && e.Code == ErrorCodeNoAcceptableFormat
	case ErrInvalidRequest:
		return e.TEA && e.Code == ErrorCodeInvalidRequest
	case ErrInvalidPageToken:
		return e.TEA && e.Code == ErrorCodeInvalidPageToken
	case ErrUnauthorized:
		return e.Status == http.StatusUnauthorized
	case ErrForbidden:
		return e.Status == http.StatusForbidden
	case ErrServer:
		return e.Status >= 500 && e.Status <= 599
	}
	return false
}

// UnexpectedResponseError is a response the client cannot use: a 2xx body
// that is missing or does not decode to the declared type, a response that
// breaks a rule callers rely on (hasNext without nextPageToken), or a status
// the operation does not expect.
type UnexpectedResponseError struct {
	Operation string
	Status    int
	Reason    string
}

func (e *UnexpectedResponseError) Error() string {
	return fmt.Sprintf("%s: unexpected response (HTTP %d): %s", e.Operation, e.Status, e.Reason)
}

func unexpected(op string, status int, reason string) error {
	return &UnexpectedResponseError{Operation: op, Status: status, Reason: sanitize(reason, maxMessageBytes)}
}

// URLPolicyError is a URL the client refused to request or follow. URL is
// redacted: scheme, host, port and path only, never userinfo or query.
type URLPolicyError struct {
	URL    string
	Reason string
	err    error // ErrInsecureURL or ErrRedirectLimit
}

func (e *URLPolicyError) Error() string {
	return fmt.Sprintf("tea: refused %s: %s", e.URL, e.Reason)
}

// Unwrap returns ErrInsecureURL or ErrRedirectLimit.
func (e *URLPolicyError) Unwrap() error { return e.err }

// sanitize drops control characters and invalid UTF-8 and truncates to max
// bytes on a rune boundary.
func sanitize(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isJSONContentType reports whether ct is application/json, parameters allowed.
func isJSONContentType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && mt == "application/json"
}

// mapError turns a non-2xx response into an *APIError. body is the start of
// the body, already cut at Limits.ErrorBodyBytes.
func mapError(op string, resp *http.Response, body []byte) *APIError {
	e := &APIError{Operation: op, Status: resp.StatusCode}
	if isJSONContentType(resp.Header.Get("Content-Type")) {
		var obj map[string]json.RawMessage
		if json.Unmarshal(body, &obj) == nil && obj != nil {
			var code string
			if raw, ok := obj["error"]; ok && json.Unmarshal(raw, &code) == nil {
				e.TEA = true
				e.Code = parseErrorCode(code)
				if e.Code == ErrorCodeUnknown {
					e.RawCode = sanitize(code, maxCodeBytes)
				}
				var msg string
				if raw, ok := obj["message"]; ok && json.Unmarshal(raw, &msg) == nil {
					e.Message = sanitize(msg, maxMessageBytes)
				}
			}
		}
	}
	if resp.StatusCode == http.StatusUnauthorized {
		e.Challenge = parseChallenge(resp.Header.Values("WWW-Authenticate"))
	}
	return e
}

// parseChallenge reads the first challenge of WWW-Authenticate: its scheme
// and its error parameter (RFC 9110 section 11.6.1, RFC 6750 section 3).
func parseChallenge(values []string) *Challenge {
	if len(values) == 0 {
		return nil
	}
	s := strings.TrimSpace(values[0])
	scheme, rest, _ := strings.Cut(s, " ")
	if scheme == "" {
		return nil
	}
	ch := &Challenge{Scheme: sanitize(scheme, maxCodeBytes)}
	for rest = strings.TrimSpace(rest); rest != ""; {
		key, after, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		key = strings.TrimSpace(key)
		if strings.ContainsAny(key, " ,") {
			break // the next challenge starts here
		}
		after = strings.TrimLeft(after, " ")
		var val string
		if strings.HasPrefix(after, `"`) {
			end := 1
			var vb strings.Builder
			for end < len(after) && after[end] != '"' {
				if after[end] == '\\' && end+1 < len(after) {
					end++
				}
				vb.WriteByte(after[end])
				end++
			}
			val = vb.String()
			if end < len(after) {
				end++
			}
			after = after[end:]
		} else {
			v, a, _ := strings.Cut(after, ",")
			val, after = strings.TrimSpace(v), ","+a
		}
		if strings.EqualFold(key, "error") {
			ch.Error = sanitize(val, maxCodeBytes)
		}
		rest = strings.TrimLeft(strings.TrimSpace(after), ",")
		rest = strings.TrimSpace(rest)
	}
	return ch
}
