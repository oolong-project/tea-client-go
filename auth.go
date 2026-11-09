package tea

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/oolong-project/tea-client-go/teaapi"
)

// TokenError is an OAuth 2.0 token-error-response (RFC 6749 section 5.2)
// from /token. Code is as received, sanitised and truncated to 64 bytes;
// Description is sanitised and truncated to 200 bytes.
type TokenError struct {
	Status      int
	Code        teaapi.TokenErrorResponseError
	Description string
}

func (e *TokenError) Error() string {
	s := fmt.Sprintf("requesting token: HTTP %d: %s", e.Status, e.Code)
	if e.Description != "" {
		s += fmt.Sprintf(": %q", e.Description)
	}
	return s
}

// RequestToken exchanges an API key for an access token with the
// client_credentials grant: one POST to <API base>/token, with the key id
// and secret each form-urlencoded before joining them for HTTP Basic (RFC
// 6749 section 2.3.1). The request follows no redirect: a 3xx answer is an
// *UnexpectedResponseError and no request reaches its Location, so the
// credentials reach exactly the URL built from this API's base. A configured
// bearer token is not sent on it. A 404 wraps ErrNotImplemented (the server
// has no authentication); a token-error-response is a *TokenError. The
// response is bounded by Limits.ErrorBodyBytes and the call by CallTimeout.
// Neither the key id nor the secret appears in any error or trace event.
func (a *API) RequestToken(ctx context.Context, keyID, secret string) (*teaapi.TokenResponse, error) {
	return a.requestToken(ctx, keyID, secret)
}

// requestToken is the one token request of the client (architecture 3.7).
func (a *API) requestToken(ctx context.Context, keyID, secret string) (*teaapi.TokenResponse, error) {
	const op = "requesting token"
	form := url.Values{"grant_type": {"client_credentials"}}.Encode()
	req, err := teaapi.NewRequestTokenRequestWithBody(a.base.String()+"/", "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", op, ErrInvalidArgument, err)
	}
	req = req.WithContext(withKind(ctx, kindToken))
	basic := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(keyID) + ":" + url.QueryEscape(secret)))
	req.Header.Set("Authorization", "Basic "+basic)
	req.Header.Set("Accept", "application/json")

	resp, err := a.d.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	body, err := readBody(resp)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	switch s := resp.StatusCode; {
	case s >= 300 && s <= 399:
		return nil, unexpected(op, s, "redirect from /token refused")
	case s == http.StatusNotFound:
		return nil, fmt.Errorf("%w: %w", ErrNotImplemented, mapError(op, resp, body))
	case s == http.StatusBadRequest || s == http.StatusUnauthorized:
		if te := parseTokenError(s, resp, body); te != nil {
			return nil, te
		}
		return nil, mapError(op, resp, body)
	case s < 200 || s > 299:
		return nil, mapError(op, resp, body)
	}
	tr, err := decodeBody[teaapi.TokenResponse](op, resp.StatusCode, body)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(string(tr.TokenType), string(teaapi.Bearer)) {
		return nil, unexpected(op, resp.StatusCode, "token_type is not Bearer")
	}
	if tr.AccessToken == "" {
		return nil, unexpected(op, resp.StatusCode, "empty access_token")
	}
	return tr, nil
}

// parseTokenError reads a token-error-response, or returns nil when the body
// is not one (a JSON object with a string "error" in the snake_case form).
func parseTokenError(status int, resp *http.Response, body []byte) *TokenError {
	if !isJSONContentType(resp.Header.Get("Content-Type")) {
		return nil
	}
	var v struct {
		Error       *string `json:"error"`
		Description *string `json:"error_description"`
	}
	if json.Unmarshal(body, &v) != nil || v.Error == nil {
		return nil
	}
	code := teaapi.TokenErrorResponseError(sanitize(*v.Error, maxCodeBytes))
	if !code.Valid() {
		return nil // a TEA error-response on /token, mapped as an APIError
	}
	te := &TokenError{Status: status, Code: code}
	if v.Description != nil {
		te.Description = sanitize(*v.Description, maxMessageBytes)
	}
	return te
}
