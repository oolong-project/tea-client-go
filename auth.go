package tea

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

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
	return a.d.requestToken(ctx, keyID, secret)
}

// requestToken is the one token request of the client (architecture 3.7),
// used by RequestToken and by the WithAPIKey recovery: POST <API base>/token.
func (d *doer) requestToken(ctx context.Context, keyID, secret string) (*teaapi.TokenResponse, error) {
	const op = "requesting token"
	form := url.Values{"grant_type": {"client_credentials"}}.Encode()
	req, err := teaapi.NewRequestTokenRequestWithBody(d.apiBase.String()+"/", "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", op, ErrInvalidArgument, err)
	}
	req = req.WithContext(withKind(ctx, kindToken))
	basic := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(keyID) + ":" + url.QueryEscape(secret)))
	req.Header.Set("Authorization", "Basic "+basic)
	req.Header.Set("Accept", "application/json")

	resp, err := d.Do(req)
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

// tokenLeeway is taken off a token's expires_in before the cached token is
// considered expired (architecture 3.7).
const tokenLeeway = 30 * time.Second

// apiKey is a WithAPIKey credential and its cached access token.
type apiKey struct {
	id, secret string

	mu      sync.Mutex
	token   string
	expires time.Time // zero: no expiry known
}

// cached returns the cached token, or "" when there is none or it expired.
func (k *apiKey) cached(now time.Time) string {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.token != "" && !k.expires.IsZero() && !now.Before(k.expires) {
		k.token, k.expires = "", time.Time{}
	}
	return k.token
}

// store caches a token. expiresIn (seconds) minus tokenLeeway bounds its
// use; a token whose expires_in leaves nothing after the leeway is not
// cached (the retry that obtained it still uses it).
func (k *apiKey) store(token string, expiresIn *int, now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.token, k.expires = token, time.Time{}
	if expiresIn != nil {
		life := time.Duration(*expiresIn)*time.Second - tokenLeeway
		if life <= 0 {
			k.token = ""
			return
		}
		k.expires = now.Add(life)
	}
}

// drop forgets the cached token if it is the one a refused request carried.
func (k *apiKey) drop(sent string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if sent != "" && k.token == sent {
		k.token, k.expires = "", time.Time{}
	}
}

// bearer is the token the auth transport sends under the credential's root:
// the configured bearer token, or for an API key the token of a recovery
// retry (carried on the request context) or else the cached one.
func (cr *credential) bearer(ctx context.Context, now time.Time) string {
	if cr.key == nil {
		return cr.token
	}
	if o, ok := ctx.Value(tokenOverrideKey{}).(tokenOverride); ok && o.key == cr.key {
		return o.token
	}
	return cr.key.cached(now)
}
