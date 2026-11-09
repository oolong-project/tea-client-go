// Package tea is a client for the Transparency Exchange API (TEA) v1.0.0.
//
//	import tea "github.com/oolong-project/tea-client-go"
//
// The client is built in two layers. Package teaapi is generated from the
// pinned OpenAPI document (spec/openapi.yaml) and holds every spec type and a
// low-level client. This package is the API people use: it returns teaapi
// types and owns what the specification leaves to the client.
//
//   - URL policy: every URL is https, or http under a base the caller
//     configured with WithInsecureHTTPBase. Userinfo and dot segments are
//     refused. Nothing a server sends widens the policy.
//   - Credentials are bound to one API root (WithBearerToken) and decided by
//     the client's transport on every hop, redirects included; they never
//     leave their root.
//   - Every response is bounded in bytes and in time (Limits), whatever
//     http.Client the caller passes, and Generated() calls are bounded too.
//   - Errors are typed (*APIError, *UnexpectedResponseError,
//     *URLPolicyError) and match sentinels with errors.Is. No error carries a
//     credential or a response body beyond a sanitised server message.
//
// Every server is treated as untrusted. Every call that does I/O takes a
// context.Context, and the library's own time bounds apply inside it.
package tea
