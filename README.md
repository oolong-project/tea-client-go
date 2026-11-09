# tea-client-go

A Go client for the [Transparency Exchange API](https://github.com/CycloneDX/transparency-exchange-api)
(TEA) v1.0.0.

```go
import tea "github.com/oolong-project/tea-client-go"
```

Two packages do the work:

- `teaapi` is generated from the pinned OpenAPI document (`spec/openapi.yaml`) by
  oapi-codegen: every spec type (`teaapi.Product`, `teaapi.Collection`, ...) and a
  low-level client. It is never edited by hand.
- `tea` (the module root) is the API to use. It returns `teaapi` types and owns what
  the specification leaves to the client: the URL policy, limits, credentials and
  typed errors.
- `tei` parses TEIs (`tei://<domain>/<type>/<id>`) exactly as written.

Discovery, verified artifact downloads and the full-flow helper are being added in
follow-up changes.

## Install

```sh
go get github.com/oolong-project/tea-client-go
```

Go 1.26 or later.

## Example

From `example_test.go`:

```go
c, err := tea.New()
base, err := tea.ParseAPIBase("https://demo.rearmhq.com/tea", "1.0.0")
api, err := c.API(base)
release, err := api.GetProductRelease(ctx, uuid.MustParse("b9f115fb-6688-4a3f-a262-3acc04e1fc9e"))
fmt.Println(release.Version, release.LatestCollection.Version)

for p, err := range api.AllProducts(ctx, tea.ProductQuery{Page: tea.Page{PageSize: 50}}) {
	// ...
}
```

`api.Generated()` gives the generated client, on the same bounded, credential-aware
transport, for anything not wrapped.

## Every server is untrusted

- **URLs.** Every URL the client requests is `https`, or `http` under a base passed
  with `WithInsecureHTTPBase`. "Under" means the same scheme, host and port, and a
  path equal to the base's path or below it by whole segments
  (`http://h:8086/tea` covers `/tea/v1.0.0/...` but not `/teapot`). There is no
  global switch, and nothing a server sends adds an allowance. URLs with userinfo or
  dot segments are refused. Redirects follow the same rules, at most
  `Limits.Redirects` of them.
- **Credentials.** `WithBearerToken(root, token)` sends the token on requests under
  `root` and nowhere else; the client's transport decides the `Authorization` header
  on every hop, redirects included, and removes it off the root. `API.RequestToken`
  sends the API key over HTTP Basic to `<base>/token` only and follows no redirect.
  A transport you pass with `WithHTTPClient` sits below that transport and so sees
  `Authorization` headers: use `WithTrace` for debug output, not a header-dumping
  transport. Trace events carry no headers, query strings or credentials.
- **Limits.** Every response is bounded in bytes (`Limits.JSONBytes`,
  `ErrorBodyBytes`, `DownloadBytes`, ...) after transport decompression, and in time
  (`Limits.CallTimeout` per JSON call, `AttemptTimeout` per discovery attempt,
  `IdleTimeout` for downloads). The time bounds use the request context, so they hold
  with your own `http.Client` too; your context's deadline applies on top. A negative
  duration disables that bound. Iterators stop after `Limits.Pages` pages.
- **Errors.** `*APIError` (with `errors.Is` sentinels such as `ErrObjectUnknown`,
  `ErrNotImplemented`, `ErrUnauthorized`), `*UnexpectedResponseError`,
  `*URLPolicyError`, `ErrResponseTooLarge`, `ErrTimeout`. Errors never carry a
  credential or a response body beyond a sanitised, truncated server message.
- **Server-side use.** A TEI from an untrusted party makes the client fetch `https`
  URLs its documents choose, possibly internal addresses. A service resolving
  user-supplied TEIs should pass an `http.Client` whose dialer refuses private
  address ranges.

## Legacy `urn:tei:` identifiers

`tei.Parse` refuses the old `urn:tei:<type>:<domain>:<id>` form. `tei.ParseLegacyURN`
converts it explicitly (a migration aid; the result may not be the TEI the publisher
prints), and `tei.ParseCompat` accepts both and reports which one it saw.

## Regenerating `teaapi`

```sh
go generate ./...
```

runs oapi-codegen as pinned in `tools.mod` (a separate modfile, so the generator's
dependencies never reach your build). Never edit `teaapi/tea.gen.go`; a regenerate is
a commit of its own. To bump the generator:
`go get -modfile=tools.mod -tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@<version>`,
then regenerate. `spec/SPEC_PIN.md` says how `spec/` is pinned.

The generated code imports `github.com/oapi-codegen/runtime`, whose own `go.mod`
lists further modules; they enter your module graph as minimum versions (they are
not compiled into your binary unless you import them).

## Tests

```sh
gofmt -l .                # must print nothing
go vet ./...
go test ./...             # offline unit tests
go test -race ./...
```

Integration tests run against an oolong server
([oolong-project/oolong](https://github.com/oolong-project/oolong)):

```sh
# a server you already run, e.g. oolong/docker-compose.tea-interop.yml
OOLONG_BASE_URL=http://127.0.0.1:3005 go test -tags integration -run Integration ./...

# or let the tests start one (Node 24; npm ci && npm run build in oolong-server first)
OOLONG_SERVER_DIR=/path/to/oolong/oolong/oolong-server go test -tags integration -run Integration ./...
```

Without either variable the integration tests skip (set `TEA_INTEGRATION_REQUIRED=1`
to make that a failure).

## Versioning

This module is tagged `v0.x.y` until the ReARM CLI has switched to it and the API has
settled. Every exported identifier, `teaapi`'s included, is public API.

- In `v0`, a change that alters or removes an exported identifier (a spec re-pin or a
  generator bump that changes `teaapi`, or a change to `tea`) is a new minor version
  (`v0.N+1.0`), and "Changes" below names what broke. A regenerate that changes no
  exported identifier, and any fix that keeps the API, is a patch.
- From `v1.0.0`, such a breaking change needs a new major version (module path
  `/v2`), so a re-pin to a TEA version with an incompatible schema is a major
  release; an additive regenerate is a minor one.

The default `User-Agent` is `tea-client-go/<module version>` (`devel` when the
version is unknown); `WithUserAgent` replaces it.

### Changes

None yet.

## Licence

This module is MIT-licensed (`LICENSE`). The files in `spec/` are copies of the TEA
specification and are licensed under the Apache License 2.0 (`spec/LICENSE`).
Package `teaapi` is generated from `spec/openapi.yaml` and includes text from it
(its doc comments), so it includes Apache-2.0 material; see `teaapi/doc.go`.
