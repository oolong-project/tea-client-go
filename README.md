# tea-client-go

A Go client for the [Transparency Exchange API](https://github.com/CycloneDX/transparency-exchange-api)
(TEA) v1.0.0: typed calls generated from the pinned OpenAPI document, TEI parsing,
discovery as the specification defines it, verified artifact downloads and a
full-flow helper.

```go
import tea "github.com/oolong-project/tea-client-go"
```

Three packages:

- `teaapi` is generated from the pinned OpenAPI document (`spec/openapi.yaml`) by
  oapi-codegen: every spec type (`teaapi.Product`, `teaapi.Collection`, ...) and a
  low-level client. It is never edited by hand.
- `tea` (the module root) is the API to use. It returns `teaapi` types and owns what
  the specification leaves to the client: the URL policy, limits, credentials,
  typed errors, discovery, checksum verification and the flow helper.
- `tei` parses TEIs (`tei://<domain>/<type>/<id>`) exactly as written.

## Install

```sh
go get github.com/oolong-project/tea-client-go
```

Go 1.26 or later.

## Example

From `example_test.go` (`ExampleClient_FullFlow`):

```go
c, err := tea.New()
t, err := tei.Parse("tei://demo.rearmhq.com/uuid/b9f115fb-6688-4a3f-a262-3acc04e1fc9e")
res, err := c.FullFlow(ctx, t, tea.FlowOptions{})
fmt.Println(*res.Release.ProductName, res.Release.Version)
```

`FullFlow` discovers the TEI, reads the product release at the server discovery
names, its lifecycle (CLE) and each component (a pinned component release, or for
an unpinned component its newest release by `createdDate`). A component that fails
carries its error in `FlowComponent.Err` and the others are still read. When
discovery returns several results, `FullFlow` returns `*tea.AmbiguousError` unless
`FlowOptions.Select` chooses among the `Candidates` (each result with its server
and product release); the library never prompts. More component refs than
`Limits.FlowComponents` is `ErrTooManyComponents`, never a silent truncation.

Typed calls on a known API base:

```go
base, err := tea.ParseAPIBase("https://demo.rearmhq.com/tea", "1.0.0")
api, err := c.API(base)
release, err := api.GetProductRelease(ctx, uuid.MustParse("b9f115fb-6688-4a3f-a262-3acc04e1fc9e"))
for p, err := range api.AllProducts(ctx, tea.ProductQuery{Page: tea.Page{PageSize: 50}}) {
	// ...
}
```

`api.Generated()` gives the generated client, on the same bounded, credential-aware
transport, for anything not wrapped (it reads downloads into memory; use the
download helpers below to stream).

### Discovery

```go
results, err := c.Discover(ctx, t)      // every result, in the server's order
base, err := c.SelectServer(results[0]) // a servers[] root, not the /discovery base
```

It fetches `https://<domain>/.well-known/tea` (or the base given with
`WithWellKnownLocation`), tries its endpoints by the greatest supported version and
then priority, and fails over on connection and TLS errors, timeouts, `5xx`, a `404`
that is not a TEA error and invalid answers, within `WithDiscoveryAttempts` attempts
(every request counts, default 4) with backoff. A TEA `404` stops with
`*NotResolvedError`; `400`, `401` and `403` stop with `*APIError` (a `401` under an
API-key root is first answered with a token, once); an exhausted bound
gives `*DiscoveryError` listing each failed attempt. An answer with more than
`Limits.DiscoveryResults` results is refused whole. `DiscoverPURL` asks one API base
by PURL.

### Verified downloads

```go
ref := tea.ArtifactRef{UUID: art.Uuid, Version: art.Version}
res, err := api.DownloadArtifactToFile(ctx, ref, art.Formats[0], "sbom.json", tea.DownloadOptions{})
```

- The bytes come from the format's external `url` when it has one (no credential is
  sent there, on any hop), else from the versioned endpoint
  `/artifact/{uuid}/{version}/download?mediaType=...`, so they belong to the revision
  whose checksums are checked. `DownloadLatestArtifact` reads the latest revision's
  metadata and downloads that version the same way.
- They are hashed while streaming. Every listed checksum of a supported algorithm
  must match (`*ChecksumError` otherwise), and at least one must be strong.
  Supported: SHA-256/384/512, SHA3-256/384/512, BLAKE2b-256/384/512, and SHA-1, which
  alone is refused unless `DownloadOptions.AllowSHA1Only` is set. BLAKE3 is not
  supported (neither the standard library nor `golang.org/x/crypto` implements it):
  a format with only BLAKE3, only unknown algorithms or no checksum fails closed with
  `ErrNoUsableChecksum`, before any request. An `algValue` that is not lowercase hex
  of its algorithm's length is refused. `Repr-Digest` is not used.
- Checksums cover the bytes before HTTP content coding: the transport's own gzip is
  decoded, and any other remaining `Content-Encoding` is
  `ErrUnsupportedContentEncoding`. `Content-Disposition` is ignored.
- `DownloadArtifact` may have written bytes to its writer when it fails: discard
  them. `DownloadArtifactToFile` writes a temporary file (mode 0600) next to the
  target and renames it into place only after verification; on failure the target
  is untouched and nothing is left behind.
- `DownloadSignature` fetches a format's detached signature (`signatureUrl`, or the
  signature endpoint). Signatures are not verified: the specification does not
  define the technology. A compromised TEA server can publish checksums that match
  forged bytes; the checksums protect against tampered mirrors, redirects and
  transport errors, not against the server itself.
- `VerifyChecksums` applies the same rules to any reader.

## Options

| Option | |
| --- | --- |
| `WithHTTPClient(hc)` | send through a copy of `hc` (its `CheckRedirect` is replaced, its transport wrapped) |
| `WithUserAgent(ua)` | replace the default `tea-client-go/<version>` |
| `WithInsecureHTTPBase(url)` | allow plain `http` under `url` (repeatable; below) |
| `WithWellKnownLocation(domain, url)` | fetch `<url>/.well-known/tea` for TEIs of `domain` |
| `WithBearerToken(root, token)` | send a bearer token under `root` |
| `WithAPIKey(root, id, secret)` | obtain a token with an API key when a server under `root` asks for one |
| `WithPreemptiveAPIKey(root, id, secret)` | obtain a token with an API key before the first request under `root`, and present it on every request there |
| `WithLimits(l)` | byte, count and time limits (below) |
| `WithDiscoveryAttempts(n, backoff)` | discovery attempt bound and first backoff |
| `WithTrace(f)` | observe each request, response, failed discovery attempt and backoff (for debug output) |

### Limits and time bounds

Zero means the default. A negative duration disables that bound and leaves only your
context; byte and count limits must not be negative.

| `Limits` field | Default | Applies to |
| --- | --- | --- |
| `WellKnownBytes` | 64 KiB | `.well-known/tea` |
| `DiscoveryBytes` | 1 MiB | `/discovery` |
| `DiscoveryResults` | 32 | results in one `/discovery` answer, and results given to `Candidates` |
| `JSONBytes` | 16 MiB | every other JSON response |
| `ErrorBodyBytes` | 64 KiB | non-2xx bodies (read to classify, then discarded) and `/token` |
| `DownloadBytes` | 512 MiB | artifact content (`DownloadOptions.MaxBytes` overrides it per call) |
| `SignatureBytes` | 16 MiB | signature content (`DownloadOptions.MaxBytes` overrides it per call) |
| `Redirects` | 5 | per request |
| `Pages` | 1000 | per iterator |
| `FlowComponents` | 1000 | component refs walked by the flow helper |
| `AttemptTimeout` | 15 s | each discovery attempt, headers and body |
| `CallTimeout` | 30 s | each other non-download request, headers and body |
| `IdleTimeout` | 30 s | downloads and signatures: the longest wait for the headers or the next body byte |

Byte limits apply after the transport's decompression, and a `Content-Length` over
the limit is refused before reading. The time bounds use the request context, so
they hold with your own `http.Client` too; your context's deadline applies on top,
and when it ends first you get its error, not `ErrTimeout`. A download that keeps
sending is never cut off by `IdleTimeout`; there is no whole-download limit beyond
your context.

## Every server is untrusted

- **URLs.** Every URL the client requests is `https`, or `http` under a base passed
  with `WithInsecureHTTPBase`. "Under" means the same scheme, host and port, and a
  path equal to the base's path or below it by whole segments
  (`http://h:8086/tea` covers `/tea/v1.0.0/...` but not `/teapot`; the origin
  `http://h:8086` covers every path on it). There is no global switch, and nothing a
  server sends adds or widens an allowance: a base learned from a well-known
  document, a `servers[]` entry, a redirect or an artifact `url` is usable over
  `http` only when it is under an allowance you configured. URLs with userinfo or dot
  segments are refused. Redirects follow the same rules, at most `Limits.Redirects`
  of them. TLS verification is your `http.Client`'s; the library has no option to
  turn it off.
- **Credentials.** A credential is bound to one API root and the client's transport
  decides the `Authorization` header on every hop, redirects included: it sends the
  credential under the root and removes any `Authorization` header elsewhere. So a
  redirect to another host, port or subdomain, an external artifact URL, a
  well-known location or a `servers[]` root on another host never sees it.
  - `WithBearerToken(root, token)` sends the token under `root`.
  - `WithAPIKey(root, id, secret)` requests no token up front. When a `GET` under
    `root` (an API call, or a `/discovery` request of `Discover` or `DiscoverPURL`) is
    answered `401` with a `Bearer` challenge from under `root`, the client posts the
    key, with the `client_credentials` grant and HTTP Basic credentials, to
    `<root>/v<version>/token` (the version of the API that made the request, whose
    base must be under `root`), caches the token (until its `expires_in` minus 30 s)
    and retries the request once. A `401` on a request that carried the cached token
    drops it and gets one fresh token. There is never more than one recovery per
    request, and none on `403`. Concurrent requests share one token request.
  - `WithPreemptiveAPIKey(root, id, secret)` is for a server that answers an
    anonymous caller with less instead of a `401` (a filtered listing, only the public
    results of a discovery). Before an API sends a request under `root` (a typed or
    `Generated()` call, a download from the server, a `/discovery` request), the
    client makes sure it holds a token, obtaining one from `<root>/v<version>/token`
    when it holds none, and sends it on that request; when none can be obtained, the
    request is not sent and the error matches `ErrNoAccessToken`. A `.well-known/tea`
    request and a redirect hop never cause a token request (they carry a token only
    once one is held); an external artifact or signature URL never carries one. Per
    call there is at most one token request and one retry: a `401` on a cached token
    gets one fresh token and one retry, a `401` on a token obtained for that request
    is returned at once, and a refused token is dropped. When the well-known document
    lists an endpoint outside `root` and that endpoint answers first, the results are
    its anonymous answer: `DiscoveryResult.DiscoveredAt` says who answered (or use
    `DiscoverPURL` or the API at your root). A token is requested once per token
    lifetime per `Client`: reuse the `Client` across calls. This departs from the
    specification, whose `/token` description says clients do not probe it to find
    out whether authentication is required; configuring a key for a root is the
    caller saying it is, and against a server without `/token` every request under
    the root fails instead of going on anonymously. `New` refuses the option on a root
    that is also the root of another credential.
  - `API.RequestToken` exchanges a key for a token explicitly.
  - Token requests follow no redirect: a `3xx` from `/token` is an error and the key
    reaches exactly one URL.
  - A transport you pass with `WithHTTPClient` sits below the client's transport and
    so sees `Authorization` headers: use `WithTrace` for debug output, not a
    header-dumping transport. Trace events carry scheme, host, port and path only:
    no headers, query strings (presigned URLs carry secrets there) or credentials.
- **Limits.** Every response is bounded in bytes and in time (above).
- **Errors.** `*APIError` (with `errors.Is` sentinels such as `ErrObjectUnknown`,
  `ErrNotImplemented`, `ErrSignatureNotFound`, `ErrUnauthorized`),
  `*UnexpectedResponseError`, `*URLPolicyError`, `*NotResolvedError`,
  `*DiscoveryError`, `*TokenError`, `*ChecksumError`, `*AmbiguousError`, and the
  sentinels `ErrResponseTooLarge`, `ErrTimeout`, `ErrNoUsableChecksum`,
  `ErrTooManyResults`, `ErrTooManyComponents`, `ErrNoAccessToken` (an API key could
  not obtain the token a request needed; the cause is wrapped). Errors never carry a
  credential or a response body beyond a sanitised, truncated server message and
  error code. The refusal of an option or `ParseAPIBase` argument never repeats the
  userinfo, query or fragment of a URL, nor any part of a value that does not parse
  as an http or https URL or that holds `@`.
- **Server-side use.** A TEI from an untrusted party makes the client fetch `https`
  URLs its documents choose, possibly internal addresses. A service resolving
  user-supplied TEIs should pass an `http.Client` whose dialer refuses private
  address ranges.

## Legacy `urn:tei:` identifiers

`tei.Parse` refuses the old `urn:tei:<type>:<domain>:<id>` form. `tei.ParseLegacyURN`
converts it explicitly (a migration aid; the result may not be the TEI the publisher
prints, in which case discovery answers `OBJECT_UNKNOWN`), and `tei.ParseCompat`
accepts both and reports which one it saw. The legacy types `swid` and `gs1` have no
TEA v1.0.0 registry entry and are refused with `tei.ErrLegacyTypeUnsupported`.

## For the ReARM CLI

What the TEA commands of the ReARM CLI (`cmd/tea.go`) do today, and what replaces it
here:

| CLI today | This library |
| --- | --- |
| `urn:tei:` input | `tei.ParseCompat`, with a deprecation warning when `legacy` |
| `--usehttp --useport P` | with `O = "http://<domain>:P"`: `WithWellKnownLocation(domain, O)` and `WithInsecureHTTPBase(O)` |
| `--useport P` without `--usehttp` | `WithWellKnownLocation(domain, "https://<domain>:P")`, no allowance |
| `resolveTEI` / `discovery` | `Client.Discover` |
| prompt on stdin when discovery has several results | `*AmbiguousError` and `Client.Candidates`; the prompt stays in the CLI |
| `full_tea_flow` | `Client.FullFlow`; the printing stays in the CLI |
| `getCle` / `printCLE` | the `Get...CLE` calls (typed `teaapi.Cle`) |
| `debug=true` prints of the URLs it requests | `WithTrace`: print each `TraceRequest`'s `URL` (and the TEI itself) |
| `http.Client{Timeout: 30s}` per call | the defaults of `CallTimeout` (30 s), `AttemptTimeout` and `IdleTimeout` |

With `--usehttp`, the allowance for the origin `O` also covers any endpoint `url` and
`servers[].rootUrl` on that origin, whatever their path, so a local ReARM that serves
`http://localhost:8086/.well-known/tea` listing `http://localhost:8086/tea` works as
today. Two things are stricter than today: an `http` URL on any other host or port is
refused (a second plain-http origin needs one more `WithInsecureHTTPBase`), and
without `--usehttp` nothing is fetched over `http`. The flow reads an unpinned
component's newest release (sorted by `createdDate` descending), where the CLI took
the first of the default ascending listing, the oldest.

The CLI at tea-client-go `v0.0.0` exchanges its API key itself (`API.RequestToken`,
then `WithBearerToken`), because `v0.0.0` did not recover a `401` on `/discovery`
and could not present a token unasked. From `v0.0.1`,
`WithPreemptiveAPIKey(root, id, secret)` with the same root does both inside the
library, refreshes the token at expiry, and marks every failure of the token request
with `ErrNoAccessToken` (with `*TokenError` or `ErrNotImplemented` under it, as
`RequestToken` returns them). Two differences to know: the token is requested when
the first request under the root is about to be sent, not at start, so a TEI that
resolves elsewhere causes no token request; and the token endpoint is at the root
itself (`<root>/v<version>/token`).

## Regenerating `teaapi`

```sh
go generate ./...
```

runs oapi-codegen as pinned in `tools.mod` (a separate modfile, so the generator's
dependencies never reach your build). Never edit `teaapi/tea.gen.go`; a regenerate is
a commit of its own. To bump the generator:
`go get -modfile=tools.mod -tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@<version>`,
then regenerate. `spec/SPEC_PIN.md` says how `spec/` is pinned.

Runtime dependencies: `github.com/oapi-codegen/runtime` (imported by the generated
code), `github.com/google/uuid`, `golang.org/x/crypto` (BLAKE2b) and
`golang.org/x/mod` (SemVer). The `runtime` module's own `go.mod` lists further
modules; they enter your module graph as minimum versions (they are not compiled
into your binary unless you import them).

## Tests

```sh
gofmt -l .                # must print nothing
go vet ./...
go test ./...             # offline unit tests
go test -race ./...
go test -run '^$' -fuzz '^FuzzParse$' -fuzztime 30s ./tei   # and the other fuzz targets
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
to make that a failure). They create their data in temporary directories and send
nothing off the machine (the one external artifact URL of the fixtures is answered
in-process).

A live test runs against the public demo (https://demo.rearmhq.com) only when asked
for, never in the default run:

```sh
TEA_LIVE=1 go test -tags live -run Live ./...
```

CI (`.github/workflows/test-submit-release.yaml`) runs gofmt, `go vet`, `go test`,
the generated-code and ASCII checks and the integration tests on every push; it does
not run `-race`, so run that before sending a change.

## Versioning

This module is tagged `v0.x.y` until the ReARM CLI has switched to it and the API has
settled. Every exported identifier, `teaapi`'s included, is public API.

- In `v0`, a change that alters or removes an exported identifier (a spec re-pin or a
  generator bump that changes `teaapi`, or a change to `tea`) is a new minor version
  (`v0.N+1.0`), and "Changes" below names what broke. A regenerate that changes no
  exported identifier, and any fix that keeps the API, is a patch, also when it adds
  an exported identifier.
- From `v1.0.0`, such a breaking change needs a new major version (module path
  `/v2`), so a re-pin to a TEA version with an incompatible schema is a major
  release; an additive regenerate is a minor one.

The default `User-Agent` is `tea-client-go/<module version>` (`devel` when the
version is unknown); `WithUserAgent` replaces it.

### Changes

`v0.0.1`:

- A `401` with a `Bearer` challenge on `/discovery` under a `WithAPIKey` root is
  recovered like one on an API call (one token request, one retry).
- `WithPreemptiveAPIKey`: obtain the token before the first request under the root
  and present it on every request there.
- `ErrNoAccessToken` marks a failure to obtain an API key's token; such a failure
  ends discovery at once, and the flow no longer reads it as "no CLE" (a `404` from
  `/token` wraps `ErrNotImplemented`).
- The automatic token request goes to `<root>/v<version>/token` of the key's root.
  This differs from `v0.0.0` only for an API whose root is strictly below the key's
  root: `v0.0.0` posted the key to that API's own `/token`.
- Concurrent requests share one token request (`v0.0.0` made one per request
  answered `401`).
- Errors no longer repeat the userinfo, query or fragment of a refused URL argument,
  nor a redirect `Location` that does not parse (now a `*URLPolicyError`).

Nothing exported changed or was removed.

## Licence

This module is MIT-licensed (`LICENSE`). The files in `spec/` are copies of the TEA
specification and are licensed under the Apache License 2.0 (`spec/LICENSE`).
Package `teaapi` is generated from `spec/openapi.yaml` and includes text from it
(its doc comments), so it includes Apache-2.0 material; see `teaapi/doc.go`.
