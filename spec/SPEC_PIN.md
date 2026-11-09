# Pinned TEA specification

The files in this directory are byte copies of upstream files. They are never
edited. Moving to another upstream commit is a re-pin: copy the new files,
update this file and the blob ids checked by `spec_test.go`, then regenerate
`teaapi` (`go generate ./...`) in a commit of its own.

- Repository: https://github.com/CycloneDX/transparency-exchange-api
- Commit: `962a0228af1bfcc1232ac3f79239317ff33fdb04`
- Retrieved: 2026-11-09 (from raw.githubusercontent.com at that commit)

| File here | Upstream path | Git blob id |
| --- | --- | --- |
| `openapi.yaml` | `spec/openapi.yaml` | `c96baa3e102c195895643fab81ae468ee54b8182` |
| `tea-well-known.schema.json` | `discovery/tea-well-known.schema.json` | `b0804f1ae79c8ec72adea6d5c12e8f75f6036729` |
| `LICENSE` | `LICENSE` | `0808751c23d827d483dc3673d6e3f49514e49d1f` |

`openapi.yaml` is OpenAPI 3.1.1, `info.version` 1.0.0; the API prefix is
`/v1.0.0`. It is byte-identical to `tea-spec/openapi.yaml` in
oolong-project/oolong.

## Licence

The files in this directory are licensed under the Apache License, Version
2.0 (Copyright OWASP Foundation); `LICENSE` is the upstream licence file at
the pinned commit (blob `0808751c23d827d483dc3673d6e3f49514e49d1f`). The
upstream repository has no `NOTICE` file at that commit, so none is carried.
`openapi.yaml` declares `info.license` Apache-2.0. The rest of
tea-client-go is MIT-licensed (`../LICENSE`); package `teaapi` includes text
from `openapi.yaml` (see `../teaapi/doc.go`).
