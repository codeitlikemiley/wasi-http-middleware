# Canonical ownership

`codeitlikemiley/wasi-http-middleware` is the canonical source for the HTTP
middleware crates, portable components, and WIT contract in this repository.
`codeitlikemiley/wasi-auth` must not keep a second implementation under
`legacy/wasi-http-middleware`.

## Evidence

Compared on 2026-10-24:

| Tree | Git revision | Date |
|---|---|---|
| This repository `HEAD` | `61b41995812220c69c4a10530efb0cd5f7522840` | 2026-07-11 |
| `wasi-auth` `HEAD` | `31aef996f196e54d0ff5d584dfd4add4340850c1` | 2026-09-05 |
| Revision recorded by `wasi-auth` | `006352a4d334cef06e7a5f8bdafe8968861cab8b` | ancestor of this `HEAD` |

`legacy/wasi-http-middleware` at that `wasi-auth` revision is 99 files. A
`sha256sum` of every file, excluding `.git`, matched this repository's `HEAD`
exactly. There is no source file that exists on only one side, and no content
hash mismatch.

`wasi-auth/compatibility.toml` records
`wasi_http_middleware_revision = "006352a4d334cef06e7a5f8bdafe8968861cab8b"`.
`scripts/check-sibling-source.sh` only checks that this revision is an ancestor
of `wasi-auth` `HEAD`. It does not hash the vendored tree. The vendored bytes
match this repository's later `HEAD`, including commits `036c1fc`, `42db2e1`,
and `61b4199` (documentation, Spin bootstrap pinning, and gitignore of
generated artifacts). None of those commits change Rust policy code.

No bug fix exists only in the legacy copy. Nothing was ported from it.

`wasi-auth`'s own `TrustedContextCodec` and `apply_response_security` are a
different product surface, not a fork of these crates. Do not merge them into
this repository. In particular, `Referrer-Policy: same-origin`, CSP, and HSTS
stay in `wasi-auth`. This middleware keeps `nosniff` and
`strict-origin-when-cross-origin` and leaves HSTS to the TLS terminator.
When this middleware runs outside `wasi-auth` on the same response, it fills
only absent baseline fields. It does not replace `Referrer-Policy`,
`X-Content-Type-Options`, CSP, HSTS, or an existing `Access-Control-*` policy.
`Vary` is merged and is not narrowed.

## Context formats that must stay distinct

| | This repository | `wasi-auth` native ingress |
|---|---|---|
| Header name | `x-wasi-auth-context` | `x-wasi-auth-context` |
| Encoding | canonical base64url JSON, no padding | `base64url(json).base64url(hmac-sha256)` |
| Integrity | none; trustworthy only behind the composed middleware boundary | HMAC-SHA-256 over the payload, 32-byte deployment key |
| Binding | service ID, audiences, and broker claims inside `AuthContextV1` | audience, method, path, request ID, and a short replay window |
| API | `AuthContextV1`, `decode_auth_context`, `accept_trusted_ingress` | `TrustedContextCodec` |

`decode_auth_context` rejects the dotted HMAC envelope as invalid base64url and
rejects a payload-only copy of the signed JSON as the wrong schema. It does
not verify the MAC. `accept_trusted_ingress` strips that header and returns
`InvalidBoundary`.

## Distribution

Crate version and component artifacts move only with this repository.

- Crate version is `[workspace.package].version`, currently `0.2.0-alpha.3`,
  and must stay equal to `[release].version` in `compatibility.toml`.
- The git tag for a release is `v` plus that version, for example
  `v0.2.0-alpha.3`. Do not tag the stabilization commit as `v0.2.0-alpha.3`;
  that version already describes `61b4199`. The next operator release bumps
  both version fields together to `0.2.0-alpha.4` and tags `v0.2.0-alpha.4`.
- Publishable library crates, in registry order, are `wasi-http-metadata`,
  `wasi-http-middleware-component-support`, then `wasi-http-policy-core`.
  `wasi-http-authn` is the in-process crate. Components and
  `wasi-http-authn-runtime` stay `publish = false`.
- Component artifacts are generated, not committed:
  `artifacts/components/request-id.wasm`, `security-headers.wasm`, `cors.wasm`,
  `authn-policy.wasm`, and `secure-defaults.wasm`, plus `artifacts/SHA256SUMS`,
  `artifacts/sbom/`, and `reports/wit/`. Build them with
  `scripts/build-components.sh` and `scripts/generate-checksums.sh`. Attach
  them to the GitHub release for the `v*` tag of this repository.
- `wasi-auth`'s tag glob `wasi-http-middleware-v*` and
  `.github/workflows/release-middleware.yml` must be removed. A second release
  workflow will publish a second set of digests for the same components.

Until `0.2.0-alpha.4` is published, consumers pin the git revision. The
stabilization behavior changes (CORS method enforcement and exact audience
matching) are in this branch and are not described by a new crate version yet.

## Removal plan for `wasi-auth` (Agent 4)

Do this in `codeitlikemiley/wasi-auth` only. Do not copy the fixes back into
`legacy/`.

1. Delete the directory `legacy/wasi-http-middleware/`.
2. Delete `.github/workflows/release-middleware.yml`.
3. In the workspace `Cargo.toml`:
   - Remove `"legacy/wasi-http-middleware"` from `exclude`.
   - Replace the three path dependencies with one git revision of this
     repository. Use the full SHA of the stabilization commit once it is on
     `main` (not `006352a` and not `61b4199`):

```toml
wasi-http-metadata = { git = "https://github.com/codeitlikemiley/wasi-http-middleware", rev = "<STABILIZATION_SHA>", version = "=0.2.0-alpha.3" }
wasi-http-policy-core = { git = "https://github.com/codeitlikemiley/wasi-http-middleware", rev = "<STABILIZATION_SHA>", version = "=0.2.0-alpha.3" }
wasi-http-middleware-component-support = { git = "https://github.com/codeitlikemiley/wasi-http-middleware", rev = "<STABILIZATION_SHA>", version = "=0.2.0-alpha.3" }
```

4. In `deny.toml`, add `https://github.com/codeitlikemiley/wasi-http-middleware`
   to `allow-git`. `unknown-git` stays `deny`.
5. Regenerate `Cargo.lock` with `cargo update -p wasi-http-metadata -p wasi-http-policy-core -p wasi-http-middleware-component-support`.
6. Update `compatibility.toml`:
   - Set `wasi_http_middleware_revision` to `<STABILIZATION_SHA>`.
   - State that the revision is a commit in `codeitlikemiley/wasi-http-middleware`,
     not an ancestor of `wasi-auth`.
   - Keep `wasi_http_middleware = "0.2.0-alpha.3"` until this repository
     publishes `0.2.0-alpha.4`.
7. Replace `scripts/check-sibling-source.sh`. It must verify the lockfile git
   revision equals `wasi_http_middleware_revision`. It must not look for
   `legacy/wasi-http-middleware/Cargo.toml`.
8. Update `scripts/generate-companion-manifest.py` so `wasi-http-authn`,
   `wasi-http-metadata`, and `wasi-http-policy-core` are recorded as git
   dependencies (`repository` + `rev`) instead of
   `path = "legacy/wasi-http-middleware/crates/..."`. Regenerate
   `companion.toml`.
9. Update `scripts/generate-sbom.sh`, `scripts/normalize-sbom.py`, and
   `scripts/test-normalize-sbom.py` to stop rewriting
   `legacy/wasi-http-middleware` paths.
10. Remove the legacy manifest check in `.claude/hooks/session-start.sh`.
11. Update `docs/CI.md`, `docs/COMPATIBILITY.md`, and
    `docs/CONSUMER_ALIGNMENT.md` so consumers pin this repository's revision
    and do not expect the sources inside the `wasi-auth` checkout.
12. Crates that use the workspace dependencies do not change their package
    manifests: `components/http-pep`, `crates/wasi-authz-http`, and
    `crates/leptos-wasi-authz`. Rebuild the HTTP PEP after the dependency
    switch. Set `legacy_middleware_wit_bindgen = "0.62.0"`.
    `wasi-http-middleware-component-support` binds with `wit-bindgen` 0.62.0,
    the same generator `wasip3` 0.9.0 embeds. Move `wasi-auth`'s own components
    to that same `=0.62.0` pin in the same change so the lock does not grow a
    second guest generator.
13. Do not vendor the sources again, including as a submodule that can be
    edited. A submodule of this repository is still a second checkout and is
    not the dependency to use.

`wasi-http-authn` is not a direct workspace dependency of `wasi-auth` today.
Consumers that imported it from `legacy/wasi-http-middleware/crates/authn`
switch that path to the same git revision and package `wasi-http-authn`.
