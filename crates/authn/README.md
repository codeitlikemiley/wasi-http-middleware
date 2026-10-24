# wasi-http-authn

In-process authentication boundary for terminal WASI HTTP applications.

It supports a private hop that already carries this workspace's
`AuthContextV1`, and a statically dispatched broker. Both modes remove
credentials and reserved identity headers before dispatch and store a
validated `VerifiedAuthContext` in `http::Extensions`.

`accept_trusted_ingress` reads the unsigned base64url `AuthContextV1` header.
That value is not `wasi-auth`'s HMAC-SHA-256 trusted-context envelope, even
though both have used the header name `x-wasi-auth-context`. An HMAC envelope
is rejected. This crate does not verify that MAC.

Portable WASI component middleware remains available separately; this crate is
the production-oriented path that avoids immutable WASI header reconstruction.
