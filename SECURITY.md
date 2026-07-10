# Security policy

## Supported versions

`0.1.0-alpha.1` is an experimental compatibility release, not a stable support
promise. Security fixes are applied to the latest alpha on `main`; older alpha
artifacts are not maintained. The exact host, WIT, and tool tuple in
`compatibility.toml` is part of the supported surface.

## Reporting

Do not open a public issue containing credentials, exploit details, or a live
deployment. Report vulnerabilities privately to the maintainer address in
`Cargo.toml`. Include the affected artifact checksum, runtime/version tuple,
minimal reproduction, and whether the terminal application can be reached
without the declared middleware chain.

## Deployment boundary

Before reporting an identity-header bypass, verify that every externally
reachable application route passes through `auth-policy` and that the terminal
component is not exposed by a second trigger. Run
`scripts/audit-spin-manifest.py` against the deployed manifest. Ingress TLS,
host deadlines, static assets, distributed rate limiting, and application
domain authorization remain outside this component chain.
