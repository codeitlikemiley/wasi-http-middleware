//! Pure policy logic for reusable WASI HTTP middleware components.
//!
//! This crate performs no host I/O. Component wrappers load configuration,
//! forward requests, and apply the resulting decisions without buffering HTTP
//! bodies.

use std::{collections::BTreeSet, fmt};

use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
    header::{
        ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
        ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_REQUEST_HEADERS,
        ACCESS_CONTROL_REQUEST_METHOD, ORIGIN, VARY,
    },
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasi_http_metadata::{ActorV1, AuthContextV1, MetadataError, PrincipalV1, REQUEST_ID_HEADER};

/// Maximum accepted request ID size.
pub const MAX_REQUEST_ID_LEN: usize = 128;
/// Maximum accepted authorization header size.
pub const MAX_AUTHORIZATION_LEN: usize = 8 * 1024;
/// Maximum normalized path size sent to the policy service.
pub const MAX_POLICY_PATH_LEN: usize = 8 * 1024;

/// Errors produced by middleware policy validation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum PolicyError {
    /// A generated request ID violated the canonical request ID contract.
    #[error("request ID generator produced an invalid value")]
    InvalidGeneratedRequestId,
    /// Middleware configuration is invalid.
    #[error("invalid middleware configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// An HTTP header could not be represented safely.
    #[error("invalid HTTP header value")]
    InvalidHeader,
    /// More than one authorization value was supplied.
    #[error("duplicate authorization header")]
    DuplicateAuthorization,
    /// The authorization value was too large or not valid HTTP text.
    #[error("invalid authorization header")]
    InvalidAuthorization,
    /// A policy-provider success response was malformed.
    #[error("invalid policy provider response")]
    InvalidPolicyResponse,
    /// A request path was ambiguous or could not be normalized safely.
    #[error("invalid request path")]
    InvalidPath,
}

/// Canonicalizes request IDs without performing host-specific generation.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestIdPolicy;

impl RequestIdPolicy {
    /// Returns the accepted incoming ID or obtains a replacement from
    /// `generate` when the header is absent, duplicated, or invalid.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidGeneratedRequestId`] if the supplied
    /// generator does not produce a canonical value.
    pub fn canonicalize(
        self,
        headers: &HeaderMap,
        generate: impl FnOnce() -> String,
    ) -> Result<String, PolicyError> {
        canonicalize_request_id_bytes(
            headers
                .get_all(&REQUEST_ID_HEADER)
                .iter()
                .map(HeaderValue::as_bytes),
            generate,
        )
    }
}

/// Returns the single canonical request ID, or `None` when the caller must
/// replace it.
///
/// Native header maps and portable WASI field lists both use this predicate.
/// A missing, duplicated, non-UTF-8, or non-canonical value is `None`.
pub fn accepted_request_id<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Option<&'a str> {
    let mut values = values.into_iter();
    let candidate = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let text = std::str::from_utf8(candidate).ok()?;
    is_valid_request_id(text).then_some(text)
}

/// Canonicalizes request-ID field values for both `http::HeaderMap` callers
/// and portable WASI field lists.
///
/// # Errors
///
/// Returns [`PolicyError::InvalidGeneratedRequestId`] if `generate` does not
/// produce a canonical value.
pub fn canonicalize_request_id_bytes(
    values: impl IntoIterator<Item = impl AsRef<[u8]>>,
    generate: impl FnOnce() -> String,
) -> Result<String, PolicyError> {
    let owned = values
        .into_iter()
        .map(|value| value.as_ref().to_vec())
        .collect::<Vec<_>>();
    if let Some(value) = accepted_request_id(owned.iter().map(Vec::as_slice)) {
        return Ok(value.to_owned());
    }

    let generated = generate();
    if is_valid_request_id(&generated) {
        Ok(generated)
    } else {
        Err(PolicyError::InvalidGeneratedRequestId)
    }
}

/// Returns whether a request ID is safe to propagate and log.
pub fn is_valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUEST_ID_LEN
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

/// Response headers set by every security-header enforcement path.
///
/// Native [`apply_security_headers`] and the portable components both read
/// this table, and both write a field only when that name is absent. HSTS and
/// CSP stay outside this crate: HSTS belongs at the TLS terminator, and CSP
/// is application-specific. An existing value is never replaced.
pub const SECURITY_RESPONSE_HEADERS: &[(&str, &str)] = &[
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
];

/// Returns the baseline security headers whose names are not in
/// `existing_names`.
///
/// Comparison is case-insensitive. Returned names use the canonical lowercase
/// spelling from [`SECURITY_RESPONSE_HEADERS`].
pub fn absent_security_header_fields<'a>(
    existing_names: impl IntoIterator<Item = &'a str>,
) -> Vec<(&'static str, &'static str)> {
    let existing = existing_names.into_iter().collect::<Vec<_>>();
    SECURITY_RESPONSE_HEADERS
        .iter()
        .copied()
        .filter(|(name, _)| {
            !existing
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(name))
        })
        .collect()
}

/// Inserts baseline security headers that are not already present.
///
/// A downstream `Referrer-Policy` or `X-Content-Type-Options` is preserved
/// even when its value differs from [`SECURITY_RESPONSE_HEADERS`].
pub fn apply_security_headers(headers: &mut HeaderMap) {
    for (name, value) in absent_security_header_fields(headers.keys().map(HeaderName::as_str)) {
        headers.insert(name, HeaderValue::from_static(value));
    }
}

/// Appends baseline security headers that are not already present.
///
/// This is the portable field-list form of [`apply_security_headers`].
pub fn apply_security_headers_to_fields(fields: &mut Vec<(String, Vec<u8>)>) {
    for (name, value) in absent_security_header_fields(fields.iter().map(|(name, _)| name.as_str()))
    {
        fields.push((name.to_owned(), value.as_bytes().to_vec()));
    }
}

/// Returns whether `name` is an `Access-Control-*` field.
///
/// Any such field means the response already carries a CORS policy. `Vary`
/// is not included; cache keys are merged separately.
pub fn is_cors_response_header(name: &str) -> bool {
    const PREFIX: &[u8] = b"access-control-";
    name.as_bytes()
        .get(..PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PREFIX) && name.len() > PREFIX.len())
}

/// CORS fields that may be added to a downstream response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorsFieldEdits {
    /// `Access-Control-*` fields to append.
    ///
    /// Empty when `existing` already contains a CORS response field, so a
    /// downstream policy is left intact and sibling fields are not mixed in.
    pub access_control: Vec<(String, Vec<u8>)>,
    /// Replacement `Vary` value.
    ///
    /// `Some` when `decision` contains `Vary`. The bytes preserve existing
    /// tokens and do not narrow `*`. `None` when `Vary` should be left alone.
    pub vary: Option<Vec<u8>>,
}

/// Decides which CORS fields can be written without clobbering `existing`.
///
/// `decision` is the header map returned by [`CorsDecision::response_headers`].
pub fn cors_field_edits<'a>(
    existing: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    decision: &HeaderMap,
) -> CorsFieldEdits {
    let existing = existing.into_iter().collect::<Vec<_>>();
    let foreign = existing
        .iter()
        .any(|(name, _)| is_cors_response_header(name));
    let access_control = if foreign {
        Vec::new()
    } else {
        decision
            .iter()
            .filter(|(name, _)| *name != VARY)
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect()
    };
    let vary = decision.contains_key(VARY).then(|| {
        vary_value_with_origin(
            existing
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("vary"))
                .map(|(_, value)| *value),
        )
    });
    CorsFieldEdits {
        access_control,
        vary,
    }
}

/// Merges `decision` into `headers` without replacing a downstream CORS policy.
///
/// `Access-Control-*` fields are copied only when `headers` has none. `Vary`
/// is still merged when `decision` carries it.
pub fn apply_cors_headers(headers: &mut HeaderMap, decision: &HeaderMap) {
    let edits = cors_field_edits(
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes())),
        decision,
    );
    for (name, value) in edits.access_control {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_bytes(&value) else {
            continue;
        };
        headers.append(name, value);
    }
    if let Some(vary) = edits.vary
        && let Ok(value) = HeaderValue::from_bytes(&vary)
    {
        headers.insert(VARY, value);
    }
}

/// Merges `decision` into a portable field list.
///
/// This is the field-list form of [`apply_cors_headers`].
pub fn apply_cors_headers_to_fields(fields: &mut Vec<(String, Vec<u8>)>, decision: &HeaderMap) {
    let edits = cors_field_edits(
        fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice())),
        decision,
    );
    fields.extend(edits.access_control);
    if let Some(vary) = edits.vary {
        fields.retain(|(name, _)| !name.eq_ignore_ascii_case("vary"));
        fields.push(("vary".to_owned(), vary));
    }
}

/// Merges an `Origin` cache key into existing `Vary` field values.
///
/// A `*` token is preserved and is not narrowed. A non-UTF-8 field discards
/// tokens seen so far and stops, so the result is `Origin` unless an earlier
/// field was already `*`. Portable CORS middleware and `secure-defaults` both
/// call this function.
pub fn vary_value_with_origin<'a>(existing: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut tokens = Vec::<String>::new();
    for value in existing {
        let Ok(value) = std::str::from_utf8(value) else {
            tokens.clear();
            break;
        };
        for token in value
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            if token == "*" {
                return b"*".to_vec();
            }
            if !tokens
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(token))
            {
                tokens.push(token.to_owned());
            }
        }
    }
    if !tokens
        .iter()
        .any(|token| token.eq_ignore_ascii_case("origin"))
    {
        tokens.push("Origin".to_owned());
    }
    tokens.join(", ").into_bytes()
}

/// Validated CORS middleware configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorsConfig {
    origins: BTreeSet<String>,
    methods: BTreeSet<Method>,
    headers: BTreeSet<String>,
    allow_credentials: bool,
}

impl CorsConfig {
    /// Creates an explicit CORS policy.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when an origin, method, or header is invalid,
    /// or when wildcard origins are combined with credentials.
    pub fn new(
        origins: impl IntoIterator<Item = impl AsRef<str>>,
        methods: impl IntoIterator<Item = impl AsRef<str>>,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
        allow_credentials: bool,
    ) -> Result<Self, PolicyError> {
        let origins = origins
            .into_iter()
            .map(|origin| origin.as_ref().trim().to_owned())
            .filter(|origin| !origin.is_empty())
            .collect::<BTreeSet<_>>();
        if origins.is_empty() {
            return Err(PolicyError::InvalidConfiguration(
                "at least one CORS origin is required",
            ));
        }
        if allow_credentials && origins.contains("*") {
            return Err(PolicyError::InvalidConfiguration(
                "wildcard CORS origin cannot allow credentials",
            ));
        }
        if origins.iter().any(|origin| !is_valid_cors_origin(origin)) {
            return Err(PolicyError::InvalidConfiguration("invalid CORS origin"));
        }

        let methods = methods
            .into_iter()
            .map(|method| {
                Method::from_bytes(method.as_ref().trim().as_bytes())
                    .map_err(|_| PolicyError::InvalidConfiguration("invalid CORS method"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if methods.is_empty() {
            return Err(PolicyError::InvalidConfiguration(
                "at least one CORS method is required",
            ));
        }

        let headers = headers
            .into_iter()
            .map(|header| {
                let normalized = header.as_ref().trim().to_ascii_lowercase();
                HeaderName::from_bytes(normalized.as_bytes())
                    .map(|_| normalized)
                    .map_err(|_| PolicyError::InvalidConfiguration("invalid CORS header"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;

        Ok(Self {
            origins,
            methods,
            headers,
            allow_credentials,
        })
    }

    /// Parses the four `WASI_MIDDLEWARE_CORS_*` values used by component
    /// wrappers.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] for invalid or unsafe configuration.
    pub fn from_values(
        origins: &str,
        methods: Option<&str>,
        headers: Option<&str>,
        allow_credentials: Option<&str>,
    ) -> Result<Self, PolicyError> {
        let methods = methods.unwrap_or("GET,HEAD,POST");
        let headers = headers.unwrap_or("content-type,authorization");
        let allow_credentials = match allow_credentials.unwrap_or("false") {
            "true" => true,
            "false" => false,
            _ => {
                return Err(PolicyError::InvalidConfiguration(
                    "CORS credentials must be true or false",
                ));
            }
        };
        Self::new(
            split_csv(origins),
            split_csv(methods),
            split_csv(headers),
            allow_credentials,
        )
    }

    /// Evaluates request CORS headers and returns response mutations.
    ///
    /// A returned preflight status indicates that the middleware should not
    /// invoke downstream.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] if request headers are malformed.
    pub fn evaluate(
        &self,
        method: &Method,
        headers: &HeaderMap,
    ) -> Result<CorsDecision, PolicyError> {
        let Some(origin) = single_text_header(headers, ORIGIN)? else {
            return Ok(CorsDecision::pass_through());
        };
        if !self.origins.contains("*") && !self.origins.contains(origin) {
            return Ok(CorsDecision::rejected_for_origin(StatusCode::FORBIDDEN));
        }

        let is_preflight =
            method == Method::OPTIONS && headers.contains_key(ACCESS_CONTROL_REQUEST_METHOD);
        if is_preflight {
            let requested_method = single_text_header(headers, ACCESS_CONTROL_REQUEST_METHOD)?
                .ok_or(PolicyError::InvalidHeader)
                .and_then(|value| {
                    Method::from_bytes(value.as_bytes()).map_err(|_| PolicyError::InvalidHeader)
                })?;
            if !self.methods.contains(&requested_method) {
                return Ok(CorsDecision::rejected_for_origin(StatusCode::FORBIDDEN));
            }

            let requested_headers = single_text_header(headers, ACCESS_CONTROL_REQUEST_HEADERS)?
                .map(split_csv)
                .unwrap_or_default()
                .into_iter()
                .map(|header| {
                    HeaderName::from_bytes(header.as_bytes())
                        .map_err(|_| PolicyError::InvalidHeader)
                })
                .collect::<Result<Vec<_>, _>>()?;
            if requested_headers
                .iter()
                .any(|header| !self.headers.contains(header.as_str()))
            {
                return Ok(CorsDecision::rejected_for_origin(StatusCode::FORBIDDEN));
            }
        } else if !self.methods.contains(method) {
            // Browsers send simple requests without a preflight. The method
            // allowlist has to apply to those requests as well, or a GET from
            // an allowed origin can read a response the operator did not allow.
            return Ok(CorsDecision::rejected_for_origin(StatusCode::FORBIDDEN));
        }

        let mut response_headers = HeaderMap::new();
        let allow_origin = if self.origins.contains("*") {
            "*"
        } else {
            origin
        };
        response_headers.insert(
            ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_str(allow_origin).map_err(|_| PolicyError::InvalidHeader)?,
        );
        response_headers.insert(VARY, HeaderValue::from_static("Origin"));
        if self.allow_credentials {
            response_headers.insert(
                ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }

        if !is_preflight {
            return Ok(CorsDecision {
                response_headers,
                status: None,
            });
        }

        response_headers.insert(
            ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_str(
                &self
                    .methods
                    .iter()
                    .map(Method::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
            )
            .map_err(|_| PolicyError::InvalidHeader)?,
        );
        if !self.headers.is_empty() {
            response_headers.insert(
                ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_str(
                    &self
                        .headers
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(", "),
                )
                .map_err(|_| PolicyError::InvalidHeader)?,
            );
        }

        Ok(CorsDecision {
            response_headers,
            status: Some(StatusCode::NO_CONTENT),
        })
    }
}

/// Result of evaluating CORS for one request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorsDecision {
    response_headers: HeaderMap,
    status: Option<StatusCode>,
}

impl CorsDecision {
    fn pass_through() -> Self {
        Self {
            response_headers: HeaderMap::new(),
            status: None,
        }
    }

    fn rejected_for_origin(status: StatusCode) -> Self {
        let mut response_headers = HeaderMap::new();
        response_headers.insert(VARY, HeaderValue::from_static("Origin"));
        Self {
            response_headers,
            status: Some(status),
        }
    }

    /// Returns headers to merge into the response.
    pub fn response_headers(&self) -> &HeaderMap {
        &self.response_headers
    }

    /// Returns a short-circuit status, or `None` when downstream should run.
    pub fn status(&self) -> Option<StatusCode> {
        self.status
    }
}

/// Version-one request sent to an external authentication broker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthnRequestV1 {
    /// Authentication broker request schema version.
    pub version: u8,
    /// Immutable terminal-service identifier.
    pub service_id: String,
    /// Immutable configured audiences.
    pub audiences: Vec<String>,
    /// Canonical request ID.
    pub request_id: String,
}

/// Produces the canonical path sent to the policy service.
///
/// The query is removed, percent escapes are decoded exactly once, encoded
/// separators and double-encoding are rejected, and ambiguous dot or empty
/// segments are rejected. A literal dot inside a larger segment remains valid.
///
/// # Errors
///
/// Returns [`PolicyError::InvalidPath`] when the path is malformed, ambiguous,
/// not valid UTF-8 after decoding, or exceeds [`MAX_POLICY_PATH_LEN`].
pub fn normalize_policy_path(path_with_query: &str) -> Result<String, PolicyError> {
    let raw_path = path_with_query
        .split_once('?')
        .map_or(path_with_query, |(path, _)| path);
    if raw_path.is_empty() {
        return Ok("/".to_owned());
    }
    if !raw_path.starts_with('/') || raw_path.len() > MAX_POLICY_PATH_LEN {
        return Err(PolicyError::InvalidPath);
    }

    let input = raw_path.as_bytes();
    let mut decoded = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        let byte = input[index];
        if byte == b'%' {
            let Some(high) = input.get(index + 1).and_then(|byte| hex_value(*byte)) else {
                return Err(PolicyError::InvalidPath);
            };
            let Some(low) = input.get(index + 2).and_then(|byte| hex_value(*byte)) else {
                return Err(PolicyError::InvalidPath);
            };
            let decoded_byte = (high << 4) | low;
            if decoded_byte == b'%'
                || decoded_byte == b'/'
                || decoded_byte == b'\\'
                || decoded_byte == b'?'
                || decoded_byte == b'#'
                || decoded_byte.is_ascii_control()
            {
                return Err(PolicyError::InvalidPath);
            }
            decoded.push(decoded_byte);
            index += 3;
            continue;
        }
        if byte == b'\\' || byte == b'#' || byte.is_ascii_control() {
            return Err(PolicyError::InvalidPath);
        }
        decoded.push(byte);
        index += 1;
    }

    let decoded = String::from_utf8(decoded).map_err(|_| PolicyError::InvalidPath)?;
    if decoded.len() > MAX_POLICY_PATH_LEN
        || decoded.contains("//")
        || decoded
            .split('/')
            .skip(1)
            .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(PolicyError::InvalidPath);
    }
    Ok(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Successful authentication-broker response body.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct AuthnSuccessV1 {
    version: u8,
    subject: String,
    issuer: String,
    tenant_id: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    scopes: Vec<String>,
    acr: Option<String>,
    #[serde(default)]
    amr: Vec<String>,
    actor: Option<AuthnActorV1>,
    auth_time: Option<u64>,
    expires_at: Option<u64>,
    session_id: Option<String>,
    decision_id: String,
    policy_revision: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct AuthnActorV1 {
    issuer: String,
    subject: String,
}

/// Broker-validated claims awaiting binding to deployment configuration.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedClaimsV1 {
    principal: PrincipalV1,
    decision_id: String,
    policy_revision: String,
}

impl fmt::Debug for AuthenticatedClaimsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedClaimsV1")
            .field("claims", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl AuthenticatedClaimsV1 {
    /// Binds broker claims to immutable service and audience configuration.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError`] if deployment configuration is invalid.
    pub fn into_context(
        self,
        service_id: impl Into<String>,
        audiences: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<AuthContextV1, MetadataError> {
        AuthContextV1::authenticated(
            service_id,
            audiences,
            self.principal,
            self.decision_id,
            self.policy_revision,
        )
    }

    /// Returns the canonical authenticated principal.
    pub fn principal(&self) -> &PrincipalV1 {
        &self.principal
    }

    /// Returns the broker decision identifier.
    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }

    /// Returns the authentication policy revision.
    pub fn policy_revision(&self) -> &str {
        &self.policy_revision
    }
}

/// Authentication decision returned by the broker bridge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthDecision {
    /// Authentication succeeded and claims passed strict validation.
    Allow(Box<AuthenticatedClaimsV1>),
    /// No acceptable identity was supplied.
    Unauthenticated,
    /// The external authentication broker failed or violated its contract.
    Unavailable,
}

/// Fail-closed result of applying an authentication policy hook to a broker
/// decision.
///
/// `wasi-http-authn` and the portable `wasi-http-authn-runtime` both use
/// [`accepted_claims`]. A rejected or unavailable broker response never
/// becomes anonymous success on only one of those paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthHookRejection {
    /// The broker rejected the supplied credential.
    InvalidCredentials,
    /// The broker failed or its success payload was not usable.
    Unavailable,
}

/// Converts a broker decision into claims or a shared rejection.
///
/// Missing-credential handling stays with the caller: optional mode may skip
/// the broker only when no credential was supplied. This function is the
/// overlap after the broker has already been consulted.
///
/// # Errors
///
/// Returns [`AuthHookRejection::InvalidCredentials`] when the broker rejected
/// the credential and [`AuthHookRejection::Unavailable`] when the broker failed
/// or its success payload could not be used.
pub fn accepted_claims(decision: AuthDecision) -> Result<AuthenticatedClaimsV1, AuthHookRejection> {
    match decision {
        AuthDecision::Allow(claims) => Ok(*claims),
        AuthDecision::Unauthenticated => Err(AuthHookRejection::InvalidCredentials),
        AuthDecision::Unavailable => Err(AuthHookRejection::Unavailable),
    }
}

/// Validates one authorization header without exposing its contents.
///
/// # Errors
///
/// Returns [`PolicyError`] for duplicate, non-text, or oversized values.
pub fn authorization_value(headers: &HeaderMap) -> Result<Option<&str>, PolicyError> {
    let mut values = headers.get_all(http::header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(PolicyError::DuplicateAuthorization);
    }
    let value = value
        .to_str()
        .map_err(|_| PolicyError::InvalidAuthorization)?;
    if value.len() > MAX_AUTHORIZATION_LEN {
        return Err(PolicyError::InvalidAuthorization);
    }
    Ok(Some(value))
}

/// Converts an authentication-broker response into a fail-closed decision.
pub fn parse_authn_response(status: StatusCode, body: &[u8]) -> AuthDecision {
    match status {
        StatusCode::OK => serde_json::from_slice::<AuthnSuccessV1>(body)
            .ok()
            .and_then(authenticated_claims)
            .map_or(AuthDecision::Unavailable, |claims| {
                AuthDecision::Allow(Box::new(claims))
            }),
        StatusCode::UNAUTHORIZED => AuthDecision::Unauthenticated,
        _ => AuthDecision::Unavailable,
    }
}

fn authenticated_claims(success: AuthnSuccessV1) -> Option<AuthenticatedClaimsV1> {
    if success.version != 1 {
        return None;
    }
    let actor = success
        .actor
        .map(|actor| ActorV1::new(actor.issuer, actor.subject))
        .transpose()
        .ok()?;
    let principal = PrincipalV1::new(success.issuer, success.subject)
        .and_then(|principal| principal.with_tenant_id(success.tenant_id))
        .and_then(|principal| principal.with_roles(success.roles))
        .and_then(|principal| principal.with_scopes(success.scopes))
        .and_then(|principal| principal.with_acr(success.acr))
        .and_then(|principal| principal.with_amr(success.amr))
        .map(|principal| principal.with_actor(actor))
        .and_then(|principal| principal.with_times(success.auth_time, success.expires_at))
        .and_then(|principal| principal.with_session_id(success.session_id))
        .ok()?;
    AuthContextV1::authenticated(
        "validation",
        ["validation"],
        principal.clone(),
        &success.decision_id,
        &success.policy_revision,
    )
    .ok()?;
    Some(AuthenticatedClaimsV1 {
        principal,
        decision_id: success.decision_id,
        policy_revision: success.policy_revision,
    })
}

fn single_text_header(headers: &HeaderMap, name: HeaderName) -> Result<Option<&str>, PolicyError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(PolicyError::InvalidHeader);
    }
    value
        .to_str()
        .map(Some)
        .map_err(|_| PolicyError::InvalidHeader)
}

fn split_csv(value: &str) -> Vec<&str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect()
}

fn is_valid_cors_origin(origin: &str) -> bool {
    if matches!(origin, "*" | "null") {
        return true;
    }
    if !origin.is_ascii() || origin.bytes().any(|byte| byte.is_ascii_control()) {
        return false;
    }
    let Ok(uri) = origin.parse::<Uri>() else {
        return false;
    };
    let Some(scheme @ ("http" | "https")) = uri.scheme_str() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    !authority.as_str().contains('@') && origin == format!("{scheme}://{authority}")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn request_id_accepts_one_canonical_value() {
        let mut headers = HeaderMap::new();
        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static("request-123"));

        let value = RequestIdPolicy
            .canonicalize(&headers, || "generated".to_owned())
            .expect("valid fixture");

        assert_eq!(value, "request-123");
    }

    #[test]
    fn request_id_replaces_duplicate_values() {
        let mut headers = HeaderMap::new();
        headers.append(REQUEST_ID_HEADER, HeaderValue::from_static("one"));
        headers.append(REQUEST_ID_HEADER, HeaderValue::from_static("two"));

        let value = RequestIdPolicy
            .canonicalize(&headers, || "generated".to_owned())
            .expect("valid fixture");

        assert_eq!(value, "generated");
    }

    #[test]
    fn security_headers_preserve_existing_values_and_fill_gaps() {
        let mut headers = HeaderMap::new();
        headers.insert("x-content-type-options", HeaderValue::from_static("unsafe"));

        apply_security_headers(&mut headers);

        assert_eq!(headers["x-content-type-options"], "unsafe");
        assert_eq!(
            headers["referrer-policy"],
            "strict-origin-when-cross-origin"
        );
    }

    #[test]
    fn cors_rejects_wildcard_credentials() {
        let result = CorsConfig::new(["*"], ["GET"], ["content-type"], true);

        assert!(matches!(result, Err(PolicyError::InvalidConfiguration(_))));
    }

    #[test]
    fn cors_rejects_non_origin_urls() {
        for origin in [
            "https://example.com/path",
            "https://user@example.com",
            "file://example.com",
            "example.com",
            "https://example.com?query=yes",
        ] {
            assert!(
                CorsConfig::new([origin], ["GET"], ["content-type"], false).is_err(),
                "{origin}"
            );
        }
    }

    #[test]
    fn cors_preflight_short_circuits_with_explicit_headers() {
        let config = CorsConfig::new(
            ["https://example.com"],
            ["GET", "POST"],
            ["content-type"],
            false,
        )
        .expect("valid fixture");
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://example.com"));
        headers.insert(
            ACCESS_CONTROL_REQUEST_METHOD,
            HeaderValue::from_static("POST"),
        );
        headers.insert(
            ACCESS_CONTROL_REQUEST_HEADERS,
            HeaderValue::from_static("content-type"),
        );

        let decision = config
            .evaluate(&Method::OPTIONS, &headers)
            .expect("valid request");

        assert_eq!(decision.status(), Some(StatusCode::NO_CONTENT));
        assert_eq!(
            decision.response_headers()[ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://example.com"
        );
    }

    #[test]
    fn cors_rejection_varies_by_origin() {
        let config = CorsConfig::new(
            ["https://allowed.example"],
            ["GET"],
            ["content-type"],
            false,
        )
        .expect("valid fixture");
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://denied.example"));

        let decision = config
            .evaluate(&Method::GET, &headers)
            .expect("valid request");

        assert_eq!(decision.status(), Some(StatusCode::FORBIDDEN));
        assert_eq!(decision.response_headers()[VARY], "Origin");
    }

    #[test]
    fn request_id_boundaries_and_ascii_contract_are_exhaustive() {
        assert!(!is_valid_request_id(""));
        assert!(is_valid_request_id(&"a".repeat(MAX_REQUEST_ID_LEN)));
        assert!(!is_valid_request_id(&"a".repeat(MAX_REQUEST_ID_LEN + 1)));

        for byte in u8::MIN..=u8::MAX {
            let value = String::from_utf8(vec![byte]);
            let expected =
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/');
            assert_eq!(value.as_deref().is_ok_and(is_valid_request_id), expected);
        }
    }

    #[test]
    fn authorization_size_boundary_is_exact() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&"a".repeat(MAX_AUTHORIZATION_LEN)).expect("valid header"),
        );
        assert!(authorization_value(&headers).is_ok());

        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&"a".repeat(MAX_AUTHORIZATION_LEN + 1)).expect("valid header"),
        );
        assert_eq!(
            authorization_value(&headers),
            Err(PolicyError::InvalidAuthorization)
        );
    }

    #[test]
    fn policy_path_is_decoded_once_and_query_free() {
        assert_eq!(
            normalize_policy_path("/%61dmin/report?token=secret"),
            Ok("/admin/report".to_owned())
        );
        assert_eq!(
            normalize_policy_path("/assets/app..min.js"),
            Ok("/assets/app..min.js".to_owned())
        );
    }

    #[test]
    fn policy_path_rejects_ambiguous_forms() {
        for path in [
            "/admin/../public",
            "/%2e%2e/public",
            "/%2Fetc/passwd",
            "/%5cwindows",
            "/%252e%252e/public",
            "/two//segments",
            "/bad%",
            "/bad%0g",
        ] {
            assert_eq!(
                normalize_policy_path(path),
                Err(PolicyError::InvalidPath),
                "{path}"
            );
        }
    }

    #[test]
    fn authn_response_fails_closed_on_malformed_success() {
        let decision = parse_authn_response(StatusCode::OK, br#"{"subject":"missing"}"#);

        assert_eq!(decision, AuthDecision::Unavailable);
    }

    #[test]
    fn broker_forbidden_is_not_treated_as_domain_authorization() {
        assert_eq!(
            parse_authn_response(StatusCode::FORBIDDEN, b""),
            AuthDecision::Unavailable
        );
    }

    #[test]
    fn authn_response_builds_valid_versioned_claims() {
        let decision = parse_authn_response(
            StatusCode::OK,
            br#"{"version":1,"subject":"user-1","issuer":"mock","scopes":["read"],"acr":"loa2","amr":["pwd"],"actor":{"issuer":"workload","subject":"job-1"},"decision_id":"decision-1","policy_revision":"revision-1"}"#,
        );

        let AuthDecision::Allow(claims) = decision else {
            panic!("valid broker response must authenticate");
        };
        assert_eq!(claims.principal().identity_key(), ("mock", "user-1"));
        assert_eq!(claims.principal().acr(), Some("loa2"));
        assert_eq!(
            claims.principal().actor().map(ActorV1::identity_key),
            Some(("workload", "job-1"))
        );
        assert_eq!(claims.decision_id(), "decision-1");
        assert_eq!(claims.policy_revision(), "revision-1");
    }

    #[test]
    fn authenticated_claims_debug_output_is_redacted() {
        let decision = parse_authn_response(
            StatusCode::OK,
            br#"{"version":1,"subject":"identity-debug-sentinel","issuer":"issuer-debug-sentinel","scopes":["scope-debug-sentinel"],"decision_id":"decision-debug-sentinel","policy_revision":"policy-debug-sentinel"}"#,
        );
        let debug = format!("{decision:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("debug-sentinel"));
    }

    #[test]
    fn authorization_rejects_duplicates() {
        let mut headers = HeaderMap::new();
        headers.append(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer one"),
        );
        headers.append(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer two"),
        );

        assert_eq!(
            authorization_value(&headers),
            Err(PolicyError::DuplicateAuthorization)
        );
    }

    #[test]
    fn native_header_map_and_portable_fields_share_request_id_decisions() {
        let cases = [
            vec![("x-request-id", &b"request-123"[..])],
            vec![("x-request-id", &b"one"[..]), ("X-Request-ID", &b"two"[..])],
            vec![("X-Request-ID", &b"bad id"[..])],
            vec![("content-type", &b"text/plain"[..])],
            vec![("x-request-id", &b""[..])],
        ];

        for pairs in cases {
            assert_same_request_id(&pairs);
        }
        let oversized = "a".repeat(MAX_REQUEST_ID_LEN + 1);
        assert_same_request_id(&[("x-request-id", oversized.as_bytes())]);
    }

    fn assert_same_request_id(pairs: &[(&str, &[u8])]) {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            if value.is_empty() {
                continue;
            }
            let header_name = HeaderName::from_bytes(name.as_bytes()).expect("fixture header name");
            map.append(
                header_name,
                HeaderValue::from_bytes(value).expect("fixture header value"),
            );
        }
        let from_map = RequestIdPolicy
            .canonicalize(&map, || "generated".to_owned())
            .expect("generator is canonical");
        let field_values = pairs
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(REQUEST_ID_HEADER.as_str()))
            .map(|(_, value)| *value);
        let from_fields = canonicalize_request_id_bytes(field_values, || "generated".to_owned())
            .expect("generator is canonical");
        assert_eq!(from_map, from_fields, "{pairs:?}");
        let borrowed = accepted_request_id(
            map.get_all(REQUEST_ID_HEADER)
                .iter()
                .map(HeaderValue::as_bytes),
        );
        match borrowed {
            Some(value) => assert_eq!(from_map, value),
            None => assert_eq!(from_map, "generated"),
        }
    }

    #[test]
    fn native_and_portable_response_policy_preserves_downstream_headers() {
        let decision = app_cors_decision();
        let preserved = apply_both(
            &[
                ("Referrer-Policy", b"same-origin"),
                ("x-content-type-options", b"nosniff"),
                ("content-security-policy", b"default-src 'none'"),
                (
                    "strict-transport-security",
                    b"max-age=31536000; includeSubDomains",
                ),
                ("access-control-allow-origin", b"https://auth.example"),
                ("vary", b"Accept-Encoding"),
                ("cache-control", b"no-store"),
            ],
            &decision,
        );
        assert_eq!(single(&preserved, "referrer-policy"), b"same-origin");
        assert_eq!(single(&preserved, "x-content-type-options"), b"nosniff");
        assert_eq!(
            single(&preserved, "content-security-policy"),
            b"default-src 'none'"
        );
        assert_eq!(
            single(&preserved, "strict-transport-security"),
            b"max-age=31536000; includeSubDomains"
        );
        assert_eq!(
            single(&preserved, "access-control-allow-origin"),
            b"https://auth.example"
        );
        assert!(!preserved.contains_key("access-control-allow-credentials"));
        assert_eq!(single(&preserved, "vary"), b"Accept-Encoding, Origin");
        assert_eq!(single(&preserved, "cache-control"), b"no-store");

        let filled = apply_both(&[], &decision);
        assert_eq!(
            single(&filled, "referrer-policy"),
            b"strict-origin-when-cross-origin"
        );
        assert_eq!(single(&filled, "x-content-type-options"), b"nosniff");
        assert_eq!(
            single(&filled, "access-control-allow-origin"),
            b"https://app.example"
        );
        assert_eq!(single(&filled, "access-control-allow-credentials"), b"true");
        assert_eq!(single(&filled, "vary"), b"Origin");
        assert!(!filled.contains_key("content-security-policy"));
        assert!(!filled.contains_key("strict-transport-security"));

        let partial = apply_both(
            &[
                ("referrer-policy", b"same-origin"),
                ("access-control-allow-credentials", b"true"),
                ("vary", b"*"),
            ],
            &decision,
        );
        assert_eq!(single(&partial, "referrer-policy"), b"same-origin");
        assert_eq!(single(&partial, "x-content-type-options"), b"nosniff");
        assert_eq!(
            single(&partial, "access-control-allow-credentials"),
            b"true"
        );
        assert!(!partial.contains_key("access-control-allow-origin"));
        assert_eq!(single(&partial, "vary"), b"*");

        let kept = apply_both(
            &[
                ("x-content-type-options", b"unsafe"),
                ("referrer-policy", b"unsafe-url"),
            ],
            &HeaderMap::new(),
        );
        assert_eq!(single(&kept, "x-content-type-options"), b"unsafe");
        assert_eq!(single(&kept, "referrer-policy"), b"unsafe-url");
    }

    fn app_cors_decision() -> HeaderMap {
        let config = CorsConfig::new(
            ["https://app.example"],
            ["GET", "POST"],
            ["content-type"],
            true,
        )
        .expect("valid fixture");
        let mut request = HeaderMap::new();
        request.insert(ORIGIN, HeaderValue::from_static("https://app.example"));
        config
            .evaluate(&Method::GET, &request)
            .expect("valid request")
            .response_headers()
            .clone()
    }

    fn apply_both(
        downstream: &[(&str, &[u8])],
        decision: &HeaderMap,
    ) -> BTreeMap<String, Vec<Vec<u8>>> {
        let mut map = HeaderMap::new();
        let mut fields = Vec::new();
        for (name, value) in downstream {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).expect("fixture header name"),
                HeaderValue::from_bytes(value).expect("fixture header value"),
            );
            fields.push(((*name).to_owned(), value.to_vec()));
        }
        apply_security_headers(&mut map);
        apply_cors_headers(&mut map, decision);
        apply_security_headers_to_fields(&mut fields);
        apply_cors_headers_to_fields(&mut fields, decision);

        let native = header_values_from_map(&map);
        let portable = header_values_from_fields(&fields);
        assert_eq!(native, portable, "{downstream:?}");
        native
    }

    fn header_values_from_map(headers: &HeaderMap) -> BTreeMap<String, Vec<Vec<u8>>> {
        let mut values = BTreeMap::<String, Vec<Vec<u8>>>::new();
        for (name, value) in headers {
            values
                .entry(name.as_str().to_owned())
                .or_default()
                .push(value.as_bytes().to_vec());
        }
        values
    }

    fn header_values_from_fields(fields: &[(String, Vec<u8>)]) -> BTreeMap<String, Vec<Vec<u8>>> {
        let mut values = BTreeMap::<String, Vec<Vec<u8>>>::new();
        for (name, value) in fields {
            values
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(value.clone());
        }
        values
    }

    fn single<'a>(fields: &'a BTreeMap<String, Vec<Vec<u8>>>, name: &str) -> &'a [u8] {
        let values = fields.get(name).unwrap_or_else(|| panic!("missing {name}"));
        assert_eq!(values.len(), 1, "{name}");
        &values[0]
    }

    #[test]
    fn vary_merge_preserves_tokens_and_does_not_narrow_wildcard() {
        assert_eq!(
            vary_value_with_origin([b"Accept-Encoding".as_slice()]),
            b"Accept-Encoding, Origin"
        );
        assert_eq!(
            vary_value_with_origin([b"Accept-Encoding".as_slice(), b"Accept-Language".as_slice()]),
            b"Accept-Encoding, Accept-Language, Origin"
        );
        assert_eq!(vary_value_with_origin([b"*".as_slice()]), b"*");
        assert_eq!(vary_value_with_origin([b"origin".as_slice()]), b"origin");
        assert_eq!(
            vary_value_with_origin([b"Accept-Encoding".as_slice(), b"\xff".as_slice()]),
            b"Origin"
        );
        assert_eq!(
            vary_value_with_origin([b"*".as_slice(), b"\xff".as_slice()]),
            b"*"
        );
    }

    #[test]
    fn cors_credentials_reflect_the_exact_origin_and_vary() {
        let config = CorsConfig::new(
            ["https://app.example"],
            ["GET", "POST"],
            ["content-type"],
            true,
        )
        .expect("valid fixture");
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://app.example"));

        let decision = config
            .evaluate(&Method::GET, &headers)
            .expect("valid request");

        assert_eq!(decision.status(), None);
        assert_eq!(
            decision.response_headers()[ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://app.example"
        );
        assert_eq!(
            decision.response_headers()[ACCESS_CONTROL_ALLOW_CREDENTIALS],
            "true"
        );
        assert_eq!(decision.response_headers()[VARY], "Origin");
    }

    #[test]
    fn cors_wildcard_origin_does_not_reflect_or_allow_credentials() {
        let config =
            CorsConfig::new(["*"], ["GET"], ["content-type"], false).expect("valid fixture");
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://evil.example"));

        let decision = config
            .evaluate(&Method::GET, &headers)
            .expect("valid request");

        assert_eq!(
            decision.response_headers()[ACCESS_CONTROL_ALLOW_ORIGIN],
            "*"
        );
        assert!(
            !decision
                .response_headers()
                .contains_key(ACCESS_CONTROL_ALLOW_CREDENTIALS)
        );
        assert_eq!(decision.response_headers()[VARY], "Origin");
    }

    #[test]
    fn cors_denies_cross_origin_method_outside_the_allowlist() {
        let config = CorsConfig::new(["https://app.example"], ["POST"], ["content-type"], false)
            .expect("valid fixture");
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://app.example"));

        let decision = config
            .evaluate(&Method::GET, &headers)
            .expect("valid request");

        assert_eq!(decision.status(), Some(StatusCode::FORBIDDEN));
        assert_eq!(decision.response_headers()[VARY], "Origin");
        assert!(
            !decision
                .response_headers()
                .contains_key(ACCESS_CONTROL_ALLOW_ORIGIN)
        );
        assert!(
            !decision
                .response_headers()
                .contains_key(ACCESS_CONTROL_ALLOW_CREDENTIALS)
        );
    }

    #[test]
    fn cors_same_origin_omission_ignores_the_method_allowlist() {
        let config = CorsConfig::new(["https://app.example"], ["POST"], ["content-type"], false)
            .expect("valid fixture");

        let decision = config
            .evaluate(&Method::DELETE, &HeaderMap::new())
            .expect("valid request");

        assert_eq!(decision.status(), None);
        assert!(decision.response_headers().is_empty());
    }

    #[test]
    fn cors_preflight_denies_headers_outside_the_allowlist() {
        let config = CorsConfig::new(["https://app.example"], ["POST"], ["content-type"], true)
            .expect("valid fixture");
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://app.example"));
        headers.insert(
            ACCESS_CONTROL_REQUEST_METHOD,
            HeaderValue::from_static("POST"),
        );
        headers.insert(
            ACCESS_CONTROL_REQUEST_HEADERS,
            HeaderValue::from_static("x-custom"),
        );

        let decision = config
            .evaluate(&Method::OPTIONS, &headers)
            .expect("valid request");

        assert_eq!(decision.status(), Some(StatusCode::FORBIDDEN));
        assert_eq!(decision.response_headers()[VARY], "Origin");
        assert!(
            !decision
                .response_headers()
                .contains_key(ACCESS_CONTROL_ALLOW_ORIGIN)
        );
        assert!(
            !decision
                .response_headers()
                .contains_key(ACCESS_CONTROL_ALLOW_CREDENTIALS)
        );
    }

    #[test]
    fn cors_star_request_header_is_literal_not_a_wildcard() {
        let config = CorsConfig::new(["https://app.example"], ["POST"], ["*"], false)
            .expect("valid fixture");
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://app.example"));
        headers.insert(
            ACCESS_CONTROL_REQUEST_METHOD,
            HeaderValue::from_static("POST"),
        );
        headers.insert(
            ACCESS_CONTROL_REQUEST_HEADERS,
            HeaderValue::from_static("content-type"),
        );

        let decision = config
            .evaluate(&Method::OPTIONS, &headers)
            .expect("valid request");

        assert_eq!(decision.status(), Some(StatusCode::FORBIDDEN));
    }

    #[test]
    fn cors_rejection_does_not_echo_a_denied_origin() {
        let config = CorsConfig::new(["https://allowed.example"], ["GET"], ["content-type"], true)
            .expect("valid fixture");
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://denied.example"));

        let decision = config
            .evaluate(&Method::GET, &headers)
            .expect("valid request");

        assert!(
            !decision
                .response_headers()
                .contains_key(ACCESS_CONTROL_ALLOW_ORIGIN)
        );
        assert!(
            !decision
                .response_headers()
                .contains_key(ACCESS_CONTROL_ALLOW_CREDENTIALS)
        );
    }

    #[test]
    fn broker_hook_rejects_unauthenticated_and_unavailable_decisions() {
        let unauthenticated = accepted_claims(parse_authn_response(StatusCode::UNAUTHORIZED, b""));
        let unavailable = accepted_claims(parse_authn_response(StatusCode::FORBIDDEN, b""));
        let malformed = accepted_claims(parse_authn_response(StatusCode::OK, b"{}"));

        assert_eq!(unauthenticated, Err(AuthHookRejection::InvalidCredentials));
        assert_eq!(unavailable, Err(AuthHookRejection::Unavailable));
        assert_eq!(malformed, Err(AuthHookRejection::Unavailable));
    }
}
