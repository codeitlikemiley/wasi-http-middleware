//! Pure policy logic for reusable WASI HTTP middleware components.
//!
//! This crate performs no host I/O. Component wrappers load configuration,
//! forward requests, and apply the resulting decisions without buffering HTTP
//! bodies.

use std::collections::BTreeSet;

use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
    header::{
        ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
        ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_REQUEST_HEADERS,
        ACCESS_CONTROL_REQUEST_METHOD, ORIGIN, REFERRER_POLICY, VARY,
    },
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasi_http_metadata::{Principal, REQUEST_ID_HEADER};

/// Maximum accepted request ID size.
pub const MAX_REQUEST_ID_LEN: usize = 128;
/// Maximum accepted authorization header size.
pub const MAX_AUTHORIZATION_LEN: usize = 8 * 1024;

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
        let mut values = headers.get_all(&REQUEST_ID_HEADER).iter();
        let candidate = values.next();
        let duplicate = values.next().is_some();
        if !duplicate
            && let Some(value) = candidate
            && let Ok(value) = value.to_str()
            && is_valid_request_id(value)
        {
            return Ok(value.to_owned());
        }

        let generated = generate();
        if is_valid_request_id(&generated) {
            Ok(generated)
        } else {
            Err(PolicyError::InvalidGeneratedRequestId)
        }
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

/// Applies the fixed baseline security response headers.
pub fn apply_security_headers(headers: &mut HeaderMap) {
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
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
        if origins.iter().any(|origin| {
            origin != "*"
                && (!origin.is_ascii() || origin.bytes().any(|byte| byte.is_ascii_control()))
        }) {
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
            return Ok(CorsDecision::rejected(StatusCode::FORBIDDEN));
        }

        let mut response_headers = HeaderMap::new();
        response_headers.insert(
            ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_str(if self.origins.contains("*") {
                "*"
            } else {
                origin
            })
            .map_err(|_| PolicyError::InvalidHeader)?,
        );
        response_headers.insert(VARY, HeaderValue::from_static("Origin"));
        if self.allow_credentials {
            response_headers.insert(
                ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }

        let is_preflight =
            method == Method::OPTIONS && headers.contains_key(ACCESS_CONTROL_REQUEST_METHOD);
        if !is_preflight {
            return Ok(CorsDecision {
                response_headers,
                status: None,
            });
        }

        let requested_method = single_text_header(headers, ACCESS_CONTROL_REQUEST_METHOD)?
            .ok_or(PolicyError::InvalidHeader)
            .and_then(|value| {
                Method::from_bytes(value.as_bytes()).map_err(|_| PolicyError::InvalidHeader)
            })?;
        if !self.methods.contains(&requested_method) {
            return Ok(CorsDecision::rejected(StatusCode::FORBIDDEN));
        }

        let requested_headers = single_text_header(headers, ACCESS_CONTROL_REQUEST_HEADERS)?
            .map(split_csv)
            .unwrap_or_default()
            .into_iter()
            .map(|header| {
                HeaderName::from_bytes(header.as_bytes()).map_err(|_| PolicyError::InvalidHeader)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if requested_headers
            .iter()
            .any(|header| !self.headers.contains(header.as_str()))
        {
            return Ok(CorsDecision::rejected(StatusCode::FORBIDDEN));
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

    fn rejected(status: StatusCode) -> Self {
        Self {
            response_headers: HeaderMap::new(),
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

/// Minimal information sent to an external authorization policy service.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyRequest {
    /// Incoming HTTP method.
    pub method: String,
    /// Incoming URI scheme when known.
    pub scheme: Option<String>,
    /// Incoming authority when known.
    pub authority: Option<String>,
    /// Request path without a query string.
    pub path: String,
    /// Canonical request ID.
    pub request_id: String,
}

/// Successful policy-service response body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct PolicySuccess {
    subject: String,
    issuer: String,
    #[serde(default)]
    scopes: Vec<String>,
}

/// Authentication decision returned by the policy bridge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthDecision {
    /// Authentication and coarse policy checks succeeded.
    Allow(Principal),
    /// No acceptable identity was supplied.
    Unauthenticated,
    /// Identity was valid but the coarse policy denied access.
    Forbidden,
    /// The external policy service failed or violated its contract.
    Unavailable,
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

/// Converts an external policy response into a fail-closed decision.
pub fn parse_policy_response(status: StatusCode, body: &[u8]) -> AuthDecision {
    match status {
        StatusCode::OK => serde_json::from_slice::<PolicySuccess>(body)
            .ok()
            .and_then(|success| {
                Principal::new(success.subject, success.issuer, success.scopes).ok()
            })
            .map_or(AuthDecision::Unavailable, AuthDecision::Allow),
        StatusCode::UNAUTHORIZED => AuthDecision::Unauthenticated,
        StatusCode::FORBIDDEN => AuthDecision::Forbidden,
        _ => AuthDecision::Unavailable,
    }
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

#[cfg(test)]
mod tests {
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
    fn security_headers_replace_unsafe_existing_values() {
        let mut headers = HeaderMap::new();
        headers.insert("x-content-type-options", HeaderValue::from_static("unsafe"));

        apply_security_headers(&mut headers);

        assert_eq!(headers["x-content-type-options"], "nosniff");
    }

    #[test]
    fn cors_rejects_wildcard_credentials() {
        let result = CorsConfig::new(["*"], ["GET"], ["content-type"], true);

        assert!(matches!(result, Err(PolicyError::InvalidConfiguration(_))));
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
    fn policy_response_fails_closed_on_malformed_success() {
        let decision = parse_policy_response(StatusCode::OK, br#"{"subject":"missing"}"#);

        assert_eq!(decision, AuthDecision::Unavailable);
    }

    #[test]
    fn policy_response_builds_valid_principal() {
        let decision = parse_policy_response(
            StatusCode::OK,
            br#"{"subject":"user-1","issuer":"mock","scopes":["read"]}"#,
        );

        assert!(matches!(decision, AuthDecision::Allow(_)));
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
}
