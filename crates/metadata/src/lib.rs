//! Trusted metadata shared by WASI HTTP middleware and terminal services.
//!
//! The headers in this crate are trustworthy only when an application is
//! reachable exclusively through a composed middleware chain that removes
//! client-supplied values before inserting canonical metadata.

use http::{HeaderMap, HeaderName, HeaderValue};
use thiserror::Error;

/// Request correlation header used by the middleware chain.
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
/// Canonical authenticated subject header.
pub const AUTH_SUBJECT_HEADER: HeaderName = HeaderName::from_static("x-wasi-auth-subject");
/// Canonical identity issuer header.
pub const AUTH_ISSUER_HEADER: HeaderName = HeaderName::from_static("x-wasi-auth-issuer");
/// Canonical space-separated scope header.
pub const AUTH_SCOPES_HEADER: HeaderName = HeaderName::from_static("x-wasi-auth-scopes");

const RESERVED_AUTH_PREFIX: &str = "x-wasi-auth-";
const MAX_IDENTITY_VALUE_LEN: usize = 256;
const MAX_SCOPE_VALUE_LEN: usize = 2_048;

/// A validated identity produced by authentication middleware.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principal {
    subject: String,
    issuer: String,
    scopes: Vec<String>,
}

impl Principal {
    /// Validates and constructs a principal.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError`] when an identity field cannot safely be
    /// represented in the canonical header contract.
    pub fn new(
        subject: impl Into<String>,
        issuer: impl Into<String>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, MetadataError> {
        let subject = subject.into();
        let issuer = issuer.into();
        validate_identity_value("subject", &subject)?;
        validate_identity_value("issuer", &issuer)?;

        let scopes = scopes.into_iter().map(Into::into).collect::<Vec<_>>();
        if scopes.iter().any(|scope| !is_scope_token(scope)) {
            return Err(MetadataError::InvalidScopes);
        }
        let encoded_len =
            scopes.iter().map(String::len).sum::<usize>() + scopes.len().saturating_sub(1);
        if encoded_len > MAX_SCOPE_VALUE_LEN {
            return Err(MetadataError::InvalidScopes);
        }

        Ok(Self {
            subject,
            issuer,
            scopes,
        })
    }

    /// Returns the authenticated subject.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the trusted issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the validated scope tokens.
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
}

/// Errors produced while validating trusted identity metadata.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum MetadataError {
    /// An identity value was empty, too long, or contained unsafe bytes.
    #[error("invalid authentication {field}")]
    InvalidIdentityValue {
        /// Name of the invalid field.
        field: &'static str,
    },
    /// Scope tokens were malformed or exceeded the encoded size limit.
    #[error("invalid authentication scopes")]
    InvalidScopes,
    /// A canonical header appeared more than once.
    #[error("duplicate trusted metadata header: {0}")]
    DuplicateHeader(&'static str),
    /// A required canonical header was absent.
    #[error("missing trusted metadata header: {0}")]
    MissingHeader(&'static str),
    /// A canonical header contained invalid text.
    #[error("invalid trusted metadata header: {0}")]
    InvalidHeader(&'static str),
}

/// Removes every header reserved for trusted authentication metadata.
pub fn strip_reserved_auth_headers(headers: &mut HeaderMap) {
    let reserved = headers
        .keys()
        .filter(|name| name.as_str().starts_with(RESERVED_AUTH_PREFIX))
        .cloned()
        .collect::<Vec<_>>();
    for name in reserved {
        headers.remove(name);
    }
}

/// Inserts a validated principal into an HTTP header map.
///
/// Existing reserved authentication headers are removed first.
///
/// # Errors
///
/// Returns [`MetadataError`] if a validated value unexpectedly cannot be
/// encoded as an HTTP header.
pub fn insert_principal(
    headers: &mut HeaderMap,
    principal: &Principal,
) -> Result<(), MetadataError> {
    strip_reserved_auth_headers(headers);
    let subject = HeaderValue::from_str(principal.subject())
        .map_err(|_| MetadataError::InvalidHeader("subject"))?;
    let issuer = HeaderValue::from_str(principal.issuer())
        .map_err(|_| MetadataError::InvalidHeader("issuer"))?;
    let scopes = HeaderValue::from_str(&principal.scopes().join(" "))
        .map_err(|_| MetadataError::InvalidHeader("scopes"))?;
    headers.insert(AUTH_SUBJECT_HEADER, subject);
    headers.insert(AUTH_ISSUER_HEADER, issuer);
    headers.insert(AUTH_SCOPES_HEADER, scopes);
    Ok(())
}

/// Parses canonical identity headers into a validated principal.
///
/// # Errors
///
/// Returns [`MetadataError`] for missing, duplicate, non-text, or invalid
/// canonical identity values.
pub fn parse_principal(headers: &HeaderMap) -> Result<Principal, MetadataError> {
    let subject = one_header(headers, &AUTH_SUBJECT_HEADER, "subject")?;
    let issuer = one_header(headers, &AUTH_ISSUER_HEADER, "issuer")?;
    let scopes = one_header(headers, &AUTH_SCOPES_HEADER, "scopes")?;
    Principal::new(subject, issuer, scopes.split_whitespace())
}

fn one_header<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
    label: &'static str,
) -> Result<&'a str, MetadataError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(MetadataError::MissingHeader(label))?;
    if values.next().is_some() {
        return Err(MetadataError::DuplicateHeader(label));
    }
    value
        .to_str()
        .map_err(|_| MetadataError::InvalidHeader(label))
}

fn validate_identity_value(field: &'static str, value: &str) -> Result<(), MetadataError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_IDENTITY_VALUE_LEN
        && value.bytes().all(|byte| matches!(byte, 0x21..=0x7e));
    if valid {
        Ok(())
    } else {
        Err(MetadataError::InvalidIdentityValue { field })
    }
}

fn is_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= 128
        && scope.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_reserved_headers_removes_unknown_reserved_names() {
        let mut headers = HeaderMap::new();
        headers.insert("x-wasi-auth-spoofed", HeaderValue::from_static("yes"));
        headers.insert("x-unrelated", HeaderValue::from_static("kept"));

        strip_reserved_auth_headers(&mut headers);

        assert!(headers.contains_key("x-unrelated"));
        assert!(!headers.contains_key("x-wasi-auth-spoofed"));
    }

    #[test]
    fn principal_round_trips_through_headers() {
        let principal =
            Principal::new("user-1", "issuer.example", ["read", "write"]).expect("valid fixture");
        let mut headers = HeaderMap::new();
        insert_principal(&mut headers, &principal).expect("valid fixture");

        assert_eq!(parse_principal(&headers), Ok(principal));
    }

    #[test]
    fn principal_rejects_header_injection() {
        let error =
            Principal::new("user\r\nadmin", "issuer", ["read"]).expect_err("CRLF must be rejected");

        assert_eq!(
            error,
            MetadataError::InvalidIdentityValue { field: "subject" }
        );
    }

    #[test]
    fn parser_rejects_duplicate_subject() {
        let mut headers = HeaderMap::new();
        headers.append(AUTH_SUBJECT_HEADER, HeaderValue::from_static("one"));
        headers.append(AUTH_SUBJECT_HEADER, HeaderValue::from_static("two"));
        headers.insert(AUTH_ISSUER_HEADER, HeaderValue::from_static("issuer"));
        headers.insert(AUTH_SCOPES_HEADER, HeaderValue::from_static("read"));

        assert_eq!(
            parse_principal(&headers),
            Err(MetadataError::DuplicateHeader("subject"))
        );
    }
}
