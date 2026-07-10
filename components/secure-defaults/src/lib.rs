//! Fused production defaults for one `WASIp3` HTTP middleware boundary.
//!
//! Request handling is semantically equivalent to
//! `request-id -> security-headers -> cors -> authn-policy -> application`,
//! while requiring only one composed middleware component.

#![deny(missing_docs)]

use std::{borrow::Cow, sync::OnceLock};

use http::{
    HeaderMap, HeaderValue, Method as HttpMethod,
    header::{AUTHORIZATION, VARY},
};
use thiserror::Error;
use wasi_http_authn_runtime::{
    AuthnConfig, AuthnConfigError, AuthnOutcome, AuthnRejection, authenticate,
};
use wasi_http_metadata::{REQUEST_ID_HEADER, insert_auth_context, strip_reserved_auth_headers};
use wasi_http_middleware_component_support::{
    Header, empty_response, from_header_map, header_values, merge_header_map,
    replace_request_headers, replace_response_headers, request_headers, response_headers,
    set_header, to_header_map,
};
use wasi_http_policy_core::{CorsConfig, RequestIdPolicy, apply_security_headers};
use wasip3::{
    cli::environment::get_environment,
    http::types::{ErrorCode, Method, Request, Response},
};

#[allow(missing_docs)]
mod bindings {
    wasi_http_middleware_component_support::generate_middleware_bindings!();
}

use bindings::wasi::http::handler;

const CORS_ORIGINS: &str = "WASI_MIDDLEWARE_CORS_ORIGINS";
const CORS_METHODS: &str = "WASI_MIDDLEWARE_CORS_METHODS";
const CORS_HEADERS: &str = "WASI_MIDDLEWARE_CORS_HEADERS";
const CORS_ALLOW_CREDENTIALS: &str = "WASI_MIDDLEWARE_CORS_ALLOW_CREDENTIALS";
const VARY_HEADER: &str = "vary";
const REQUEST_ID_BYTES: usize = 16;

static CORS_CONFIG: OnceLock<Result<CorsConfig, CorsConfigError>> = OnceLock::new();
static AUTHN_CONFIG: OnceLock<Result<AuthnConfig, AuthnConfigError>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Error)]
enum CorsConfigError {
    #[error("missing CORS origin configuration")]
    MissingOrigins,
    #[error("duplicate middleware environment key")]
    DuplicateEnvironment,
    #[error("invalid CORS policy")]
    InvalidPolicy,
}

struct Component;

bindings::export!(Component with_types_in bindings);

impl bindings::exports::wasi::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let fields = request_headers(&request);
        let Ok(mut headers) = to_header_map(&fields) else {
            return controlled_response(400, Vec::new(), &HeaderMap::new(), None);
        };
        let request_id = canonical_request_id(&headers)?;
        headers.insert(
            REQUEST_ID_HEADER,
            HeaderValue::from_str(&request_id).map_err(|_| ErrorCode::InternalError(None))?,
        );

        let environment = get_environment();
        let Ok(cors) = CORS_CONFIG
            .get_or_init(|| load_cors_config(&environment))
            .as_ref()
        else {
            return controlled_response(503, retry_after(), &HeaderMap::new(), Some(&request_id));
        };
        let Ok(method) = to_http_method(&request.get_method()) else {
            return controlled_response(400, Vec::new(), &HeaderMap::new(), Some(&request_id));
        };
        let Ok(cors_decision) = cors.evaluate(&method, &headers) else {
            return controlled_response(400, Vec::new(), &HeaderMap::new(), Some(&request_id));
        };
        if let Some(status) = cors_decision.status() {
            return controlled_response(
                status.as_u16(),
                Vec::new(),
                cors_decision.response_headers(),
                Some(&request_id),
            );
        }

        let Ok(authn) = AUTHN_CONFIG
            .get_or_init(|| AuthnConfig::from_environment(&environment))
            .as_ref()
        else {
            return controlled_response(
                503,
                retry_after(),
                cors_decision.response_headers(),
                Some(&request_id),
            );
        };
        match authenticate(&headers, &request_id, authn).await {
            AuthnOutcome::Pass(context) => {
                headers.remove(AUTHORIZATION);
                strip_reserved_auth_headers(&mut headers);
                insert_auth_context(&mut headers, &context)
                    .map_err(|_| ErrorCode::InternalError(None))?;
                headers.insert(
                    REQUEST_ID_HEADER,
                    HeaderValue::from_str(&request_id)
                        .map_err(|_| ErrorCode::InternalError(None))?,
                );
                let request = replace_request_headers(request, &from_header_map(&headers))?;
                let response = handler::handle(request).await?;
                finalize_response(
                    response,
                    cors_decision.response_headers(),
                    Some(&request_id),
                )
            }
            AuthnOutcome::Reject(rejection) => rejection_response(
                rejection,
                authn.service_id(),
                cors_decision.response_headers(),
                &request_id,
            ),
            _ => rejection_response(
                AuthnRejection::Unavailable,
                authn.service_id(),
                cors_decision.response_headers(),
                &request_id,
            ),
        }
    }
}

fn load_cors_config(environment: &[(String, String)]) -> Result<CorsConfig, CorsConfigError> {
    let origins =
        environment_value(environment, CORS_ORIGINS)?.ok_or(CorsConfigError::MissingOrigins)?;
    let methods = environment_value(environment, CORS_METHODS)?;
    let headers = environment_value(environment, CORS_HEADERS)?;
    let allow_credentials = environment_value(environment, CORS_ALLOW_CREDENTIALS)?;
    CorsConfig::from_values(origins, methods, headers, allow_credentials)
        .map_err(|_| CorsConfigError::InvalidPolicy)
}

fn environment_value<'a>(
    environment: &'a [(String, String)],
    key: &str,
) -> Result<Option<&'a str>, CorsConfigError> {
    let mut values = environment
        .iter()
        .filter(|(name, _)| name == key)
        .map(|(_, value)| value.as_str());
    let value = values.next();
    if values.next().is_some() {
        return Err(CorsConfigError::DuplicateEnvironment);
    }
    Ok(value)
}

fn canonical_request_id(headers: &HeaderMap) -> Result<String, ErrorCode> {
    RequestIdPolicy
        .canonicalize(headers, || {
            encode_hex(&wasip3::random::random::get_random_bytes(
                REQUEST_ID_BYTES as u64,
            ))
        })
        .map_err(|_| ErrorCode::InternalError(None))
}

fn rejection_response(
    rejection: AuthnRejection,
    realm: &str,
    cors_headers: &HeaderMap,
    request_id: &str,
) -> Result<Response, ErrorCode> {
    let mut headers = Vec::<Header>::new();
    if let Some(challenge) = rejection.bearer_challenge(realm) {
        headers.push(("www-authenticate".to_owned(), challenge.into_bytes()));
    }
    if rejection == AuthnRejection::Unavailable {
        headers.extend(retry_after());
    }
    controlled_response(rejection.status(), headers, cors_headers, Some(request_id))
}

fn controlled_response(
    status: u16,
    headers: Vec<Header>,
    cors_headers: &HeaderMap,
    request_id: Option<&str>,
) -> Result<Response, ErrorCode> {
    let response = empty_response(status, headers)?;
    finalize_response(response, cors_headers, request_id)
}

fn finalize_response(
    response: Response,
    cors_headers: &HeaderMap,
    request_id: Option<&str>,
) -> Result<Response, ErrorCode> {
    let fields = response_headers(&response);
    let mut headers =
        to_header_map(&fields).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
    strip_reserved_auth_headers(&mut headers);
    apply_security_headers(&mut headers);
    if let Some(request_id) = request_id {
        headers.insert(
            REQUEST_ID_HEADER,
            HeaderValue::from_str(request_id).map_err(|_| ErrorCode::InternalError(None))?,
        );
    }
    let mut fields = from_header_map(&headers);
    merge_cors_headers(&mut fields, cors_headers);
    replace_response_headers(response, &fields)
}

fn retry_after() -> Vec<Header> {
    vec![("retry-after".to_owned(), b"1".to_vec())]
}

fn to_http_method(method: &Method) -> Result<HttpMethod, ()> {
    let value: Cow<'_, str> = match method {
        Method::Get => Cow::Borrowed("GET"),
        Method::Head => Cow::Borrowed("HEAD"),
        Method::Post => Cow::Borrowed("POST"),
        Method::Put => Cow::Borrowed("PUT"),
        Method::Delete => Cow::Borrowed("DELETE"),
        Method::Connect => Cow::Borrowed("CONNECT"),
        Method::Options => Cow::Borrowed("OPTIONS"),
        Method::Trace => Cow::Borrowed("TRACE"),
        Method::Patch => Cow::Borrowed("PATCH"),
        Method::Other(value) => Cow::Borrowed(value),
    };
    HttpMethod::from_bytes(value.as_bytes()).map_err(|_| ())
}

fn merge_cors_headers(target: &mut Vec<Header>, source: &HeaderMap) {
    let has_vary = source.contains_key(VARY);
    let mut source_without_vary = source.clone();
    source_without_vary.remove(VARY);
    merge_header_map(target, &source_without_vary);
    if has_vary {
        merge_vary_origin(target);
    }
}

fn merge_vary_origin(headers: &mut Vec<Header>) {
    let mut tokens = Vec::<String>::new();
    for value in header_values(headers, VARY_HEADER) {
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
                set_header(headers, VARY_HEADER, b"*".as_slice());
                return;
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
    set_header(headers, VARY_HEADER, tokens.join(", ").into_bytes());
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cors_configuration_is_required() {
        assert!(matches!(
            load_cors_config(&[]),
            Err(CorsConfigError::MissingOrigins)
        ));
    }

    #[test]
    fn vary_merge_preserves_downstream_cache_keys() {
        let mut headers = vec![("vary".to_owned(), b"Accept-Encoding".to_vec())];
        merge_vary_origin(&mut headers);
        assert_eq!(
            headers,
            vec![("vary".to_owned(), b"Accept-Encoding, Origin".to_vec())]
        );
    }

    #[test]
    fn request_id_hex_encoding_is_lowercase_and_fixed_width() {
        assert_eq!(encode_hex(&[0, 15, 16, 255]), "000f10ff");
    }
}
