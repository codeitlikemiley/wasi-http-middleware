//! Fused production defaults for one `WASIp3` HTTP middleware boundary.
//!
//! Request handling is semantically equivalent to
//! `request-id -> security-headers -> cors -> authn-policy -> application`,
//! while requiring only one composed middleware component.

#![deny(missing_docs)]

use std::{borrow::Cow, sync::OnceLock};

use http::{
    HeaderMap, HeaderName, HeaderValue, Method as HttpMethod,
    header::{
        ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, AUTHORIZATION, ORIGIN,
    },
};
use thiserror::Error;
use wasi_http_authn_runtime::{
    AuthnConfig, AuthnConfigError, AuthnOutcome, AuthnRejection, authenticate_with_diagnostics,
};
use wasi_http_metadata::{AUTH_CONTEXT_HEADER, REQUEST_ID_HEADER};
use wasi_http_middleware_component_support::{
    Header, diagnostic_stage, edit_request_headers, edit_response_headers_from_original,
    empty_response, generated_request_id, header_values, request_headers,
};
use wasi_http_policy_core::{
    CorsConfig, absent_security_header_fields, canonicalize_request_id_bytes, cors_field_edits,
};
use wasip3::{
    cli::environment::get_environment,
    http::types::{ErrorCode, Method, Request, Response},
};

#[allow(unknown_lints, missing_docs, clippy::same_length_and_capacity)]
mod bindings {
    wasi_http_middleware_component_support::generate_middleware_bindings!("../../wit");
}

use bindings::wasi::http::handler;

const CORS_ORIGINS: &str = "WASI_MIDDLEWARE_CORS_ORIGINS";
const CORS_METHODS: &str = "WASI_MIDDLEWARE_CORS_METHODS";
const CORS_HEADERS: &str = "WASI_MIDDLEWARE_CORS_HEADERS";
const CORS_ALLOW_CREDENTIALS: &str = "WASI_MIDDLEWARE_CORS_ALLOW_CREDENTIALS";
const VARY_HEADER: &str = "vary";
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
        let Ok(headers) = policy_headers(&fields) else {
            return controlled_response(400, Vec::new(), &HeaderMap::new(), None);
        };
        let request_id = canonical_request_id(&fields)?;

        let Ok(cors) = CORS_CONFIG
            .get_or_init(|| load_cors_config(&get_environment()))
            .as_ref()
        else {
            diagnostic_stage("secure_defaults_cors_config");
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
            .get_or_init(|| AuthnConfig::from_environment(&get_environment()))
            .as_ref()
        else {
            diagnostic_stage("secure_defaults_authn_config");
            return controlled_response(
                503,
                retry_after(),
                cors_decision.response_headers(),
                Some(&request_id),
            );
        };
        let (outcome, stage) = authenticate_with_diagnostics(&headers, &request_id, authn).await;
        if let Some(stage) = stage {
            diagnostic_stage(stage.as_str());
        }
        match outcome {
            AuthnOutcome::Pass(context) => {
                let mut delete_names = Vec::new();
                if fields
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case(AUTHORIZATION.as_str()))
                {
                    delete_names.push(AUTHORIZATION.as_str());
                }
                delete_names.extend(fields.iter().filter_map(|(name, _)| {
                    name.get(.."x-wasi-auth-".len())
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("x-wasi-auth-"))
                        .then_some(name.as_str())
                }));
                let auth_context_header = AUTH_CONTEXT_HEADER;
                let request_id_header = REQUEST_ID_HEADER;
                let replacements = [
                    (auth_context_header.as_str(), context.as_bytes()),
                    (request_id_header.as_str(), request_id.as_bytes()),
                ];
                let request = edit_request_headers(request, &delete_names, &replacements)?;
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

fn canonical_request_id(headers: &[Header]) -> Result<String, ErrorCode> {
    canonicalize_request_id_bytes(
        header_values(headers, REQUEST_ID_HEADER.as_str()),
        generated_request_id,
    )
    .map_err(|_| ErrorCode::InternalError(None))
}

fn policy_headers(fields: &[Header]) -> Result<HeaderMap, ()> {
    let mut headers = HeaderMap::new();
    for (name, value) in fields {
        let selected: Option<HeaderName> = if name.eq_ignore_ascii_case(AUTHORIZATION.as_str()) {
            Some(AUTHORIZATION)
        } else if name.eq_ignore_ascii_case(ORIGIN.as_str()) {
            Some(ORIGIN)
        } else if name.eq_ignore_ascii_case(ACCESS_CONTROL_REQUEST_METHOD.as_str()) {
            Some(ACCESS_CONTROL_REQUEST_METHOD)
        } else if name.eq_ignore_ascii_case(ACCESS_CONTROL_REQUEST_HEADERS.as_str()) {
            Some(ACCESS_CONTROL_REQUEST_HEADERS)
        } else {
            None
        };
        let Some(selected) = selected else {
            continue;
        };
        let mut value = HeaderValue::from_bytes(value).map_err(|_| ())?;
        if selected == AUTHORIZATION {
            value.set_sensitive(true);
        }
        headers.append(selected, value);
    }
    Ok(headers)
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
    let original_headers = response.get_headers();
    let original_fields = original_headers.copy_all();
    let delete_names = original_fields
        .iter()
        .filter_map(|(name, _)| {
            name.get(.."x-wasi-auth-".len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("x-wasi-auth-"))
                .then_some(name.as_str())
        })
        .collect::<Vec<_>>();
    let security =
        absent_security_header_fields(original_fields.iter().map(|(name, _)| name.as_str()));
    let cors_replacements = cors_replacements(&original_fields, cors_headers);
    let request_id_header = REQUEST_ID_HEADER;
    let mut replacements = security
        .iter()
        .map(|(name, value)| (*name, value.as_bytes()))
        .collect::<Vec<_>>();
    if let Some(request_id) = request_id {
        replacements.push((request_id_header.as_str(), request_id.as_bytes()));
    }
    replacements.extend(
        cors_replacements
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice())),
    );
    edit_response_headers_from_original(response, original_headers, &delete_names, &replacements)
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

fn cors_replacements(original: &[Header], source: &HeaderMap) -> Vec<Header> {
    let edits = cors_field_edits(
        original
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice())),
        source,
    );
    let mut replacements = edits.access_control;
    if let Some(vary) = edits.vary {
        replacements.push((VARY_HEADER.to_owned(), vary));
    }
    replacements
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, header};

    use super::{CorsConfigError, cors_replacements, load_cors_config};

    #[test]
    fn cors_configuration_is_required() {
        assert!(matches!(
            load_cors_config(&[]),
            Err(CorsConfigError::MissingOrigins)
        ));
    }

    #[test]
    fn vary_merge_preserves_downstream_cache_keys() {
        let headers = vec![("vary".to_owned(), b"Accept-Encoding".to_vec())];
        let mut source = HeaderMap::new();
        source.insert(header::VARY, HeaderValue::from_static("Origin"));

        assert_eq!(
            cors_replacements(&headers, &source),
            vec![("vary".to_owned(), b"Accept-Encoding, Origin".to_vec())]
        );
    }

    #[test]
    fn cors_replacements_leave_a_downstream_policy_in_place() {
        let headers = vec![
            ("referrer-policy".to_owned(), b"same-origin".to_vec()),
            (
                "access-control-allow-origin".to_owned(),
                b"https://auth.example".to_vec(),
            ),
            ("vary".to_owned(), b"Accept-Encoding".to_vec()),
        ];
        let mut source = HeaderMap::new();
        source.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("https://app.example"),
        );
        source.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        source.insert(header::VARY, HeaderValue::from_static("Origin"));

        assert_eq!(
            cors_replacements(&headers, &source),
            vec![("vary".to_owned(), b"Accept-Encoding, Origin".to_vec())]
        );
    }
}
