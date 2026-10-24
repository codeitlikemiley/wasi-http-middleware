//! Explicit, configuration-driven CORS middleware for `WASIp3` HTTP services.

#![deny(missing_docs)]

use std::{borrow::Cow, sync::OnceLock};

use http::Method as HttpMethod;
use thiserror::Error;
use wasi_http_middleware_component_support::{
    Header, empty_response, from_header_map, replace_response_headers, request_headers,
    response_headers, to_header_map,
};
use wasi_http_policy_core::{CorsConfig, apply_cors_headers_to_fields};
use wasip3::{
    cli::environment::get_environment,
    http::types::{ErrorCode, Method, Request, Response},
};

#[allow(unknown_lints, missing_docs, clippy::same_length_and_capacity)]
mod bindings {
    wasi_http_middleware_component_support::generate_middleware_bindings!("../../wit");
}

use bindings::wasi::http::handler;

const ORIGINS: &str = "WASI_MIDDLEWARE_CORS_ORIGINS";
const METHODS: &str = "WASI_MIDDLEWARE_CORS_METHODS";
const HEADERS: &str = "WASI_MIDDLEWARE_CORS_HEADERS";
const ALLOW_CREDENTIALS: &str = "WASI_MIDDLEWARE_CORS_ALLOW_CREDENTIALS";

static CONFIG: OnceLock<Result<CorsConfig, ConfigError>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Error)]
enum ConfigError {
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
        let Ok(config) = CONFIG
            .get_or_init(|| load_config(&get_environment()))
            .as_ref()
        else {
            return empty_response(503, vec![("retry-after".to_owned(), b"1".to_vec())]);
        };
        let headers = request_headers(&request);
        let Ok(header_map) = to_header_map(&headers) else {
            return empty_response(400, Vec::new());
        };
        let Ok(method) = to_http_method(&request.get_method()) else {
            return empty_response(400, Vec::new());
        };
        let Ok(decision) = config.evaluate(&method, &header_map) else {
            return empty_response(400, Vec::new());
        };

        if let Some(status) = decision.status() {
            return empty_response(
                status.as_u16(),
                from_header_map(decision.response_headers()),
            );
        }

        let response = handler::handle(request).await?;
        if decision.response_headers().is_empty() {
            return Ok(response);
        }

        let mut response_fields = response_headers(&response);
        merge_cors_headers(&mut response_fields, decision.response_headers());
        replace_response_headers(response, &response_fields)
    }
}

fn load_config(environment: &[(String, String)]) -> Result<CorsConfig, ConfigError> {
    let origins = environment_value(environment, ORIGINS)?.ok_or(ConfigError::MissingOrigins)?;
    let methods = environment_value(environment, METHODS)?;
    let headers = environment_value(environment, HEADERS)?;
    let allow_credentials = environment_value(environment, ALLOW_CREDENTIALS)?;
    CorsConfig::from_values(origins, methods, headers, allow_credentials)
        .map_err(|_| ConfigError::InvalidPolicy)
}

fn environment_value<'a>(
    environment: &'a [(String, String)],
    key: &str,
) -> Result<Option<&'a str>, ConfigError> {
    let mut values = environment
        .iter()
        .filter(|(name, _)| name == key)
        .map(|(_, value)| value.as_str());
    let value = values.next();
    if values.next().is_some() {
        return Err(ConfigError::DuplicateEnvironment);
    }
    Ok(value)
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

fn merge_cors_headers(target: &mut Vec<Header>, source: &http::HeaderMap) {
    apply_cors_headers_to_fields(target, source);
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, header};

    use super::{ConfigError, load_config, merge_cors_headers};

    #[test]
    fn configuration_rejects_duplicate_environment_keys() {
        let environment = vec![
            (
                "WASI_MIDDLEWARE_CORS_ORIGINS".to_owned(),
                "https://one.example".to_owned(),
            ),
            (
                "WASI_MIDDLEWARE_CORS_ORIGINS".to_owned(),
                "https://two.example".to_owned(),
            ),
        ];

        assert!(matches!(
            load_config(&environment),
            Err(ConfigError::DuplicateEnvironment)
        ));
    }

    #[test]
    fn vary_merge_preserves_downstream_cache_keys() {
        let mut headers = vec![("vary".to_owned(), b"Accept-Encoding".to_vec())];

        merge_cors_headers(&mut headers, &vary_origin());

        assert_eq!(
            headers,
            vec![("vary".to_owned(), b"Accept-Encoding, Origin".to_vec())]
        );
    }

    #[test]
    fn vary_wildcard_is_not_narrowed() {
        let mut headers = vec![("vary".to_owned(), b"*".to_vec())];

        merge_cors_headers(&mut headers, &vary_origin());

        assert_eq!(headers, vec![("vary".to_owned(), b"*".to_vec())]);
    }

    #[test]
    fn merge_leaves_a_downstream_cors_policy_in_place() {
        let mut headers = vec![
            (
                "access-control-allow-origin".to_owned(),
                b"https://auth.example".to_vec(),
            ),
            ("vary".to_owned(), b"Accept-Encoding".to_vec()),
        ];
        let mut decision = vary_origin();
        decision.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("https://app.example"),
        );
        decision.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );

        merge_cors_headers(&mut headers, &decision);

        assert_eq!(
            headers,
            vec![
                (
                    "access-control-allow-origin".to_owned(),
                    b"https://auth.example".to_vec(),
                ),
                ("vary".to_owned(), b"Accept-Encoding, Origin".to_vec()),
            ]
        );
    }

    fn vary_origin() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
        headers
    }
}
