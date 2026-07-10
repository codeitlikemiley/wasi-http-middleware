//! Fail-closed authentication backed by an external policy service.

#![deny(missing_docs)]

use std::{borrow::Cow, sync::OnceLock};

use http::{HeaderMap, HeaderValue, StatusCode, Uri};
use thiserror::Error;
use wasi_http_metadata::{REQUEST_ID_HEADER, insert_principal, strip_reserved_auth_headers};
use wasi_http_middleware_component_support::{
    Header, empty_response, from_header_map, replace_request_headers, request_headers,
    to_header_map,
};
use wasi_http_policy_core::{
    AuthDecision, PolicyRequest, RequestIdPolicy, authorization_value, normalize_policy_path,
    parse_policy_response,
};
use wasip3::{
    cli::environment::get_environment,
    clocks::monotonic_clock,
    http::{
        client,
        types::{ErrorCode, Headers, Method, Request, RequestOptions, Response, Scheme},
    },
    wit_future, wit_stream,
};
use wit_bindgen::StreamResult;

#[allow(missing_docs)]
mod bindings {
    wasi_http_middleware_component_support::generate_middleware_bindings!();
}

use bindings::wasi::http::handler;

const POLICY_URL: &str = "WASI_MIDDLEWARE_POLICY_URL";
const POLICY_TIMEOUT_MS: &str = "WASI_MIDDLEWARE_POLICY_TIMEOUT_MS";
const DEFAULT_TIMEOUT_MS: u64 = 2_000;
const MAX_TIMEOUT_MS: u64 = 60_000;
const MAX_POLICY_RESPONSE_SIZE: usize = 64 * 1024;
const REQUEST_ID_BYTES: usize = 16;

static CONFIG: OnceLock<Result<AuthConfig, ConfigError>> = OnceLock::new();

#[derive(Clone, Debug)]
struct AuthConfig {
    scheme: Scheme,
    authority: String,
    path_with_query: String,
    timeout_ns: u64,
}

#[derive(Clone, Copy, Debug, Error)]
enum ConfigError {
    #[error("missing policy URL")]
    MissingPolicyUrl,
    #[error("invalid policy URL")]
    InvalidPolicyUrl,
    #[error("invalid policy timeout")]
    InvalidTimeout,
    #[error("duplicate middleware environment key")]
    DuplicateEnvironment,
}

#[derive(Clone, Copy, Debug, Error)]
enum PolicyCallError {
    #[error("policy request serialization failed")]
    Serialization,
    #[error("policy request construction failed")]
    RequestConstruction,
    #[error("policy transport failed")]
    Transport,
    #[error("policy response status was invalid")]
    InvalidStatus,
    #[error("policy response body failed")]
    ResponseBody,
    #[error("policy deadline elapsed")]
    Deadline,
}

struct Component;

bindings::export!(Component with_types_in bindings);

impl bindings::exports::wasi::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let config = CONFIG
            .get_or_init(|| load_config(&get_environment()))
            .as_ref()
            .map_err(|_| ErrorCode::ConfigurationError)?;
        let fields = request_headers(&request);
        let Ok(mut headers) = to_header_map(&fields) else {
            return empty_response(400, Vec::new());
        };
        let request_id = match canonical_request_id(&headers) {
            Ok(request_id) => request_id,
            Err(error) => return Err(error),
        };
        let authorization = match authorization_value(&headers) {
            Ok(value) => value.map(str::to_owned),
            Err(_) => return rejection_response(400, &request_id),
        };

        strip_reserved_auth_headers(&mut headers);
        headers.insert(
            REQUEST_ID_HEADER,
            HeaderValue::from_str(&request_id).map_err(|_| ErrorCode::InternalError(None))?,
        );

        let Ok(policy_request) = policy_request_for(&request, &request_id) else {
            return rejection_response(400, &request_id);
        };
        let decision = match call_policy(config, &policy_request, authorization.as_deref()).await {
            Ok(decision) => decision,
            Err(_error) => AuthDecision::Unavailable,
        };

        match decision {
            AuthDecision::Allow(principal) => {
                insert_principal(&mut headers, &principal)
                    .map_err(|_| ErrorCode::InternalError(None))?;
                let canonical_fields = from_header_map(&headers);
                let request = replace_request_headers(request, &canonical_fields)?;
                handler::handle(request).await
            }
            AuthDecision::Unauthenticated => rejection_response(401, &request_id),
            AuthDecision::Forbidden => rejection_response(403, &request_id),
            AuthDecision::Unavailable => rejection_response(503, &request_id),
        }
    }
}

fn load_config(environment: &[(String, String)]) -> Result<AuthConfig, ConfigError> {
    let policy_url =
        environment_value(environment, POLICY_URL)?.ok_or(ConfigError::MissingPolicyUrl)?;
    if policy_url.len() > 2_048 {
        return Err(ConfigError::InvalidPolicyUrl);
    }
    let uri = policy_url
        .parse::<Uri>()
        .map_err(|_| ConfigError::InvalidPolicyUrl)?;
    let scheme = match uri.scheme_str() {
        Some("http") => Scheme::Http,
        Some("https") => Scheme::Https,
        _ => return Err(ConfigError::InvalidPolicyUrl),
    };
    let authority = uri
        .authority()
        .ok_or(ConfigError::InvalidPolicyUrl)?
        .as_str()
        .to_owned();
    let path_with_query = uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str)
        .to_owned();
    let timeout_ms = environment_value(environment, POLICY_TIMEOUT_MS)?
        .map(str::parse::<u64>)
        .transpose()
        .map_err(|_| ConfigError::InvalidTimeout)?
        .unwrap_or(DEFAULT_TIMEOUT_MS);
    if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
        return Err(ConfigError::InvalidTimeout);
    }

    Ok(AuthConfig {
        scheme,
        authority,
        path_with_query,
        timeout_ns: timeout_ms.saturating_mul(1_000_000),
    })
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

fn canonical_request_id(headers: &HeaderMap) -> Result<String, ErrorCode> {
    RequestIdPolicy
        .canonicalize(headers, || {
            encode_hex(&wasip3::random::random::get_random_bytes(
                REQUEST_ID_BYTES as u64,
            ))
        })
        .map_err(|_| ErrorCode::InternalError(None))
}

fn policy_request_for(request: &Request, request_id: &str) -> Result<PolicyRequest, ()> {
    let method_value = request.get_method();
    let method = method_text(&method_value).into_owned();
    let scheme = request
        .get_scheme()
        .map(|scheme| scheme_text(&scheme).into_owned());
    let authority = request.get_authority();
    let path_with_query = request
        .get_path_with_query()
        .unwrap_or_else(|| "/".to_owned());
    let path = normalize_policy_path(&path_with_query).map_err(|_| ())?;

    Ok(PolicyRequest {
        method,
        scheme,
        authority,
        path,
        request_id: request_id.to_owned(),
    })
}

async fn call_policy(
    config: &AuthConfig,
    policy_request: &PolicyRequest,
    authorization: Option<&str>,
) -> Result<AuthDecision, PolicyCallError> {
    let started = monotonic_clock::now();
    let body = serde_json::to_vec(policy_request).map_err(|_| PolicyCallError::Serialization)?;
    let request =
        build_policy_http_request(config, body, authorization, &policy_request.request_id)
            .map_err(|_| PolicyCallError::RequestConstruction)?;
    let response = client::send(request)
        .await
        .map_err(|_| PolicyCallError::Transport)?;
    if deadline_expired(started, config.timeout_ns) {
        return Err(PolicyCallError::Deadline);
    }
    let status = StatusCode::from_u16(response.get_status_code())
        .map_err(|_| PolicyCallError::InvalidStatus)?;
    let body = collect_policy_response(response, started, config.timeout_ns).await?;
    Ok(parse_policy_response(status, &body))
}

fn build_policy_http_request(
    config: &AuthConfig,
    body: Vec<u8>,
    authorization: Option<&str>,
    request_id: &str,
) -> Result<Request, ErrorCode> {
    let mut fields = vec![
        ("accept".to_owned(), b"application/json".to_vec()),
        ("content-type".to_owned(), b"application/json".to_vec()),
        (
            "content-length".to_owned(),
            body.len().to_string().into_bytes(),
        ),
        (
            REQUEST_ID_HEADER.as_str().to_owned(),
            request_id.as_bytes().to_vec(),
        ),
    ];
    if let Some(authorization) = authorization {
        fields.push((
            "authorization".to_owned(),
            authorization.as_bytes().to_vec(),
        ));
    }
    let headers =
        Headers::from_list(&fields).map_err(|_| ErrorCode::HttpRequestHeaderSectionSize(None))?;
    let (mut body_writer, body_reader) = wit_stream::new();
    wit_bindgen::spawn(async move {
        let remaining = body_writer.write_all(body).await;
        drop(remaining);
    });
    let (trailers_writer, trailers) = wit_future::new(|| Ok(None));
    drop(trailers_writer);

    let options = RequestOptions::new();
    options
        .set_connect_timeout(Some(config.timeout_ns))
        .and_then(|()| options.set_first_byte_timeout(Some(config.timeout_ns)))
        .and_then(|()| options.set_between_bytes_timeout(Some(config.timeout_ns)))
        .map_err(|_| ErrorCode::ConfigurationError)?;
    let (request, _transmission_result) =
        Request::new(headers, Some(body_reader), trailers, Some(options));
    request
        .set_method(&Method::Post)
        .and_then(|()| request.set_scheme(Some(&config.scheme)))
        .and_then(|()| request.set_authority(Some(&config.authority)))
        .and_then(|()| request.set_path_with_query(Some(&config.path_with_query)))
        .map_err(|()| ErrorCode::ConfigurationError)?;
    Ok(request)
}

async fn collect_policy_response(
    response: Response,
    started: u64,
    timeout_ns: u64,
) -> Result<Vec<u8>, PolicyCallError> {
    let (result_writer, body_result) = wit_future::new(|| Ok(()));
    drop(result_writer);
    let (mut body, trailers) = Response::consume_body(response, body_result);
    let mut output = Vec::new();

    loop {
        let (status, chunk) = body.read(Vec::with_capacity(8 * 1024)).await;
        if output.len().saturating_add(chunk.len()) > MAX_POLICY_RESPONSE_SIZE {
            return Err(PolicyCallError::ResponseBody);
        }
        output.extend_from_slice(&chunk);
        if deadline_expired(started, timeout_ns) {
            return Err(PolicyCallError::Deadline);
        }
        match status {
            StreamResult::Complete(_) => {}
            StreamResult::Dropped => {
                let _trailers = trailers.await.map_err(|_| PolicyCallError::ResponseBody)?;
                return Ok(output);
            }
            StreamResult::Cancelled => return Err(PolicyCallError::ResponseBody),
        }
    }
}

fn deadline_expired(started: u64, timeout_ns: u64) -> bool {
    monotonic_clock::now().saturating_sub(started) >= timeout_ns
}

fn rejection_response(status: u16, request_id: &str) -> Result<Response, ErrorCode> {
    let mut headers: Vec<Header> = vec![(
        REQUEST_ID_HEADER.as_str().to_owned(),
        request_id.as_bytes().to_vec(),
    )];
    if status == 401 {
        headers.push(("www-authenticate".to_owned(), b"Bearer".to_vec()));
    }
    empty_response(status, headers)
}

fn method_text(method: &Method) -> Cow<'_, str> {
    match method {
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
    }
}

fn scheme_text(scheme: &Scheme) -> Cow<'_, str> {
    match scheme {
        Scheme::Http => Cow::Borrowed("http"),
        Scheme::Https => Cow::Borrowed("https"),
        Scheme::Other(value) => Cow::Borrowed(value),
    }
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
    use super::{ConfigError, load_config};

    #[test]
    fn configuration_rejects_non_http_policy_url() {
        let environment = vec![(
            "WASI_MIDDLEWARE_POLICY_URL".to_owned(),
            "file:///policy".to_owned(),
        )];

        assert!(matches!(
            load_config(&environment),
            Err(ConfigError::InvalidPolicyUrl)
        ));
    }

    #[test]
    fn configuration_rejects_unbounded_timeout() {
        let environment = vec![
            (
                "WASI_MIDDLEWARE_POLICY_URL".to_owned(),
                "https://policy.example/check".to_owned(),
            ),
            (
                "WASI_MIDDLEWARE_POLICY_TIMEOUT_MS".to_owned(),
                "60001".to_owned(),
            ),
        ];

        assert!(matches!(
            load_config(&environment),
            Err(ConfigError::InvalidTimeout)
        ));
    }
}
