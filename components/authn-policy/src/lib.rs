//! Strict fail-closed authentication backed by an external broker.

#![deny(missing_docs)]

use std::sync::OnceLock;

use http::{HeaderValue, header::AUTHORIZATION};
use wasi_http_authn_runtime::{
    AuthnConfig, AuthnConfigError, AuthnOutcome, AuthnRejection, authenticate,
};
use wasi_http_metadata::{REQUEST_ID_HEADER, insert_auth_context, strip_reserved_auth_headers};
use wasi_http_middleware_component_support::{
    Header, empty_response, from_header_map, replace_request_headers, replace_response_headers,
    request_headers, response_headers, to_header_map,
};
use wasi_http_policy_core::RequestIdPolicy;
use wasip3::{
    cli::environment::get_environment,
    http::types::{ErrorCode, Request, Response},
};

#[allow(missing_docs)]
mod bindings {
    wasi_http_middleware_component_support::generate_middleware_bindings!("../../wit");
}

use bindings::wasi::http::handler;

const REQUEST_ID_BYTES: usize = 16;

static CONFIG: OnceLock<Result<AuthnConfig, AuthnConfigError>> = OnceLock::new();

struct Component;

bindings::export!(Component with_types_in bindings);

impl bindings::exports::wasi::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let fields = request_headers(&request);
        let Ok(mut headers) = to_header_map(&fields) else {
            return empty_response(400, Vec::new());
        };
        let request_id = canonical_request_id(&headers)?;
        let Ok(config) = CONFIG
            .get_or_init(|| AuthnConfig::from_environment(&get_environment()))
            .as_ref()
        else {
            return configuration_failure_response(&request_id);
        };

        match authenticate(&headers, &request_id, config).await {
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
                strip_response_auth_headers(response)
            }
            AuthnOutcome::Reject(rejection) => {
                rejection_response(rejection, config.service_id(), &request_id)
            }
            _ => rejection_response(
                AuthnRejection::Unavailable,
                config.service_id(),
                &request_id,
            ),
        }
    }
}

fn strip_response_auth_headers(response: Response) -> Result<Response, ErrorCode> {
    let fields = response_headers(&response);
    let mut headers =
        to_header_map(&fields).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
    strip_reserved_auth_headers(&mut headers);
    replace_response_headers(response, &from_header_map(&headers))
}

fn configuration_failure_response(request_id: &str) -> Result<Response, ErrorCode> {
    empty_response(
        503,
        vec![
            (
                REQUEST_ID_HEADER.as_str().to_owned(),
                request_id.as_bytes().to_vec(),
            ),
            ("retry-after".to_owned(), b"1".to_vec()),
        ],
    )
}

fn canonical_request_id(headers: &http::HeaderMap) -> Result<String, ErrorCode> {
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
    request_id: &str,
) -> Result<Response, ErrorCode> {
    let mut headers: Vec<Header> = vec![(
        REQUEST_ID_HEADER.as_str().to_owned(),
        request_id.as_bytes().to_vec(),
    )];
    if let Some(challenge) = rejection.bearer_challenge(realm) {
        headers.push(("www-authenticate".to_owned(), challenge.into_bytes()));
    }
    if rejection == AuthnRejection::Unavailable {
        headers.push(("retry-after".to_owned(), b"1".to_vec()));
    }
    empty_response(rejection.status(), headers)
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
    use super::encode_hex;

    #[test]
    fn request_id_hex_encoding_is_lowercase_and_fixed_width() {
        assert_eq!(encode_hex(&[0, 15, 16, 255]), "000f10ff");
    }
}
