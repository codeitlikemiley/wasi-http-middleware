//! A streaming-safe `WASIp3` request ID middleware component.

#![deny(missing_docs)]

use wasi_http_middleware_component_support::{
    generated_request_id, header_values, replace_request_headers, replace_response_headers,
    request_headers, response_headers, set_header,
};
use wasi_http_policy_core::canonicalize_request_id_bytes;
use wasip3::http::types::{ErrorCode, Request, Response};

#[allow(unknown_lints, missing_docs, clippy::same_length_and_capacity)]
mod bindings {
    wasi_http_middleware_component_support::generate_middleware_bindings!("../../wit");
}

use bindings::wasi::http::handler;

const REQUEST_ID_HEADER: &str = "x-request-id";
struct Component;

bindings::export!(Component with_types_in bindings);

impl bindings::exports::wasi::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let mut headers = request_headers(&request);
        let request_id = canonical_request_id(&headers);
        set_header(&mut headers, REQUEST_ID_HEADER, request_id.as_bytes());
        let request = replace_request_headers(request, &headers)?;

        let response = handler::handle(request).await?;
        let mut headers = response_headers(&response);
        set_header(&mut headers, REQUEST_ID_HEADER, request_id.as_bytes());
        replace_response_headers(response, &headers)
    }
}

fn canonical_request_id(headers: &[(String, Vec<u8>)]) -> String {
    canonicalize_request_id_bytes(
        header_values(headers, REQUEST_ID_HEADER),
        generated_request_id,
    )
    .unwrap_or_else(|_| generated_request_id())
}

#[cfg(test)]
mod tests {
    use super::canonical_request_id;

    #[test]
    fn preserves_one_safe_request_id() {
        let headers = vec![("x-request-id".to_owned(), b"safe.id/1".to_vec())];
        assert_eq!(canonical_request_id(&headers), "safe.id/1");
    }

    #[test]
    fn replaces_duplicate_request_ids() {
        let headers = vec![
            ("x-request-id".to_owned(), b"one".to_vec()),
            ("X-Request-ID".to_owned(), b"two".to_vec()),
        ];
        let replacement = canonical_request_id(&headers);
        assert_ne!(replacement, "one");
        assert_ne!(replacement, "two");
    }
}
