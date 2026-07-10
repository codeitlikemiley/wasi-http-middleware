//! A streaming-safe WASIp3 request ID middleware component.

#![deny(missing_docs)]

use wasi_http_middleware_component_support::{
    replace_request_headers, replace_response_headers, request_headers, response_headers,
    set_header, to_header_map,
};
use wasi_http_policy_core::RequestIdPolicy;
use wasip3::http::types::{ErrorCode, Request, Response};
use wasip3::random::random::get_random_bytes;

#[allow(missing_docs)]
mod bindings {
    wasi_http_middleware_component_support::generate_middleware_bindings!();
}

use bindings::wasi::http::handler;

const REQUEST_ID_HEADER: &str = "x-request-id";
const REQUEST_ID_BYTES: usize = 16;

struct Component;

bindings::export!(Component with_types_in bindings);

impl bindings::exports::wasi::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let mut headers = request_headers(&request);
        let request_id = canonical_request_id(&headers)?;
        set_header(&mut headers, REQUEST_ID_HEADER, request_id.as_bytes());
        let request = replace_request_headers(request, headers)?;

        let response = handler::handle(request).await?;
        let mut headers = response_headers(&response);
        set_header(&mut headers, REQUEST_ID_HEADER, request_id.as_bytes());
        replace_response_headers(response, headers)
    }
}

fn canonical_request_id(headers: &[(String, Vec<u8>)]) -> Result<String, ErrorCode> {
    let headers =
        to_header_map(headers).map_err(|_| ErrorCode::HttpRequestHeaderSectionSize(None))?;
    RequestIdPolicy
        .canonicalize(&headers, || {
            encode_hex(&get_random_bytes(REQUEST_ID_BYTES as u64))
        })
        .map_err(|_| ErrorCode::InternalError(None))
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
    fn hex_encoding_is_lowercase_and_fixed_width() {
        assert_eq!(encode_hex(&[0, 15, 16, 255]), "000f10ff");
    }
}
