//! Conservative response security headers for `WASIp3` HTTP services.

#![deny(missing_docs)]

use wasi_http_middleware_component_support::{
    replace_response_headers, response_headers, set_header,
};
use wasi_http_policy_core::SECURITY_RESPONSE_HEADERS;
use wasip3::http::types::{ErrorCode, Request, Response};

#[allow(unknown_lints, missing_docs, clippy::same_length_and_capacity)]
mod bindings {
    wasi_http_middleware_component_support::generate_middleware_bindings!("../../wit");
}

use bindings::wasi::http::handler;

struct Component;

bindings::export!(Component with_types_in bindings);

impl bindings::exports::wasi::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let response = handler::handle(request).await?;
        let mut headers = response_headers(&response);
        for (name, value) in SECURITY_RESPONSE_HEADERS {
            set_header(&mut headers, name, value.as_bytes());
        }
        replace_response_headers(response, &headers)
    }
}
