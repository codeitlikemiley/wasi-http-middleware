//! Conservative response security headers for `WASIp3` HTTP services.

#![deny(missing_docs)]

use wasi_http_middleware_component_support::{replace_response_headers, response_headers};
use wasi_http_policy_core::apply_security_headers_to_fields;
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
        apply_security_headers_to_fields(&mut headers);
        replace_response_headers(response, &headers)
    }
}
