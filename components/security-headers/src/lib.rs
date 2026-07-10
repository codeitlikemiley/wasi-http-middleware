//! Conservative response security headers for `WASIp3` HTTP services.

#![deny(missing_docs)]

use wasi_http_middleware_component_support::{
    from_header_map, replace_response_headers, response_headers, to_header_map,
};
use wasi_http_policy_core::apply_security_headers;
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
        let headers = response_headers(&response);
        let mut headers =
            to_header_map(&headers).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
        apply_security_headers(&mut headers);
        replace_response_headers(response, &from_header_map(&headers))
    }
}
