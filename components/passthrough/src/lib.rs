//! Transparent `WASIp3` HTTP middleware used to verify composition.

use wasip3::http::types::{ErrorCode, Request, Response};

#[allow(missing_docs)]
mod bindings {
    wasi_http_middleware_component_support::generate_middleware_bindings!();
}

use bindings::wasi::http::handler;

struct Component;

bindings::export!(Component with_types_in bindings);

impl bindings::exports::wasi::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        handler::handle(request).await
    }
}
