//! Deterministic terminal policy service for authentication tests.

#![deny(missing_docs)]

use wasip3::{
    clocks::monotonic_clock::wait_for,
    http::types::{ErrorCode, Headers, Method, Request, Response},
    wit_future, wit_stream,
};
use wit_bindgen::StreamResult;

struct Component;

wasip3::http::service::export!(Component);

impl wasip3::exports::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let method = request.get_method();
        let path = request
            .get_path_with_query()
            .unwrap_or_else(|| "/".to_owned());
        if !matches!(method, Method::Post) || path.split('?').next() != Some("/check") {
            return response(404, None);
        }

        let authorization = request.get_headers().get("authorization");
        drain_request(request).await?;
        match authorization.as_slice() {
            [value] if value == b"Bearer allow" => response(
                200,
                Some(
                    br#"{"subject":"user-1","issuer":"middleware-secret-issuer-sentinel","scopes":["read","write"]}"#
                        .to_vec(),
                ),
            ),
            [value] if value == b"Bearer deny" => response(403, None),
            [value] if value == b"Bearer error" => response(500, None),
            [value] if value == b"Bearer slow" => slow_policy_response(),
            [value] if value == b"Bearer malformed" => response(200, Some(b"not-json".to_vec())),
            [value] if value == b"Bearer invalid-identity" => response(
                200,
                Some(
                    br#"{"subject":"bad\r\nsubject","issuer":"issuer","scopes":["read"]}"#
                        .to_vec(),
                ),
            ),
            [value] if value == b"Bearer limit-ok" => sized_policy_response(64 * 1024),
            [value] if value == b"Bearer limit-over" => sized_policy_response(64 * 1024 + 1),
            [] | [_] => response(401, None),
            _ => response(400, None),
        }
    }
}

async fn drain_request(request: Request) -> Result<(), ErrorCode> {
    let (result_writer, body_result) = wit_future::new(|| Ok(()));
    drop(result_writer);
    let (mut body, trailers) = Request::consume_body(request, body_result);
    loop {
        let (status, _chunk) = body.read(Vec::with_capacity(8 * 1024)).await;
        match status {
            StreamResult::Complete(_) => {}
            StreamResult::Dropped => {
                let _trailers = trailers.await?;
                return Ok(());
            }
            StreamResult::Cancelled => return Err(ErrorCode::InternalError(None)),
        }
    }
}

fn sized_policy_response(size: usize) -> Result<Response, ErrorCode> {
    let mut body = br#"{"subject":"sized-user","issuer":"issuer","scopes":["read"]}"#.to_vec();
    body.resize(size, b' ');
    response(200, Some(body))
}

fn slow_policy_response() -> Result<Response, ErrorCode> {
    let body =
        br#"{"subject":"slow-user","issuer":"middleware-secret-issuer-sentinel","scopes":["read"]}"#
            .to_vec();
    let fields = vec![
        ("content-type".to_owned(), b"application/json".to_vec()),
        (
            "content-length".to_owned(),
            body.len().to_string().into_bytes(),
        ),
    ];
    let headers =
        Headers::from_list(&fields).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
    let chunks = body.chunks(10).map(<[u8]>::to_vec).collect::<Vec<_>>();
    let (mut writer, reader) = wit_stream::new();
    wit_bindgen::spawn(async move {
        for (index, chunk) in chunks.into_iter().enumerate() {
            if index > 0 {
                wait_for(400_000_000).await;
            }
            let remaining = writer.write_all(chunk).await;
            if !remaining.is_empty() {
                return;
            }
        }
    });
    let (trailers_writer, trailers) = wit_future::new(|| Ok(None));
    drop(trailers_writer);
    let (response, _transmission_result) = Response::new(headers, Some(reader), trailers);
    Ok(response)
}

fn response(status: u16, body: Option<Vec<u8>>) -> Result<Response, ErrorCode> {
    let body_length = body.as_ref().map_or(0, Vec::len);
    let fields = vec![
        ("content-type".to_owned(), b"application/json".to_vec()),
        (
            "content-length".to_owned(),
            body_length.to_string().into_bytes(),
        ),
    ];
    let headers =
        Headers::from_list(&fields).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
    let body = body.map(|body| {
        let (mut writer, reader) = wit_stream::new();
        wit_bindgen::spawn(async move {
            let remaining = writer.write_all(body).await;
            drop(remaining);
        });
        reader
    });
    let (trailers_writer, trailers) = wit_future::new(|| Ok(None));
    drop(trailers_writer);
    let (response, _transmission_result) = Response::new(headers, body, trailers);
    response
        .set_status_code(status)
        .map_err(|()| ErrorCode::InternalError(None))?;
    Ok(response)
}
