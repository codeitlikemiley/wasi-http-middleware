//! Deterministic terminal policy service for authentication tests.

#![deny(missing_docs)]

use wasip3::{
    http::types::{ErrorCode, Headers, Method, Request, Response},
    wit_future, wit_stream,
};

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
        match authorization.as_slice() {
            [] => response(401, None),
            [value] if value == b"Bearer allow" => response(
                200,
                Some(
                    br#"{"subject":"user-1","issuer":"mock-policy","scopes":["read","write"]}"#
                        .to_vec(),
                ),
            ),
            [value] if value == b"Bearer deny" => response(403, None),
            [value] if value == b"Bearer error" => response(500, None),
            [_] => response(401, None),
            _ => response(400, None),
        }
    }
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
