//! Deterministic terminal WASIp3 service for middleware composition tests.

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
        let path = path.split('?').next().unwrap_or("/");

        match (&method, path) {
            (Method::Get | Method::Head, "/") => {
                let body = matches!(method, Method::Get).then(|| b"echo-service\n".to_vec());
                response(200, vec![], body)
            }
            (_, "/echo") => echo_body(request),
            (Method::Get, "/identity") => {
                let headers = request.get_headers();
                let subject = single_header(&headers, "x-wasi-auth-subject")
                    .unwrap_or_else(|| "anonymous".to_owned());
                response(200, vec![], Some(subject.into_bytes()))
            }
            (Method::Get, "/redirect") => {
                response(302, vec![("location".to_owned(), b"/".to_vec())], None)
            }
            _ => response(404, vec![], None),
        }
    }
}

fn echo_body(request: Request) -> Result<Response, ErrorCode> {
    let content_length = request.get_headers().get("content-length");
    let (_, body_result) = wit_future::new(|| Ok(()));
    let (body, trailers) = Request::consume_body(request, body_result);
    let mut fields = vec![(
        "content-type".to_owned(),
        b"application/octet-stream".to_vec(),
    )];
    if let [value] = content_length.as_slice() {
        fields.push(("content-length".to_owned(), value.clone()));
    }
    let headers =
        Headers::from_list(&fields).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
    let (response, _transmission_result) = Response::new(headers, Some(body), trailers);
    Ok(response)
}

fn response(
    status: u16,
    mut fields: Vec<(String, Vec<u8>)>,
    body: Option<Vec<u8>>,
) -> Result<Response, ErrorCode> {
    let body_length = body.as_ref().map_or(0, Vec::len);
    fields.push((
        "content-length".to_owned(),
        body_length.to_string().into_bytes(),
    ));
    if body.is_some() {
        fields.push(("content-type".to_owned(), b"text/plain".to_vec()));
    }
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

fn single_header(headers: &Headers, name: &str) -> Option<String> {
    let values = headers.get(name);
    let [value] = values.as_slice() else {
        return None;
    };
    std::str::from_utf8(value).ok().map(str::to_owned)
}
