//! Deterministic terminal `WASIp3` service for middleware composition tests.

#![deny(missing_docs)]

use wasip3::{
    clocks::monotonic_clock::wait_for,
    http::types::{ErrorCode, Headers, Method, Request, Response},
    wit_future, wit_stream,
};

struct Component;

wasip3::http::service::export!(Component);

impl wasip3::exports::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        if request.get_headers().has("x-wasi-test-count") {
            eprintln!("wasi-http-middleware-test: terminal-invocation");
        }
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
            (Method::Get | Method::Head, "/method") => response(
                200,
                vec![("allow".to_owned(), b"GET, HEAD".to_vec())],
                matches!(method, Method::Get).then(|| b"method allowed\n".to_vec()),
            ),
            (_, "/method") => {
                response(405, vec![("allow".to_owned(), b"GET, HEAD".to_vec())], None)
            }
            (_, "/too-large") => response(413, vec![], None),
            (_, "/error") => response(500, vec![], None),
            (Method::Get, "/delayed") => delayed_response(),
            (Method::Get, "/failing-stream") => failing_stream_response(),
            (Method::Get, "/trailers") => trailers_response(),
            _ => response(404, vec![], None),
        }
    }
}

fn delayed_response() -> Result<Response, ErrorCode> {
    let fields = vec![("content-type".to_owned(), b"text/plain".to_vec())];
    let headers =
        Headers::from_list(&fields).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
    let (mut writer, reader) = wit_stream::new();
    wasip3::spawn(async move {
        let remaining = writer.write_all(b"first\n".to_vec()).await;
        if !remaining.is_empty() {
            return;
        }
        wait_for(300_000_000).await;
        let remaining = writer.write_all(b"second\n".to_vec()).await;
        drop(remaining);
    });
    let (trailers_writer, trailers) = wit_future::new(|| Ok(None));
    drop(trailers_writer);
    let (response, _transmission_result) = Response::new(headers, Some(reader), trailers);
    Ok(response)
}

fn failing_stream_response() -> Result<Response, ErrorCode> {
    let fields = vec![("content-type".to_owned(), b"text/plain".to_vec())];
    let headers =
        Headers::from_list(&fields).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
    let (mut writer, reader) = wit_stream::new();
    wasip3::spawn(async move {
        let remaining = writer.write_all(b"partial body\n".to_vec()).await;
        drop(remaining);
    });
    let (trailers_writer, trailers) =
        wit_future::new(|| Err::<Option<Headers>, ErrorCode>(ErrorCode::InternalError(None)));
    drop(trailers_writer);
    let (response, _transmission_result) = Response::new(headers, Some(reader), trailers);
    Ok(response)
}

fn trailers_response() -> Result<Response, ErrorCode> {
    let fields = vec![("content-type".to_owned(), b"text/plain".to_vec())];
    let headers =
        Headers::from_list(&fields).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
    let (mut writer, reader) = wit_stream::new();
    wasip3::spawn(async move {
        let remaining = writer.write_all(b"body with trailer\n".to_vec()).await;
        drop(remaining);
    });
    let (trailers_writer, trailers) = wit_future::new(echo_trailers);
    drop(trailers_writer);
    let (response, _transmission_result) = Response::new(headers, Some(reader), trailers);
    Ok(response)
}

fn echo_trailers() -> Result<Option<Headers>, ErrorCode> {
    let trailer_fields = vec![("x-echo-trailer".to_owned(), b"preserved".to_vec())];
    Headers::from_list(&trailer_fields)
        .map(Some)
        .map_err(|_| ErrorCode::HttpResponseTrailerSectionSize(None))
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
        wasip3::spawn(async move {
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
