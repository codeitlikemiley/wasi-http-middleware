//! Resource-preserving helpers shared by the `WASIp3` middleware components.

#![deny(missing_docs)]

use std::collections::BTreeMap;

use http::{HeaderMap, HeaderName, HeaderValue};
use wasip3::http::types::{ErrorCode, Headers, Method, Request, Response, Scheme};
use wasip3::wit_future;

/// Generates the pinned `WASIp3` middleware world while reusing `wasip3`'s
/// resource types for every shared interface.
///
/// Invoke this macro inside a private `bindings` module in each component.
/// The path is resolved relative to the invoking crate, allowing published
/// consumers to provide their own pinned WIT package directory.
#[macro_export]
macro_rules! generate_middleware_bindings {
    ($path:literal) => {
        ::wit_bindgen::generate!({
            path: $path,
            world: "wasi:http/middleware",
            with: {
                "wasi:http/types@0.3.0": ::wasip3::http::types,
                "wasi:http/client@0.3.0": ::wasip3::http::client,
                "wasi:random/random@0.3.0": ::wasip3::random::random,
                "wasi:random/insecure@0.3.0": ::wasip3::random::insecure,
                "wasi:random/insecure-seed@0.3.0": ::wasip3::random::insecure_seed,
                "wasi:cli/stdout@0.3.0": ::wasip3::cli::stdout,
                "wasi:cli/stderr@0.3.0": ::wasip3::cli::stderr,
                "wasi:cli/stdin@0.3.0": ::wasip3::cli::stdin,
                "wasi:cli/types@0.3.0": ::wasip3::cli::types,
                "wasi:clocks/monotonic-clock@0.3.0": ::wasip3::clocks::monotonic_clock,
                "wasi:clocks/system-clock@0.3.0": ::wasip3::clocks::system_clock,
                "wasi:clocks/types@0.3.0": ::wasip3::clocks::types,
            },
        });
    };
}

/// One HTTP field as exposed by `wasi:http/types`.
pub type Header = (String, Vec<u8>);

/// A field could not be converted between WASI HTTP and `http` crate types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderConversionError;

impl std::fmt::Display for HeaderConversionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid HTTP field")
    }
}

impl std::error::Error for HeaderConversionError {}

/// Returns an owned copy of a request's header fields.
pub fn request_headers(request: &Request) -> Vec<Header> {
    request.get_headers().copy_all()
}

/// Returns an owned copy of a response's header fields.
pub fn response_headers(response: &Response) -> Vec<Header> {
    response.get_headers().copy_all()
}

/// Returns every value for `name`, compared case-insensitively.
pub fn header_values<'a>(headers: &'a [Header], name: &str) -> Vec<&'a [u8]> {
    headers
        .iter()
        .filter(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_slice())
        .collect()
}

/// Removes every field named `name`, compared case-insensitively.
pub fn remove_header(headers: &mut Vec<Header>, name: &str) {
    headers.retain(|(candidate, _)| !candidate.eq_ignore_ascii_case(name));
}

/// Replaces every field named `name` with one canonical field.
pub fn set_header(headers: &mut Vec<Header>, name: &str, value: impl Into<Vec<u8>>) {
    remove_header(headers, name);
    headers.push((name.to_ascii_lowercase(), value.into()));
}

/// Converts WASI HTTP fields to an `http` header map without collapsing
/// duplicate values.
///
/// # Errors
///
/// Returns [`HeaderConversionError`] when a field name or value is invalid.
pub fn to_header_map(headers: &[Header]) -> Result<HeaderMap, HeaderConversionError> {
    let mut output = HeaderMap::new();
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| HeaderConversionError)?;
        let value = HeaderValue::from_bytes(value).map_err(|_| HeaderConversionError)?;
        output.append(name, value);
    }
    Ok(output)
}

/// Converts an `http` header map to WASI HTTP fields while retaining all
/// duplicate values.
pub fn from_header_map(headers: &HeaderMap) -> Vec<Header> {
    let mut output = Vec::with_capacity(headers.len());
    for name in headers.keys() {
        for value in headers.get_all(name) {
            output.push((name.as_str().to_owned(), value.as_bytes().to_vec()));
        }
    }
    output
}

/// Replaces fields in `target` with every field present in `source`.
pub fn merge_header_map(target: &mut Vec<Header>, source: &HeaderMap) {
    for name in source.keys() {
        remove_header(target, name.as_str());
        for value in source.get_all(name) {
            target.push((name.as_str().to_owned(), value.as_bytes().to_vec()));
        }
    }
}

/// Rebuilds `request` with `headers` while forwarding its body stream, trailers,
/// request options, method, scheme, path/query, and authority unchanged.
///
/// The body stream is transferred directly into the new request and is never
/// read, buffered, or copied.
///
/// # Errors
///
/// Returns a WASI HTTP error when the requested header changes or request
/// metadata cannot be applied to the forwarded request.
pub fn replace_request_headers(request: Request, headers: &[Header]) -> Result<Request, ErrorCode> {
    let original_headers = request.get_headers();
    let original_fields = original_headers.copy_all();
    let forwarded_headers = original_headers.clone();
    drop(original_headers);
    apply_header_diff(&forwarded_headers, &original_fields, headers)
        .map_err(|()| request_header_error())?;

    let method = request.get_method();
    let scheme = request.get_scheme();
    let path_with_query = request.get_path_with_query();
    let authority = request.get_authority();
    let options = request.get_options();
    let (body_result_writer, body_result) = wit_future::new(|| Err(ErrorCode::InternalError(None)));
    let (body, trailers) = Request::consume_body(request, body_result);

    let (forwarded, transmission_result) =
        Request::new(forwarded_headers, Some(body), trailers, options);
    wit_bindgen::spawn_local(async move {
        let result = transmission_result.await;
        let _write_result = body_result_writer.write(result).await;
    });
    restore_request_metadata(
        &forwarded,
        &method,
        scheme.as_ref(),
        path_with_query.as_deref(),
        authority.as_deref(),
    )?;
    Ok(forwarded)
}

/// Rebuilds `response` with `headers` while forwarding its status, body stream,
/// and trailers unchanged.
///
/// The body stream is transferred directly into the new response and is never
/// read, buffered, or copied.
///
/// # Errors
///
/// Returns a WASI HTTP error when the requested header changes or original
/// status code cannot be applied to the forwarded response.
pub fn replace_response_headers(
    response: Response,
    headers: &[Header],
) -> Result<Response, ErrorCode> {
    let original_headers = response.get_headers();
    let original_fields = original_headers.copy_all();
    let forwarded_headers = original_headers.clone();
    drop(original_headers);
    apply_header_diff(&forwarded_headers, &original_fields, headers)
        .map_err(|()| response_header_error())?;

    let status = response.get_status_code();
    let (body_result_writer, body_result) = wit_future::new(|| Err(ErrorCode::InternalError(None)));
    let (body, trailers) = Response::consume_body(response, body_result);
    let (forwarded, transmission_result) = Response::new(forwarded_headers, Some(body), trailers);
    wit_bindgen::spawn_local(async move {
        let result = transmission_result.await;
        let _write_result = body_result_writer.write(result).await;
    });
    forwarded
        .set_status_code(status)
        .map_err(|()| ErrorCode::InternalError(None))?;
    Ok(forwarded)
}

/// Constructs a response with no body and no trailers.
///
/// # Errors
///
/// Returns a WASI HTTP error when the supplied headers or status code cannot
/// be used to construct the response.
pub fn empty_response(status: u16, mut headers: Vec<Header>) -> Result<Response, ErrorCode> {
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        headers.push(("content-length".to_owned(), b"0".to_vec()));
    }
    let headers = Headers::from_list(&headers).map_err(|_| response_header_error())?;
    let (trailers_writer, trailers) = wit_future::new(|| Ok(None));
    drop(trailers_writer);
    let (response, _transmission_result) = Response::new(headers, None, trailers);
    response
        .set_status_code(status)
        .map_err(|()| ErrorCode::InternalError(None))?;
    Ok(response)
}

fn restore_request_metadata(
    request: &Request,
    method: &Method,
    scheme: Option<&Scheme>,
    path_with_query: Option<&str>,
    authority: Option<&str>,
) -> Result<(), ErrorCode> {
    request
        .set_method(method)
        .and_then(|()| request.set_scheme(scheme))
        .and_then(|()| request.set_path_with_query(path_with_query))
        .and_then(|()| request.set_authority(authority))
        .map_err(|()| ErrorCode::InternalError(None))
}

fn apply_header_diff(fields: &Headers, original: &[Header], desired: &[Header]) -> Result<(), ()> {
    let original = group_headers(original);
    let desired = group_headers(desired);

    for (name, values) in &original {
        match desired.get(name) {
            Some(desired_values) if desired_values == values => {}
            Some(desired_values) => fields.set(name, desired_values).map_err(|_| ())?,
            None => fields.delete(name).map_err(|_| ())?,
        }
    }
    for (name, values) in &desired {
        if !original.contains_key(name) {
            fields.set(name, values).map_err(|_| ())?;
        }
    }
    Ok(())
}

fn group_headers(headers: &[Header]) -> BTreeMap<String, Vec<Vec<u8>>> {
    let mut grouped = BTreeMap::<String, Vec<Vec<u8>>>::new();
    for (name, value) in headers {
        grouped
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(value.clone());
    }
    grouped
}

fn request_header_error() -> ErrorCode {
    ErrorCode::HttpRequestHeaderSectionSize(None)
}

fn response_header_error() -> ErrorCode {
    ErrorCode::HttpResponseHeaderSectionSize(None)
}
