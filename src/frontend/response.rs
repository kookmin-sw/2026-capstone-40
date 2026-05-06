use std::io::Cursor;
use tiny_http::{Header, Response, StatusCode};

pub type HttpResponse = Response<Cursor<Vec<u8>>>;

pub fn html(status: u16, body: String) -> HttpResponse {
    let bytes = body.into_bytes();
    let len = bytes.len();
    Response::new(
        StatusCode(status),
        vec![header("Content-Type", "text/html; charset=utf-8")],
        Cursor::new(bytes),
        Some(len),
        None,
    )
}

pub fn redirect(location: &str) -> HttpResponse {
    Response::new(
        StatusCode(303),
        vec![
            header("Location", location),
            header("Content-Type", "text/html; charset=utf-8"),
        ],
        Cursor::new(vec![]),
        Some(0),
        None,
    )
}

pub fn static_file(content_type: &str, bytes: Vec<u8>) -> HttpResponse {
    let len = bytes.len();
    Response::new(
        StatusCode(200),
        vec![
            header("Content-Type", content_type),
            header("Cache-Control", "public, max-age=3600"),
        ],
        Cursor::new(bytes),
        Some(len),
        None,
    )
}

pub fn not_found() -> HttpResponse {
    html(404, "<h1>404 Not Found</h1>".to_string())
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes())
        .expect("invalid header")
}
