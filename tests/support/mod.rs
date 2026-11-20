fn push_string(buf: &mut Vec<u8>, s: &[u8]) {
    assert!(
        s.len() < 240,
        "fixture strings stay in the 1-byte varint range"
    );
    buf.push(s.len() as u8);
    buf.extend_from_slice(s);
}

fn push_typed_string(buf: &mut Vec<u8>, name: &str, value: &[u8], type_id: u8) {
    push_string(buf, name.as_bytes());
    buf.push(type_id);
    push_string(buf, value);
}

pub fn headers(count: usize) -> Vec<u8> {
    let fields = [
        ("host", "example.com"),
        ("user-agent", "curl/8.11.1-dev"),
        ("accept", "*/*"),
        ("cookie", "session=1"),
        ("origin", "https://example.com"),
        ("accept-encoding", "gzip"),
        ("accept-language", "en"),
        ("cache-control", "no-cache"),
        ("referer", "/"),
        ("x-request-id", "1234"),
    ];
    let mut out = Vec::new();
    for (name, value) in fields.iter().take(count) {
        push_string(&mut out, name.as_bytes());
        push_string(&mut out, value.as_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// A NOTIFY frame shaped like the `check-request` message of a WAF agent: 15 arguments, as
/// `HAProxy` sends them for `args src-ip=src src-port=src_port ... req_id=unique-id`.
pub fn check_request_frame(stream_id: u8, path: &str, header_count: usize) -> Vec<u8> {
    let mut body = vec![
        0x03, // FRAME-TYPE: NOTIFY
        0x00, 0x00, 0x00, 0x01,      // FLAGS: FIN
        stream_id, // STREAM-ID
        0x01,      // FRAME-ID
    ];
    push_string(&mut body, b"check-request");
    body.push(15); // NB-ARGS

    push_string(&mut body, b"src-ip");
    body.extend_from_slice(&[0x06, 192, 0, 2, 1]); // IPV4
    push_string(&mut body, b"src-port");
    body.push(0x02); // INT32
    body.push(80);
    push_string(&mut body, b"dst-ip");
    body.extend_from_slice(&[0x06, 198, 51, 100, 7]);
    push_string(&mut body, b"dst-port");
    body.push(0x02);
    body.push(81);
    push_typed_string(&mut body, "method", b"GET", 0x08);
    push_typed_string(&mut body, "path", path.as_bytes(), 0x08);
    push_typed_string(&mut body, "query", b"q=1&page=2", 0x08);
    push_typed_string(&mut body, "version", b"1.1", 0x08);
    push_typed_string(&mut body, "headers", &headers(header_count), 0x09); // BINARY
    push_string(&mut body, b"body");
    body.push(0x00); // NULL
    push_typed_string(&mut body, "body-mode", b"none", 0x08);
    push_string(&mut body, b"body-complete");
    body.push(0x01); // BOOL false
    push_string(&mut body, b"detect-only");
    body.push(0x11); // BOOL true
    push_typed_string(&mut body, "app", b"policy:default", 0x08);
    push_typed_string(
        &mut body,
        "req_id",
        b"01a1f751-5a7b-7911-90e2-444188eece97",
        0x08,
    );

    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    frame
}

/// Builds a NOTIFY frame matching `spoe-test.conf`'s `log-request` message.
pub fn notify_frame(args: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();

    body.push(0x03); // FRAME-TYPE: NOTIFY
    body.extend_from_slice(&1u32.to_be_bytes()); // FLAGS: FIN
    body.push(0x01); // STREAM-ID varint
    body.push(0x01); // FRAME-ID varint

    push_string(&mut body, b"log-request");
    body.push(args.len() as u8); // NB-ARGS
    for (key, value) in args {
        push_string(&mut body, key.as_bytes());
        body.push(0x08); // TYPED-DATA: STRING
        push_string(&mut body, value.as_bytes());
    }

    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    frame
}
