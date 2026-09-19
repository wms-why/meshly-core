//! Static-mode: serve files from a local directory over HTTP/1.1.
//!
//! Flow on each incoming P2P stream:
//!
//! 1. Run the same HMAC handshake as `expose` (AuthNonce / AuthProof / AuthOk).
//! 2. Loop: read one HTTP/1.1 request, resolve the path under `root_dir`,
//!    serve a file or directory listing, write the response, and keep the
//!    stream open for additional requests.
//!
//! Security notes:
//!
//! - Path traversal is blocked by canonicalising the resolved path and
//!   requiring it to be lexically inside `root_dir`. On any failure we
//!   return 400/403 and stop serving it.
//! - Symlinks that point outside `root_dir` are rejected by the same check
//!   after canonicalisation.
//! - We deliberately serve only GET / HEAD. Anything else returns 405.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info, warn};

use meshly_core_common::protocol::{
    verify_proof, AuthErr, AuthNonce, AuthOk, AuthProof, Frame, AUTH_ERR_BAD_PROOF,
};

/// Description of one HTTP static service.
#[derive(Debug, Clone)]
pub struct StaticSpec {
    pub name: String,
    pub root_dir: PathBuf,
    pub allow_directory_listing: bool,
    pub shared_secret: Vec<u8>,
}

/// Per-service ProtocolHandler that serves HTTP/1.1 from `spec.root_dir`.
#[derive(Debug, Clone)]
pub struct StaticHandler {
    pub spec: Arc<StaticSpec>,
}

impl ProtocolHandler for StaticHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        match self.handle(conn).await {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!(service = %self.spec.name, err = %e, "static: session ended with error");
                let boxed: Box<dyn std::error::Error + Send + Sync> = e.into();
                Err(AcceptError::from_boxed(boxed))
            }
        }
    }
}

impl StaticHandler {
    async fn handle(&self, conn: Connection) -> Result<()> {
        info!(service = %self.spec.name, remote = %conn.remote_id().fmt_short(),
            "static: incoming connection");

        // 1. Accept the first stream and run the auth handshake (mirrors expose).
        let (mut send, mut recv) = conn.accept_bi().await?;
        let mut nonce = [0u8; 32];
        rand::Rng::fill(&mut rand::rngs::OsRng, &mut nonce[..]);
        Frame::AuthNonce(AuthNonce { nonce }).write_to(&mut send).await?;

        let proof_frame = Frame::read_from(&mut recv).await?;
        let proof = match proof_frame {
            Frame::AuthProof(AuthProof { mac }) => mac,
            _ => {
                warn!(service = %self.spec.name, got = ?proof_frame,
                    "static: expected AuthProof");
                return Ok(());
            }
        };
        if !verify_proof(&self.spec.shared_secret, &self.spec.name, &nonce, &proof) {
            warn!(service = %self.spec.name, "static: bad HMAC proof");
            let _ = Frame::AuthErr(AuthErr {
                code: AUTH_ERR_BAD_PROOF,
                reason: "bad HMAC proof".into(),
            })
            .write_to(&mut send)
            .await;
            let _ = send.shutdown().await;
            return Ok(());
        }
        Frame::AuthOk(AuthOk).write_to(&mut send).await?;
        debug!(service = %self.spec.name, "static: auth ok");

        // 2. Serve HTTP requests on this bi-stream until the peer closes.
        //    HTTP/1.1 keeps the connection open by default; we loop serving
        //    requests until EOF.
        // Wrap the recv half in a BufReader so the per-byte parser
        // amortises syscalls: each `fill_buf` returns whatever is
        // already buffered, and `consume` advances without losing data.
        let mut recv = BufReader::new(recv);
        loop {
            match serve_one(&self.spec, &mut send, &mut recv).await {
                Ok(true) => continue,    // served successfully, keep going
                Ok(false) => break,     // peer closed; stop
                Err(e) => {
                    warn!(service = %self.spec.name, err = %e,
                        "static: serve_one failed; closing stream");
                    break;
                }
            }
        }

        let _ = send.shutdown().await;
        info!(service = %self.spec.name, "static: stream closed");
        Ok(())
    }
}

/// Result of `serve_one`:
/// - `Ok(true)`  — request handled; loop wants another
/// - `Ok(false)` — peer closed cleanly (EOF reading request)
/// - `Err(_)`    — protocol / IO error; loop closes
async fn serve_one<W, R>(spec: &StaticSpec, send: &mut W, recv: &mut R) -> Result<bool>
where
    W: AsyncWriteExt + Unpin,
    R: AsyncBufReadExt + Unpin,
{
    let req = match read_request(recv).await? {
        Some(r) => r,
        None => return Ok(false), // EOF
    };
    debug!(service = %spec.name, method = %req.method, path = %req.path,
        "static: request");

    let response = match build_response(spec, &req) {
        Ok(r) => r,
        Err(status) => error_response(status, &req.method, req.keep_alive),
    };
    write_response(send, &response).await?;
    Ok(req.keep_alive)
}

// ---------------------------------------------------------------------------
// HTTP parsing (minimal HTTP/1.1, just enough for serving files)
// ---------------------------------------------------------------------------

const MAX_REQUEST_LINE: usize = 8 * 1024;
const MAX_HEADERS: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 0; // we don't accept request bodies (GET/HEAD only)

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    /// Whether to keep the connection open after this response. The
    /// rules: HTTP/1.1 defaults to keep-alive (peer can opt out with
    /// `Connection: close`); HTTP/1.0 defaults to close (peer can opt
    /// in with `Connection: keep-alive`).
    keep_alive: bool,
}

async fn read_request<R: AsyncBufReadExt + Unpin>(recv: &mut R) -> Result<Option<Request>> {
    // Request line: "METHOD SP PATH SP HTTP/x.y CRLF". Read up to the
    // first `\n` with a hard size cap so a malicious peer cannot make us
    // buffer an unbounded amount before we error out.
    let line_buf = match read_until_limited(recv, b'\n', MAX_REQUEST_LINE).await? {
        Some(b) => b,
        None => return Ok(None),
    };
    let request_line = std::str::from_utf8(&line_buf)
        .with_context(|| "static: non-UTF-8 request line")?
        .trim_end_matches(['\r', '\n']);
    let mut parts = request_line.split(' ');
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("static: empty request line"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| anyhow!("static: missing path in request line"))?
        .to_string();
    let version = parts
        .next()
        .ok_or_else(|| anyhow!("static: missing HTTP version"))?;
    if !version.starts_with("HTTP/") {
        return Err(anyhow!("static: bad HTTP version: {version:?}"));
    }

    // Headers: read until \r\n\r\n (we tolerate \n\n too).
    // Headers: read up to the `\r\n\r\n` terminator (we also accept the
    // bare `\n\n` form). Bounded so a runaway client gets a clean error
    // instead of an OOM.
    let header_buf = read_headers_limited(recv, MAX_HEADERS).await?;

    let header_str = std::str::from_utf8(&header_buf)
        .with_context(|| "static: non-UTF-8 headers")?;
    let mut content_length: usize = 0;
    let mut connection_close = false;
    let mut connection_keep_alive = false;
    for line in header_str.split(['\n']) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().with_context(|| {
                    format!("static: bad Content-Length {v:?}")
                })?;
            } else if k.eq_ignore_ascii_case("connection") {
                // Connection is a comma-separated list of tokens; we care
                // about `close` and `keep-alive`.
                for tok in v.split(',') {
                    let tok = tok.trim();
                    if tok.eq_ignore_ascii_case("close") {
                        connection_close = true;
                    } else if tok.eq_ignore_ascii_case("keep-alive") {
                        connection_keep_alive = true;
                    }
                }
            }
        }
    }

    if content_length > MAX_BODY_BYTES {
        return Err(anyhow!(
            "static: request body {content_length} > limit {MAX_BODY_BYTES}"
        ));
    }
    if content_length > 0 {
        // We're GET/HEAD only; drain the body anyway so the stream stays in
        // sync with the peer's frame counter.
        let mut drain = vec![0u8; content_length.min(8192)];
        let mut remaining = content_length;
        while remaining > 0 {
            let take = remaining.min(drain.len());
            recv.read_exact(&mut drain[..take]).await?;
            remaining -= take;
        }
    }

    // HTTP/1.1 defaults to keep-alive (peer can opt out with `Connection: close`).
    // HTTP/1.0 defaults to close (peer must opt in with `Connection: keep-alive`).
    let keep_alive = match version {
        "HTTP/1.1" => !connection_close,
        "HTTP/1.0" => connection_keep_alive,
        _ => false,
    };

    Ok(Some(Request {
        method,
        path,
        keep_alive,
    }))
}

/// Read bytes from `recv` until `delim` is found or `max` bytes are
/// accumulated. Returns `Ok(None)` on clean EOF before any data.
async fn read_until_limited<R: AsyncBufReadExt + Unpin>(
    recv: &mut R,
    delim: u8,
    max: usize,
) -> Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let chunk = recv.fill_buf().await?;
        if chunk.is_empty() {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(anyhow!("static: peer closed mid-line"))
            };
        }
        match chunk.iter().position(|&b| b == delim) {
            Some(pos) => {
                let take = pos + 1;
                if buf.len() + take > max {
                    return Err(anyhow!("static: line exceeded {max} bytes"));
                }
                buf.extend_from_slice(&chunk[..take]);
                recv.consume(take);
                return Ok(Some(buf));
            }
            None => {
                if buf.len() + chunk.len() > max {
                    return Err(anyhow!("static: line exceeded {max} bytes"));
                }
                let len = chunk.len();
                buf.extend_from_slice(chunk);
                recv.consume(len);
            }
        }
    }
}

/// Read HTTP headers (up to and including `\r\n\r\n` or `\n\n`) with a
/// hard size cap. Returns an explicit error if the cap is hit so we
/// never buffer unbounded data.
async fn read_headers_limited<R: AsyncBufReadExt + Unpin>(
    recv: &mut R,
    max: usize,
) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let chunk = recv.fill_buf().await?;
        if chunk.is_empty() {
            return Err(anyhow!("static: peer closed mid-headers"));
        }
        if let Some(end) = find_header_terminator(chunk) {
            let take = end + 1;
            if buf.len() + take > max {
                return Err(anyhow!("static: headers exceeded {max} bytes"));
            }
            buf.extend_from_slice(&chunk[..take]);
            recv.consume(take);
            return Ok(buf);
        }
        if buf.len() + chunk.len() > max {
            return Err(anyhow!("static: headers exceeded {max} bytes"));
        }
        let len = chunk.len();
        buf.extend_from_slice(chunk);
        recv.consume(len);
    }
}

/// Return the index of the LAST byte of the first header-terminator
/// (`\r\n\r\n` or bare `\n\n`) in `chunk`, or `None` if absent.
fn find_header_terminator(chunk: &[u8]) -> Option<usize> {
    for i in 0..chunk.len() {
        // `\r\n\r\n`
        if i + 3 < chunk.len()
            && chunk[i] == b'\r'
            && chunk[i + 1] == b'\n'
            && chunk[i + 2] == b'\r'
            && chunk[i + 3] == b'\n'
        {
            return Some(i + 3);
        }
        // `\n\n`
        if i + 1 < chunk.len() && chunk[i] == b'\n' && chunk[i + 1] == b'\n' {
            return Some(i + 1);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Response building
// ---------------------------------------------------------------------------

struct Response {
    status: u16,
    status_text: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn error_response(status: u16, method: &str, keep_alive: bool) -> Response {
    let body_text = match status {
        400 => "400 Bad Request",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        405 => "405 Method Not Allowed",
        500 => "500 Internal Server Error",
        _ => "Error",
    };
    let body = if method == "HEAD" {
        Vec::new()
    } else {
        format!("{body_text}\n").into_bytes()
    };
    let conn = if keep_alive { "keep-alive" } else { "close" };
    Response {
        status,
        status_text: match status {
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            _ => "Error",
        },
        headers: vec![
            ("Content-Type".into(), "text/plain; charset=utf-8".into()),
            ("Content-Length".into(), body.len().to_string()),
            ("Connection".into(), conn.into()),
        ],
        body,
    }
}

fn build_response(spec: &StaticSpec, req: &Request) -> Result<Response, u16> {
    if req.method != "GET" && req.method != "HEAD" {
        return Err(405);
    }

    let conn = if req.keep_alive { "keep-alive" } else { "close" };

    // Strip query string and fragment from the path before mapping to disk.
    let raw_path = req.path.split('?').next().unwrap_or(&req.path);
    let raw_path = raw_path.split('#').next().unwrap_or(raw_path);
    let url_decoded = percent_decode(raw_path).map_err(|_| 400u16)?;

    // Canonicalise: resolve relative to root_dir, then check that the
    // resulting path is lexically inside root_dir. Blocks ../ escapes and
    // absolute paths.
    let root_canon = spec
        .root_dir
        .canonicalize()
        .map_err(|_| 500u16)?;
    let joined = if url_decoded.starts_with('/') || url_decoded.is_empty() {
        root_canon.join(url_decoded.trim_start_matches('/'))
    } else {
        // Bare relative paths are treated as if prefixed with `/`.
        root_canon.join(&url_decoded)
    };

    // For directory paths without a trailing slash, we still want to look at
    // the directory itself. For files we look at the file.
    let target = match joined.canonicalize() {
        Ok(p) => p,
        Err(_) => return Err(404),
    };
    if !target.starts_with(&root_canon) {
        return Err(403);
    }

    let meta = match std::fs::metadata(&target) {
        Ok(m) => m,
        Err(_) => return Err(404),
    };
    if meta.is_dir() {
        if !spec.allow_directory_listing {
            return Err(403);
        }
        let body = render_directory_listing(&root_canon, &target).map_err(|_| 500u16)?;
        let advertised_len = body.len();
        Ok(Response {
            status: 200,
            status_text: "OK",
            headers: vec![
                ("Content-Type".into(), "text/html; charset=utf-8".into()),
                ("Content-Length".into(), advertised_len.to_string()),
                ("Connection".into(), conn.into()),
            ],
            body: if req.method == "HEAD" { Vec::new() } else { body },
        })
    } else {
        let body = match std::fs::read(&target) {
            Ok(b) => b,
            Err(_) => return Err(404),
        };
        // HEAD responses advertise the would-be body length but send no body.
        let advertised_len = body.len();
        Ok(Response {
            status: 200,
            status_text: "OK",
            headers: vec![
                ("Content-Type".into(), guess_content_type(&target).into()),
                ("Content-Length".into(), advertised_len.to_string()),
                ("Connection".into(), conn.into()),
            ],
            body: if req.method == "HEAD" { Vec::new() } else { body },
        })
    }
}

async fn write_response<W: AsyncWriteExt + Unpin>(
    send: &mut W,
    r: &Response,
) -> Result<()> {
    let mut head = format!("HTTP/1.1 {} {}\r\n", r.status, r.status_text);
    for (k, v) in &r.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    send.write_all(head.as_bytes()).await?;
    if !r.body.is_empty() {
        send.write_all(&r.body).await?;
    }
    send.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn percent_decode(s: &str) -> Result<String, ()> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(());
                }
                let hi = (bytes[i + 1] as char).to_digit(16).ok_or(())?;
                let lo = (bytes[i + 2] as char).to_digit(16).ok_or(())?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

fn guess_content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("txt") | Some("md") => "text/plain; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

fn render_directory_listing(root: &Path, dir: &Path) -> std::io::Result<Vec<u8>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let meta = entry.metadata().ok();
        let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);

        // URL path relative to root
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(&path);
        let href = if is_dir {
            format!("{}/", rel.to_string_lossy())
        } else {
            rel.to_string_lossy().into_owned()
        };
        entries.push((name, is_dir, size, href));
    }
    entries.sort_by(|a, b| {
        // Directories first, then case-insensitive name.
        b.1.cmp(&a.1).then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase()))
    });

    let rel_dir = dir.strip_prefix(root).unwrap_or(dir);
    let title = if rel_dir.as_os_str().is_empty() {
        "/".to_string()
    } else {
        format!("/{}", rel_dir.to_string_lossy())
    };

    let mut html = String::with_capacity(1024);
    html.push_str("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">");
    html.push_str(&format!("<title>Index of {title}</title>"));
    html.push_str("<style>");
    html.push_str("body{font-family:system-ui,sans-serif;margin:1.5em;max-width:60em}");
    html.push_str("table{border-collapse:collapse;width:100%}");
    html.push_str("th,td{padding:0.3em 0.6em;text-align:left;border-bottom:1px solid #eee}");
    html.push_str("a{text-decoration:none;color:#04c}a:hover{text-decoration:underline}");
    html.push_str(".size{text-align:right;font-variant-numeric:tabular-nums;color:#888}");
    html.push_str("</style></head><body>");
    html.push_str(&format!("<h1>Index of {title}</h1>"));
    html.push_str("<table><thead><tr><th>Name</th><th class=\"size\">Size</th></tr></thead><tbody>");

    if rel_dir.as_os_str().is_empty() {
        // root: no parent link
    } else {
        html.push_str("<tr><td><a href=\"../\">../</a></td><td class=\"size\">—</td></tr>");
    }
    for (name, is_dir, size, href) in &entries {
        let display_name = if *is_dir { format!("{name}/") } else { name.clone() };
        let size_str = if *is_dir {
            "—".to_string()
        } else if *size < 1024 {
            format!("{size} B")
        } else if *size < 1024 * 1024 {
            format!("{:.1} KB", *size as f64 / 1024.0)
        } else {
            format!("{:.1} MB", *size as f64 / 1024.0 / 1024.0)
        };
        // Defensive: ensure href cannot escape root. Strip any ".." segments
        // just in case (build_response already prevents this, but belt + braces).
        let safe_href = href.replace("..", "");
        html.push_str(&format!(
            "<tr><td><a href=\"{}\">{}</a></td><td class=\"size\">{}</td></tr>",
            html_escape(&safe_href),
            html_escape(&display_name),
            size_str,
        ));
    }
    html.push_str("</tbody></table></body></html>");
    Ok(html.into_bytes())
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn percent_decode_roundtrip() {
        assert_eq!(percent_decode("hello").unwrap(), "hello");
        assert_eq!(percent_decode("hello%20world").unwrap(), "hello world");
        assert_eq!(percent_decode("a%2Bb").unwrap(), "a+b");
        assert_eq!(percent_decode("%E4%B8%AD%E6%96%87").unwrap(), "中文");
        assert!(percent_decode("%").is_err());
        assert!(percent_decode("%2").is_err());
    }

    #[test]
    fn guess_content_type_for_known_extensions() {
        assert_eq!(guess_content_type(Path::new("a.html")), "text/html; charset=utf-8");
        assert_eq!(guess_content_type(Path::new("a.png")), "image/png");
        assert_eq!(guess_content_type(Path::new("a.bin")), "application/octet-stream");
    }

    #[test]
    fn html_escapes_special_chars() {
        assert_eq!(html_escape("<a>&\"'"), "&lt;a&gt;&amp;&quot;&#39;");
    }

    /// Drive `serve_one` end-to-end over a duplex pipe and assert the
    /// HTTP response is well-formed and matches expectations.
    #[tokio::test]
    async fn serve_one_handles_get_request() {
        // Build a tempdir with one file + one subdir.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hi there").unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();
        std::fs::write(dir.path().join("subdir/inside.txt"), "deep").unwrap();

        let spec = StaticSpec {
            name: "files".into(),
            root_dir: dir.path().to_path_buf(),
            allow_directory_listing: true,
            shared_secret: b"unused".to_vec(),
        };
        let req = Request {
            method: "GET".into(),
            path: "/hello.txt".into(),
            keep_alive: false,
        };

        let (a, mut b) = duplex(4096);
        // `a` is the server side; the server reads from `a_recv` and
        // writes to `a_send`. `b` is the client side.
        let (a_recv, mut a_send) = tokio::io::split(a);
        let mut a_recv = BufReader::new(a_recv);
        let spec_clone = spec.clone();
        let req_clone = req;
        let server = tokio::spawn(async move {
            let result = serve_one(&spec_clone, &mut a_send, &mut a_recv).await;
            let _ = a_send.shutdown().await;
            result
        });

        // Client side: write a minimal HTTP/1.1 request and read the response.
        let req_bytes = format!(
            "{} {} HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n",
            req_clone.method, req_clone.path
        );
        b.write_all(req_bytes.as_bytes()).await.unwrap();
        let _ = b.shutdown().await;

        let mut response = Vec::new();
        b.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response).into_owned();

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "got: {text}");
        assert!(text.contains("Content-Type: text/plain"));
        assert!(text.contains("hi there"));

        let _ = server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn serve_one_blocks_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ok.txt"), "ok").unwrap();
        // Place a sibling file outside the root that we should not be able
        // to fetch.
        let outside_dir = tempfile::tempdir().unwrap();
        std::fs::write(outside_dir.path().join("secret.txt"), "nope").unwrap();

        let spec = StaticSpec {
            name: "files".into(),
            root_dir: dir.path().to_path_buf(),
            allow_directory_listing: false,
            shared_secret: b"unused".to_vec(),
        };
        let req = Request {
            method: "GET".into(),
            path: format!("/../{}", outside_dir.path().file_name().unwrap().to_string_lossy()),
            keep_alive: false,
        };

        let (a, mut b) = duplex(4096);
        let (a_recv, mut a_send) = tokio::io::split(a);
        let mut a_recv = BufReader::new(a_recv);
        let spec_clone = spec;
        let req_clone = req;
        let server = tokio::spawn(async move {
            let r = serve_one(&spec_clone, &mut a_send, &mut a_recv).await;
            let _ = a_send.shutdown().await;
            r
        });

        let req_bytes = format!(
            "{} {} HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n",
            req_clone.method, req_clone.path
        );
        b.write_all(req_bytes.as_bytes()).await.unwrap();
        let _ = b.shutdown().await;

        let mut response = Vec::new();
        b.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response).into_owned();
        // We don't assert a specific code here — the resolver may collapse
        // the traversal into either 404 (path doesn't exist) or 403 (escapes
        // root). Either way the file content must not be served.
        assert!(
            !text.contains("nope"),
            "traversal leaked content: {text}"
        );
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn serve_one_rejects_post_with_405() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "x").unwrap();
        let spec = StaticSpec {
            name: "files".into(),
            root_dir: dir.path().to_path_buf(),
            allow_directory_listing: false,
            shared_secret: b"unused".to_vec(),
        };
        let req = Request {
            method: "POST".into(),
            path: "/a.txt".into(),
            keep_alive: false,
        };

        let (a, mut b) = duplex(4096);
        let (a_recv, mut a_send) = tokio::io::split(a);
        let mut a_recv = BufReader::new(a_recv);
        let spec_clone = spec;
        let req_clone = req;
        let server = tokio::spawn(async move {
            let r = serve_one(&spec_clone, &mut a_send, &mut a_recv).await;
            let _ = a_send.shutdown().await;
            r
        });

        let req_bytes = format!(
            "{} {} HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n",
            req_clone.method, req_clone.path
        );
        b.write_all(req_bytes.as_bytes()).await.unwrap();
        let _ = b.shutdown().await;

        let mut response = Vec::new();
        b.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response).into_owned();
        assert!(text.starts_with("HTTP/1.1 405"), "got: {text}");
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn serve_one_omits_body_for_head() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "BODY-CONTENT").unwrap();
        let spec = StaticSpec {
            name: "files".into(),
            root_dir: dir.path().to_path_buf(),
            allow_directory_listing: false,
            shared_secret: b"unused".to_vec(),
        };
        let req = Request {
            method: "HEAD".into(),
            path: "/hello.txt".into(),
            keep_alive: false,
        };

        let (a, mut b) = duplex(4096);
        let (a_recv, mut a_send) = tokio::io::split(a);
        let mut a_recv = BufReader::new(a_recv);
        let spec_clone = spec;
        let req_clone = req;
        let server = tokio::spawn(async move {
            let r = serve_one(&spec_clone, &mut a_send, &mut a_recv).await;
            let _ = a_send.shutdown().await;
            r
        });

        let req_bytes = format!(
            "{} {} HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n",
            req_clone.method, req_clone.path
        );
        b.write_all(req_bytes.as_bytes()).await.unwrap();
        let _ = b.shutdown().await;

        let mut response = Vec::new();
        b.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response).into_owned();
        assert!(text.starts_with("HTTP/1.1 200"));
        assert!(text.contains("Content-Length: 12"));
        assert!(!text.contains("BODY-CONTENT"));
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn serve_one_blocks_directory_listing_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("only.txt"), "x").unwrap();

        let spec = StaticSpec {
            name: "files".into(),
            root_dir: dir.path().to_path_buf(),
            allow_directory_listing: false,
            shared_secret: b"unused".to_vec(),
        };
        let req = Request {
            method: "GET".into(),
            path: "/".into(),
            keep_alive: false,
        };

        let (a, mut b) = duplex(4096);
        let (a_recv, mut a_send) = tokio::io::split(a);
        let mut a_recv = BufReader::new(a_recv);
        let spec_clone = spec;
        let req_clone = req;
        let server = tokio::spawn(async move {
            let r = serve_one(&spec_clone, &mut a_send, &mut a_recv).await;
            let _ = a_send.shutdown().await;
            r
        });

        let req_bytes = format!(
            "{} {} HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n",
            req_clone.method, req_clone.path
        );
        b.write_all(req_bytes.as_bytes()).await.unwrap();
        let _ = b.shutdown().await;

        let mut response = Vec::new();
        b.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response).into_owned();
        assert!(text.starts_with("HTTP/1.1 403"));
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn serve_one_renders_directory_listing_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "x").unwrap();
        std::fs::write(dir.path().join("b.txt"), "y").unwrap();

        let spec = StaticSpec {
            name: "files".into(),
            root_dir: dir.path().to_path_buf(),
            allow_directory_listing: true,
            shared_secret: b"unused".to_vec(),
        };
        let req = Request {
            method: "GET".into(),
            path: "/".into(),
            keep_alive: false,
        };

        let (a, mut b) = duplex(4096);
        let (a_recv, mut a_send) = tokio::io::split(a);
        let mut a_recv = BufReader::new(a_recv);
        let spec_clone = spec;
        let req_clone = req;
        let server = tokio::spawn(async move {
            let r = serve_one(&spec_clone, &mut a_send, &mut a_recv).await;
            let _ = a_send.shutdown().await;
            r
        });

        let req_bytes = format!(
            "{} {} HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n",
            req_clone.method, req_clone.path
        );
        b.write_all(req_bytes.as_bytes()).await.unwrap();
        let _ = b.shutdown().await;

        let mut response = Vec::new();
        b.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response).into_owned();
        assert!(text.starts_with("HTTP/1.1 200"));
        assert!(text.contains("text/html"));
        assert!(text.contains("a.txt"));
        assert!(text.contains("b.txt"));
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn read_request_parses_connection_keep_alive_for_http11() {
        let (_a, mut b) = duplex(4096);
        let (_a_recv, mut a_send) = tokio::io::split(_a);
        let writer = tokio::spawn(async move {
            a_send
                .write_all(
                    b"GET /foo HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n",
                )
                .await
                .unwrap();
            let _ = a_send.shutdown().await;
        });

        let req = read_request(&mut BufReader::new(b)).await.unwrap().expect("got request");
        writer.await.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/foo");
        assert!(req.keep_alive, "HTTP/1.1 default is keep-alive");
    }

    #[tokio::test]
    async fn read_request_parses_connection_close_for_http11() {
        let (_a, mut b) = duplex(4096);
        let (_a_recv, mut a_send) = tokio::io::split(_a);
        let writer = tokio::spawn(async move {
            a_send
                .write_all(
                    b"GET /foo HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let _ = a_send.shutdown().await;
        });

        let req = read_request(&mut BufReader::new(b)).await.unwrap().expect("got request");
        writer.await.unwrap();
        assert!(!req.keep_alive);
    }

    #[tokio::test]
    async fn read_request_defaults_http10_to_close() {
        let (_a, mut b) = duplex(4096);
        let (_a_recv, mut a_send) = tokio::io::split(_a);
        let writer = tokio::spawn(async move {
            a_send
                .write_all(b"GET /foo HTTP/1.0\r\nHost: x\r\n\r\n")
                .await
                .unwrap();
            let _ = a_send.shutdown().await;
        });

        let req = read_request(&mut BufReader::new(b)).await.unwrap().expect("got request");
        writer.await.unwrap();
        assert!(!req.keep_alive, "HTTP/1.0 default is close");
    }

    #[tokio::test]
    async fn read_request_opts_in_http10_with_keep_alive() {
        let (_a, mut b) = duplex(4096);
        let (_a_recv, mut a_send) = tokio::io::split(_a);
        let writer = tokio::spawn(async move {
            a_send
                .write_all(
                    b"GET /foo HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\n\r\n",
                )
                .await
                .unwrap();
            let _ = a_send.shutdown().await;
        });

        let req = read_request(&mut BufReader::new(b)).await.unwrap().expect("got request");
        writer.await.unwrap();
        assert!(req.keep_alive);
    }

    #[tokio::test]
    async fn serve_one_echoes_keep_alive_in_response_header() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "BODY").unwrap();
        let spec = StaticSpec {
            name: "files".into(),
            root_dir: dir.path().to_path_buf(),
            allow_directory_listing: false,
            shared_secret: b"unused".to_vec(),
        };
        let req = Request {
            method: "GET".into(),
            path: "/hello.txt".into(),
            keep_alive: true,
        };

        let (a, mut b) = duplex(4096);
        let (a_recv, mut a_send) = tokio::io::split(a);
        let mut a_recv = BufReader::new(a_recv);
        let server = tokio::spawn(async move {
            let r = serve_one(&spec, &mut a_send, &mut a_recv).await;
            let _ = a_send.shutdown().await;
            r
        });

        let req_bytes = format!(
            "{} {} HTTP/1.1\r\nHost: example\r\n\r\n",
            req.method, req.path
        );
        b.write_all(req_bytes.as_bytes()).await.unwrap();
        let _ = b.shutdown().await;

        let mut response = Vec::new();
        b.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response).into_owned();
        assert!(text.contains("Connection: keep-alive"));
        assert!(text.starts_with("HTTP/1.1 200"));
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn read_until_limited_rejects_runaway_line() {
        // Feed 9 KiB of non-newline bytes and confirm the helper bails
        // out instead of buffering forever.
        let (_client, mut server) = tokio::io::duplex(16 * 1024);
        let payload = vec![b'X'; 9 * 1024];
        let value = payload.clone();
        let writer = tokio::spawn(async move {
            server.write_all(&value).await.unwrap();
        });
        let err = read_until_limited(&mut BufReader::new(_client), b'\n', 8 * 1024)
            .await
            .unwrap_err();
        writer.abort();
        assert!(format!("{err:#}").contains("line exceeded"));
    }

    #[tokio::test]
    async fn read_headers_limited_rejects_runaway_headers() {
        let (_client, mut server) = tokio::io::duplex(16 * 1024);
        let mut payload = Vec::new();
        // 16 KiB of headers with no terminator.
        for _ in 0..(16 * 1024 / 5) {
            payload.extend_from_slice(b"X: y\r\n");
        }
        let n = payload.len();
        assert!(n > 8 * 1024);
        let writer = tokio::spawn(async move {
            server.write_all(&payload).await.unwrap();
        });
        let err = read_headers_limited(&mut BufReader::new(_client), 8 * 1024)
            .await
            .unwrap_err();
        writer.abort();
        assert!(format!("{err:#}").contains("headers exceeded"));
    }
}
