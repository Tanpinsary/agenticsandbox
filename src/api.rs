use crate::{
    error::{Error, Result, check, ensure},
    service::Service,
    util::*,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufReader, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}
struct Request {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    prefetched: Vec<u8>,
}
fn read_headers(bytes: &[u8]) -> Result<Option<Request>> {
    if let Some(end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
        check(
            end <= 16384,
            "HTTP headers too large",
            "request_too_large",
            413,
        )?;
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        ensure(
            req.parse(&bytes[..end + 4])
                .map_err(|_| Error::new("Malformed HTTP request", "invalid_request", 400))?
                .is_complete(),
            "Malformed HTTP request",
        )?;
        let mut map = BTreeMap::new();
        for header in req.headers.iter() {
            let name = header.name.to_ascii_lowercase();
            let value = std::str::from_utf8(header.value)
                .map_err(|_| Error::new("Invalid HTTP header", "invalid_request", 400))?
                .to_owned();
            ensure(
                map.insert(name, value).is_none(),
                "Duplicate HTTP headers unsupported",
            )?;
        }
        ensure(
            !map.contains_key("transfer-encoding"),
            "Transfer encoding unsupported",
        )?;
        return Ok(Some(Request {
            method: req.method.unwrap_or("").into(),
            path: req.path.unwrap_or("").into(),
            headers: map,
            prefetched: bytes[end + 4..].to_vec(),
        }));
    }
    check(
        bytes.len() <= 16384,
        "HTTP headers too large",
        "request_too_large",
        413,
    )?;
    Ok(None)
}
fn header<'a>(req: &'a Request, name: &str) -> &'a str {
    req.headers.get(name).map(String::as_str).unwrap_or("")
}
fn send_json(stream: &mut dyn Stream, status: u16, value: &Value) -> Result<()> {
    let bytes = canonical(value);
    write!(
        stream,
        "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        bytes.len()
    )?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}
fn token(req: &Request) -> Result<&str> {
    header(req, "authorization")
        .strip_prefix("Bearer ")
        .ok_or_else(|| Error::new("Authentication required", "unauthorized", 401))
}
fn request_length(service: &Service, req: &Request) -> Result<u64> {
    check(
        req.method == "POST" && req.path == "/rpc",
        "Unknown endpoint",
        "not_found",
        404,
    )?;
    service.authenticate(token(req)?)?;
    let limit = (service.config.limit("max_file_bytes") * 4 / 3 + 4194304).min(104857600);
    ensure(
        matches!(header(req, "content-encoding"), "" | "identity"),
        "Compressed requests unsupported",
    )?;
    ensure(
        header(req, "content-type").split(';').next() == Some("application/json"),
        "Expected application/json",
    )?;
    let length = header(req, "content-length").parse::<u64>().unwrap_or(0);
    check(
        length > 0 && length <= limit,
        "Invalid request size",
        "request_too_large",
        413,
    )?;
    Ok(length)
}
struct Ready {
    stream: Box<dyn Stream>,
    socket: TcpStream,
    request: Request,
    bytes: Vec<u8>,
    _budget: BufferBudget,
}
// Keep queued and active request bodies in the same ingress budget. Moving a
// complete request to a worker must not make its memory disappear from the cap.
struct BufferBudget {
    total: Arc<AtomicU64>,
    owned: u64,
    limit: u64,
}
impl BufferBudget {
    fn grow(&mut self, count: u64) -> Result<()> {
        self.total
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
                total.checked_add(count).filter(|next| *next <= self.limit)
            })
            .map_err(|_| Error::new("HTTP ingress buffer full", "server_busy", 503))?;
        self.owned += count;
        Ok(())
    }
    fn clear(&mut self) {
        self.total.fetch_sub(self.owned, Ordering::Relaxed);
        self.owned = 0;
    }
}
impl Drop for BufferBudget {
    fn drop(&mut self) {
        self.clear();
    }
}
fn handle(ready: Ready, service: &Service) {
    let Ready {
        mut stream,
        socket,
        request: req,
        bytes,
        _budget,
    } = ready;
    let mut started = false;
    let result = (|| -> Result<()> {
        let length = request_length(service, &req)?;
        let token = token(&req)?;
        ensure(bytes.len() as u64 == length, "Incomplete request body")?;
        let payload: Value = serde_json::from_slice(&bytes)?;
        obj(&payload)?;
        let result = service.invoke(
            token,
            &s(&payload, "method"),
            payload.get("params").unwrap_or(&json!({})),
        )?;
        started = true;
        send_json(stream.as_mut(), 200, &json!({"result":result}))
    })();
    if let Err(error) = result
        && !started
    {
        let _ = send_json(
            stream.as_mut(),
            error.status,
            &json!({"error":error.json()}),
        );
    }
    // An early rejection can leave request bytes unread. Closing such a TCP
    // socket sends a reset on some platforms, losing the error response.
    // Half-close first, then drain a small bounded amount with a short timeout.
    let _ = socket.shutdown(Shutdown::Write);
    let _ = socket.set_read_timeout(Some(Duration::from_millis(100)));
    let _ = socket.take(65536).read_to_end(&mut Vec::new());
}
enum Progress {
    Waiting,
    Ready(Ready),
    Closed,
}
struct Pending {
    stream: Option<Box<dyn Stream>>,
    socket: TcpStream,
    request: Option<Request>,
    bytes: Vec<u8>,
    length: u64,
    deadline: Instant,
    closing: bool,
    drained: usize,
    budget: Option<BufferBudget>,
}
impl Pending {
    fn progress(&mut self, service: &Service) -> Result<Progress> {
        if self.closing {
            if Instant::now() >= self.deadline || self.drained >= 65536 {
                return Ok(Progress::Closed);
            }
            let mut buf = [0; 4096];
            return match self.stream.as_mut().unwrap().read(&mut buf) {
                Ok(0) => Ok(Progress::Closed),
                Ok(n) => {
                    self.drained += n;
                    Ok(Progress::Waiting)
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(Progress::Waiting),
                Err(_) => Ok(Progress::Closed),
            };
        }
        check(
            Instant::now() < self.deadline,
            "HTTP request timed out",
            "request_timeout",
            408,
        )?;
        let mut buf = [0; 65536];
        let cap = if self.request.is_some() {
            (self.length.saturating_sub(self.bytes.len() as u64) + 1).min(65536) as usize
        } else {
            4096
        };
        match self.stream.as_mut().unwrap().read(&mut buf[..cap]) {
            Ok(0) => {
                return Err(Error::new(
                    "Incomplete HTTP request",
                    "invalid_request",
                    400,
                ));
            }
            Ok(n) => {
                self.budget.as_mut().unwrap().grow(n as u64)?;
                self.bytes.extend_from_slice(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(Progress::Waiting),
            Err(e) => return Err(e.into()),
        }
        if self.request.is_none() {
            let Some(mut req) = read_headers(&self.bytes)? else {
                return Ok(Progress::Waiting);
            };
            self.bytes = std::mem::take(&mut req.prefetched);
            self.length = if req.method == "GET" {
                0
            } else {
                request_length(service, &req)?
            };
            self.request = Some(req);
            self.deadline = Instant::now()
                + Duration::from_secs(service.config.limit("http_body_timeout_seconds"));
        }
        ensure(
            self.bytes.len() as u64 <= self.length,
            "Request exceeds declared length",
        )?;
        if self.bytes.len() as u64 != self.length {
            return Ok(Progress::Waiting);
        }
        Ok(Progress::Ready(Ready {
            stream: self.stream.take().unwrap(),
            socket: self.socket.try_clone()?,
            request: self.request.take().unwrap(),
            bytes: std::mem::take(&mut self.bytes),
            _budget: self.budget.take().unwrap(),
        }))
    }
    fn reject(&mut self, error: &Error) {
        if let Some(stream) = &mut self.stream {
            let _ = send_json(
                stream.as_mut(),
                error.status,
                &json!({"error":error.json()}),
            );
        }
        let _ = self.socket.shutdown(Shutdown::Write);
        self.bytes = Vec::new();
        self.budget.as_mut().unwrap().clear();
        self.closing = true;
        self.deadline = Instant::now() + Duration::from_millis(100);
    }
}
pub fn serve(
    service: Service,
    host: &str,
    port: u16,
    cert: Option<&Path>,
    key: Option<&Path>,
) -> Result<()> {
    ensure(
        matches!(host, "localhost" | "127.0.0.1" | "::1") || cert.is_some() && key.is_some(),
        "Public listeners require TLS",
    )?;
    ensure(
        cert.is_some() == key.is_some(),
        "Provide TLS certificate and key together",
    )?;
    // Load and validate TLS before binding a socket.
    let tls = if let (Some(cert), Some(key)) = (cert, key) {
        let certificates = rustls_pemfile::certs(&mut BufReader::new(fs::File::open(cert)?))
            .collect::<std::io::Result<Vec<_>>>()?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(fs::File::open(key)?))?
            .ok_or_else(|| Error::new("Missing TLS private key", "configuration_error", 400))?;
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::new("TLS setup failed", "configuration_error", 400))?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|_| Error::new("Invalid TLS certificate or key", "configuration_error", 400))?;
        Some(Arc::new(config))
    } else {
        None
    };
    let interval = n(&service.config.value, "reconcile_interval_seconds", 5).max(1);
    let monitor = service.connection()?;
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(interval));
            let _ = monitor.invoke(&monitor.admin, "task.reconcile", &json!({}));
        }
    });
    let listener = TcpListener::bind((host, port))?;
    listener.set_nonblocking(true)?;
    let (sender, receiver) = mpsc::sync_channel::<Ready>(32);
    for receiver in [receiver] {
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..16 {
            let receiver = receiver.clone();
            let service = service.connection()?;
            std::thread::spawn(move || {
                loop {
                    let ready = match receiver.lock().unwrap().recv() {
                        Ok(ready) => ready,
                        Err(_) => return,
                    };
                    let _ = ready.socket.set_nonblocking(false);
                    let _ = ready
                        .socket
                        .set_write_timeout(Some(Duration::from_secs(30)));
                    handle(ready, &service);
                }
            });
        }
    }
    // Incomplete TLS handshakes, headers and bodies never occupy operation
    // workers. Absolute deadlines prevent trickle traffic from renewing them.
    let mut pending = Vec::<Pending>::new();
    let buffer_total = Arc::new(AtomicU64::new(0));
    loop {
        for _ in 0..32 {
            let socket = match listener.accept() {
                Ok((socket, _)) => socket,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            };
            socket.set_nonblocking(true)?;
            if pending.len() as u64 >= service.config.limit("max_http_connections") {
                let _ = socket.shutdown(Shutdown::Both);
                continue;
            }
            let close_socket = socket.try_clone()?;
            let stream: Box<dyn Stream> = if let Some(config) = &tls {
                let connection = rustls::ServerConnection::new(config.clone())
                    .map_err(|_| Error::new("TLS setup failed", "internal_error", 500))?;
                Box::new(rustls::StreamOwned::new(connection, socket))
            } else {
                Box::new(socket)
            };
            pending.push(Pending {
                stream: Some(stream),
                socket: close_socket,
                request: None,
                bytes: Vec::new(),
                length: 0,
                closing: false,
                drained: 0,
                budget: Some(BufferBudget {
                    total: buffer_total.clone(),
                    owned: 0,
                    limit: service.config.limit("max_http_buffer_bytes"),
                }),
                deadline: Instant::now()
                    + Duration::from_millis(service.config.limit("http_header_timeout_ms")),
            });
        }
        let mut index = 0;
        while index < pending.len() {
            match pending[index].progress(&service) {
                Ok(Progress::Closed) => {
                    pending.swap_remove(index);
                }
                Ok(Progress::Ready(mut ready)) => {
                    pending.swap_remove(index);
                    if ready.request.method == "GET" {
                        let health = ready.request.path == "/health";
                        let _ = send_json(
                            ready.stream.as_mut(),
                            if health { 200 } else { 404 },
                            &if health {
                                json!({"service":"agenticsandbox","version":crate::VERSION})
                            } else {
                                json!({"error":"not_found"})
                            },
                        );
                        let _ = ready.socket.shutdown(Shutdown::Write);
                    } else if let Err(error) = sender.try_send(ready) {
                        let mut ready = match error {
                            mpsc::TrySendError::Full(ready) => ready,
                            mpsc::TrySendError::Disconnected(_) => {
                                return Err(Error::new(
                                    "HTTP workers unavailable",
                                    "internal_error",
                                    500,
                                ));
                            }
                        };
                        let _ = send_json(
                            ready.stream.as_mut(),
                            503,
                            &json!({"error":{"code":"server_busy","message":"Controller operation queue full"}}),
                        );
                        let _ = ready.socket.shutdown(Shutdown::Write);
                    }
                }
                Ok(Progress::Waiting) => {
                    index += 1;
                }
                Err(error) => {
                    pending[index].reject(&error);
                    index += 1;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queued_request_keeps_budget_until_worker_releases_it() {
        let total = Arc::new(AtomicU64::new(0));
        let mut queued = BufferBudget {
            total: total.clone(),
            owned: 0,
            limit: 10,
        };
        queued.grow(8).unwrap();
        let mut pending = BufferBudget {
            total: total.clone(),
            owned: 0,
            limit: 10,
        };
        assert!(pending.grow(3).is_err());
        assert_eq!(total.load(Ordering::Relaxed), 8);
        drop(queued);
        pending.grow(10).unwrap();
        pending.clear();
        assert_eq!(total.load(Ordering::Relaxed), 0);
    }
}
