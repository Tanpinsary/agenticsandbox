use serde_json::{Value, json};
use std::fmt;

#[derive(Debug)]
pub struct Error {
    pub message: String,
    pub code: String,
    pub status: u16,
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn new(message: impl Into<String>, code: &str, status: u16) -> Self {
        Self {
            message: message.into(),
            code: code.into(),
            status,
        }
    }
    pub fn json(&self) -> Value {
        json!({"code": self.code, "message": self.message})
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::new(e.to_string(), "worker_error", 409)
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::new("Malformed JSON", "invalid_request", 400)
    }
}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::new(e.to_string(), "storage_error", 500)
    }
}
impl From<reqwest::Error> for Error {
    fn from(_: reqwest::Error) -> Self {
        Self::new("HTTPS connection failed", "connection_error", 503)
    }
}
pub fn ensure(ok: bool, message: &str) -> Result<()> {
    check(ok, message, "invalid_request", 400)
}
pub fn check(ok: bool, message: &str, code: &str, status: u16) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::new(message, code, status))
    }
}
