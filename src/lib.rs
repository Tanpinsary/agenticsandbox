pub mod api;
pub mod backend;
pub mod config;
pub mod coordination;
pub mod error;
pub mod git;
pub mod isolation;
pub mod process_scope;
pub mod remote;
pub mod runtime;
pub mod service;
pub mod store;
pub mod transport;
pub mod util;
pub mod worker;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const WORKER_PROTOCOL: u64 = 1;
#[cfg(test)]
mod native_tests;
