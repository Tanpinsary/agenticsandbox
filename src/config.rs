use crate::{
    error::{Result, ensure},
    util::*,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
#[derive(Clone)]
pub struct Config {
    pub value: Value,
    pub state: PathBuf,
    pub admin_file: PathBuf,
    pub backend: String,
    pub repos: BTreeMap<String, PathBuf>,
    pub limits: Value,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let path = std::fs::canonicalize(path)?;
        Self::new(load(&path)?, path.parent().unwrap())
    }
    pub fn new(value: Value, base: &Path) -> Result<Self> {
        obj(&value)?;
        let backend = s(&value, "backend");
        ensure(!backend.is_empty(), "Configure a backend")?;
        ensure(
            matches!(backend.as_str(), "local" | "remote"),
            "Unknown backend",
        )?;
        ensure(
            backend != "local" || b(&value, "allow_unsafe_local"),
            "Local backend requires allow_unsafe_local: true",
        )?;
        if backend == "remote" {
            crate::remote::validate_config(&value["remote"])?;
        }
        ensure(
            value["runtimes"].as_object().is_some_and(|o| !o.is_empty()),
            "Configure at least one runtime",
        )?;
        let mut limits = json!({"max_file_bytes":8388608,"max_total_bytes":67108864,"max_files":10000,"max_ttl_minutes":360,"max_output_bytes":4194304,"max_execution_seconds":3600,"max_scan_entries":100000,"max_tasks":32,"max_concurrent_executions":8,"max_bundle_bytes":67108864,"max_http_connections":128,"max_http_buffer_bytes":134217728,"http_header_timeout_ms":2000,"http_body_timeout_seconds":30});
        if let Some(overrides) = value.get("limits") {
            for (k, v) in obj(overrides)? {
                ensure(
                    v.as_u64()
                        .is_some_and(|n| n > 0 && n <= i64::MAX as u64 / 8),
                    "Limits must be positive integers",
                )?;
                limits[k] = v.clone();
            }
        }
        let mut repos = BTreeMap::new();
        if let Some(repositories) = value.get("repos") {
            for (k, v) in obj(repositories)? {
                let path = v.as_str().ok_or_else(|| {
                    crate::error::Error::new("Invalid repository path", "invalid_request", 400)
                })?;
                repos.insert(k.clone(), absolute(base, path));
            }
        }
        Ok(Self {
            state: absolute(base, value["state_dir"].as_str().unwrap_or(".state")),
            admin_file: absolute(
                base,
                value["admin_token_file"]
                    .as_str()
                    .unwrap_or(".state/admin.token"),
            ),
            value,
            backend,
            repos,
            limits,
        })
    }
    pub fn limit(&self, key: &str) -> u64 {
        n(&self.limits, key, 0)
    }
    pub fn runtime(&self, name: &str, network: &str) -> Result<Value> {
        let p = &self.value["runtimes"][name];
        ensure(p.is_object(), "Unknown runtime profile")?;
        ensure(
            self.value
                .get("networks")
                .unwrap_or(&json!({"none":{}}))
                .get(network)
                .is_some(),
            "Unknown network profile",
        )?;
        ensure(
            strings(p.get("networks").unwrap_or(&json!(["none"])))?.contains(&network.to_owned()),
            "Network profile is not allowed",
        )?;
        if self.backend == "remote" {
            crate::remote::validate_profile(p, network)?;
            crate::remote::resolve_host(&self.value["remote"], p)?;
        }
        Ok(p.clone())
    }
}
pub fn pinned_image(image: &str) -> bool {
    regex::Regex::new(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
        .unwrap()
        .is_match(image)
}
