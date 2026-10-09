//! Task control service: shared state, authorization, tool dispatch and reconciliation.

use crate::{
    backend::Backend,
    config::Config,
    coordination::{Coordination, Guard},
    error::{Error, Result, check, ensure},
    git,
    store::Store,
    util::*,
};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::Arc,
};
pub const SCOPES: &[&str] = &[
    "exec",
    "read",
    "write",
    "search",
    "status",
    "logs",
    "checkpoint",
    "submit",
    "create",
];
pub struct Service {
    pub config: Config,
    pub store: Store,
    pub backend: Backend,
    pub admin: String,
    pub(crate) coordination: Arc<Coordination>,
}
pub(super) fn remove(value: &mut Value, key: &str) {
    if let Some(o) = value.as_object_mut() {
        o.remove(key);
    }
}
pub(super) fn merge(value: &mut Value, other: Value) -> Result<()> {
    for (k, v) in obj(&other)? {
        value[k] = v.clone();
    }
    Ok(())
}
pub(super) fn push(value: &mut Value, key: &str, item: Value) {
    let list = value[key].as_array_mut().expect("stored array");
    if !list.contains(&item) {
        list.push(item);
    }
}
pub(super) fn running(record: &Value) -> bool {
    matches!(record["state"].as_str(), Some("starting" | "running"))
}
pub(super) fn admin(p: &Value) -> Result<()> {
    check(
        b(p, "admin"),
        "Administrator authorization required",
        "forbidden",
        403,
    )
}
mod delivery;
mod execution;
mod files;
mod registry;
mod task;

impl Service {
    pub fn new(config: Config) -> Result<Self> {
        let store = Store::new(&config.state)?;
        ensure(
            config.admin_file.metadata()?.mode() & 0o077 == 0,
            "Admin credential must be private",
        )?;
        let admin = fs::read_to_string(&config.admin_file)?.trim().to_owned();
        ensure(admin.len() >= 32, "Admin token too short")?;
        let backend = Backend {
            config: config.clone(),
        };
        Ok(Self {
            config,
            store,
            backend,
            admin,
            coordination: Arc::new(Coordination::default()),
        })
    }
    pub fn connection(&self) -> Result<Self> {
        let mut value = Self::new(self.config.clone())?;
        value.coordination = self.coordination.clone();
        Ok(value)
    }
    pub(crate) fn task_lock(&self, id: &str) -> Result<Guard> {
        self.coordination.acquire(format!("task:{id}"))
    }
    pub fn authenticate(&self, token: &str) -> Result<Value> {
        if digest(token.as_bytes()) == digest(self.admin.as_bytes()) {
            Ok(json!({"id":"admin","admin":true}))
        } else {
            self.store.authenticate(token)
        }
    }
    pub fn authorize(&self, p: &Value, scope: &str, t: &Value) -> Result<()> {
        check(
            b(p, "admin")
                || (p["task_id"] == t["id"]
                    && p["scopes"]
                        .as_array()
                        .is_some_and(|a| a.contains(&json!(scope)))),
            "Task capability does not authorize operation",
            "forbidden",
            403,
        )
    }
    pub fn live(&self, t: &Value) -> Result<()> {
        check(
            t["environment_state"] == "ready",
            "Task environment is not ready",
            "not_ready",
            409,
        )?;
        check(
            t["expires_at"].as_f64().unwrap_or(0.0) > now(),
            "Task expired",
            "expired",
            409,
        )
    }
    pub fn refresh(&self, t: &mut Value) -> Result<()> {
        if !matches!(
            t["environment_state"].as_str(),
            Some("ready" | "stopped" | "starting")
        ) {
            return Ok(());
        }
        let state = self.backend.state(t)?;
        if t["environment_state"] != state {
            if state == "ready" {
                self.backend.verify(t)?;
            }
            t["environment_state"] = json!(state);
            if state == "lost" {
                for id in strings(&t["executions"])? {
                    let mut r = self.store.get("execution", &id)?;
                    if r["generation"] == t["generation"] && running(&r) {
                        r["state"] = json!("lost");
                        r["completed_at"] = json!(now());
                        self.store.put("execution", &r)?;
                    }
                }
            }
            self.store.put("task", t)?;
        }
        Ok(())
    }
    pub(super) fn task_result(&self, t: &Value, p: &Value) -> Value {
        let mut value = t.clone();
        remove(&mut value, "handle");
        remove(&mut value, "source_path");
        if !b(p, "admin") {
            remove(&mut value, "repo");
        }
        value["workspace"] = json!("/workspace/repo");
        value
    }
    pub(super) fn id(&self, prefix: &str, p: &Value, op: &str, req: &Value) -> String {
        format!(
            "{prefix}{}",
            if let Some(key) = req["idempotency_key"].as_str() {
                digest(&canonical(&json!([p["id"], op, key])))[..24].to_owned()
            } else {
                uuid::Uuid::new_v4().simple().to_string()[..24].to_owned()
            }
        )
    }
    pub(super) fn artifact(&self, kind: &str, id: &str) -> Result<PathBuf> {
        ensure(
            !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric()),
            "Invalid artifact ID",
        )?;
        Ok(self
            .config
            .state
            .join("artifacts")
            .join(kind)
            .join(format!("{id}.json")))
    }
    pub(super) fn save_artifact(&self, kind: &str, id: &str, value: &Value) -> Result<String> {
        let path = self.artifact(kind, id)?;
        let bytes = canonical(value);
        if path.exists() {
            check(
                fs::read(&path)? == bytes,
                "Cannot overwrite immutable artifact",
                "conflict",
                409,
            )?;
        } else {
            atomic(&path, &bytes, 0o600)?;
        }
        Ok(digest(&bytes))
    }
    pub(super) fn load_artifact(&self, kind: &str, id: &str, sum: &Value) -> Result<Value> {
        let data = read_limit(
            File::open(self.artifact(kind, id)?)?,
            crate::worker::MAX_REQUEST,
        )?;
        if !sum.is_null() {
            check(
                sum == &digest(&data),
                "Stored artifact checksum mismatch",
                "corrupt_artifact",
                409,
            )?;
        }
        Ok(serde_json::from_slice(&data)?)
    }
    pub(super) fn get_task(
        &self,
        p: &Value,
        req: &Value,
        scope: &str,
        live: bool,
    ) -> Result<Value> {
        let mut t = self.store.get("task", &s(req, "task_id"))?;
        self.authorize(p, scope, &t)?;
        if live {
            self.refresh(&mut t)?;
            self.live(&t)?;
        }
        Ok(t)
    }
    pub(super) fn capability(&self, t: &Value) -> Result<String> {
        self.store.capability(
            &s(t, "id"),
            t["expires_at"].as_f64().unwrap_or(0.0),
            &json!(SCOPES),
        )
    }
    pub(super) fn finish_task(&self, p: &Value, op: &str, req: &Value, t: &Value) -> Result<Value> {
        let mut value = self.task_result(t, p);
        self.store.finish(p, op, req, &value)?;
        value["task_token"] = json!(self.capability(t)?);
        Ok(value)
    }
    pub fn invoke(&self, token: &str, method: &str, req: &Value) -> Result<Value> {
        obj(req)?;
        let p = self.authenticate(token)?;
        let _request = if let Some(key) = req["idempotency_key"].as_str() {
            Some(
                self.coordination
                    .acquire(format!("request:{}:{method}:{key}", s(&p, "id")))?,
            )
        } else {
            None
        };
        let _task = if req["task_id"].is_string() {
            Some(self.task_lock(&s(req, "task_id"))?)
        } else if method == "task.create" && req["parent_task_id"].is_string() {
            Some(self.task_lock(&s(req, "parent_task_id"))?)
        } else {
            None
        };
        let _candidate = if req["candidate_id"].is_string() {
            Some(
                self.coordination
                    .acquire(format!("candidate:{}", s(req, "candidate_id")))?,
            )
        } else {
            None
        };
        // A restore may revoke a capability while this request waits for its
        // resource. Never authorize a new generation with the old principal.
        let p = self.authenticate(token)?;
        match method {
            "task.create" => self.create(&p, req, false),
            "task.status" => self.status(&p, req),
            "task.exec" => self.execute(&p, req, None),
            "task.read" | "task.write" | "task.search" => self.files(&p, method, req),
            "task.logs" => self.logs(&p, req),
            "task.cancel" => self.cancel(&p, req),
            "task.checkpoint" => self.checkpoint(&p, req, false),
            "task.submit" => self.submit(&p, req),
            "task.result" => self.result(&p, req),
            "task.destroy" => self.destroy(&p, req),
            "task.restore" => self.restore(&p, req),
            "task.extend" => self.extend(&p, req),
            "task.reconcile" => self.reconcile(&p),
            "repo.register" => self.register_repository(&p, req),
            "sandbox.info" => self.sandbox_info(&p),
            "task.prepare_integration" => self.prepare(&p, req),
            "task.validate" => self.validate(&p, req),
            "task.integrate" => self.integrate(&p, req),
            _ => Err(Error::new("Unknown method", "not_found", 404)),
        }
    }
}
