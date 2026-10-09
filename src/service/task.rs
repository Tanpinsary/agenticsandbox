//! Task records: creation, status, deadlines, checkpoints, freezing, recovery and reconciliation.

use super::*;

impl Service {
    pub fn create(&self, p: &Value, req: &Value, verification: bool) -> Result<Value> {
        ensure(
            obj(req)?.keys().all(|k| {
                [
                    "repo",
                    "base",
                    "workspace_mode",
                    "files",
                    "runtime",
                    "network",
                    "ttl_minutes",
                    "purpose",
                    "parent_task_id",
                    "idempotency_key",
                    "include_dirty",
                    "role",
                ]
                .contains(&k.as_str())
            }),
            "Unknown task creation field",
        )?;
        if let Some(mut prev) = self.store.reserve(p, "create", req)? {
            let t = self.store.get("task", &s(&prev, "id"))?;
            prev["task_token"] = json!(self.capability(&t)?);
            return Ok(prev);
        }
        let mode = req["workspace_mode"].as_str().unwrap_or("snapshot");
        ensure(
            matches!(mode, "snapshot" | "repository"),
            "Unknown workspace mode",
        )?;
        ensure(
            !b(req, "include_dirty"),
            "Commit changes before providing input",
        )?;
        let role = req["role"].as_str().unwrap_or("implementation");
        ensure(
            matches!(role, "implementation" | "scratch") || verification && role == "verification",
            "Verification tasks are created by task.validate",
        )?;
        let repo = req["repo"].clone();
        let network = req["network"].as_str().unwrap_or("none");
        let profile = self.config.runtime(&s(req, "runtime"), network)?;
        let ttl = n(req, "ttl_minutes", 60);
        ensure(
            req.get("ttl_minutes").is_none() || req["ttl_minutes"].as_u64().is_some(),
            "Invalid TTL",
        )?;
        ensure(
            ttl > 0 && ttl <= self.config.limit("max_ttl_minutes"),
            "Invalid TTL",
        )?;
        let parent = if !b(p, "admin") {
            let t = self.store.get("task", &s(req, "parent_task_id"))?;
            self.authorize(p, "create", &t)?;
            self.live(&t)?;
            check(
                repo == t["repo"]
                    && req["base"] == t["base"]
                    && mode == s(&t, "workspace_mode")
                    && req["runtime"] == t["runtime"]
                    && network == s(&t, "network")
                    && ttl <= n(&t, "ttl_minutes", 0),
                "Child input/runtime/network/TTL exceeds parent",
                "forbidden",
                403,
            )?;
            Some(t)
        } else {
            None
        };
        let policy = if let Some(parent) = &parent {
            Policy::parse(&parent["files"])?.child(req.get("files").unwrap_or(&json!({})))?
        } else {
            Policy::parse(req.get("files").unwrap_or(&json!({})))?
        };
        let id = self.id("t", p, "create", req);
        let _task = self.task_lock(&id)?;
        let allocation = self.coordination.acquire("quota:tasks".into())?;
        let existing = self.store.list("task")?.into_iter().find(|t| t["id"] == id);
        if let Some(t) = &existing
            && t["environment_state"] == "ready"
        {
            return self.finish_task(p, "create", req, t);
        }
        let mut t = if let Some(t) = existing {
            check(
                matches!(
                    t["environment_state"].as_str(),
                    Some("preparing_input" | "creating" | "failed")
                ),
                "Task creation already complete",
                "conflict",
                409,
            )?;
            t
        } else {
            check(
                (self
                    .store
                    .list("task")?
                    .iter()
                    .filter(|t| {
                        !matches!(
                            t["environment_state"].as_str(),
                            Some("destroyed" | "lost" | "expired")
                        )
                    })
                    .count() as u64)
                    < self.config.limit("max_tasks"),
                "Active task limit reached",
                "quota_exceeded",
                429,
            )?;
            if repo.is_null() {
                check(
                    b(p, "admin") && mode == "snapshot",
                    "Scratch tasks require administrator and snapshot mode",
                    "forbidden",
                    403,
                )?;
            } else {
                self.repository(repo.as_str().unwrap_or(""))?;
            }
            // Reserve the slot durably before Git/worker I/O. Concurrent creates
            // can prepare different inputs without bypassing the global quota.
            let mut value = json!({"id":id,"repo":repo,"base":null,"input_base_revision":req["base"],"files":policy.json(),"workspace_mode":mode,"runtime":req["runtime"],"network":network,"ttl_minutes":ttl,"purpose":req["purpose"].as_str().unwrap_or(""),"role":role,"parent_task_id":parent.as_ref().map(|t|t["id"].clone()),"environment_state":"preparing_input","created_at":now(),"expires_at":now()+ttl as f64*60.0,"generation":0,"isolated":self.backend.isolated(),"image_digest":profile["image_digest"],"isolation_basis":if self.config.backend=="remote"{"docker_controls"}else if self.backend.isolated(){"operator_audit"}else{"none"},"executions":[],"results":[],"checkpoints":[]});
            if let Some(parent) = &parent {
                value["expires_at"] = json!(
                    value["expires_at"]
                        .as_f64()
                        .unwrap()
                        .min(parent["expires_at"].as_f64().unwrap_or(0.0))
                );
            }
            self.store.put("task", &value)?;
            value
        };
        drop(allocation);
        let preparation = (|| -> Result<()> {
            if t["input_checksum"].is_null()
                || mode == "repository" && t["repository_bundle_checksum"].is_null()
            {
                let (files, bundle) = if repo.is_null() {
                    (json!({}), None)
                } else {
                    let source = &self.repository(repo.as_str().unwrap())?;
                    if t["base"].is_null() {
                        t["base"] = json!(git::resolve(source, &s(&t, "input_base_revision"))?);
                        self.store.put("task", &t)?;
                    }
                    let base = s(&t, "base");
                    let files = git::export(
                        source,
                        &base,
                        &if mode == "repository" {
                            Policy::all()
                        } else {
                            policy.clone()
                        },
                        &self.config.limits,
                    )?;
                    let bundle = if mode == "repository" {
                        Some(git::bundle(source, &base, &self.config.limits)?)
                    } else {
                        None
                    };
                    (files, bundle)
                };
                t["input_checksum"] = json!(self.save_artifact(
                    "inputs",
                    &id,
                    &json!({"base":t["base"],"files":files,"workspace_mode":mode})
                )?);
                if let Some(bundle) = bundle {
                    t["repository_bundle_checksum"] = json!(self.save_artifact(
                        "bundles",
                        &id,
                        &json!({"base":t["base"],"data":encode(&bundle)})
                    )?);
                }
                remove(&mut t, "input_base_revision");
                t["environment_state"] = json!("creating");
                self.store.put("task", &t)?;
            }
            Ok(())
        })();
        if let Err(error) = preparation {
            t["environment_state"] = json!("failed");
            t["error"] = json!(error.message);
            self.store.put("task", &t)?;
            return Err(error);
        }
        let frozen = self.load_artifact("inputs", &id, &t["input_checksum"])?;
        let bundle = self.input_bundle(&t)?;
        match self
            .backend
            .create(&mut t, &frozen["files"], bundle.as_deref())
        {
            Ok(value) => {
                merge(&mut t, value)?;
                t["environment_state"] = json!("ready");
                remove(&mut t, "error");
            }
            Err(e) => {
                t["environment_state"] = json!("failed");
                t["error"] = json!(e.message);
                self.store.put("task", &t)?;
                return Err(e);
            }
        }
        self.store.put("task", &t)?;
        self.finish_task(p, "create", req, &t)
    }
    pub fn status(&self, p: &Value, req: &Value) -> Result<Value> {
        let _task = self.task_lock(&s(req, "task_id"))?;
        let mut t = self.get_task(p, req, "status", false)?;
        self.refresh(&mut t)?;
        let mut records = Vec::new();
        for id in strings(&t["executions"])? {
            records.push(if t["environment_state"] == "ready" {
                self.update_execution(&t, &id)?
            } else {
                self.store.get("execution", &id)?
            });
        }
        let mut response = self.task_result(&t, p);
        response["execution_records"] = json!(records);
        Ok(response)
    }
    pub(super) fn extend(&self, p: &Value, req: &Value) -> Result<Value> {
        let mut t = self.get_task(p, req, "extend", true)?;
        let ttl = n(req, "ttl_minutes", 0);
        ensure(
            ttl > 0 && ttl <= self.config.limit("max_ttl_minutes"),
            "Invalid TTL",
        )?;
        t["expires_at"] = json!(self.backend.extend(&t, ttl)?);
        for key in ["expiry_checkpoint", "expiry_notice", "expiry_error"] {
            remove(&mut t, key);
        }
        self.store.put("task", &t)?;
        let mut result = self.task_result(&t, p);
        result["task_token"] = json!(self.capability(&t)?);
        Ok(result)
    }
    pub(super) fn destroy(&self, p: &Value, req: &Value) -> Result<Value> {
        let mut t = self.get_task(p, req, "destroy", false)?;
        if t["environment_state"] == "destroyed" {
            return Ok(self.task_result(&t, p));
        }
        if self.backend.exists(&t)? {
            self.refresh(&mut t)?;
            check(
                t["environment_state"] == "ready" || b(req, "abandon"),
                "Start workspace or explicitly abandon data",
                "not_ready",
                409,
            )?;
            if t["environment_state"] == "ready" {
                for id in strings(&t["executions"])? {
                    let cached = self.store.get("execution", &id)?;
                    if cached["generation"] != t["generation"] {
                        continue;
                    }
                    let r = self.backend.call(&t, "execution", &json!({"id":id}))?;
                    check(
                        !running(&r),
                        "Cancel running executions before destroying",
                        "running",
                        409,
                    )?;
                }
                self.collect_logs(&t)?;
            }
            if !b(req, "abandon") {
                let record = self.checkpoint(p, &json!({"task_id":t["id"]}), true)?;
                t = self.store.get("task", &s(&t, "id"))?;
                t["destruction_checkpoint"] = record["id"].clone();
            }
            self.backend.destroy(&t)?;
        }
        t["environment_state"] = json!("destroyed");
        self.store.put("task", &t)?;
        Ok(self.task_result(&t, p))
    }
    pub(super) fn restore(&self, p: &Value, req: &Value) -> Result<Value> {
        admin(p)?;
        let mut t = self.get_task(p, req, "restore", false)?;
        if let Some(mut prev) = self.store.reserve(p, "restore", req)? {
            check(
                prev["generation"] == t["generation"],
                "Restore belongs to earlier generation",
                "stale_restore",
                409,
            )?;
            prev["task_token"] = json!(self.capability(&t)?);
            return Ok(prev);
        }
        let checkpoint = self.store.get("checkpoint", &s(req, "checkpoint_id"))?;
        ensure(
            checkpoint["task_id"] == t["id"],
            "Checkpoint belongs to another task",
        )?;
        let resuming = t["restore_checkpoint_id"] == checkpoint["id"]
            && matches!(t["environment_state"].as_str(), Some("creating" | "failed"));
        let finished =
            t["restored_checkpoint_id"] == checkpoint["id"] && t["environment_state"] == "ready";
        ensure(
            resuming
                || finished
                || matches!(
                    t["environment_state"].as_str(),
                    Some("destroyed" | "lost" | "expired" | "failed")
                ),
            "Reclaim environment before recovery",
        )?;
        if finished {
            return self.finish_task(p, "restore", req, &t);
        }
        let value = self.load_artifact(
            "checkpoints",
            &s(&checkpoint, "id"),
            &checkpoint["checksum"],
        )?;
        let frozen = self.load_artifact("inputs", &s(&t, "id"), &t["input_checksum"])?;
        if !resuming {
            check(
                !self.backend.exists(&t)?,
                "Old environment must be reclaimed",
                "environment_exists",
                409,
            )?;
            self.store.revoke(&s(&t, "id"))?;
            t["generation"] = json!(n(&t, "generation", 0) + 1);
            t["restore_checkpoint_id"] = checkpoint["id"].clone();
            t["expires_at"] = json!(now() + n(&t, "ttl_minutes", 60) as f64 * 60.0);
        }
        t["environment_state"] = json!("creating");
        self.store.put("task", &t)?;
        let bundle = self.input_bundle(&t)?;
        let result = (|| {
            let created = self
                .backend
                .create(&mut t, &frozen["files"], bundle.as_deref())?;
            merge(&mut t, created)?;
            self.backend.call(&t,"restore",&json!({"committed_files":value["files"],"working_files":value["working_files"],"limits":self.config.limits,"workspace_mode":t["workspace_mode"],"base_sha":t["base"],"sha":value["sha"],"bundle":value["bundle"],"bundle_sha256":value["bundle_sha256"],"files":t["files"]}))?;
            Ok::<_, Error>(())
        })();
        if let Err(e) = result {
            t["environment_state"] = json!("failed");
            t["error"] = json!(e.message);
            self.store.put("task", &t)?;
            return Err(e);
        }
        t["environment_state"] = json!("ready");
        t["restored_checkpoint_id"] = checkpoint["id"].clone();
        remove(&mut t, "restore_checkpoint_id");
        remove(&mut t, "error");
        self.store.put("task", &t)?;
        self.finish_task(p, "restore", req, &t)
    }
    pub(super) fn checkpoint(&self, p: &Value, req: &Value, expired: bool) -> Result<Value> {
        let mut t = self.get_task(p, req, "checkpoint", !expired)?;
        let value = self.export(&t, "checkpoint")?;
        let id = self.id("k", p, "checkpoint", &json!({}));
        self.collect_logs(&t)?;
        let record = json!({"id":id,"task_id":t["id"],"created_at":now(),"omitted":value["omitted"],"checksum":self.save_artifact("checkpoints",&id,&value)?});
        self.store.put("checkpoint", &record)?;
        push(&mut t, "checkpoints", json!(id));
        self.store.put("task", &t)?;
        Ok(record)
    }
    pub fn submit(&self, p: &Value, req: &Value) -> Result<Value> {
        let mut t = self.get_task(p, req, "submit", true)?;
        ensure(!t["repo"].is_null(), "Scratch tasks use checkpoints")?;
        if let Some(prev) = self.store.reserve(p, "submit", req)? {
            return Ok(prev);
        }
        let id = self.id("r", p, "submit", req);
        let stage = self.artifact("submissions", &id)?;
        let (mut value, mut record) = if stage.exists() {
            let staged = self.load_artifact("submissions", &id, &Value::Null)?;
            (staged["value"].clone(), staged["record"].clone())
        } else {
            let value = self.export(&t, "export")?;
            self.collect_logs(&t)?;
            let records = strings(&t["executions"])?
                .iter()
                .map(|id| self.store.get("execution", id))
                .collect::<Result<Vec<_>>>()?;
            let record = json!({"id":id,"task_id":t["id"],"base":t["base"],"baseline_sha":t["baseline_sha"],"result_sha":value["sha"],"files":t["files"],"image_digest":t["image_digest"],"workspace_mode":t["workspace_mode"],"commit_metadata":value["commit_metadata"],"commits":value["commits"],"executions":records});
            self.save_artifact("submissions", &id, &json!({"value":value,"record":record}))?;
            (value, record)
        };
        let temp = tempfile::tempdir_in(&self.config.state)?;
        let before = self.load_artifact("inputs", &s(&t, "id"), &t["input_checksum"])?;
        let patch = git::patch(
            &temp.path().join("patch"),
            &before["files"],
            &value["files"],
        )?;
        value["patch"] = json!(encode(&patch));
        value["patch_sha256"] = json!(digest(&patch));
        record["checksum"] = json!(self.save_artifact("results", &id, &value)?);
        self.store.put("result", &record)?;
        push(&mut t, "results", json!(id));
        self.store.put("task", &t)?;
        self.store.finish(p, "submit", req, &record)?;
        Ok(record)
    }
    pub(super) fn result(&self, p: &Value, req: &Value) -> Result<Value> {
        let record = self.store.get("result", &s(req, "result_id"))?;
        let t = self.store.get("task", &s(&record, "task_id"))?;
        self.authorize(p, "status", &t)?;
        let value = self.load_artifact("results", &s(&record, "id"), &record["checksum"])?;
        Ok(json!({"record":record,"artifact":value}))
    }
    pub(super) fn input_bundle(&self, t: &Value) -> Result<Option<Vec<u8>>> {
        if t["workspace_mode"] != "repository" {
            return Ok(None);
        }
        let value = self.load_artifact("bundles", &s(t, "id"), &t["repository_bundle_checksum"])?;
        Ok(Some(decode(
            &value["data"],
            self.config.limit("max_bundle_bytes"),
        )?))
    }
    pub fn reconcile(&self, p: &Value) -> Result<Value> {
        admin(p)?;
        let mut changed = Vec::new();
        for listed in self.store.list("task")? {
            let _task = self.task_lock(&s(&listed, "id"))?;
            let mut t = self.store.get("task", &s(&listed, "id"))?;
            if b(&t, "runtime_cleanup_pending") {
                match self.backend.destroy(&t) {
                    Ok(()) => {
                        for key in ["runtime_cleanup_pending", "handle", "cleanup_error"] {
                            remove(&mut t, key);
                        }
                        changed.push(json!({"id":t["id"],"state":"cleanup_complete"}));
                    }
                    Err(e) => t["cleanup_error"] = json!(e.message),
                }
                self.store.put("task", &t)?;
                continue;
            }
            if !matches!(
                t["environment_state"].as_str(),
                Some("ready" | "stopped" | "starting" | "expiring")
            ) {
                continue;
            }
            self.refresh(&mut t)?;
            if matches!(
                t["environment_state"].as_str(),
                Some("stopped" | "starting" | "lost")
            ) {
                changed.push(self.task_result(&t, p));
                continue;
            }
            if t["expires_at"].as_f64().unwrap_or(0.0) <= now()
                || t["environment_state"] == "expiring"
            {
                t["environment_state"] = json!("expiring");
                self.store.put("task", &t)?;
                if !self.backend.exists(&t)? {
                    t["environment_state"] = json!("expired");
                    self.store.put("task", &t)?;
                    continue;
                }
                let mut active = false;
                for id in strings(&t["executions"])? {
                    let cached = self.store.get("execution", &id)?;
                    if cached["generation"] != t["generation"] {
                        continue;
                    }
                    let r = self.update_execution(&t, &id)?;
                    if running(&r) {
                        self.backend.call(&t, "cancel", &json!({"id":id}))?;
                        active = true;
                    }
                }
                if !active {
                    match self.checkpoint(p, &json!({"task_id":t["id"]}), true) {
                        Ok(cp) => {
                            t = self.store.get("task", &s(&t, "id"))?;
                            t["expiry_checkpoint"] = cp["id"].clone();
                            match self.backend.destroy(&t) {
                                Ok(()) => t["environment_state"] = json!("expired"),
                                Err(e) => t["expiry_error"] = json!(e.message),
                            }
                        }
                        Err(e) => t["expiry_error"] = json!(e.message),
                    }
                }
                self.store.put("task", &t)?;
                changed.push(self.task_result(&t, p));
            } else {
                self.collect_logs(&t)?;
                if t["expires_at"].as_f64().unwrap_or(0.0) - now() <= 60.0
                    && t.get("expiry_checkpoint").is_none()
                {
                    match self.checkpoint(p, &json!({"task_id":t["id"]}), false) {
                        Ok(cp) => {
                            t = self.store.get("task", &s(&t, "id"))?;
                            t["expiry_checkpoint"] = cp["id"].clone();
                            t["expiry_notice"] =
                                json!("Environment expires within 60 seconds; checkpoint saved");
                        }
                        Err(e) => t["expiry_error"] = json!(e.message),
                    }
                    self.store.put("task", &t)?;
                }
            }
        }
        self.advance_validations(p)?;
        Ok(json!({"changed":changed}))
    }
}
