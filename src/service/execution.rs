//! Command execution, approved agent launch, cancellation and job artefact export.

use super::*;

impl Service {
    pub fn execute(&self, p: &Value, req: &Value, environment: Option<Value>) -> Result<Value> {
        let _task = self.task_lock(&s(req, "task_id"))?;
        let mut t = self.get_task(p, req, "exec", true)?;
        let has_argv = req["argv"].as_array().is_some_and(|a| !a.is_empty());
        let has_shell = req["shell"].as_str().is_some_and(|s| !s.is_empty());
        ensure(
            has_argv != has_shell,
            "Specify argv or explicit shell command",
        )?;
        let argv = if has_argv {
            strings(&req["argv"])?
        } else {
            vec!["/bin/sh".into(), "-lc".into(), s(req, "shell")]
        };
        ensure(
            !argv.is_empty() && argv.len() <= 256 && argv.iter().all(|s| !s.contains('\0')),
            "Invalid argv",
        )?;
        let timeout = n(
            req,
            "timeout_seconds",
            300.min(self.config.limit("max_execution_seconds")),
        );
        ensure(
            req.get("timeout_seconds").is_none() || req["timeout_seconds"].as_u64().is_some(),
            "Invalid timeout",
        )?;
        ensure(
            timeout > 0 && timeout <= self.config.limit("max_execution_seconds"),
            "Invalid timeout",
        )?;
        let work_dir = req["work_dir"].as_str().unwrap_or("repo");
        ensure(
            matches!(work_dir, "repo" | "build"),
            "Invalid work directory",
        )?;
        if let Some(cwd) = req["cwd"].as_str() {
            relative(cwd)?;
        }
        if let Some(prev) = self.store.reserve(p, "exec", req)? {
            return Ok(prev);
        }
        let id = self.id("e", p, "exec", req);
        let allocation = self.coordination.acquire("quota:executions".into())?;
        let cached = self
            .store
            .list("execution")?
            .into_iter()
            .find(|r| r["id"] == id);
        if cached.is_none() {
            check(
                (self
                    .store
                    .list("execution")?
                    .iter()
                    .filter(|r| running(r))
                    .count() as u64)
                    < self.config.limit("max_concurrent_executions"),
                "Concurrent execution limit reached",
                "quota_exceeded",
                409,
            )?;
        }
        let profile = self.config.runtime(&s(&t, "runtime"), &s(&t, "network"))?;
        let mut start = json!({"id":id,"argv":argv,"cwd":req["cwd"],"work_dir":work_dir,"timeout_seconds":timeout.min((t["expires_at"].as_f64().unwrap_or(0.0)-now()).max(1.0) as u64),"max_output_bytes":self.config.limit("max_output_bytes"),"task_uid":if self.backend.isolated(){json!(n(&profile,"task_uid",10001))}else{Value::Null},"network_mode":if t["network"]=="none"{"deny"}else{"external-audit"}});
        if let Some(env) = environment {
            start["environment"] = env;
        }
        if let Some(dispatch) = self
            .store
            .list("dispatch")?
            .into_iter()
            .find(|r| r["id"] == id)
        {
            start = dispatch["request"].clone();
        } else {
            self.store.put(
                "dispatch",
                &json!({"id":id,"task_id":t["id"],"generation":t["generation"],"request":start}),
            )?;
        }
        if cached.is_none() {
            let mut record = start.clone();
            record["state"] = json!("starting");
            record["dispatch_pending"] = json!(true);
            self.persist_execution(&t, record)?;
        }
        drop(allocation);
        push(&mut t, "executions", json!(id));
        self.store.put("task", &t)?;
        let mut r = self.backend.call(&t, "start", &start)?;
        if r["state"] == "starting" {
            r["dispatch_pending"] = json!(true);
        }
        let state = r["state"].clone();
        self.persist_execution(&t, r)?;
        let response = json!({"execution_id":id,"task_id":t["id"],"state":state});
        self.store.finish(p, "exec", req, &response)?;
        Ok(response)
    }
    pub(super) fn cancel(&self, p: &Value, req: &Value) -> Result<Value> {
        let t = self.get_task(p, req, "exec", true)?;
        let id = s(req, "execution_id");
        check(
            strings(&t["executions"])?.contains(&id),
            "Execution does not belong to task",
            "forbidden",
            403,
        )?;
        let r = self.store.get("execution", &id)?;
        check(
            r["generation"] == t["generation"],
            "Execution belongs to earlier generation",
            "stale_execution",
            409,
        )?;
        self.persist_execution(&t, self.backend.call(&t, "cancel", &json!({"id":id}))?)
    }
    pub(super) fn export(&self, t: &Value, op: &str) -> Result<Value> {
        let mut value=self.backend.call(t,op,&json!({"files":t["files"],"limits":self.config.limits,"baseline_sha":t["baseline_sha"],"workspace_mode":t["workspace_mode"]}))?;
        let sum = value["checksum"].clone();
        remove(&mut value, "checksum");
        check(
            sum == digest(&canonical(&value)),
            "Export checksum mismatch",
            "corrupt_artifact",
            409,
        )?;
        sha(&s(&value, "sha"))?;
        git::validate_files(&value["files"], &self.config.limits)?;
        let before = self.load_artifact("inputs", &s(t, "id"), &t["input_checksum"])?;
        let policy = Policy::parse(&t["files"])?;
        for path in git::changes(&before["files"], &value["files"])? {
            check(
                policy.allows(&path)?,
                "Result contains unauthorized path",
                "forbidden",
                403,
            )?;
        }
        if t["workspace_mode"] == "repository" {
            let temp = tempfile::tempdir_in(&self.config.state)?;
            let input = temp.path().join("input.bundle");
            atomic(&input, &self.input_bundle(t)?.unwrap(), 0o600)?;
            let receiver = temp.path().join("repo");
            git::run(
                temp.path(),
                &[
                    "clone",
                    "--no-local",
                    "--no-tags",
                    "--no-checkout",
                    "--template=",
                    &input.display().to_string(),
                    &receiver.display().to_string(),
                ],
            )?;
            git::run(&receiver, &["remote", "remove", "origin"])?;
            let bundle = if value["bundle"].is_null() {
                None
            } else {
                Some(decode(
                    &value["bundle"],
                    self.config.limit("max_bundle_bytes"),
                )?)
            };
            git::receive(
                &receiver,
                &s(t, "base"),
                &s(&value, "sha"),
                bundle.as_deref(),
                &value["bundle_sha256"],
                &policy,
                &value["files"],
                &self.config.limits,
            )?;
        }
        Ok(value)
    }
    pub(super) fn persist_execution(&self, t: &Value, mut record: Value) -> Result<Value> {
        record["task_id"] = t["id"].clone();
        record["generation"] = t["generation"].clone();
        remove(&mut record, "environment");
        self.store.put("execution", &record)?;
        Ok(record)
    }
    pub(super) fn update_execution(&self, t: &Value, id: &str) -> Result<Value> {
        let cached = self.store.get("execution", id)?;
        if cached["generation"] != t["generation"] {
            return Ok(cached);
        }
        let mut r = if b(&cached, "dispatch_pending") {
            let dispatch = self.store.get("dispatch", id)?;
            self.backend.call(t, "start", &dispatch["request"])?
        } else {
            self.backend.call(t, "execution", &json!({"id":id}))?
        };
        if b(&cached, "dispatch_pending") && r["state"] == "starting" {
            r["dispatch_pending"] = json!(true);
        }
        self.persist_execution(t, r)
    }
}
