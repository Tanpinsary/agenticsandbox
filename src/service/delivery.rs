//! Delivery pipeline: candidate preparation, independent validation and conditional integration.

use super::*;

impl Service {
    pub(super) fn prepare(&self, p: &Value, req: &Value) -> Result<Value> {
        admin(p)?;
        let result = self.store.get("result", &s(req, "result_id"))?;
        let t = self.store.get("task", &s(&result, "task_id"))?;
        let source = &self.repository(&s(&t, "repo"))?;
        let branch = req["target_branch"].as_str().unwrap_or("main");
        ensure(
            !branch.starts_with('-') && !branch.contains(".."),
            "Invalid target branch",
        )?;
        git::run(
            source,
            &["check-ref-format", &format!("refs/heads/{branch}")],
        )?;
        let mut target = git::resolve(source, &format!("refs/heads/{branch}"))?;
        if let Some(prev) = self.store.reserve(p, "prepare", req)? {
            return Ok(prev);
        }
        let id = self.id("c", p, "prepare", req);
        if let Some(c) = self
            .store
            .list("candidate")?
            .into_iter()
            .find(|c| c["id"] == id)
        {
            if c["candidate_sha"].is_string() {
                self.store.finish(p, "prepare", req, &c)?;
                return Ok(c);
            }
            target = s(&c, "target_sha");
        } else {
            self.store.put("candidate",&json!({"id":id,"result_id":result["id"],"task_id":t["id"],"repo":t["repo"],"target_branch":branch,"target_sha":target,"state":"preparing","integrated":false}))?;
        }
        let receiver = self.config.state.join("receivers").join(&id);
        if receiver.exists() {
            fs::remove_dir_all(&receiver)?;
        }
        git::clone_base(source, &receiver, &s(&result, "base"))?;
        let input = self.load_artifact("inputs", &s(&t, "id"), &t["input_checksum"])?;
        let value = self.load_artifact("results", &s(&result, "id"), &result["checksum"])?;
        git::validate_files(&value["files"], &self.config.limits)?;
        git::export(
            &receiver,
            &s(&result, "base"),
            &Policy::all(),
            &self.config.limits,
        )?;
        let changed = git::changes(&input["files"], &value["files"])?;
        let policy = Policy::parse(&result["files"])?;
        for path in &changed {
            check(
                policy.allows(path)?,
                "Result exceeds authorized scope",
                "forbidden",
                403,
            )?;
        }
        let incoming = if result["workspace_mode"] == "repository" {
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
                &s(&result, "base"),
                &s(&result, "result_sha"),
                bundle.as_deref(),
                &value["bundle_sha256"],
                &policy,
                &value["files"],
                &self.config.limits,
            )?;
            s(&result, "result_sha")
        } else {
            git::update_index(&receiver, &input["files"], &value["files"])?;
            for path in &changed {
                if value["files"].get(path).is_none() {
                    let target = receiver.join(path);
                    if target.is_file() {
                        fs::remove_file(target)?;
                    }
                }
            }
            let tree = git::text(&receiver, &["write-tree"])?;
            git::commit(
                &receiver,
                &tree,
                &[&s(&result, "base")],
                &format!(
                    "Task {}: {}\n",
                    s(&t, "id"),
                    s(&t, "purpose").chars().take(500).collect::<String>()
                ),
                true,
            )?
        };
        git::run(&receiver, &["update-ref", "HEAD", &incoming])?;
        git::run(&receiver, &["reset", "--hard", &incoming])?;
        let incoming_ref = format!("refs/heads/incoming/{}", s(&result, "id"));
        git::run(
            source,
            &[
                "fetch",
                "--no-tags",
                &receiver.display().to_string(),
                &format!("{incoming}:{incoming_ref}"),
            ],
        )?;
        git::run(&receiver, &["checkout", "--detach", &target])?;
        if git::run(&receiver, &["merge", "--no-ff", "--no-commit", &incoming]).is_err() {
            return Err(Error::new(
                "Merge conflict; resolve into a new candidate and validate again",
                "merge_conflict",
                409,
            ));
        }
        let tree = git::text(&receiver, &["write-tree"])?;
        let candidate = git::commit(
            &receiver,
            &tree,
            &[&target, &incoming],
            &format!("Candidate {id}\n"),
            true,
        )?;
        git::run(
            source,
            &[
                "fetch",
                "--no-tags",
                &receiver.display().to_string(),
                &format!("{candidate}:refs/heads/candidates/{id}"),
            ],
        )?;
        let record = json!({"id":id,"result_id":result["id"],"task_id":t["id"],"repo":t["repo"],"target_branch":branch,"target_sha":target,"candidate_sha":candidate,"incoming_sha":incoming,"incoming_ref":incoming_ref,"changed_paths":changed,"validation_id":null,"integrated":false,"state":"prepared"});
        self.store.put("candidate", &record)?;
        self.store.finish(p, "prepare", req, &record)?;
        Ok(record)
    }
    pub(super) fn validate(&self, p: &Value, req: &Value) -> Result<Value> {
        admin(p)?;
        let mut candidate = self.store.get("candidate", &s(req, "candidate_id"))?;
        let commands = req["commands"]
            .as_array()
            .ok_or_else(|| Error::new("Provide acceptance commands", "invalid_request", 400))?;
        ensure(!commands.is_empty(), "Provide acceptance commands")?;
        for cmd in commands {
            ensure(
                !strings(cmd)?.is_empty(),
                "Acceptance commands must be argv arrays",
            )?;
        }
        let t=self.create(p,&json!({"repo":candidate["repo"],"base":candidate["candidate_sha"],"runtime":req["runtime"],"network":req["network"].as_str().unwrap_or("none"),"files":req.get("files").cloned().unwrap_or(Policy::all().json()),"purpose":format!("Verify candidate {}",s(&candidate,"id")),"ttl_minutes":n(req,"ttl_minutes",60),"role":"verification"}),true)?;
        let timeout = n(
            req,
            "timeout_seconds",
            300.min(self.config.limit("max_execution_seconds")),
        );
        let exec = self.execute(
            p,
            &json!({"task_id":t["id"],"argv":commands[0],"timeout_seconds":timeout}),
            None,
        )?;
        let id = self.id("v", p, "validate", &json!({}));
        let record = json!({"id":id,"candidate_id":candidate["id"],"result_id":candidate["result_id"],"target_sha":candidate["target_sha"],"candidate_sha":candidate["candidate_sha"],"task_id":t["id"],"execution_ids":[exec["execution_id"]],"commands":commands,"timeout_seconds":timeout,"state":"running"});
        self.store.put("validation", &record)?;
        candidate["validation_id"] = json!(id);
        self.store.put("candidate", &candidate)?;
        Ok(record)
    }
    pub(super) fn advance_validations(&self, p: &Value) -> Result<()> {
        self.advance_validations_for(p, None)
    }
    pub(super) fn advance_validations_for(&self, p: &Value, candidate: Option<&str>) -> Result<()> {
        for listed in self.store.list("validation")? {
            if candidate.is_some_and(|id| listed["candidate_id"] != id) {
                continue;
            }
            let _candidate = self
                .coordination
                .acquire(format!("candidate:{}", s(&listed, "candidate_id")))?;
            let _task = self.task_lock(&s(&listed, "task_id"))?;
            let mut v = self.store.get("validation", &s(&listed, "id"))?;
            if v["state"] != "running" {
                continue;
            }
            let status = self.status(p, &json!({"task_id":v["task_id"]}))?;
            if status["environment_state"] != "ready"
                || status["expires_at"].as_f64().unwrap_or(0.0) <= now()
            {
                v["state"] = json!("failed");
                v["error"] = json!("Verification environment unavailable or expired");
                self.store.put("validation", &v)?;
                continue;
            }
            let ids = strings(&v["execution_ids"])?;
            let latest = status["execution_records"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == *ids.last().unwrap())
                .ok_or_else(|| {
                    Error::new("Missing validation execution", "corrupt_artifact", 409)
                })?;
            if running(latest) {
                continue;
            }
            if latest["state"] != "completed" || latest["exit_code"] != 0 {
                v["state"] = json!("failed");
            } else if ids.len() < v["commands"].as_array().unwrap().len() {
                let exec=self.execute(p,&json!({"task_id":v["task_id"],"argv":v["commands"][ids.len()],"timeout_seconds":v["timeout_seconds"],"idempotency_key":format!("{}-{}",s(&v,"id"),ids.len())}),None)?;
                push(&mut v, "execution_ids", exec["execution_id"].clone());
            } else {
                v["state"] = json!("commands_passed");
            }
            self.store.put("validation", &v)?;
        }
        Ok(())
    }
    pub(super) fn integrate(&self, p: &Value, req: &Value) -> Result<Value> {
        admin(p)?;
        let mut candidate = self.store.get("candidate", &s(req, "candidate_id"))?;
        if let Some(prev) = self.store.reserve(p, "integrate", req)? {
            return Ok(prev);
        }
        if b(&candidate, "integrated") {
            self.store.finish(p, "integrate", req, &candidate)?;
            return Ok(candidate);
        }
        let source = &self.repository(&s(&candidate, "repo"))?;
        let branch = format!("refs/heads/{}", s(&candidate, "target_branch"));
        if b(&candidate, "accepting")
            && git::resolve(source, &branch)? == s(&candidate, "candidate_sha")
        {
            candidate["integrated"] = json!(true);
            candidate["accepting"] = json!(false);
            candidate["integrated_at"] = json!(now());
            self.store.put("candidate", &candidate)?;
            self.store.finish(p, "integrate", req, &candidate)?;
            return Ok(candidate);
        }
        self.advance_validations_for(p, Some(&s(&candidate, "id")))?;
        let mut validation = self
            .store
            .get("validation", &s(&candidate, "validation_id"))?;
        ensure(
            ["candidate_sha", "target_sha", "result_id"]
                .iter()
                .all(|k| validation[*k] == candidate[*k]),
            "Validation does not bind candidate",
        )?;
        let t = self.store.get("task", &s(&validation, "task_id"))?;
        let _verification = self.task_lock(&s(&t, "id"))?;
        let status = self.status(p, &json!({"task_id":t["id"]}))?;
        let ids = strings(&validation["execution_ids"])?;
        let records: Vec<_> = status["execution_records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| ids.contains(&s(r, "id")))
            .cloned()
            .collect();
        check(
            validation["state"] == "commands_passed"
                && records.len() == validation["commands"].as_array().unwrap().len()
                && !records.is_empty()
                && records
                    .iter()
                    .all(|r| r["state"] == "completed" && r["exit_code"] == 0),
            "Candidate verification incomplete or failed",
            "verification_failed",
            409,
        )?;
        let verified = self.export(&t, "export")?;
        let frozen = self.load_artifact("inputs", &s(&t, "id"), &t["input_checksum"])?;
        check(
            verified["files"] == frozen["files"],
            "Verification changed source code",
            "verification_failed",
            409,
        )?;
        self.collect_logs(&t)?;
        validation["state"] = json!("passed");
        validation["executions"] = json!(records);
        self.store.put("validation", &validation)?;
        check(
            git::resolve(source, &branch)? == s(&candidate, "target_sha"),
            "Target branch advanced; prepare and validate new candidate",
            "stale_candidate",
            409,
        )?;
        check(
            !git::text(source, &["worktree", "list", "--porcelain"])?
                .lines()
                .any(|line| line == format!("branch {branch}")),
            "Target branch is checked out; switch worktree before accepting",
            "checked_out_target",
            409,
        )?;
        candidate["accepting"] = json!(true);
        self.store.put("candidate", &candidate)?;
        git::run(
            source,
            &[
                "update-ref",
                &branch,
                &s(&candidate, "candidate_sha"),
                &s(&candidate, "target_sha"),
            ],
        )?;
        candidate["integrated"] = json!(true);
        candidate["accepting"] = json!(false);
        candidate["integrated_at"] = json!(now());
        self.store.put("candidate", &candidate)?;
        self.store.finish(p, "integrate", req, &candidate)?;
        Ok(candidate)
    }
}
