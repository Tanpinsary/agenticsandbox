//! Task file API (read, write, search) and incremental execution logs.

use super::*;

impl Service {
    pub(super) fn files(&self, p: &Value, method: &str, req: &Value) -> Result<Value> {
        let op = method.strip_prefix("task.").unwrap();
        let t = self.get_task(p, req, op, true)?;
        if op == "search" {
            return self.backend.call(
                &t,
                "search",
                &json!({"query":req["query"],"files":t["files"],"limits":self.config.limits}),
            );
        }
        check(
            Policy::parse(&t["files"])?.allows(&s(req, "path"))?,
            "Path not authorized",
            "forbidden",
            403,
        )?;
        if op == "write" {
            check(
                t["role"] != "verification",
                "Verification source is read-only",
                "forbidden",
                403,
            )?;
        }
        self.backend.call(&t,op,&json!({"path":req["path"],"data":req["data"],"limit":self.config.limit("max_file_bytes")}))
    }
    pub fn logs(&self, p: &Value, req: &Value) -> Result<Value> {
        let t = self.get_task(p, req, "logs", false)?;
        let id = s(req, "execution_id");
        check(
            strings(&t["executions"])?.contains(&id),
            "Execution does not belong to task",
            "forbidden",
            403,
        )?;
        ensure(
            req.get("cursor").is_none() || req["cursor"].as_u64().is_some(),
            "Invalid log cursor",
        )?;
        let cursor = n(req, "cursor", 0);
        let cached = self.store.get("execution", &id)?;
        if t["environment_state"] == "ready" && cached["generation"] == t["generation"] {
            let response = self
                .backend
                .call(&t, "logs", &json!({"id":id,"cursor":cursor}))?;
            self.append_log(&id, cursor, &decode(&response["data"], 65536)?)?;
            return Ok(response);
        }
        let path = self.log_path(&id);
        let mut bytes = vec![];
        if path.exists() {
            let mut f = File::open(path)?;
            f.seek(SeekFrom::Start(cursor))?;
            f.take(65536).read_to_end(&mut bytes)?;
        }
        Ok(
            json!({"data":encode(&bytes),"cursor":cursor+bytes.len() as u64,"state":cached["state"]}),
        )
    }
    pub(super) fn log_path(&self, id: &str) -> PathBuf {
        self.config.state.join("logs").join(format!("{id}.log"))
    }
    pub(super) fn append_log(&self, id: &str, cursor: u64, data: &[u8]) -> Result<()> {
        let path = self.log_path(id);
        fs::create_dir_all(path.parent().unwrap())?;
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        let size = f.metadata()?.len();
        if cursor <= size {
            f.write_all(&data[(size - cursor).min(data.len() as u64) as usize..])?;
            f.sync_all()?;
        }
        Ok(())
    }
    pub(super) fn collect_logs(&self, t: &Value) -> Result<()> {
        for id in strings(&t["executions"])? {
            let cached = self.store.get("execution", &id)?;
            if cached["generation"] != t["generation"] {
                continue;
            }
            if b(&cached, "dispatch_pending") {
                self.update_execution(t, &id)?;
            }
            let mut cursor = self.log_path(&id).metadata().map(|m| m.len()).unwrap_or(0);
            loop {
                let response = self
                    .backend
                    .call(t, "logs", &json!({"id":id,"cursor":cursor}))?;
                let data = decode(&response["data"], 65536)?;
                self.append_log(&id, cursor, &data)?;
                cursor = n(&response, "cursor", cursor);
                if data.is_empty() {
                    break;
                }
            }
            self.persist_execution(t, self.backend.call(t, "execution", &json!({"id":id}))?)?;
        }
        Ok(())
    }
}
