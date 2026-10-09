//! Repository registration and `sandbox.info` discovery.

use super::*;

impl Service {
    pub(super) fn repository(&self, name: &str) -> Result<PathBuf> {
        if let Some(path) = self.config.repos.get(name) {
            return Ok(path.clone());
        }
        let value = self.store.get("repository", name)?;
        Ok(PathBuf::from(s(&value, "path")))
    }
    pub(super) fn register_repository(&self, p: &Value, req: &Value) -> Result<Value> {
        admin(p)?;
        ensure(
            obj(req)?
                .keys()
                .all(|k| ["name", "path"].contains(&k.as_str())),
            "Unknown repository registration field",
        )?;
        let name = s(req, "name");
        ensure(
            regex::Regex::new(r"^[A-Za-z0-9_.-]{1,80}$")
                .unwrap()
                .is_match(&name),
            "Invalid repository name",
        )?;
        let path = PathBuf::from(s(req, "path"));
        ensure(
            path.is_absolute(),
            "Repository path must be absolute on the controller",
        )?;
        let path = fs::canonicalize(path)?;
        let head = git::resolve(&path, "HEAD")?;
        let _guard = self.coordination.acquire(format!("repository:{name}"))?;
        match self.repository(&name) {
            Ok(previous) => check(
                fs::canonicalize(previous)? == path,
                "Repository name already refers to another path",
                "conflict",
                409,
            )?,
            Err(e) if e.status == 404 => {}
            Err(e) => return Err(e),
        }
        let value = json!({"id":name,"path":path,"head":head});
        self.store.put("repository", &value)?;
        Ok(value)
    }
    /// Runtimes, registered repositories and live task records. Host names are
    /// reported without their addresses.
    pub(super) fn sandbox_info(&self, p: &Value) -> Result<Value> {
        admin(p)?;
        let tasks: Vec<_> = self
            .store
            .list("task")?
            .iter()
            .filter(|t| {
                !matches!(
                    t["environment_state"].as_str(),
                    Some("destroyed" | "expired")
                )
            })
            .map(|t| self.task_result(t, p))
            .collect();
        let mut repositories: Vec<_> = self.config.repos.keys().cloned().collect();
        for repo in self.store.list("repository")? {
            let name = s(&repo, "id");
            if !repositories.contains(&name) {
                repositories.push(name);
            }
        }
        let mut result = json!({"backend":self.config.backend,"runtimes":self.config.value["runtimes"],"repositories":repositories,"tasks":tasks});
        if let Some(hosts) = self.config.value["remote"]
            .get("hosts")
            .and_then(|v| v.as_object())
        {
            let mut names: Vec<&String> = hosts.keys().collect();
            names.sort();
            result["remote_hosts"] = json!(names);
            if let Some(default) = self.config.value["remote"]["default"].as_str() {
                result["remote_default"] = json!(default);
            }
        }
        Ok(result)
    }
}
