//! Backend dispatch: `remote` runs the worker in an SSH-managed Docker
//! container, `local` runs it in a private directory as the host user.

use crate::{
    config::Config,
    error::{Error, Result, ensure},
    util::*,
    worker,
};
use serde_json::{Value, json};
use std::{fs, path::PathBuf, time::Duration};

pub struct Backend {
    pub config: Config,
}
impl Backend {
    pub fn isolated(&self) -> bool {
        self.config.backend == "remote"
    }
    fn remote<'a>(&'a self, t: &Value) -> Result<crate::remote::Remote<'a>> {
        crate::remote::Remote::new(&self.config, t)
    }
    pub fn root(&self, t: &Value) -> PathBuf {
        self.config
            .state
            .join("environments")
            .join(s(t, "id"))
            .join(n(t, "generation", 0).to_string())
    }
    pub fn call(&self, t: &Value, op: &str, req: &Value) -> Result<Value> {
        if self.isolated() {
            return self.remote(t)?.call(t, op, req);
        }
        worker::dispatch(&self.root(t), op, req)
    }
    pub fn verify(&self, t: &Value) -> Result<()> {
        if self.isolated() {
            crate::runtime::validate_identity(
                &self.call(t, "identity", &json!({}))?,
                &self.config.runtime(&s(t, "runtime"), &s(t, "network"))?,
            )?;
        }
        Ok(())
    }
    pub fn create(&self, t: &mut Value, files: &Value, bundle: Option<&[u8]>) -> Result<Value> {
        if self.isolated() {
            let remote = self.remote(t)?;
            return remote.create(t, files, bundle);
        }
        // The local backend runs as the host user: it is a development fixture
        // rather than a sandbox, so input is installed without a task UID.
        let mut result = if t["workspace_mode"] == "repository" {
            let bundle = bundle
                .ok_or_else(|| Error::new("Missing input bundle", "corrupt_artifact", 409))?;
            self.call(
                t,
                "install_repository",
                &json!({
                "bundle":encode(bundle),
                "base_sha":t["base"],
                "bundle_sha256":digest(bundle),
                "limits":self.config.limits,
                "task_uid":Value::Null,
                "read_only_source":t["role"]=="verification"}),
            )?
        } else {
            self.call(
                t,
                "install",
                &json!({
                "files":files,
                "limits":self.config.limits,
                "task_uid":Value::Null,
                "read_only_source":t["role"]=="verification"}),
            )?
        };
        result["handle"] = json!(self.root(t).display().to_string());
        Ok(result)
    }
    pub fn exists(&self, t: &Value) -> Result<bool> {
        if self.isolated() {
            return Ok(self.remote(t)?.state(t)? != "lost");
        }
        Ok(self.root(t).is_dir())
    }
    pub fn state(&self, t: &Value) -> Result<String> {
        if self.isolated() {
            return self.remote(t)?.state(t);
        }
        Ok(if self.exists(t)? { "ready" } else { "lost" }.into())
    }
    pub fn destroy(&self, t: &Value) -> Result<()> {
        if self.isolated() {
            return self.remote(t)?.destroy(t);
        }
        let root = self.root(t);
        if root.exists() {
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }
    /// Deadlines bound environments with their own lifecycle; the remote
    /// backend keeps TTL in the controller, so this is pure bookkeeping.
    pub fn extend(&self, _t: &Value, minutes: u64) -> Result<f64> {
        Ok(now() + minutes as f64 * 60.0)
    }
}
pub fn origin(url: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(url)
        .map_err(|_| Error::new("Expected HTTPS origin", "configuration_error", 500))?;
    ensure(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && matches!(url.path(), "" | "/")
            && url.query().is_none()
            && url.fragment().is_none(),
        "Expected HTTPS origin",
    )?;
    Ok(url)
}
pub fn http_client(
    ca: Option<&std::path::Path>,
    timeout: u64,
) -> Result<reqwest::blocking::Client> {
    let mut builder = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(timeout));
    if let Some(ca) = ca {
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&fs::read(ca)?)?);
    }
    Ok(builder.build()?)
}
