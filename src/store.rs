use crate::{
    error::{Result, check, ensure},
    util::*,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};
pub struct Store {
    db: Connection,
}
impl Store {
    pub fn new(root: &Path) -> Result<Self> {
        if !root.exists() {
            private_dir(root)?;
        }
        ensure(
            std::fs::symlink_metadata(root)?.is_dir() && root.metadata()?.mode() & 0o077 == 0,
            "Control storage must be private",
        )?;
        let path = root.join("control.sqlite3");
        let db = Connection::open(&path)?;
        db.busy_timeout(std::time::Duration::from_secs(30))?;
        db.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS records(kind TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(kind,id)); CREATE TABLE IF NOT EXISTS capabilities(hash TEXT PRIMARY KEY,task_id TEXT NOT NULL,expires REAL NOT NULL,scopes TEXT NOT NULL); CREATE TABLE IF NOT EXISTS idempotency(principal TEXT NOT NULL,operation TEXT NOT NULL,key TEXT NOT NULL,fingerprint TEXT NOT NULL,response TEXT,PRIMARY KEY(principal,operation,key));")?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self { db })
    }
    pub fn put(&self, kind: &str, value: &Value) -> Result<()> {
        self.db.execute("INSERT INTO records VALUES(?1,?2,?3) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",params![kind,s(value,"id"),value.to_string()])?;
        Ok(())
    }
    pub fn get(&self, kind: &str, id: &str) -> Result<Value> {
        let result: Option<String> = self
            .db
            .query_row(
                "SELECT data FROM records WHERE kind=?1 AND id=?2",
                params![kind, id],
                |r| r.get(0),
            )
            .optional()?;
        let data = result
            .ok_or_else(|| crate::error::Error::new(format!("Unknown {kind}"), "not_found", 404))?;
        Ok(serde_json::from_str(&data)?)
    }
    pub fn list(&self, kind: &str) -> Result<Vec<Value>> {
        let mut stmt = self
            .db
            .prepare("SELECT data FROM records WHERE kind=?1 ORDER BY id")?;
        let rows = stmt.query_map([kind], |r| r.get::<_, String>(0))?;
        rows.map(|r| Ok(serde_json::from_str(&r?)?)).collect()
    }
    pub fn capability(&self, task: &str, expires: f64, scopes: &Value) -> Result<String> {
        let token = token();
        self.db.execute(
            "INSERT INTO capabilities VALUES(?1,?2,?3,?4)",
            params![digest(token.as_bytes()), task, expires, scopes.to_string()],
        )?;
        Ok(token)
    }
    pub fn authenticate(&self, token: &str) -> Result<Value> {
        let hash = digest(token.as_bytes());
        let r: Option<(String, f64, String)> = self
            .db
            .query_row(
                "SELECT task_id,expires,scopes FROM capabilities WHERE hash=?1",
                [&hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (task, expires, scopes) = r.ok_or_else(|| {
            crate::error::Error::new("Invalid or expired task capability", "unauthorized", 401)
        })?;
        check(
            expires > now(),
            "Invalid or expired task capability",
            "unauthorized",
            401,
        )?;
        Ok(
            json!({"id":hash,"admin":false,"task_id":task,"scopes":serde_json::from_str::<Value>(&scopes)?}),
        )
    }
    pub fn revoke(&self, task: &str) -> Result<()> {
        self.db
            .execute("DELETE FROM capabilities WHERE task_id=?1", [task])?;
        Ok(())
    }
    pub fn reserve(&self, principal: &Value, op: &str, request: &Value) -> Result<Option<Value>> {
        let Some(key) = request.get("idempotency_key").filter(|v| !v.is_null()) else {
            return Ok(None);
        };
        ensure(
            key.as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 200),
            "Invalid idempotency key",
        )?;
        let key = key.as_str().unwrap();
        let fp = digest(&canonical(request));
        self.db.execute(
            "INSERT OR IGNORE INTO idempotency VALUES(?1,?2,?3,?4,NULL)",
            params![s(principal, "id"), op, key, fp],
        )?;
        let (saved,response):(String,Option<String>) = self.db.query_row("SELECT fingerprint,response FROM idempotency WHERE principal=?1 AND operation=?2 AND key=?3",params![s(principal,"id"),op,key],|r|Ok((r.get(0)?,r.get(1)?)))?;
        check(
            saved == fp,
            "Idempotency key reused with different request",
            "conflict",
            409,
        )?;
        response.map(|s| Ok(serde_json::from_str(&s)?)).transpose()
    }
    pub fn finish(
        &self,
        principal: &Value,
        op: &str,
        request: &Value,
        response: &Value,
    ) -> Result<()> {
        if let Some(key) = request["idempotency_key"].as_str() {
            self.db.execute(
                "UPDATE idempotency SET response=?1 WHERE principal=?2 AND operation=?3 AND key=?4",
                params![response.to_string(), s(principal, "id"), op, key],
            )?;
        }
        Ok(())
    }
}
