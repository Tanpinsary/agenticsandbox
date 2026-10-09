use agenticsandbox::{
    config::Config,
    error::{Error, Result, ensure},
    service::Service,
    util::*,
};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, BufRead, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(name = "agenticsandbox", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Init {
        #[arg(long, default_value = "config.json")]
        config: PathBuf,
    },
    Serve {
        #[arg(long, default_value = "config.json")]
        config: PathBuf,
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 8765)]
        port: u16,
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        #[arg(long)]
        tls_key: Option<PathBuf>,
    },
    Call {
        method: String,
        #[arg(long, default_value = "http://127.0.0.1:8765")]
        url: String,
        #[arg(long)]
        ca_file: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        token_file: PathBuf,
        #[arg(long, default_value = "-")]
        params: PathBuf,
    },
    Mcp {
        #[arg(long, default_value = "http://127.0.0.1:8765")]
        url: String,
        #[arg(long)]
        ca_file: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        token_file: PathBuf,
    },
    Worker {
        #[arg(num_args=0..)]
        args: Vec<String>,
    },
    RuntimeManifest {
        #[command(subcommand)]
        command: Manifest,
    },
    RuntimeLimits,
    RuntimeStorage {
        #[arg(long, default_value = "/workspace")]
        root: PathBuf,
        #[arg(long)]
        ephemeral: bool,
    },
    Probe {
        #[arg(long, default_value_t = 10001)]
        expected_uid: u32,
    },
}
#[derive(Subcommand)]
enum Manifest {
    Build {
        #[arg(long)]
        base_image: String,
        #[arg(long)]
        node_image: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Verify,
}
struct Client {
    service: Option<Service>,
    _lock: Option<fs::File>,
    url: String,
    token: String,
    http: reqwest::blocking::Client,
}
fn controller(config: &Config) -> Result<fs::File> {
    if !config.state.exists() {
        private_dir(&config.state)?;
    }
    ensure(
        config.state.metadata()?.mode() & 0o077 == 0,
        "Control storage must be private",
    )?;
    lock(&config.state.join("controller.lock"))
}
impl Client {
    fn new(
        config: Option<&Path>,
        url: String,
        token_file: &Path,
        ca: Option<&Path>,
    ) -> Result<Self> {
        let token = fs::read_to_string(token_file)?.trim().into();
        let (service, lock) = if let Some(path) = config {
            let c = Config::load(path)?;
            let l = controller(&c)?;
            (Some(Service::new(c)?), Some(l))
        } else {
            (None, None)
        };
        let parsed = reqwest::Url::parse(&url)
            .map_err(|_| Error::new("Invalid controller URL", "invalid_request", 400))?;
        ensure(
            parsed.scheme() == "https"
                || parsed.scheme() == "http"
                    && matches!(
                        parsed.host_str(),
                        Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
                    ),
            "Remote controllers require HTTPS",
        )?;
        Ok(Self {
            service,
            _lock: lock,
            url,
            token,
            http: agenticsandbox::backend::http_client(ca, 120)?,
        })
    }
    fn invoke(&self, method: &str, params: &Value) -> Result<Value> {
        if let Some(service) = &self.service {
            return service.invoke(&self.token, method, params);
        }
        let response = self
            .http
            .post(format!("{}/rpc", self.url.trim_end_matches('/')))
            .bearer_auth(&self.token)
            .json(&json!({"method":method,"params":params}))
            .send()?;
        let value: Value =
            serde_json::from_slice(&read_limit(response, agenticsandbox::worker::MAX_REQUEST)?)?;
        if value.get("error").is_some() {
            return Err(Error::new(
                s(&value["error"], "message"),
                &s(&value["error"], "code"),
                400,
            ));
        }
        Ok(value["result"].clone())
    }
}
fn mcp(client: Client) -> Result<()> {
    let tools: Value = serde_json::from_str(include_str!("tools.json"))?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    loop {
        let mut bytes = Vec::new();
        let mut overflow = false;
        loop {
            let buffer = input.fill_buf()?;
            if buffer.is_empty() {
                break;
            }
            let length = buffer
                .iter()
                .position(|c| *c == b'\n')
                .map(|i| i + 1)
                .unwrap_or(buffer.len());
            if bytes.len() + length <= 32 * 1024 * 1024 {
                bytes.extend_from_slice(&buffer[..length]);
            } else {
                overflow = true;
            }
            let ended = buffer[length - 1] == b'\n';
            input.consume(length);
            if ended {
                break;
            }
        }
        if bytes.is_empty() && !overflow {
            break;
        }
        let mut id = Value::Null;
        let result = (|| -> Result<Option<Value>> {
            ensure(!overflow, "MCP request too large")?;
            let req: Value = serde_json::from_slice(&bytes)?;
            obj(&req)?;
            id = req["id"].clone();
            let result = match s(&req, "method").as_str() {
                "initialize" => {
                    json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"agenticsandbox","version":agenticsandbox::VERSION},"instructions":"Use sandbox.info to discover runtimes, registered repositories and tasks. Use repo.register with an absolute controller path for project tasks; task.create transfers committed input only. For scratch use task.create with runtime=agentic, role=scratch, network=none, files={include:[**],exclude:[]}. Files/logs use base64. task.exec is asynchronous: poll task.status and task.logs. Commands run inside the remote sandbox; local paths are not automatically uploaded. Save task IDs, retrieve outputs before task.destroy, and use task tokens for delegated runners. Destroy only your own completed sandboxes."})
                }
                "notifications/initialized" | "notifications/cancelled" => return Ok(None),
                "ping" => json!({}),
                "tools/list" => json!({"tools":tools}),
                "tools/call" => {
                    let name = s(&req["params"], "name");
                    ensure(
                        tools.as_array().unwrap().iter().any(|t| t["name"] == name),
                        "Unknown tool",
                    )?;
                    match client.invoke(&name, req["params"].get("arguments").unwrap_or(&json!({})))
                    {
                        Ok(value) => {
                            json!({"content":[{"type":"text","text":value.to_string()}],"isError":false})
                        }
                        Err(e) => {
                            json!({"content":[{"type":"text","text":e.json().to_string()}],"isError":true})
                        }
                    }
                }
                _ => {
                    return Ok(Some(
                        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Method not found"}}),
                    ));
                }
            };
            if id.is_null() {
                Ok(None)
            } else {
                Ok(Some(json!({"jsonrpc":"2.0","id":id,"result":result})))
            }
        })();
        match result {
            Ok(Some(v)) => {
                println!("{v}");
                io::stdout().flush()?;
            }
            Ok(None) => {}
            Err(_) => {
                println!(
                    "{}",
                    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"Invalid request"}})
                );
                io::stdout().flush()?;
            }
        }
    }
    Ok(())
}
fn run() -> Result<()> {
    match Cli::parse().command {
        Commands::Init { config } => {
            let c = Config::load(&config)?;
            let _guard = controller(&c)?;
            if !c.admin_file.exists() {
                atomic(&c.admin_file, format!("{}\n", token()).as_bytes(), 0o600)?;
            }
            println!(
                "{}",
                json!({"state_dir":c.state,"admin_token_file":c.admin_file})
            );
            Ok(())
        }
        Commands::Serve {
            config,
            host,
            port,
            tls_cert,
            tls_key,
        } => {
            let c = Config::load(&config)?;
            let _guard = controller(&c)?;
            let service = Service::new(c)?;
            if !service.backend.isolated() {
                eprintln!(
                    "Development local backend: commands have host access; OS isolation is not enforced."
                );
            }
            agenticsandbox::api::serve(
                service,
                &host,
                port,
                tls_cert.as_deref(),
                tls_key.as_deref(),
            )
        }
        Commands::Call {
            method,
            url,
            ca_file,
            config,
            token_file,
            params,
        } => {
            let client = Client::new(config.as_deref(), url, &token_file, ca_file.as_deref())?;
            let bytes = if params == Path::new("-") {
                read_limit(io::stdin(), agenticsandbox::worker::MAX_REQUEST)?
            } else {
                read_limit(fs::File::open(params)?, agenticsandbox::worker::MAX_REQUEST)?
            };
            let params = if bytes.is_empty() {
                json!({})
            } else {
                serde_json::from_slice(&bytes)?
            };
            let result = client.invoke(&method, &params)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        Commands::Mcp {
            url,
            ca_file,
            config,
            token_file,
        } => mcp(Client::new(
            config.as_deref(),
            url,
            &token_file,
            ca_file.as_deref(),
        )?),
        Commands::Worker { args } => {
            if args == ["files"] {
                let req: Value = serde_json::from_slice(&read_limit(
                    io::stdin(),
                    agenticsandbox::worker::MAX_REQUEST,
                )?)?;
                println!(
                    "{}",
                    agenticsandbox::worker::filesystem(
                        Path::new(&s(&req, "root")),
                        &s(&req, "operation"),
                        &req["request"]
                    )?
                );
                return Ok(());
            }
            if args == ["recover"] {
                let req: Value = serde_json::from_slice(&read_limit(
                    io::stdin(),
                    agenticsandbox::worker::MAX_REQUEST,
                )?)?;
                let root = PathBuf::from(s(&req, "root"));
                let _scope = agenticsandbox::git::Scope::new(&root, None, false);
                println!(
                    "{}",
                    json!({"sha":agenticsandbox::worker::recover_files(&root,&req["request"])?})
                );
                return Ok(());
            }
            if args.len() == 3 && args[0] == "supervise" {
                return agenticsandbox::worker::supervise(Path::new(&args[1]), &args[2]);
            }
            ensure(args.is_empty(), "Invalid worker arguments")?;
            let response = (|| {
                let req: Value = serde_json::from_slice(&read_limit(
                    io::stdin(),
                    agenticsandbox::worker::MAX_REQUEST,
                )?)?;
                obj(&req)?;
                ensure(req["root"].is_string(), "Worker root required")?;
                agenticsandbox::worker::dispatch(
                    Path::new(&s(&req, "root")),
                    &s(&req, "operation"),
                    &req["request"],
                )
            })();
            match response {
                Ok(value) => {
                    println!("{}", json!({"result":value}));
                    Ok(())
                }
                Err(e) => {
                    println!("{}", json!({"error":e.message,"code":e.code}));
                    std::process::exit(1)
                }
            }
        }
        Commands::RuntimeManifest { command } => match command {
            Manifest::Build {
                base_image,
                node_image,
                output,
            } => agenticsandbox::runtime::build_manifest(
                &base_image,
                &node_image,
                &output.unwrap_or_else(agenticsandbox::runtime::manifest_path),
            ),
            Manifest::Verify => {
                let value = agenticsandbox::runtime::identity()?;
                ensure(
                    b(&value, "runtime_manifest_verified"),
                    "Runtime build manifest missing",
                )?;
                println!("{value}");
                Ok(())
            }
        },
        Commands::RuntimeLimits => {
            let value = agenticsandbox::runtime::pid_limit(Path::new("/sys/fs/cgroup"))?;
            println!("{}", json!({"passed":true,"pids_max":value}));
            Ok(())
        }
        Commands::RuntimeStorage { root, ephemeral } => {
            let mode = std::env::var("AGENTICSANDBOX_STORAGE").unwrap_or("persistent".into());
            ensure(
                matches!(mode.as_str(), "persistent" | "ephemeral"),
                "Unknown storage mode",
            )?;
            println!(
                "{}",
                agenticsandbox::runtime::storage(&root, !ephemeral && mode != "ephemeral", None)?
            );
            Ok(())
        }
        Commands::Probe { expected_uid } => {
            let value = agenticsandbox::runtime::probe(expected_uid)?;
            println!("{value}");
            if !b(&value, "passed") {
                std::process::exit(1)
            }
            Ok(())
        }
    }
}
fn main() {
    // Protect newly created SQLite/log/control files, including WAL sidecars.
    unsafe {
        libc::umask(0o077);
    }
    if let Err(error) = run() {
        eprintln!(
            "{}",
            json!({"error":error.code,"message":error.message,"status":error.status})
        );
        std::process::exit(1)
    }
}
