# AgenticSandbox

AgenticSandbox 是面向编程 agent 的远程任务执行与 Git 交付服务，使用 Rust 实现。控制服务运行在一台主机上，通过 SSH 在另一台 Linux 主机上为每个任务创建独立的 Docker 容器和具名数据卷；任务只看到获准的已提交代码。

它把一项开发任务串成完整流程：提供获准代码，让 agent 在独立环境中修改并提交，冻结成果，再在新环境中验证，通过后合入目标分支。控制服务保管仓库凭据，任务使用只作用于自己的权限令牌。

例如，可以只把解析器源码和相关测试交给子 agent。子 agent 完成修复后，控制服务把成果放回完整项目构造候选版本，在新的只读源码环境中跑测试，再检查目标分支是否变化并决定合入。

适合自托管、多种 agent CLI 共用执行环境，以及需要限制代码暴露范围、独立验收成果的任务委派。对于可信 agent 的日常单项目开发，直接使用 Git worktree 和 CLI 通常更简单。

## 工作流程

```text
批准仓库、代码范围和运行环境
  → task.create：建立独立任务仓库
  → task.exec：执行任务并创建 Git 提交
  → task.submit：冻结成果
  → task.prepare_integration：构造候选版本
  → task.validate：在新环境中独立验证
  → task.integrate：按预期旧 SHA 更新目标分支
```

项目由三个部分组成：

- **控制服务**：管理注册仓库、任务权限、SQLite 状态、日志和检查点，接收 Git 成果，组织验证与合入。
- **Worker 与运行环境**：控制服务经 SSH 在目标主机上为每个任务创建容器与数据卷；容器内的 Rust worker 负责安装输入、执行命令、读写文件和导出成果。自有镜像 `agentic-container` 提供 Node.js/npm、Git、Python、编译工具和 worker，不预装 agent CLI。
- **客户端接口**：CLI、HTTP/HTTPS RPC 和 stdio MCP。外部主 agent 通过 MCP 操作任务，模型循环留在客户端。

## 已实现的能力

- **按任务授权**：任务令牌只能操作自己的任务；候选准备、独立验证和合入需要管理员权限。仓库凭据留在控制侧。
- **异步执行**：返回执行 ID，支持增量日志、超时和取消；SSH 断开后 supervisor 继续运行，并在报告终态前回收派生进程。
- **每次调用复核隔离**：容器只读根文件系统、任务固定 UID、默认丢弃全部 capability 后仅加回 4 个、只挂载本任务数据卷、网络关闭。控制服务在每次操作前重新 inspect 实际容器配置，而不是相信一次性的审计结论。
- **固定成果与独立验收**：成果绑定提交 SHA，后续编辑不会覆盖已提交成果；验证使用新任务环境，源码只读、构建目录可写。目标分支前进后需要重新构造候选并验证。
- **持久化与恢复**：每个任务有独立具名卷保存 `/workspace`（代码、独立 `.git`、任务 HOME、构建产物），容器销毁不删卷；另支持外部代码检查点及重建任务环境。停止后进程不自动恢复，外部检查点暂不包含 CLI HOME。

### 两种代码输入模式

| 模式 | 任务获得什么 | 适用场景 |
| --- | --- | --- |
| `snapshot` | 获准的已提交文件，初始化成新的独立 Git 仓库；不传原仓库历史 | 限制代码暴露范围、委派局部修改 |
| `repository` | 固定提交及其完整可达历史，以独立 Git bundle 传输 | 需要 `blame`、历史调查或保留任务提交 SHA |

`repository` 的文件策略限制文件 API 和成果回收范围，**不能隐藏历史中的文件**。需要路径保密时使用 `snapshot`。

仓库必须注册在控制主机上，支持普通仓库、bare 仓库和 linked worktree；客户端路径不会自动上传。当前只接受已提交输入，`include_dirty: true` 会被拒绝。

## 快速开始

需要 Rust 1.88+ 和 Git；Linux 构建还需要 libseccomp 开发库，例如 Debian 的 `libseccomp-dev`。控制端支持 Linux/macOS，沙箱主机必须是 Linux。完整协议验收需要允许本机 TCP 监听。

### 通过 MCP 分配远程沙箱（当前主路径）

沙箱主机只需要 sshd、Docker 权限和已存在的固定镜像；控制端需要能被外部 agent 调用。配置命名主机表后，一个控制服务可以管理多台 Linux Docker 主机。

```sh
cargo build --locked --release
cp examples/remote.json /private/path/remote.json   # 填入主机、namespace 与镜像摘要
python3 scripts/install-macos-mcp.py \
  --binary target/release/agenticsandbox \
  --config /private/path/remote.json
codex mcp list && claude mcp get agenticsandbox
```

安装器目前只有 macOS 版本（LaunchAgent + 用户级 MCP 注册，已覆盖 Codex / Claude Code / DeepSeek Harness 三种客户端）。Linux 作为控制端需要等价的 systemd 服务单元。安装细节、多主机配置和新主机准备的说明保留在本地 `docs/`。

之后外部 agent 用 MCP 工具即可操作任务：

```text
sandbox.info            查看 runtime、已注册仓库和现有任务
repo.register           注册控制主机上的绝对路径仓库（跨会话保存）
task.create             按 runtime、文件范围和固定提交建立任务
task.exec / task.logs   执行命令并读取增量日志
task.read / task.write  读写任务内文件（base64）
task.destroy            回收容器与数据卷
```

### 本地协议开发

`local` 后端用于开发和协议测试，命令拥有宿主机用户权限，不提供隔离。需要隔离时使用上面的 SSH Docker 路径。

```sh
cargo install --locked --path .
cp examples/local.json config.json
agenticsandbox init --config config.json
agenticsandbox serve --config config.json
```

确保 Cargo 的 bin 目录在 `PATH` 中。服务默认监听 `127.0.0.1:8765`；`init` 创建控制凭据，不创建远程环境。配置中的相对路径以配置文件目录为基准。

在另一个终端创建空白任务并执行一条命令：

```sh
agenticsandbox call task.create --token-file .state/admin.token <<'JSON'
{
  "runtime": "agentic",
  "network": "none",
  "role": "scratch",
  "purpose": "运行一条示例命令",
  "files": {"include": ["**"], "exclude": []}
}
JSON

agenticsandbox call task.exec --token-file .state/admin.token <<'JSON'
{
  "task_id": "<task_id>",
  "argv": ["/bin/echo", "hello from AgenticSandbox"],
  "timeout_seconds": 10
}
JSON

agenticsandbox call task.status --token-file .state/admin.token <<'JSON'
{"task_id": "<task_id>"}
JSON

agenticsandbox call task.logs --token-file .state/admin.token <<'JSON'
{"task_id": "<task_id>", "execution_id": "<execution_id>", "cursor": 0}
JSON

agenticsandbox call task.destroy --token-file .state/admin.token <<'JSON'
{"task_id": "<task_id>"}
JSON
```

命令异步返回 `execution_id`，日志的 `data` 字段为 base64，`cursor` 用于继续读取。创建响应还包含 `task_token`，供子 agent 操作该任务；不要把管理员令牌交给子 agent。

## 接入外部 agent

把获准令牌保存到私有文件后，外部 agent 通过 stdio MCP 连接控制服务：

```sh
agenticsandbox mcp --url https://controller.example.com --token-file /path/to/task.token
```

远程访问要求 HTTPS，私有 CA 可通过 `--ca-file` 指定；`127.0.0.1` 上允许 HTTP。工具接口定义在 `src/tools.json`，任务级权限与子任务范围限制实现在 `src/service/`。

## 当前状态与边界

当前是**已测试的候选实现**：产品代码统一为 Rust 0.2.0，Python 只用于测试 fixture 和验收脚本。当前镜像是 Arch 本地 `agentic-container:rename-20261009`（完整 ID `sha256:69a20f1d5de39eca4a148a831065039c7612e527c3390f372da2edffd7a4d438`），未发布 registry。截至 2026-10-09：21 项原生测试、fmt、clippy `-D warnings` 通过；macOS 完整协议 64 项通过（debug 与 release 各一次，零失败/错误/跳过，源码与 binary 匹配）；实机验收包括原生 MCP 12 项、安装后 MCP 11 项、DSH 用户配置 16 项、命名主机 SSH Docker 回归 7 项，以及更名后的真实任务（创建、受限 UID 执行、销毁、无残留）。

尚未完成：

- 镜像分发：创建容器使用 `--pull=never`，新主机必须先预置镜像；也没有 registry digest。
- 多主机：只用一台物理主机上的两个名称验证过解析与派发，第二台真机、跨网延迟和主机密钥预置未验收。
- 存储与生命周期：没有每任务磁盘配额；控制服务离线时没有 TTL 回收；`reconcile` 在 stopped/starting/lost 分支会跳过 TTL 处理。
- CLI HOME 恢复：外部检查点只包含代码，不含 CLI HOME 与会话。
- 生产隔离批准：所有候选报告保持 `production_approved: false`。

使用时还需要注意：

- `network: none` 关闭容器网络，也限制任务内本地开发服务的 socket；配置名称不会自动建立防火墙。
- 合入只更新控制主机仓库的目标 ref，不自动 push 或创建 PR；目标分支已被 worktree 检出时会拒绝更新。
- `local` 后端没有隔离，只用于开发和协议测试。

最新验收、未完成项与历史批次记录在本地 `docs/implementation-status.md`。

## 开发与文档

```text
src/                  Rust 控制服务（service/）、worker、CLI/MCP
runtime/              镜像 Dockerfile 与 entrypoint
scripts/              打包、协议验收、运行环境审计与 MCP 安装器
tests/                调用 Rust 二进制的集成测试与 fixture
examples/             配置示例
docs/                 使用、开发与当前状态；history/ 保存历史报告
artifacts/            原始验收证据，README 提供批次索引
```

```sh
cargo build --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
python3 scripts/protocol-acceptance.py --binary target/debug/agenticsandbox
python3 scripts/package-runtime.py --development --output /tmp/development.tar.gz
```

Python 3.11+、Git、OpenSSL 仅用于测试 fixture 和验收脚本，无需安装 Python 产品包或第三方 Python 依赖。发布构建使用 `cargo build --locked --release`，并向验收入口传入 `--binary target/release/agenticsandbox`。

- [运行环境](runtime/README.md)：镜像构成、worker、持久化与 Linux 验收。
- [脚本索引](scripts/README.md)：打包、协议验收与运行环境审计入口。

架构设计、部署说明、构建主机接入和逐批验收证据保存在本地 `docs/` 与 `artifacts/`，不随仓库发布。
