# agentic-container

`runtime/Dockerfile` 构建 `remote` 后端使用的任务镜像：控制服务经 SSH 在目标主机上为每个任务启动一个容器，镜像本身只提供基础软件和 Rust worker，不预装任何 agent CLI。模型循环由外部客户端（Codex / Claude Code / DeepSeek Harness）经 MCP 操作沙箱完成。

当前候选为 Arch AMD64 `agentic-container:rename-20261009`，本地 ID `sha256:69a20f1d5de39eca4a148a831065039c7612e527c3390f372da2edffd7a4d438`；worker 源码摘要 `4c906d0f0c48282685280cb085140bddf4bf05cdbd80f83507553e11fcd11100`，manifest 摘要 `b4b5d7dd976fa27826f4381a8910a0e44034ad1894387b9d51d5e96d18b07413`。镜像未发布 registry，构建与验收主机信息见本地 `docs/`。

## 镜像构成和环境

| 内容 | 当前配置 |
| --- | --- |
| 系统 | Debian 12 bookworm，官方固定 digest 的 Python 3.12.15 基础镜像 |
| JavaScript | 官方固定 digest 的 Node 24 LTS；当前 AMD64 构建 Node 24.21.0、npm 11.19.0 |
| 编程 agent | 不预装；由外部客户端驱动 |
| 开发工具 | Python、Git、bash、ripgrep、curl、GCC/G++/make（build-essential）、pkg-config |
| 运行支持 | libseccomp、tini、CA、libatomic/libstdc++、本项目 Rust worker |
| 任务身份 | UID/GID 10001，HOME `/workspace/home`，工作目录 `/workspace/repo` |
| 固定路径 | `/opt/agenticsandbox/agenticsandbox`（worker）、`/opt/agenticsandbox/runtime-manifest.json` |

镜像内没有 `/opt/agents`，也没有系统级的 `codex` / `claude` / `dsh`。

### worker 是什么

worker 是本项目随镜像安装的 Rust 执行程序，源码位于 `src/worker.rs`，运行时位于只读 `/opt/agenticsandbox/agenticsandbox`。控制服务通过 `docker exec` 调用 `agenticsandbox worker`，经 stdin/stdout 交换 JSON；它没有对外监听端口，也不包含模型推理循环。

它负责检查镜像身份、安装获准项目输入、建立独立 Git 仓库、读写/搜索文件、启动及取消命令、提供状态和日志、导出成果和检查点。执行命令时派生独立 supervisor，切换到任务 UID 并施加环境、syscall、超时和输出限制。

Linux supervisor 使用 subreaper/pidfd 回收本次执行的后代，包含新 session、进程组和双重 fork；正常主命令结束也清理 daemon，回收完成才报告终态。需要 Linux pidfd 支持。

## 容器与持久化

`remote` 后端为每个任务创建：

- 一个具名数据卷挂到 `/workspace`，保存代码、独立 `.git`、任务 HOME、构建产物和任务临时文件；
- 一个容器，`--read-only` 根文件系统、`--network none`、私有 IPC/cgroup namespace、4 GiB 内存、2 CPU、PID 上限 128、丢弃全部 capability 后仅加回 `CHOWN`/`SETUID`/`SETGID`/`KILL`、`no-new-privileges`、`/run` 与 `/tmp` 为 128 MiB tmpfs。

控制服务在每次操作前重新 `inspect` 容器并核对上述配置与标签归属；不匹配则拒绝执行。销毁任务时删除本任务的容器与卷；没有每任务磁盘配额，也没有控制服务离线时的 TTL 回收。

## 构建和静态检查

在项目根目录构建。默认基础镜像为 2026-10-06 从官方 registry 核实的 Python 3.12.15 / bookworm 多架构 index，固定完整 digest；可以通过 `PYTHON_IMAGE` 覆盖为另一个审核过的完整摘要。生产任务使用最终镜像的 registry digest。

```sh
docker build --platform linux/amd64 -f runtime/Dockerfile -t agentic-container:candidate .
```

`.dockerignore` 只允许 Dockerfile、entrypoint、Rust 源码、Cargo.toml/Cargo.lock/build.rs 进入 build context，排除 `.state`、`.git`、`.env`、本机配置。需要转交构建主机时生成可重复的公开构建包：

```sh
python3 scripts/package-runtime.py --output /tmp/agentic-container-runtime.tar.gz
```

输出含归档 SHA-256 和 worker 源码摘要；归档内 `build-context-manifest.json` 保存逐文件摘要。传输后核对归档摘要，在新目录解压并按上面的命令构建。镜像必须按 provisioner 架构构建；ARM64 验证不能替代 AMD64 验证。

## Worker 构建身份与启动校验

构建时产生只读 `/opt/agenticsandbox/runtime-manifest.json`，schema v3 记录基础镜像 digest、架构、Node/npm 版本、task UID、Rust 版本/协议、构建源码摘要和可执行文件摘要。entrypoint 校验 manifest；`worker identity` 返回经校验的 manifest、manifest 摘要及实际源码摘要。

控制服务在安装任何项目输入前检查 protocol v1、Linux、固定 image digest、task UID、manifest 验证状态与 worker 源码。默认要求 worker 源码与当前控制服务包相同；管理员可在 runtime profile 中指定 `worker_source_sha256` 固定经过兼容性验证的版本，并可指定 `runtime_manifest_sha256` 与 `architecture`。这些字段可从实际镜像的 identity 中取得，不取代运行时隔离复核。

缺少 manifest 的旧镜像、旧协议或源码变更会被拒绝。修改 worker 后须重新构建镜像；仅更新控制服务可能与已有镜像不匹配。

## 候选镜像的 Docker 验收

在可访问 Docker daemon 的环境中，先完成镜像构建，再使用固定 registry digest 或本地完整 `sha256:...` image ID：

```sh
python3 scripts/docker-runtime-audit.py \
  --image '<完整镜像 digest 或 image ID>' \
  --output /tmp/agenticsandbox-runtime-audit.json
```

可以传入已有的 `--context`，也可以用 `--pids-limit` 覆盖审计值（默认 128）。脚本拒绝可变 tag、不拉取镜像、不挂载主机目录、不公开端口、不修改 daemon 配置。它创建带唯一审计标签的独立容器，沿用后端实际的资源与 namespace 参数，并显式传入 per-container `--pids-limit 128`，再经过真实 supervisor 启动 UID 10001 的任务。

检查包括镜像 manifest、挂载/只读配置、PID 配额、namespace、任务 probe、跨任务文件/活跃进程不可见、验证源码只读和 Git/二进制导出，以及受限 UID 下的 Node/npm 与离线安装。结束只删除本次标签的容器和卷；无法确认清理完成则失败。

JSON 证据保存在容器之外，命令返回其 SHA-256。报告始终标记 `production_approved: false`：显式 Docker 参数不能替代实际 provisioner 的资源配置，namespace/PID 配置检查也不能替代 CPU/内存/磁盘/fork 压力测试。
