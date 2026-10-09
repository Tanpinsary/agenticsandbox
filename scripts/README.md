# 构建与验收脚本

Python 仅用于打包、fixture 与审计；产品入口是 Rust `agenticsandbox`。从仓库根目录执行脚本，先构建原生程序。完整命令与依赖见本地 docs/development.md。

| 脚本 | 用途与运行条件 |
| --- | --- |
| `package-runtime.py` | 可重复的公开运行包；`--development` 另含测试与审计输入 |
| `protocol-acceptance.py` | 发现并运行全部原生协议与审计回归，支持 `--binary` |
| `install-macos-mcp.py` | 安装 Rust 控制服务、用户 LaunchAgent、Codex/Claude/DSH 用户级 MCP；写入用户目录需要授权；`--dsh-only` 只补注册 |
| `remote-smoke.py` | 真实 SSH Docker 后端的 MCP 创建/读写/执行/隔离/销毁；`--url` 可验收已安装服务 |
| `service-delivery-audit.py` | 合成仓库的完整任务交付；`--local` 是开发 fixture，`--config` 指向已配置的远端 runtime |
| `docker-runtime-audit.py` | Linux Docker worker、隔离与持久化检查；要求完整本地 image ID 或 registry digest |
| `sideways-audit.py` | 复现指定的侧向诊断；属于问题定位，不能代替完整验收 |

Linux 构建与 Docker/Terraform 检查使用已授权的 Arch 主机，接入信息不随仓库发布。报告按批次留在本地 `artifacts/`，脚本失败时仍保留诊断并核对清理结果。

`tests/fixtures/dsh-mcp-audit.mjs` 是本机 DSH 安装验收 fixture，复用已安装 DSH 的 MCP plugin 和工具运行时，不创建 agent 或调用模型。示例：`node tests/fixtures/dsh-mcp-audit.mjs /tmp/dsh-mcp-report.json`。
