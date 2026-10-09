# 项目工作约定

- 产品实现仅保留标准 `src/` 下的 Rust；Python 只用于 `tests/` fixture 和 `scripts/` 打包/验收。不要恢复旧 Python 产品包或创建第二套产品入口。

- 用户已决定使用自己的通用镜像，名称为 `agentic-container`，不复用 Claude Code 镜像。
- 镜像只预装 Node.js/npm、worker 和开发工具，不预装 agent CLI；模型循环由外部客户端（Codex / Claude Code / DeepSeek Harness）经 MCP 操作沙箱完成。
- 后端只有 `local`（开发 fixture，无隔离）和 `remote`（SSH 管理 Docker 容器，每任务独立容器与数据卷）。镜像构成、worker 职责、持久化与验收见 [runtime/README.md](runtime/README.md)；逐项证据见本地 docs/implementation-status.md。
- 构建、Linux Docker 验收优先使用已授权的 Arch 主机。新会话先阅读本地 docs/build-hosts.md（与主机无关的操作约定）和控制主机上的 `~/.local/share/agenticsandbox/build-hosts.local.md`（私有接入信息，不入库）；两处都没有所需信息时再向用户索取。仓库中不写内网地址、账号或凭据。
- 本机磁盘空间不足时继续使用 Arch，不能自行清理其他项目或 Docker 资产。
- 不丢弃已有改动，不把本地、mock 或容器功能测试报告当作 BYR 生产隔离批准。
- 未经用户明确要求，不启动子 agent，不代用户发送对外消息。
