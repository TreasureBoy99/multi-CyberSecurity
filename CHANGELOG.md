# Changelog

## [v4.2.12] - 2026-07-10

### 🚀 新增功能

#### 子仓库扩展
- 添加 `external/Claude-BugHunter` (71 skills, Bug Hunting & Red Team)
- 添加 `external/Anthropic-Cybersecurity-Skills` (817 skills, 29 安全领域)
- 更新 `ACKNOWLEDGEMENTS.md` 鸣谢文档

#### 子仓库管理体系
新增 3 个 GitHub Actions 工作流：

| 工作流 | 触发条件 | 功能 |
|--------|----------|------|
| `submodule-health-check.yml` | 每天 06:00 | 检测 404/403 异常 |
| `submodule-sync.yml` | 每周一 08:00 | 自动同步 + PR合并 |
| `submodule-report.yml` | 每周一/四 10:00 | 生成状态报告 |

#### Agents 外部技能集成
- 新增 `EXTERNAL_SKILLS_ROUTING.md` — 900+ 技能路由指南
- 更新 `exploit_agent.md` — Bug Hunting / Red Team 技能引用
- 更新 `recon_agent.md` — Recon / OSINT 技能引用

### 🔧 修复

- `submodule-sync.yml` — 添加 PR/push 触发，自动合并逻辑
- `update-submodules.yml` — 统一工作流风格
- `submodule-report.yml` — 修复 YAML 语法问题

### 📁 新增文件

```
.github/workflows/submodule-health-check.yml
.github/workflows/submodule-sync.yml
.github/workflows/submodule-report.yml
EXTERNAL_SKILLS_ROUTING.md
ACKNOWLEDGEMENTS.md
external/Claude-BugHunter/
external/Anthropic-Cybersecurity-Skills/
```

---

## [v4.2.1] - 2026-05-29

### 🚀 新增功能

#### reverse-skill 子仓库集成
- 添加 `external/reverse-skill` (40 CTF场景, 20+ 专项技能)
- 包含 Burp MCP 扩展、工具链路由矩阵

#### CodeGraph 集成
- 添加 `vendor/codegraph` 子仓库
- ~35% 成本节省, ~70% 工具调用减少

#### 多层破限策略
- 新增 `.ctf/UNRESTRICTION_PROTOCOL.md`
- Layer 1-6 完整策略文档

### 📁 新增文件

```
.ctf/UNRESTRICTION_PROTOCOL.md
vendor/codegraph/
```

---

## [v4.2.0] - 2026-05-29

### 🚀 新增功能

#### RedTeam 模式与破限框架

**CTF/Sandbox 破限指令** — 多平台支持：

| 平台 | 破限文件 |
|------|----------|
| Codex | `.codex/instruction.md` |
| Claude Code | `.claude/REDTEAM.md` |
| Cursor | `.cursor/rules/redteam-mode.mdc` |
| Hermes | `.hermes/redteam-mode.md` |
| Trae | `.trae/REDTEAM_MODE.md` |
| OpenClaw | `.openclaw/REDTEAM.md` |

#### RedTeam 工具集
- 新增 `24-红蓝对抗-RedTeam/` 目录
- 15+ 红队工具自动安装脚本

#### CTF 模式指令集
- `.ctf/CTF_MODE.md` — CTF 模式核心指令
- `.ctf/REDTEAM.md` — RedTeam 执行指南
- `.ctf/AD_ATTACK.md` — AD 攻击链路

---

## [v4.1.0] - 2026-05-29

### 🚀 新增功能

#### Cursor IDE 支持
- `.cursor/AGENTS.md`
- `.cursor/rules/security-rules.mdc`
- `.cursor/rules/code-audit.mdc`
- `.cursor/mcp.json`

#### Claude Code 支持
- `CLAUDE.md` — 项目级指令
- `.claude/rules/framework-dev.md`
- `.claude/agents/security-auditor.md`

#### OpenAI Codex CLI 支持
- `AGENTS.md` — 项目级 Agent 指令
- `.codex/config.toml`

---

## [v4.0.0] - 2026-05-29

### 🚀 Major Features

#### 8-Stage Security Audit Pipeline
- Recon → Hunt → Validate → Gapfill → Dedupe → Trace → Feedback → Report
- SQLite 状态管理
- 预算控制 (`--max-cost-usd`)

#### MCP Service Integration
- `wxmini-server`: 微信小程序分析 (port 43827)
- `java-server`: Java 代码审计 (port 8082)
- `burp-bridge`: Burp Suite 集成 (port 8090)
- `kali-bridge`: Kali Linux 工具 (port 8081)

#### Specialized Audit Agents

**微信小程序审计** — 7-Agent 架构
- Decompiler, SecretScanner, EndpointMiner
- CryptoAnalyzer, VulnAnalyzer, Reporter

**Java 代码审计** — 5-stage 管道
- Info Gathering → Cross Analysis → Route Tracing
- Deep Analysis → Quality Check

#### Multi-Platform IDE 支持
- Trae, Hermes, OpenClaw, Cursor, Claude, Codex

---

## [v3.0.0] - 2026-05-20

### 初始发布

- 7 核心 Agent
- 39 安全模块
- Mission Control dashboard
- MCP 集成 Burp/Kali

---

*旧版本历史见 [CHANGELOG_v3.md](CHANGELOG_v3.md), [CHANGELOG_v4.md](CHANGELOG_v4.md)*
