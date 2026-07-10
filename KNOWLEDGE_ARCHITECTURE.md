# 🗃️ 知识库架构方案 (Knowledge Base Architecture)

> 漏洞知识库 + 工具 MCP 模块，方便 Agents 协同调用

---

## 1. 漏洞知识库 (Vulnerability Knowledge Base)

### 设计目标

```
用户任务 → Agent → 查询知识库 → 获取漏洞模式/攻击链/修复建议
```

### 目录结构

```
knowledge/
├── cve/                       # CVE 漏洞库
│   ├── index.json             # SQLite 索引备份
│   ├── 2024/                 # 按年份
│   │   ├── cve-2024-*.md
│   │   └── cve-2024-*.json
│   ├── 2025/
│   └── 2026/
├── vuln-patterns/              # 漏洞模式库 (按类型)
│   ├── injection/
│   │   ├── sql-injection/
│   │   │   ├── pattern.json  # 检测模式
│   │   │   ├── payloads.txt  # 常用 payload
│   │   │   └── fix.md        # 修复建议
│   │   ├── xss/
│   │   ├── ssrf/
│   │   ├── ssti/
│   │   └── command-injection/
│   ├── auth-bypass/
│   │   ├── oauth/
│   │   ├── jwt/
│   │   └── session-fixation/
│   └── logic/
│       ├── race-condition/
│       ├── mass-assignment/
│       └── business-logic/
├── attack-chains/              # 攻击链模板
│   ├── ad-attack-chain.json
│   ├── cloud-attack-chain.json
│   ├── web-attack-chain.json
│   └── iot-attack-chain.json
├── techniques/                 # ATT&CK 技术详情
│   ├── T1059/                # Command and Scripting Interpreter
│   │   ├── index.json
│   │   ├── detection.md
│   │   └── mitigation.md
│   └── ...
├── cwe/                       # CWE 弱点枚举
│   ├── CWE-79.json           # XSS
│   ├── CWE-89.json           # SQLi
│   └── ...
└── patterns.sqlite             # SQLite 主数据库
```

### SQLite 数据库设计

```sql
-- 漏洞模式表
CREATE TABLE vuln_patterns (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,           -- injection, auth-bypass, etc.
    severity TEXT,                -- critical, high, medium, low
    cwe_id TEXT,
    cvss_score REAL,
    description TEXT,
    detection_pattern TEXT,        -- regex or pattern
    payload_examples TEXT,        -- JSON array
    remediation TEXT,
    references TEXT,              -- JSON array of URLs
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- 攻击链表
CREATE TABLE attack_chains (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    platform TEXT NOT NULL,        -- ad, cloud, web, iot
    steps TEXT NOT NULL,          -- JSON array of steps
    prerequisites TEXT,           -- JSON array
    tools_required TEXT,          -- JSON array
    difficulty TEXT,
    effectiveness REAL,
    created_at TIMESTAMP
);

-- CVE 索引表
CREATE TABLE cve_index (
    id TEXT PRIMARY KEY,          -- CVE-YYYY-NNNNN
    year INTEGER,
    severity TEXT,
    cvss_score REAL,
    cwe_id TEXT,
    description TEXT,
    affected_products TEXT,       -- JSON array
    mitigation TEXT,
    poc_available BOOLEAN,
    created_at TIMESTAMP
);

-- ATT&CK 技术表
CREATE TABLE attack_techniques (
    id TEXT PRIMARY KEY,          -- TXXXX
    name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    description TEXT,
    detection TEXT,
    mitigation TEXT,
    evade_techniques TEXT,       -- JSON array
    created_at TIMESTAMP
);

-- 全文搜索
CREATE VIRTUAL TABLE vuln_patterns_fts USING fts5(
    name, description, detection_pattern,
    content='vuln_patterns',
    content_rowid='id'
);
```

### Agent 调用接口

```python
# framework/knowledge/knowledge_base.py

class KnowledgeBase:
    def __init__(self, db_path="knowledge/patterns.sqlite"):
        self.db = sqlite3.connect(db_path)
        self.markdown_root = "knowledge/vuln-patterns"
        self.cve_root = "knowledge/cve"

    def search_vuln_pattern(self, keyword: str, vuln_type: str = None):
        """搜索漏洞模式"""
        query = """
            SELECT * FROM vuln_patterns
            WHERE name LIKE ? OR description LIKE ?
        """
        # ... 执行查询

    def get_attack_chain(self, platform: str):
        """获取攻击链"""
        return self.db.execute(
            "SELECT * FROM attack_chains WHERE platform = ?",
            (platform,)
        ).fetchall()

    def get_cve_details(self, cve_id: str):
        """获取 CVE 详情"""
        # 先查 SQLite，找不到再查 markdown 文件
        pass

    def get_detection_rules(self, technique_id: str):
        """获取检测规则 (for Blue Agent)"""
        pass
```

---

## 2. 工具 MCP 模块 (Tools MCP Module)

### 设计目标

```
Agent → ToolRouter → MCP/Tools → 实际工具执行
                        ↓
              Playwright, CDP, Burp, fscan, Kali
```

### 目录结构

```
tools/
├── burp/                       # BurpSuite MCP
│   ├── config.json             # 扩展配置
│   ├── extensions/             # BApp 扩展
│   │   ├── active-scan-plus/
│   │   └── logger-plus/
│   ├── macros/                #宏
│   └── scripts/               # Python 脚本
│       └── *.py
├── chromium/                   # Chrome/Edge CDP
│   ├── config.json
│   ├── cdp-commands/          # CDP 命令模板
│   │   ├── network.json
│   │   ├── dom.json
│   │   └── runtime.json
│   └── exploit-scripts/        # CDP 利用脚本
├── playwright/                 # Playwright 自动化
│   ├── config.json
│   ├── browsers/              # 浏览器配置
│   ├── scripts/               # 自动化脚本
│   │   ├── login-sequence.js
│   │   ├── api-fuzzer.js
│   │   └── vuln-checker.js
│   └── templates/             # 页面模板
├── fscan/                     # fscan 封装
│   ├── config.json
│   ├── templates/             # 扫描模板
│   │   ├── quick-scan.json
│   │   ├── deep-scan.json
│   │   └── domain-enum.json
│   └── output-parsers/       # 输出解析
├── kali/                      # Kali 工具链
│   ├── config.json
│   ├── tool-routing.json      # 工具路由配置
│   ├── wordlists/            # 字典
│   └── scripts/              # 工具封装脚本
└── mcp-config.json          # 统一 MCP 配置
```

### MCP 工具路由配置

```json
{
  "tools": {
    "burp": {
      "type": "mcp",
      "host": "localhost",
      "port": 8090,
      "capabilities": ["proxy", "scanner", "intruder", "repeater"],
      "scripts": "tools/burp/scripts/*.py"
    },
    "playwright": {
      "type": "local",
      "command": "npx playwright",
      "browsers": ["chromium", "firefox", "webkit"],
      "scripts": "tools/playwright/scripts/*.js"
    },
    "chromium-cdp": {
      "type": "cdp",
      "executable": "/usr/bin/chromium",
      "remote-debugging-port": 9222,
      "commands": "tools/chromium/cdp-commands/*.json"
    },
    "fscan": {
      "type": "local",
      "binary": "/opt/fscan/fscan",
      "templates": "tools/fscan/templates/*.json"
    },
    "kali": {
      "type": "ssh",
      "host": "kali.local",
      "port": 22,
      "user": "root",
      "tools": ["nmap", "sqlmap", "nikto", "hydra"]
    }
  },
  "routing": {
    "web-recon": ["nmap", "ffuf", "nuclei"],
    "vuln-scan": ["nuclei", "sqlmap", "xsstrike"],
    "privesc": ["linpeas", "winpeas", "powerupsql"],
    "ad-attack": ["bloodhound", "impacket", "mimikatz"]
  }
}
```

### Agent 工具调用示例

```python
# exploit_agent.md 中引用的工具调用

"""
### 工具调用示例

当需要执行 Web 漏洞扫描时:
1. 通过 MCP 调用 BurpSuite Scanner
2. 或通过 Playwright 调用浏览器自动化
3. 或直接调用 fscan/nuclei

ToolRouter 会根据任务类型自动选择合适的工具:

```python
from framework.tools.tool_router import ToolRouter

router = ToolRouter()

# 自动路由
result = await router.execute(
    task="web-vuln-scan",
    target="https://example.com",
    tools=["nuclei", "sqlmap"]  # 备选
)
```

工具调用结果会自动记录到知识库供后续使用。
"""
```

---

## 3. 知识库更新机制

### 自动化更新

```yaml
# .github/workflows/knowledge-sync.yml
name: Knowledge Base Sync

on:
  schedule:
    # 每周一更新 CVE 数据
    - cron: '0 9 * * 1'
  workflow_dispatch:

jobs:
  sync-cve:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true

      - name: Sync CVE Data
        run: |
          # 下载最新 CVE 数据
          curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz
          # 解析并更新 SQLite
          python scripts/update_cve_db.py

      - name: Update Markdown Files
        run: |
          python scripts/cve_to_markdown.py

      - name: Commit Changes
        run: |
          git add knowledge/
          git commit -m "chore: update vulnerability knowledge base"
          git push
```

---

## 4. Agent 集成示例

### Exploit Agent 调用知识库

```markdown
### 漏洞知识查询

当发现潜在漏洞时，先查询知识库:

```python
# 1. 搜索已知漏洞模式
kb = KnowledgeBase()
patterns = kb.search_vuln_pattern("SQL injection", type="injection")

# 2. 获取对应 CVE
cves = kb.get_cves_by_cwe("CWE-89")

# 3. 获取攻击链模板
chain = kb.get_attack_chain("web", vulnerability_type="sqli")

# 4. 获取修复建议
fix = kb.get_remediation("sql-injection")
```
```

### Blue Agent 调用检测规则

```markdown
### 检测规则查询

```python
# 获取 ATT&CK 技术检测规则
detection = kb.get_detection_rules("T1059")  # Command Execution

# 获取监控建议
monitoring = kb.get_monitoring_advice(technique_id="T1059")
```
```

---

## 5. 实施计划

### Phase 1: 基础架构 (1-2天)
- [ ] 创建 `knowledge/` 目录结构
- [ ] 初始化 SQLite 数据库
- [ ] 创建基础表结构

### Phase 2: 知识填充 (3-5天)
- [ ] 从子仓库迁移已有漏洞模式
- [ ] 添加 CVE 索引
- [ ] 添加 ATT&CK 技术详情

### Phase 3: 工具 MCP 整合 (2-3天)
- [ ] 统一工具路由配置
- [ ] 封装 Playwright/CDP 调用
- [ ] 创建 fscan/Kali 封装脚本

### Phase 4: Agent 集成 (2-3天)
- [ ] 更新 Exploit Agent 引用知识库
- [ ] 更新 Blue Agent 引用检测规则
- [ ] 更新 Recon Agent 引用 OSINT 模板

---

## 6. 相关文件

- `SUBMODULE_STRATEGY.md` - 子仓库管理策略
- `EXTERNAL_SKILLS_ROUTING.md` - 外部技能路由
- `framework/tools/tool_router.py` - 工具路由器 (待实现)

---

*最后更新: 2026-07-10*
