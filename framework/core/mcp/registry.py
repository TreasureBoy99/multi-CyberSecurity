"""
MCP 工具注册表
==============
统一工具元数据管理和注册

工具元数据规范:
- 名称、描述、版本
- 分类 (recon, exploit, validate, etc.)
- 输入/输出 Schema
- 认证要求
- 速率限制
- MCP 服务映射
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class ToolCategory(str, Enum):
    """工具分类"""
    # 侦察阶段
    RECON = "recon"                    # 资产发现
    PORT_SCAN = "port_scan"            # 端口扫描
    SERVICE_DETECT = "service_detect"  # 服务识别
    OSINT = "osint"                    # 开源情报
    SUBDOMAIN = "subdomain"            # 子域名枚举

    # 漏洞挖掘
    WEB_SCAN = "web_scan"              # Web 漏洞扫描
    FUZZ = "fuzz"                      # Fuzzing
    NUCLEI = "nuclei"                  # Nuclei 模板扫描

    # 利用
    EXPLOIT = "exploit"                # 漏洞利用
    SHELL = "shell"                    # Shell 管理
    PIVOT = "pivot"                    # 横向移动

    # 验证
    VALIDATE = "validate"              # 漏洞验证
    ORACLE = "oracle"                  # Oracle 验证
    BURP = "burp"                      # Burp Suite

    # 后渗透
    CREDENTIALS = "credentials"        # 凭证获取
    PRIVESC = "privesc"                # 权限提升
    PERSISTENCE = "persistence"        # 持久化

    # 报告
    REPORT = "report"                  # 报告生成
    NOTES = "notes"                    # 笔记

    # 通用
    UTILITY = "utility"                # 通用工具
    CUSTOM = "custom"                  # 自定义


@dataclass
class ToolMetadata:
    """
    工具元数据

    包含工具的完整描述信息，用于:
    - 工具注册和发现
    - 参数验证
    - 权限控制
    - MCP 路由
    """
    # 基本信息
    name: str                          # 工具名称 (唯一标识)
    display_name: str                  # 显示名称
    description: str                   # 工具描述
    version: str = "1.0.0"             # 版本号
    author: str = ""                   # 作者

    # 分类
    category: ToolCategory = ToolCategory.UTILITY
    tags: list[str] = field(default_factory=list)  # 标签

    # 功能
    capabilities: list[str] = field(default_factory=list)  # 能力列表
    exploit_types: list[str] = field(default_factory=list)  # 漏洞类型 (sqli, xss, rce, etc.)

    # 输入 Schema (JSON Schema 格式)
    input_schema: dict = field(default_factory=dict)

    # 输出 Schema
    output_schema: dict = field(default_factory=dict)

    # 执行配置
    timeout_sec: int = 30              # 超时时间
    retry_count: int = 0               # 重试次数
    rate_limit: int = 0                # 速率限制 (0=无限制)

    # 认证要求
    requires_auth: bool = False        # 是否需要认证
    auth_type: str = ""                # 认证类型 (api_key, oauth, etc.)

    # MCP 配置
    mcp_server: str = ""               # MCP 服务器名称
    mcp_tool_name: str = ""            # MCP 工具名

    # 依赖
    dependencies: list[str] = field(default_factory=list)  # 依赖工具
    installed: bool = True             # 是否已安装

    # 状态
    enabled: bool = True               # 是否启用
    deprecated: bool = False           # 是否废弃
    deprecation_message: str = ""      # 废弃说明

    # 统计
    use_count: int = 0                 # 使用次数
    success_count: int = 0             # 成功次数
    last_used: Optional[str] = None    # 上次使用时间

    # 成本
    estimated_cost_usd: float = 0.0    # 预估成本

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @property
    def success_rate(self) -> float:
        """成功率"""
        if self.use_count == 0:
            return 0.0
        return self.success_count / self.use_count

    def increment_use(self, success: bool = True):
        """记录使用"""
        self.use_count += 1
        if success:
            self.success_count += 1
        self.last_used = datetime.now().isoformat()


class ToolRegistry:
    """
    工具注册表

    管理所有可用工具的元数据
    """

    def __init__(self):
        self._tools: dict[str, ToolMetadata] = {}
        self._tools_by_category: dict[ToolCategory, list[str]] = {}
        self._hooks: dict[str, Callable] = {}  # pre/post execution hooks
        self._initialized = False

    def _ensure_initialized(self):
        """确保已初始化"""
        if not self._initialized:
            self._register_builtin_tools()
            self._initialized = True

    def _register_builtin_tools(self):
        """注册内置工具"""
        # 这些是占位符，实际工具在 MCP server 启动时动态注册
        builtin_tools = [
            # 侦察工具
            ToolMetadata(
                name="nmap",
                display_name="Nmap Port Scanner",
                description="端口扫描和服务发现",
                category=ToolCategory.PORT_SCAN,
                tags=["scanning", "recon"],
                capabilities=["port_scan", "service_detection", "os_detection"],
                input_schema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "目标 IP 或 CIDR"},
                        "ports": {"type": "string", "description": "端口范围"},
                        "flags": {"type": "string", "description": "Nmap flags"},
                    },
                    "required": ["target"],
                },
                timeout_sec=300,
                mcp_server="kali-bridge",
                mcp_tool_name="nmap_scan",
            ),
            ToolMetadata(
                name="subfinder",
                display_name="Subdomain Finder",
                description="子域名发现工具",
                category=ToolCategory.SUBDOMAIN,
                tags=["recon", "subdomain"],
                capabilities=["subdomain_enumeration"],
                input_schema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string"},
                    },
                    "required": ["domain"],
                },
                timeout_sec=60,
                mcp_server="kali-bridge",
                mcp_tool_name="subfinder_scan",
            ),
            # Web 扫描
            ToolMetadata(
                name="nikto",
                display_name="Nikto Web Scanner",
                description="Web 服务器扫描",
                category=ToolCategory.WEB_SCAN,
                tags=["scanning", "web"],
                capabilities=["web_vulnerability_scan"],
                input_schema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                    },
                    "required": ["target"],
                },
                timeout_sec=600,
                mcp_server="kali-bridge",
                mcp_tool_name="nikto_scan",
            ),
            # 漏洞扫描
            ToolMetadata(
                name="nuclei",
                display_name="Nuclei Scanner",
                description="基于模板的漏洞扫描",
                category=ToolCategory.NUCLEI,
                tags=["scanning", "vulnerability", "template"],
                capabilities=["vulnerability_scan", "template_based"],
                input_schema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "templates": {"type": "array", "items": {"type": "string"}},
                        "severity": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["target"],
                },
                timeout_sec=600,
                mcp_server="kali-bridge",
                mcp_tool_name="nuclei_scan",
            ),
            # Burp Suite
            ToolMetadata(
                name="burp_active_scan",
                display_name="Burp Active Scan",
                description="Burp Suite 主动扫描",
                category=ToolCategory.BURP,
                tags=["scanning", "web", "burp"],
                capabilities=["active_scan", "vulnerability_scan"],
                input_schema={
                    "type": "object",
                    "properties": {
                        "base_url": {"type": "string"},
                        "scan_profile": {"type": "string"},
                    },
                    "required": ["base_url"],
                },
                timeout_sec=300,
                mcp_server="burp-bridge",
                mcp_tool_name="active_scan",
            ),
            # 漏洞利用
            ToolMetadata(
                name="sqlmap",
                display_name="SQLMap",
                description="SQL 注入检测和利用",
                category=ToolCategory.EXPLOIT,
                tags=["exploit", "sqli"],
                capabilities=["sql_injection", "database_dump"],
                exploit_types=["sql_injection"],
                input_schema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "data": {"type": "string"},
                        "level": {"type": "integer", "minimum": 1, "maximum": 5},
                        "risk": {"type": "integer", "minimum": 0, "maximum": 3},
                    },
                    "required": ["url"],
                },
                timeout_sec=600,
                mcp_server="kali-bridge",
                mcp_tool_name="sqlmap_scan",
            ),
            # 验证工具
            ToolMetadata(
                name="oracle_verify",
                display_name="Oracle Verifier",
                description="漏洞重放验证",
                category=ToolCategory.ORACLE,
                tags=["validate", "oracle"],
                capabilities=["vulnerability_verification", "proof_capsule"],
                input_schema={
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string"},
                        "vuln_type": {"type": "string"},
                        "target_url": {"type": "string"},
                        "payload": {"type": "string"},
                    },
                    "required": ["finding_id", "vuln_type", "target_url"],
                },
                timeout_sec=60,
            ),
            # 命令执行
            ToolMetadata(
                name="metasploit",
                display_name="Metasploit Framework",
                description="漏洞利用框架",
                category=ToolCategory.EXPLOIT,
                tags=["exploit", "meterpreter"],
                capabilities=["exploit", "payload_generation"],
                input_schema={
                    "type": "object",
                    "properties": {
                        "module": {"type": "string"},
                        "options": {"type": "object"},
                    },
                    "required": ["module"],
                },
                timeout_sec=300,
                mcp_server="kali-bridge",
                mcp_tool_name="msfconsole",
            ),
        ]

        for tool in builtin_tools:
            self.register(tool)

        logger.info(f"Registered {len(builtin_tools)} builtin tools")

    def register(self, tool: ToolMetadata) -> bool:
        """
        注册工具

        Args:
            tool: 工具元数据

        Returns:
            是否注册成功
        """
        if tool.name in self._tools:
            logger.warning(f"Tool {tool.name} already registered, skipping")
            return False

        self._tools[tool.name] = tool

        # 按分类索引
        if tool.category not in self._tools_by_category:
            self._tools_by_category[tool.category] = []
        self._tools_by_category[tool.category].append(tool.name)

        logger.debug(f"Registered tool: {tool.name} ({tool.category})")
        return True

    def unregister(self, name: str) -> bool:
        """注销工具"""
        if name not in self._tools:
            return False

        tool = self._tools[name]
        if tool.category in self._tools_by_category:
            if name in self._tools_by_category[tool.category]:
                self._tools_by_category[tool.category].remove(name)

        del self._tools[name]
        logger.info(f"Unregistered tool: {name}")
        return True

    def get(self, name: str) -> Optional[ToolMetadata]:
        """获取工具元数据"""
        self._ensure_initialized()
        return self._tools.get(name)

    def list_all(self) -> list[ToolMetadata]:
        """列出所有工具"""
        self._ensure_initialized()
        return list(self._tools.values())

    def list_by_category(self, category: ToolCategory) -> list[ToolMetadata]:
        """按分类列出工具"""
        self._ensure_initialized()
        names = self._tools_by_category.get(category, [])
        return [self._tools[n] for n in names if n in self._tools]

    def search(self, query: str, category: Optional[ToolCategory] = None) -> list[ToolMetadata]:
        """
        搜索工具

        Args:
            query: 搜索关键词
            category: 可选，限定分类

        Returns:
            匹配的工具列表
        """
        self._ensure_initialized()
        query_lower = query.lower()

        results = []
        tools = self.list_by_category(category) if category else self.list_all()

        for tool in tools:
            if tool.deprecated:
                continue

            # 匹配名称、描述、标签
            if (query_lower in tool.name.lower() or
                query_lower in tool.display_name.lower() or
                query_lower in tool.description.lower() or
                any(query_lower in tag.lower() for tag in tool.tags)):
                results.append(tool)

        return results

    def get_by_capability(self, capability: str) -> list[ToolMetadata]:
        """按能力查找工具"""
        self._ensure_initialized()
        return [
            tool for tool in self._tools.values()
            if capability in tool.capabilities and not tool.deprecated
        ]

    def get_by_exploit_type(self, exploit_type: str) -> list[ToolMetadata]:
        """按漏洞类型查找工具"""
        self._ensure_initialized()
        return [
            tool for tool in self._tools.values()
            if exploit_type in tool.exploit_types and not tool.deprecated
        ]

    def register_hook(self, event: str, hook: Callable):
        """注册钩子"""
        self._hooks[event] = hook

    def execute_hook(self, event: str, *args, **kwargs):
        """执行钩子"""
        if event in self._hooks:
            return self._hooks[event](*args, **kwargs)


# 全局注册表实例
_registry = None


def get_registry() -> ToolRegistry:
    """获取全局工具注册表"""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
        _registry._ensure_initialized()
    return _registry


def register_tool(tool: ToolMetadata) -> bool:
    """便捷注册函数"""
    return get_registry().register(tool)


def list_tools(category: Optional[ToolCategory] = None) -> list[ToolMetadata]:
    """便捷列出函数"""
    registry = get_registry()
    if category:
        return registry.list_by_category(category)
    return registry.list_all()
