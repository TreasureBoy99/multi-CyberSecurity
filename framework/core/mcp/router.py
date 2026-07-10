"""
MCP 工具路由器
==============
根据上下文自动路由工具调用

功能:
- 根据漏洞类型选择合适工具
- 根据上下文 (目标环境、认证状态) 过滤
- 负载均衡 (多 MCP server)
- 重试和故障转移
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from .registry import ToolCategory, ToolMetadata, get_registry

logger = logging.getLogger(__name__)


class RouteStrategy(str, Enum):
    """路由策略"""
    PREFERRED = "preferred"            # 优先使用特定工具
    ROUND_ROBIN = "round_robin"       # 轮询
    LEAST_USED = "least_used"         # 最少使用
    FASTEST = "fastest"               # 最快响应
    CHEAPEST = "cheapest"             # 最低成本


@dataclass
class RouteContext:
    """
    路由上下文

    描述当前任务的上下文信息，用于选择合适的工具
    """
    # 目标信息
    target: str = ""
    target_type: str = "web"          # web, api, network, host
    target_os: str = ""               # linux, windows, mac

    # 漏洞信息
    vulnerability_type: str = ""      # sqli, xss, rce, etc.
    cvss_score: float = 0.0
    pre_auth: bool = True             # 是否预认证

    # 环境信息
    has_auth: bool = False
    credentials: dict = field(default_factory=dict)

    # 约束
    max_cost_usd: float = 100.0
    max_time_sec: int = 300
    requires_api: bool = False        # 是否需要 API

    # 偏好
    preferred_tools: list[str] = field(default_factory=list)  # 优先使用的工具
    excluded_tools: list[str] = field(default_factory=list)   # 排除的工具
    strategy: RouteStrategy = RouteStrategy.PREFERRED

    # 会话信息
    session_id: str = ""
    agent_name: str = ""


class ToolRouter:
    """
    工具路由器

    根据上下文自动选择最合适的工具
    """

    def __init__(self):
        self.registry = get_registry()
        self._route_stats: dict[str, list[float]] = {}  # tool_name -> response_times

    def route(self, context: RouteContext) -> list[ToolMetadata]:
        """
        根据上下文路由工具

        Args:
            context: 路由上下文

        Returns:
            推荐的工具列表 (按优先级排序)
        """
        candidates = self._filter_candidates(context)

        if not candidates:
            logger.warning(f"No tools found for context: {context.vulnerability_type}")
            return []

        # 排序
        ranked = self._rank_tools(candidates, context)

        return ranked

    def _filter_candidates(self, context: RouteContext) -> list[ToolMetadata]:
        """过滤候选工具"""
        all_tools = self.registry.list_all()

        candidates = []
        for tool in all_tools:
            # 跳过禁用或废弃的工具
            if not tool.enabled or tool.deprecated:
                continue

            # 跳过排除的工具
            if tool.name in context.excluded_tools:
                continue

            # 成本过滤
            if tool.estimated_cost_usd > context.max_cost_usd:
                continue

            # 超时过滤
            if tool.timeout_sec > context.max_time_sec:
                continue

            # 认证过滤
            if tool.requires_auth and not context.has_auth:
                if not context.credentials:
                    continue

            # 漏洞类型匹配
            if context.vulnerability_type:
                if tool.exploit_types:
                    if context.vulnerability_type not in tool.exploit_types:
                        continue
                else:
                    # 如果没有指定漏洞类型，检查 capabilities
                    pass

            candidates.append(tool)

        return candidates

    def _rank_tools(self, tools: list[ToolMetadata], context: RouteContext) -> list[ToolMetadata]:
        """对工具进行排序"""
        if not tools:
            return []

        def score_tool(tool: ToolMetadata) -> tuple:
            """
            计算工具评分

            返回: (总分, 优先级因子)
            """
            score = 0.0

            # 1. 策略因子 (最高优先级)
            if context.strategy == RouteStrategy.PREFERRED:
                if tool.name in context.preferred_tools:
                    score += 100
                # 按优先级顺序给予分数
                pref_idx = context.preferred_tools.index(tool.name) if tool.name in context.preferred_tools else 999
                score -= pref_idx * 10

            elif context.strategy == RouteStrategy.LEAST_USED:
                score -= tool.use_count

            elif context.strategy == RouteStrategy.CHEAPEST:
                score -= tool.estimated_cost_usd * 10

            elif context.strategy == RouteStrategy.FASTEST:
                # 使用历史响应时间
                if tool.name in self._route_stats:
                    avg_time = sum(self._route_stats[tool.name]) / len(self._route_stats[tool.name])
                    score -= avg_time

            # 2. 漏洞类型匹配
            if context.vulnerability_type and tool.exploit_types:
                if context.vulnerability_type in tool.exploit_types:
                    score += 50

            # 3. 成功率
            score += tool.success_rate * 20

            # 4. 目标 OS 适配
            if context.target_os:
                if context.target_os.lower() in tool.description.lower():
                    score += 10

            # 5. 分类优先级
            category_priorities = {
                ToolCategory.ORACLE: 30,    # 验证工具优先
                ToolCategory.VALIDATE: 25,
                ToolCategory.EXPLOIT: 20,
                ToolCategory.WEB_SCAN: 15,
                ToolCategory.RECON: 10,
            }
            score += category_priorities.get(tool.category, 0)

            # 6. 能力匹配
            for cap in tool.capabilities:
                if context.vulnerability_type and context.vulnerability_type in cap:
                    score += 15

            return (score, tool.name)

        # 排序 (降序)
        tools.sort(key=score_tool, reverse=True)

        return tools

    def record_response_time(self, tool_name: str, time_sec: float):
        """记录响应时间"""
        if tool_name not in self._route_stats:
            self._route_stats[tool_name] = []
        self._route_stats[tool_name].append(time_sec)
        # 只保留最近 10 次
        if len(self._route_stats[tool_name]) > 10:
            self._route_stats[tool_name] = self._route_stats[tool_name][-10:]

    def get_best_tool(self, context: RouteContext) -> Optional[ToolMetadata]:
        """
        获取最佳工具

        Args:
            context: 路由上下文

        Returns:
            最佳工具或 None
        """
        ranked = self.route(context)
        return ranked[0] if ranked else None

    def suggest_tools_for_vuln(self, vuln_type: str) -> dict[str, list[ToolMetadata]]:
        """
        为漏洞类型推荐工具组合

        Args:
            vuln_type: 漏洞类型

        Returns:
            {"recon": [...], "exploit": [...], "validate": [...]}
        """
        suggestions = {
            "recon": [],
            "scan": [],
            "exploit": [],
            "validate": [],
            "post": [],
        }

        # 扫描工具
        scan_tools = self.registry.get_by_capability(f"{vuln_type}_scan")
        suggestions["scan"].extend(scan_tools)

        # 如果有专门的漏洞类型工具
        vuln_tools = self.registry.get_by_exploit_type(vuln_type)
        for tool in vuln_tools:
            if tool.category == ToolCategory.EXPLOIT:
                suggestions["exploit"].append(tool)
            elif tool.category == ToolCategory.WEB_SCAN:
                suggestions["scan"].append(tool)
            elif tool.category == ToolCategory.VALIDATE:
                suggestions["validate"].append(tool)

        # 通用扫描
        if not suggestions["scan"]:
            suggestions["scan"].extend(self.registry.list_by_category(ToolCategory.NUCLEI))
            suggestions["scan"].extend(self.registry.list_by_category(ToolCategory.WEB_SCAN))

        return {k: v for k, v in suggestions.items() if v}


# 全局路由器实例
_router = None


def get_router() -> ToolRouter:
    """获取全局路由器"""
    global _router
    if _router is None:
        _router = ToolRouter()
    return _router


def route_tool(context: RouteContext) -> list[ToolMetadata]:
    """便捷路由函数"""
    return get_router().route(context)
