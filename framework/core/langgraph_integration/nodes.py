"""
LangGraph 节点定义
=================
各阶段的节点实现
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from .state import PentestState, Stage, Finding, Severity

logger = logging.getLogger(__name__)


# ============================================================
# 节点基类
# ============================================================

class BaseNode:
    """节点基类"""

    name: str = "base"
    stage: Stage = Stage.RECON

    def __call__(self, state: PentestState) -> PentestState:
        """执行节点"""
        raise NotImplementedError

    def should_continue(self, state: PentestState) -> bool:
        """是否继续"""
        return True


# ============================================================
# Recon 阶段
# ============================================================

class ReconNode(BaseNode):
    """侦察节点"""

    name = "recon"
    stage = Stage.RECON

    def __init__(self, tools: list = None):
        self.tools = tools or []

    def __call__(self, state: PentestState) -> PentestState:
        """执行侦察"""
        logger.info(f"[{self.name}] Starting reconnaissance on {state.get('target')}")

        state["stage"] = Stage.RECON.value
        state.add_message(f"Starting {self.name}", agent=self.name)

        # TODO: 调用侦察工具
        # 发现的目标
        discovered = []

        # 更新目标列表
        if discovered:
            targets = state.get("targets", [])
            targets.extend(discovered)
            state["targets"] = targets

        state.add_message(f"Recon completed: {len(discovered)} targets found", agent=self.name)

        return state


# ============================================================
# Hunt 阶段
# ============================================================

class HuntNode(BaseNode):
    """漏洞挖掘节点"""

    name = "hunt"
    stage = Stage.HUNT

    def __init__(self, tools: list = None):
        self.tools = tools or []

    def __call__(self, state: PentestState) -> PentestState:
        """执行漏洞挖掘"""
        logger.info(f"[{self.name}] Starting vulnerability hunting")

        state["stage"] = Stage.HUNT.value
        state.add_message(f"Starting {self.name}", agent=self.name)

        # TODO: 调用漏洞挖掘工具
        findings = []

        for finding in findings:
            state.add_finding(finding)

        state.add_message(f"Hunt completed: {len(findings)} potential vulnerabilities found", agent=self.name)

        return state


# ============================================================
# Validate 阶段
# ============================================================

class ValidateNode(BaseNode):
    """漏洞验证节点"""

    name = "validate"
    stage = Stage.VALIDATE

    def __init__(self, verifier=None):
        self.verifier = verifier  # OracleVerifier

    def __call__(self, state: PentestState) -> PentestState:
        """验证发现"""
        logger.info(f"[{self.name}] Validating findings")

        state["stage"] = Stage.VALIDATE.value
        state.add_message(f"Starting {self.name}", agent=self.name)

        # 验证每个发现
        validated_count = 0
        for finding in state.findings:
            if not finding.validated:
                # TODO: 调用 Oracle 验证
                finding.validated = True
                validated_count += 1

        state.add_message(f"Validate completed: {validated_count} findings validated", agent=self.name)

        return state


# ============================================================
# Exploit 阶段
# ============================================================

class ExploitNode(BaseNode):
    """漏洞利用节点"""

    name = "exploit"
    stage = Stage.EXPLOIT

    def __init__(self, tools: list = None):
        self.tools = tools or []

    def __call__(self, state: PentestState) -> PentestState:
        """执行漏洞利用"""
        logger.info(f"[{self.name}] Attempting exploitation")

        state["stage"] = Stage.EXPLOIT.value
        state.add_message(f"Starting {self.name}", agent=self.name)

        # 获取可利用的发现
        exploitable_findings = [f for f in state.findings if f.validated and f.exploitable]

        exploited_count = 0
        for finding in exploitable_findings:
            # TODO: 执行利用
            exploited_count += 1

        state.add_message(f"Exploit completed: {exploited_count} findings exploited", agent=self.name)

        return state


# ============================================================
# Report 阶段
# ============================================================

class ReportNode(BaseNode):
    """报告生成节点"""

    name = "report"
    stage = Stage.REPORT

    def __call__(self, state: PentestState) -> PentestState:
        """生成报告"""
        logger.info(f"[{self.name}] Generating report")

        state["stage"] = Stage.REPORT.value
        state.add_message(f"Starting {self.name}", agent=self.name)

        # 统计
        by_severity = {
            Severity.CRITICAL: [],
            Severity.HIGH: [],
            Severity.MEDIUM: [],
            Severity.LOW: [],
            Severity.INFO: [],
        }

        for f in state.findings:
            if f.severity in by_severity:
                by_severity[f.severity].append(f)

        report = {
            "summary": {
                "total_findings": len(state.findings),
                "by_severity": {k.value: len(v) for k, v in by_severity.items()},
                "validated": sum(1 for f in state.findings if f.validated),
                "exploitable": sum(1 for f in state.findings if f.exploitable),
            },
            "findings": [f.to_dict() for f in state.findings],
        }

        state["report"] = report
        state.add_message(f"Report generated: {len(state.findings)} findings", agent=self.name)

        return state


# ============================================================
# 路由函数
# ============================================================

def route_after_recon(state: PentestState) -> str:
    """Recon 后的路由"""
    targets = state.get("targets", [])
    if not targets:
        return "report"  # 没有发现，跳到报告
    return "hunt"


def route_after_hunt(state: PentestState) -> str:
    """Hunt 后的路由"""
    findings = state.findings
    if not findings:
        return "report"

    # 有可利用的发现
    exploitable = [f for f in findings if f.exploitable]
    if exploitable:
        return "exploit"

    return "validate"


def route_after_validate(state: PentestState) -> str:
    """Validate 后的路由"""
    findings = state.findings
    validated = [f for f in findings if f.validated]

    if not validated:
        return "hunt"  # 没有验证通过的，继续挖掘

    # 有验证通过的，可以尝试利用
    exploitable = [f for f in validated if f.exploitable]
    if exploitable:
        return "exploit"

    return "report"


def route_after_exploit(state: PentestState) -> str:
    """Exploit 后的路由"""
    # 如果有新的凭证或权限，可以继续横向移动
    # 简化：直接到报告
    return "report"


def should_continue(state: PentestState) -> bool:
    """检查是否继续"""
    errors = state.get("errors", [])
    if errors and len(errors) > 3:
        logger.warning("Too many errors, stopping")
        return False

    budget = state.get("metadata", {}).get("budget_remaining", 0)
    if budget <= 0:
        logger.info("Budget exhausted, stopping")
        return False

    return True


# ============================================================
# 工厂函数
# ============================================================

def create_standard_graph() -> dict[str, Any]:
    """
    创建标准渗透测试图

    返回节点和路由定义的字典
    """
    nodes = {
        "recon": ReconNode(),
        "hunt": HuntNode(),
        "validate": ValidateNode(),
        "exploit": ExploitNode(),
        "report": ReportNode(),
    }

    edges = [
        ("recon", "hunt", route_after_recon),
        ("hunt", "validate", route_after_hunt),
        ("hunt", "report", route_after_hunt),  # 路由到 report
        ("validate", "hunt", route_after_validate),
        ("validate", "exploit", route_after_validate),
        ("validate", "report", route_after_validate),
        ("exploit", "report", route_after_exploit),
    ]

    return {
        "nodes": nodes,
        "edges": edges,
        "entry_point": "recon",
        "finish_point": "report",
        "route_functions": {
            "after_recon": route_after_recon,
            "after_hunt": route_after_hunt,
            "after_validate": route_after_validate,
            "after_exploit": route_after_exploit,
        },
        "should_continue": should_continue,
    }
