"""
渗透测试状态定义
================
定义 LangGraph 的状态结构
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from dataclasses import asdict


class Stage(str, Enum):
    """渗透测试阶段"""
    RECON = "recon"
    HUNT = "hunt"
    VALIDATE = "validate"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    REPORT = "report"


class Severity(str, Enum):
    """严重等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


@dataclass
class Target:
    """目标"""
    url: str = ""
    host: str = ""
    port: int = 0
    service: str = ""
    os_type: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    """发现"""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: Severity = Severity.UNKNOWN
    cvss: float = 0.0

    # 分类
    category: str = ""              # sql_injection, xss, rce, etc.
    vuln_type: str = ""

    # 位置
    target: str = ""
    path: str = ""
    param: str = ""

    # 证据
    evidence: dict = field(default_factory=dict)
    poc: str = ""                     # PoC
    payload: str = ""

    # 状态
    validated: bool = False
    exploitable: bool = False
    reachable: bool = False

    # ATT&CK
    technique_id: str = ""
    tactic: str = ""

    # 元数据
    confidence: float = 0.0
    agent: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


class PentestState(dict):
    """
    渗透测试状态

    这是传递给 LangGraph 节点的字典状态
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 设置默认值
        self.setdefault("session_id", str(uuid.uuid4()))
        self.setdefault("target", "")
        self.setdefault("targets", [])
        self.setdefault("stage", Stage.RECON.value)
        self.setdefault("findings", [])
        self.setdefault("completed_stages", [])
        self.setdefault("errors", [])
        self.setdefault("messages", [])
        self.setdefault("metadata", {})

    # 便捷属性
    @property
    def session_id(self) -> str:
        return self.get("session_id", "")

    @session_id.setter
    def session_id(self, value: str):
        self["session_id"] = value

    @property
    def stage(self) -> Stage:
        return Stage(self.get("stage", Stage.RECON.value))

    @stage.setter
    def stage(self, value: Stage):
        self["stage"] = value.value

    @property
    def findings(self) -> list[Finding]:
        findings_data = self.get("findings", [])
        if not findings_data:
            return []
        if isinstance(findings_data[0], dict):
            return [Finding(**f) for f in findings_data]
        return findings_data

    @findings.setter
    def findings(self, value: list[Finding]):
        if value and isinstance(value[0], Finding):
            self["findings"] = [f.to_dict() if isinstance(f, Finding) else f for f in value]
        else:
            self["findings"] = value

    def add_finding(self, finding: Finding):
        """添加发现"""
        findings = self.get("findings", [])
        if isinstance(findings[0], dict):
            findings.append(finding.to_dict())
        else:
            findings.append(finding)
        self["findings"] = findings

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """按严重等级获取发现"""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_category(self, category: str) -> list[Finding]:
        """按分类获取发现"""
        return [f for f in self.findings if f.category == category]

    def add_error(self, error: str):
        """添加错误"""
        errors = self.get("errors", [])
        errors.append({"error": error, "timestamp": datetime.now().isoformat()})
        self["errors"] = errors

    def add_message(self, message: str, agent: str = "system"):
        """添加消息"""
        messages = self.get("messages", [])
        messages.append({"agent": agent, "message": message, "timestamp": datetime.now().isoformat()})
        self["messages"] = messages

    def to_dict(self) -> dict:
        """转换为字典"""
        return dict(self)


# 状态转换规则
STAGE_TRANSITIONS = {
    Stage.RECON: [Stage.HUNT],
    Stage.HUNT: [Stage.VALIDATE, Stage.EXPLOIT],
    Stage.VALIDATE: [Stage.HUNT, Stage.EXPLOIT, Stage.REPORT],
    Stage.EXPLOIT: [Stage.POST_EXPLOIT, Stage.REPORT],
    Stage.POST_EXPLOIT: [Stage.EXPLOIT, Stage.REPORT],
    Stage.REPORT: [],  # 终态
}


def can_transition(from_stage: Stage, to_stage: Stage) -> bool:
    """检查是否可以转换"""
    return to_stage in STAGE_TRANSITIONS.get(from_stage, [])


def get_next_stages(current: Stage) -> list[Stage]:
    """获取下一阶段"""
    return STAGE_TRANSITIONS.get(current, [])
