"""
结构化经验层 Schema
===================
参考 LingXi 的 22 字段设计，定义持久化的安全经验结构。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class Category(Enum):
    """挑战分类"""
    WEB = "web"
    PWN = "pwn"
    CRYPTO = "crypto"
    REVERSE = "reverse"
    MISC = "misc"
    FORENSICS = "forensics"
    OSINT = "osint"
    AD = "ad"  # Active Directory
    NETWORK = "network"
    CVE = "cve"


class Source(Enum):
    """知识来源"""
    MAIN_BATTLE = "main_battle"      # 主战场经验
    FORUM = "forum"                  # 论坛经验
    EXTERNAL_WP = "external_wp"      # 外部WP
    MANUAL = "manual"                # 手动录入


@dataclass
class SolutionStep:
    """解决步骤"""
    step_order: int
    action: str          # 执行的操作
    tool_used: str       # 使用的工具
    result: str          # 结果
    insight: str         # 关键洞察


@dataclass
class FailureReason:
    """失败原因"""
    attempt_type: str    # 尝试类型
    reason: str          # 失败原因
    lesson_learned: str  # 教训


@dataclass
class KnowledgeRecord:
    """
    结构化知识记录 - 持久化的安全经验

    22字段设计，参考 LingXi 的知识库 Schema
    """
    # === 基础标识 ===
    record_id: str
    category: Category
    subcategory: str

    # === 内容描述 ===
    title: str
    description: str
    challenge_id: str    # 原始挑战/目标的标识

    # === 成功链路 ===
    solution_steps: list[SolutionStep]  # 解决步骤
    tools_used: list[str]               # 使用的工具列表
    key_insights: str                   # 关键洞察

    # === 失败记录 ===
    failure_reasons: list[FailureReason] = field(default_factory=list)
    failed_attempts: int = 0

    # === 关联信息 ===
    related_cves: list[str] = field(default_factory=list)    # 关联CVE
    related_techniques: list[str] = field(default_factory=list)  # ATT&CK技术
    related_weaknesses: list[str] = field(default_factory=list)  # CWE

    # === 评估信息 ===
    confidence: float = 0.0   # 置信度 0.0-1.0
    difficulty: str = ""      # 难度等级
    cvss_score: Optional[float] = None  # CVSS评分

    # === 来源追溯 ===
    source: Source = Source.MAIN_BATTLE
    source_url: str = ""
    contributor: str = ""

    # === 时间戳 ===
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    times_accessed: int = 0  # 访问次数，用于排序

    # === 标签系统 ===
    tags: list[str] = field(default_factory=list)
    target_tech: list[str] = field(default_factory=list)  # 目标技术栈

    # === 质量指标 ===
    validated: bool = False
    validation_count: int = 0
    usefulness_score: float = 0.0  # 实用性评分

    def mark_accessed(self):
        """标记为已访问"""
        self.times_accessed += 1
        self.updated_at = datetime.now()

    def add_solution_step(self, action: str, tool: str, result: str, insight: str = ""):
        """添加解决步骤"""
        step = SolutionStep(
            step_order=len(self.solution_steps) + 1,
            action=action,
            tool_used=tool,
            result=result,
            insight=insight,
        )
        self.solution_steps.append(step)

    def add_failure(self, attempt_type: str, reason: str, lesson: str = ""):
        """添加失败记录"""
        self.failed_attempts += 1
        self.failure_reasons.append(FailureReason(
            attempt_type=attempt_type,
            reason=reason,
            lesson_learned=lesson or reason,
        ))

    def to_dict(self) -> dict:
        """序列化为字典"""
        return {
            "record_id": self.record_id,
            "category": self.category.value,
            "subcategory": self.subcategory,
            "title": self.title,
            "description": self.description,
            "challenge_id": self.challenge_id,
            "solution_steps": [
                {
                    "step_order": s.step_order,
                    "action": s.action,
                    "tool_used": s.tool_used,
                    "result": s.result,
                    "insight": s.insight,
                }
                for s in self.solution_steps
            ],
            "tools_used": self.tools_used,
            "key_insights": self.key_insights,
            "failure_reasons": [
                {
                    "attempt_type": f.attempt_type,
                    "reason": f.reason,
                    "lesson_learned": f.lesson_learned,
                }
                for f in self.failure_reasons
            ],
            "failed_attempts": self.failed_attempts,
            "related_cves": self.related_cves,
            "related_techniques": self.related_techniques,
            "related_weaknesses": self.related_weaknesses,
            "confidence": self.confidence,
            "difficulty": self.difficulty,
            "cvss_score": self.cvss_score,
            "source": self.source.value,
            "source_url": self.source_url,
            "contributor": self.contributor,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "times_accessed": self.times_accessed,
            "tags": self.tags,
            "target_tech": self.target_tech,
            "validated": self.validated,
            "validation_count": self.validation_count,
            "usefulness_score": self.usefulness_score,
        }

    @classmethod
    def from_dict(cls, data: dict) -> KnowledgeRecord:
        """从字典反序列化"""
        data["category"] = Category(data["category"])
        data["source"] = Source(data.get("source", "main_battle"))
        data["created_at"] = datetime.fromisoformat(data["created_at"])
        data["updated_at"] = datetime.fromisoformat(data["updated_at"])

        data["solution_steps"] = [
            SolutionStep(**s) for s in data.get("solution_steps", [])
        ]
        data["failure_reasons"] = [
            FailureReason(**f) for f in data.get("failure_reasons", [])
        ]

        return cls(**data)
