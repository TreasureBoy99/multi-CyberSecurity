"""
信息素黑板类型定义
==================
参考 Pentest-Swarm-AI 的 Stigmergic Blackboard 设计
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class FindingType(str, Enum):
    """
    发现类型枚举 - Agent 通过订阅特定类型获取任务
    """
    # === Recon 阶段 ===
    TARGET_REGISTERED = "TARGET_REGISTERED"    # 目标注册
    SUBDOMAIN = "SUBDOMAIN"                    # 子域名发现
    HTTP_ENDPOINT = "HTTP_ENDPOINT"            # HTTP 端点
    PORT_OPEN = "PORT_OPEN"                    # 开放端口
    SERVICE = "SERVICE"                        # 服务识别
    TECHNOLOGY = "TECHNOLOGY"                  # 技术指纹

    # === Classification 阶段 ===
    CVE_MATCH = "CVE_MATCH"                    # CVE 匹配
    CVSS_SCORE = "CVSS_SCORE"                  # CVSS 评分
    MISCONFIG = "MISCONFIGURATION"             # 配置错误
    SECRET_LEAK = "SECRET_LEAK"                # 密钥泄露
    POTENTIAL_SQLI = "POTENTIAL_SQLI"          # 潜在 SQL 注入

    # === Exploit 阶段 ===
    EXPLOIT_CHAIN = "EXPLOIT_CHAIN"            # 攻击链
    EXPLOIT_RESULT = "EXPLOIT_RESULT"          # 利用结果
    SESSION = "SESSION"                        # 会话

    # === Meta ===
    CAMPAIGN_COMPLETE = "CAMPAIGN_COMPLETE"    # 任务完成
    CAMPAIGN_BUDGET_EXCEEDED = "CAMPAIGN_BUDGET_EXCEEDED"  # 预算超支
    AGENT_ERROR = "AGENT_ERROR"                # Agent 错误

    # === 产物 ===
    NUCLEI_TEMPLATE_DRAFT = "NUCLEI_TEMPLATE_DRAFT"  # Nuclei 模板草稿


@dataclass
class Finding:
    """
    发现 - 黑板上的信息素载体
    """
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    campaign_id: uuid.UUID = field(default_factory=uuid.uuid4)
    agent_name: str = ""                        # 发现来源 Agent
    type: FindingType = FindingType.TARGET_REGISTERED
    target: str = ""                            # 目标资产
    data: dict[str, Any] = field(default_factory=dict)  # 载荷

    # 信息素参数
    pheromone_base: float = 1.0     # 初始信息素 (0.0-1.0)
    half_life_sec: int = 3600       # 衰减半衰期 (默认1小时)

    # 血缘追踪
    superseded_by: Optional[uuid.UUID] = None  # 被哪个发现替代
    parent_id: Optional[uuid.UUID] = None      # 父发现ID

    created_at: datetime = field(default_factory=datetime.now)

    @property
    def age_seconds(self) -> float:
        """计算发现存在的时间(秒)"""
        return (datetime.now() - self.created_at).total_seconds()

    @property
    def pheromone(self) -> float:
        """
        计算当前信息素强度 (衰减公式)
        P(t) = P0 * exp(-decay_rate * t)
        其中 decay_rate = ln(2) / half_life
        """
        if self.pheromone_base <= 0:
            return 0.0

        decay_rate = math.log(2) / self.half_life_sec if self.half_life_sec > 0 else 0
        current = self.pheromone_base * math.exp(-decay_rate * self.age_seconds)
        return max(0.0, min(1.0, current))  # 夹紧到 [0, 1]

    def to_dict(self) -> dict:
        """序列化为字典"""
        return {
            "id": str(self.id),
            "campaign_id": str(self.campaign_id),
            "agent_name": self.agent_name,
            "type": self.type.value,
            "target": self.target,
            "data": self.data,
            "pheromone_base": self.pheromone_base,
            "half_life_sec": self.half_life_sec,
            "pheromone": self.pheromone,  # 当前衰减后的值
            "superseded_by": str(self.superseded_by) if self.superseded_by else None,
            "parent_id": str(self.parent_id) if self.parent_id else None,
            "created_at": self.created_at.isoformat(),
            "age_seconds": self.age_seconds,
        }


@dataclass
class Predicate:
    """
    订阅谓词 - 定义 Agent 感兴趣的任务条件
    """
    # 类型过滤 (OR 语义)
    types: list[FindingType] = field(default_factory=list)

    # 目标前缀过滤
    target_prefix: str = ""

    # 信息素阈值 (只关心高于此值的发现)
    min_pheromone: float = 0.0

    # 游标 (用于 exactly-once 语义)
    since_id: Optional[uuid.UUID] = None

    # 结果数量限制
    limit: int = 0  # 0 = 无限制

    def matches(self, finding: Finding) -> bool:
        """检查发现是否匹配此谓词"""
        # 类型检查
        if self.types and finding.type not in self.types:
            return False

        # 目标前缀检查
        if self.target_prefix and not finding.target.startswith(self.target_prefix):
            return False

        # 信息素阈值检查
        if finding.pheromone < self.min_pheromone:
            return False

        return True


@dataclass
class Budget:
    """
    Campaign 级别预算
    """
    campaign_id: uuid.UUID
    max_agent_hours: float = 0.0
    max_tokens: int = 0
    agent_hours_used: float = 0.0
    tokens_used: int = 0

    def exceeded(self) -> bool:
        """是否超出预算"""
        return (self.max_agent_hours > 0 and self.agent_hours_used >= self.max_agent_hours) or \
               (self.max_tokens > 0 and self.tokens_used >= self.max_tokens)

    def remaining(self) -> tuple[float, int]:
        """剩余资源 (hours, tokens)"""
        hours = max(0, self.max_agent_hours - self.agent_hours_used) if self.max_agent_hours > 0 else float('inf')
        tokens = max(0, self.max_tokens - self.tokens_used) if self.max_tokens > 0 else 2**63 - 1
        return hours, tokens


@dataclass
class AgentBudget:
    """
    Per-Agent 预算 - 防止单一 Agent 耗尽全部资源
    """
    campaign_id: uuid.UUID
    agent_name: str
    max_tokens: int = 0
    warn_at_tokens: int = 0  # 软阈值
    tokens_used: int = 0
    warned: bool = False

    def exceeded(self) -> bool:
        """是否超出硬限制"""
        return self.max_tokens > 0 and self.tokens_used >= self.max_tokens

    def should_warn(self) -> bool:
        """是否应该发出警告 (软阈值)"""
        return not self.warned and self.warn_at_tokens > 0 and self.tokens_used >= self.warn_at_tokens


@dataclass
class CampaignConfig:
    """
    Campaign 配置
    """
    campaign_id: uuid.UUID
    target: str
    mission_type: str = "web"

    # 预算
    max_agent_hours: float = 8.0
    max_tokens: int = 100000

    # Agent 限制
    per_agent_max_tokens: int = 20000
    per_agent_warn_tokens: int = 15000

    # 调度
    budget_check_interval_sec: int = 5
    agent_max_concurrency: int = 3
