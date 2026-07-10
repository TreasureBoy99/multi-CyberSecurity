"""
Blackboard 接口定义
===================
参考 Pentest-Swarm-AI 的 Board 接口设计
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .types import Finding, Predicate, Budget, AgentBudget


class Board(ABC):
    """
    黑板接口 - 所有黑板实现必须满足此接口

    Agent 只需依赖此接口，底层的 PostgreSQL/内存 fake/未来分布式存储可以自由替换。
    """

    @abstractmethod
    def write(self, finding: Finding) -> uuid.UUID:
        """
        写入发现到黑板

        Returns:
            分配的 Finding ID
        """
        pass

    @abstractmethod
    def query(self, predicate: Predicate) -> list[Finding]:
        """
        查询匹配谓词的发现 (按时间倒序)

        Returns:
            匹配发现的列表
        """
        pass

    @abstractmethod
    def subscribe(self, predicate: Predicate) -> tuple[uuid.UUID, list[Finding]]:
        """
        订阅发现 - 返回当前匹配的发现 + 订阅ID

        用于 Agent 的增量消费:
        1. 首先获取当前匹配的历史发现
        2. 然后通过 poll_subscription 等待新发现

        Returns:
            (subscription_id, current_findings)
        """
        pass

    @abstractmethod
    def poll_subscription(self, subscription_id: uuid.UUID, timeout_sec: float = 5.0) -> list[Finding]:
        """
        轮询订阅获取新发现

        Args:
            subscription_id: subscribe() 返回的订阅ID
            timeout_sec: 超时时间

        Returns:
            新发现的列表 (可能为空)
        """
        pass

    @abstractmethod
    def unsubscribe(self, subscription_id: uuid.UUID):
        """取消订阅"""
        pass

    @abstractmethod
    def cursor(self, campaign_id: uuid.UUID, agent_name: str) -> uuid.UUID | None:
        """
        获取 Agent 的最后处理游标

        Returns:
            最后处理的 Finding ID, 如果没有则返回 None
        """
        pass

    @abstractmethod
    def commit_cursor(self, campaign_id: uuid.UUID, agent_name: str, finding_id: uuid.UUID):
        """
        提交 Agent 的处理游标

        用于 exactly-once 语义:
        Agent 处理完一个 Finding 后调用此方法,
        重启后可以通过 cursor() 恢复
        """
        pass

    @abstractmethod
    def pheromone(self, finding_id: uuid.UUID) -> float:
        """
        获取发现的当前信息素强度

        Returns:
            当前信息素值 (0.0-1.0)
        """
        pass

    @abstractmethod
    def supersede(self, old_id: uuid.UUID, new_id: uuid.UUID):
        """
        标记旧发现被新发现替代

        用于分类器/利用 Agent 用更精确的发现替换旧假设
        """
        pass

    # === 预算操作 ===

    @abstractmethod
    def budget(self, campaign_id: uuid.UUID) -> Budget:
        """获取 Campaign 预算"""
        pass

    @abstractmethod
    def update_budget(self, campaign_id: uuid.UUID, delta_hours: float, delta_tokens: int):
        """更新 Campaign 预算使用"""
        pass

    @abstractmethod
    def set_budget_limits(
        self,
        campaign_id: uuid.UUID,
        max_hours: float,
        max_tokens: int,
    ):
        """设置 Campaign 预算限制"""
        pass

    @abstractmethod
    def agent_budget(self, campaign_id: uuid.UUID, agent_name: str) -> AgentBudget:
        """获取 Per-Agent 预算"""
        pass

    @abstractmethod
    def charge_agent(self, campaign_id: uuid.UUID, agent_name: str, tokens: int):
        """为 Agent 扣费"""
        pass

    @abstractmethod
    def set_agent_budget(
        self,
        campaign_id: uuid.UUID,
        agent_name: str,
        max_tokens: int,
        warn_at_tokens: int = 0,
    ):
        """设置 Per-Agent 预算"""
        pass
