"""
Agent 调度器
============
参考 Pentest-Swarm-AI 的 Scheduler 设计

特性:
- Agent 注册式，无需修改调度器即可新增 Agent
- 触发谓词 (Trigger Predicate) 驱动
- 预算强制执行
- 速率限制防止反馈循环
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

from .board import Board
from .types import (
    AgentBudget,
    Budget,
    CampaignConfig,
    Finding,
    FindingType,
    Predicate,
)

logger = logging.getLogger(__name__)


@dataclass
class SchedulerEvent:
    """调度器事件"""
    type: str  # agent_started, agent_finished, agent_error, budget_exceeded, campaign_complete
    timestamp: datetime = field(default_factory=datetime.now)
    campaign_id: uuid.UUID = field(default_factory=uuid.uuid4)
    agent_name: str = ""
    finding_id: uuid.UUID = field(default_factory=uuid.uuid4)
    detail: str = ""


class Agent(ABC):
    """
    Agent 抽象接口

    每个 Agent 定义:
    - 触发谓词: 定义感兴趣的任务类型
    - 处理函数: 处理接收到的 Finding
    """

    @abstractmethod
    def name(self) -> str:
        """Agent 名称"""
        pass

    @abstractmethod
    def trigger(self) -> Predicate:
        """返回此 Agent 的触发谓词"""
        pass

    @abstractmethod
    def max_concurrency(self) -> int:
        """最大并发处理数"""
        pass

    @abstractmethod
    def handle(self, finding: Finding, board: Board) -> Optional[str]:
        """
        处理发现

        Args:
            finding: 要处理的发现
            board: 黑板，用于写入新发现

        Returns:
            None 成功, str 错误信息
        """
        pass


class RateLimiter:
    """令牌桶限速器"""

    def __init__(self, per_second: float, burst: float = 0):
        self.per_second = per_second
        self.burst = burst if burst > 0 else per_second
        self.tokens = self.burst
        self.last_update = time.time()
        self._lock = threading.Lock()

    def take(self, timeout: float = 5.0) -> bool:
        """获取令牌，超时返回 False"""
        start = time.time()
        while True:
            with self._lock:
                now = time.time()
                # 补充令牌
                elapsed = now - self.last_update
                self.tokens = min(self.burst, self.tokens + elapsed * self.per_second)
                self.last_update = now

                if self.tokens >= 1:
                    self.tokens -= 1
                    return True

            if time.time() - start >= timeout:
                return False

            time.sleep(0.01)


class Scheduler:
    """
    调度器 - 薄协调层

    职责:
    - Agent 注册管理
    - 预算执行
    - 速率限制
    - 优雅关闭
    """

    def __init__(
        self,
        board: Board,
        campaign_id: uuid.UUID,
        config: Optional[CampaignConfig] = None,
    ):
        self.board = board
        self.campaign_id = campaign_id
        self.config = config or CampaignConfig(campaign_id=campaign_id, target="")

        self._agents: list[Agent] = []
        self._rate_limits: dict[str, RateLimiter] = {}
        self._on_event: Optional[Callable[[SchedulerEvent], None]] = None
        self._running = False
        self._lock = threading.Lock()

    def set_event_handler(self, handler: Callable[[SchedulerEvent], None]):
        """设置事件处理器"""
        self._on_event = handler

    def register(self, agent: Agent):
        """注册 Agent"""
        with self._lock:
            self._agents.append(agent)
            logger.info(f"Registered agent: {agent.name()}")

    def set_rate_limit(self, agent_name: str, per_second: float, burst: float = 0):
        """设置 Agent 速率限制"""
        with self._lock:
            self._rate_limits[agent_name] = RateLimiter(per_second, burst)

    def run(self, timeout: Optional[float] = None):
        """
        运行调度器

        Args:
            timeout: 超时时间 (秒), None 表示无限
        """
        self._running = True

        # 设置预算限制
        self.board.set_budget_limits(
            self.campaign_id,
            self.config.max_agent_hours,
            self.config.max_tokens,
        )

        # 为每个 Agent 设置预算
        for agent in self._agents:
            self.board.set_agent_budget(
                self.campaign_id,
                agent.name(),
                self.config.per_agent_max_tokens,
                self.config.per_agent_warn_tokens,
            )

        threads = []

        try:
            # 启动 Agent 协程
            for agent in self._agents:
                t = threading.Thread(target=self._run_agent, args=(agent,), daemon=True)
                t.start()
                threads.append(t)

            # 预算检查协程
            budget_checker = threading.Thread(target=self._budget_checker, daemon=True)
            budget_checker.start()
            threads.append(budget_checker)

            # 等待完成或超时
            if timeout:
                time.sleep(timeout)
            else:
                for t in threads:
                    t.join()

        except KeyboardInterrupt:
            logger.info("Scheduler interrupted")
        finally:
            self._running = False

    def _run_agent(self, agent: Agent):
        """Agent 处理循环"""
        # 恢复游标
        cursor = self.board.cursor(self.campaign_id, agent.name())
        predicate = agent.trigger()
        if cursor:
            predicate.since_id = cursor

        # 订阅
        sub_id, current = self.board.subscribe(predicate)

        logger.info(f"Agent {agent.name()} subscribed to {len(current)} existing findings")

        parallel = agent.max_concurrency()
        if parallel <= 0:
            parallel = 1

        sem = threading.Semaphore(parallel)
        inflight = threading.Semaphore(0)

        while self._running:
            # 获取下一个发现
            try:
                # 轮询订阅
                new_findings = self.board.poll_subscription(sub_id, timeout_sec=1.0)

                for finding in new_findings:
                    # 检查 Agent 预算
                    agent_budget = self.board.agent_budget(self.campaign_id, agent.name())
                    if agent_budget.exceeded():
                        self._emit(SchedulerEvent(
                            type="agent_budget_exceeded",
                            agent_name=agent.name(),
                            finding_id=finding.id,
                            detail=f"{agent_budget.tokens_used}/{agent_budget.max_tokens} tokens",
                        ))
                        continue

                    # 速率限制
                    if agent.name() in self._rate_limits:
                        if not self._rate_limits[agent.name()].take(timeout=5.0):
                            continue

                    # 并发控制
                    sem.acquire()
                    inflight.release()

                    threading.Thread(
                        target=self._handle_finding,
                        args=(agent, finding, sem, inflight),
                        daemon=True,
                    ).start()

            except Exception as e:
                logger.error(f"Agent {agent.name()} error: {e}")

        # 等待处理完成
        for _ in range(parallel):
            inflight.acquire()

        self.board.unsubscribe(sub_id)

    def _handle_finding(self, agent: Agent, finding: Finding, sem, inflight):
        """处理单个发现"""
        try:
            self._emit(SchedulerEvent(
                type="agent_started",
                agent_name=agent.name(),
                finding_id=finding.id,
            ))

            start = time.time()
            error = agent.handle(finding, self.board)
            duration = time.time() - start

            # 更新预算
            self.board.charge_agent(self.campaign_id, agent.name(), int(duration * 1000))
            self.board.update_budget(self.campaign_id, duration / 3600, int(duration * 1000))

            # 提交游标
            self.board.commit_cursor(self.campaign_id, agent.name(), finding.id)

            if error:
                self._emit(SchedulerEvent(
                    type="agent_error",
                    agent_name=agent.name(),
                    finding_id=finding.id,
                    detail=error,
                ))
            else:
                self._emit(SchedulerEvent(
                    type="agent_finished",
                    agent_name=agent.name(),
                    finding_id=finding.id,
                    detail=f"{duration:.2f}s",
                ))

        except Exception as e:
            self._emit(SchedulerEvent(
                type="agent_error",
                agent_name=agent.name(),
                finding_id=finding.id,
                detail=str(e),
            ))
        finally:
            sem.release()

    def _budget_checker(self):
        """预算检查循环"""
        while self._running:
            time.sleep(self.config.budget_check_interval_sec)

            budget = self.board.budget(self.campaign_id)
            if budget.exceeded():
                logger.warning(f"Campaign budget exceeded: {budget.agent_hours_used:.2f}h / {budget.max_agent_hours}h")

                self._emit(SchedulerEvent(
                    type="budget_exceeded",
                    detail=f"hours={budget.agent_hours_used:.2f}/{budget.max_agent_hours}, tokens={budget.tokens_used}/{budget.max_tokens}",
                ))

                # 写入 CAMPAIGN_COMPLETE，让报告 Agent 完成收尾
                self.board.write(Finding(
                    campaign_id=self.campaign_id,
                    agent_name="scheduler",
                    type=FindingType.CAMPAIGN_BUDGET_EXCEEDED,
                    target="",
                    pheromone_base=1.0,
                    half_life_sec=300,
                ))

    def _emit(self, event: SchedulerEvent):
        """发出事件"""
        if self._on_event:
            self._on_event(event)
