"""
红蓝对抗控制器
==============
协调 Red Team 和 Blue Team 的对抗
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from .agents import AgentRole
from .evidence import EvidenceBus, EvidenceType, get_evidence_bus
from .team import BlueTeam, RedTeam, TeamResult

logger = logging.getLogger(__name__)


class EngagementStatus(str, Enum):
    """对抗状态"""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ABORTED = "aborted"


@dataclass
class EngagementConfig:
    """对抗配置"""
    engagement_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    duration_minutes: int = 60
    red_team_enabled: bool = True
    blue_team_enabled: bool = True

    # 目标
    red_objectives: list[str] = field(default_factory=list)
    blue_objectives: list[str] = field(default_factory=list)

    # 限制
    max_cost_usd: float = 100.0
    allow_destructive: bool = False  # 是否允许破坏性操作

    # 场景
    scenario: str = "standard"  # standard, red_only, blue_only, coordinated


@dataclass
class EngagementResult:
    """对抗结果"""
    engagement_id: str
    status: EngagementStatus

    # 时间
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0

    # Red Team 结果
    red_result: TeamResult = None

    # Blue Team 结果
    blue_result: TeamResult = None

    # 证据统计
    total_evidence: int = 0
    red_evidence_count: int = 0
    blue_evidence_count: int = 0

    # 攻击链
    completed_chains: int = 0
    detected_chains: int = 0
    blocked_chains: int = 0

    # 评分
    red_final_score: float = 0.0
    blue_final_score: float = 0.0

    # MITRE 覆盖
    techniques_covered: list[str] = field(default_factory=list)
    techniques_detected: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        if self.red_result:
            data["red_result"] = asdict(self.red_result)
        if self.blue_result:
            data["blue_result"] = asdict(self.blue_result)
        return data


class RedBlueController:
    """
    红蓝对抗控制器

    协调 Red Team 和 Blue Team 的对抗演练
    """

    def __init__(self, config: Optional[EngagementConfig] = None):
        self.config = config or EngagementConfig()
        self.status = EngagementStatus.IDLE

        # 团队
        self.red_team = RedTeam()
        self.blue_team = BlueTeam()

        # 证据总线
        self.evidence_bus = get_evidence_bus()

        # 结果
        self.result = EngagementResult(
            engagement_id=self.config.engagement_id,
            status=EngagementStatus.IDLE,
        )

    def start(self) -> bool:
        """
        启动对抗演练

        Returns:
            是否成功启动
        """
        if self.status == EngagementStatus.RUNNING:
            logger.warning("Engagement already running")
            return False

        logger.info(f"Starting engagement {self.config.engagement_id} targeting {self.config.target}")

        self.status = EngagementStatus.RUNNING
        self.result.start_time = datetime.now().isoformat()
        self.result.status = EngagementStatus.RUNNING

        # 发布开始证据
        self.evidence_bus.publish(Evidence(
            team="system",
            agent_name="controller",
            type=EvidenceType.ENGAGEMENT_START,
            title=f"Engagement started: {self.config.target}",
            data={"config": asdict(self.config)},
            confidence=1.0,
        ))

        return True

    def stop(self):
        """停止对抗演练"""
        if self.status != EngagementStatus.RUNNING:
            return

        logger.info(f"Stopping engagement {self.config.engagement_id}")

        self.status = EngagementStatus.COMPLETED
        self.result.end_time = datetime.now().isoformat()
        self.result.status = EngagementStatus.COMPLETED

        # 计算持续时间
        start = datetime.fromisoformat(self.result.start_time)
        end = datetime.fromisoformat(self.result.end_time)
        self.result.duration_seconds = (end - start).total_seconds()

        # 发布结束证据
        self.evidence_bus.publish(Evidence(
            team="system",
            agent_name="controller",
            type=EvidenceType.ENGAGEMENT_END,
            title=f"Engagement completed",
            data={"duration": self.result.duration_seconds},
            confidence=1.0,
        ))

        # 计算最终得分
        self._calculate_final_scores()

    def pause(self):
        """暂停对抗"""
        if self.status == EngagementStatus.RUNNING:
            self.status = EngagementStatus.PAUSED
            logger.info(f"Engagement {self.config.engagement_id} paused")

    def resume(self):
        """恢复对抗"""
        if self.status == EngagementStatus.PAUSED:
            self.status = EngagementStatus.RUNNING
            logger.info(f"Engagement {self.config.engagement_id} resumed")

    def execute_red_operation(self, role: AgentRole, target: str, context: dict) -> dict:
        """
        执行 Red Team 操作

        Args:
            role: Agent 角色
            target: 目标
            context: 上下文

        Returns:
            操作结果
        """
        if not self.config.red_team_enabled:
            return {"error": "Red Team is disabled"}

        if self.status != EngagementStatus.RUNNING:
            return {"error": "Engagement not running"}

        result = self.red_team.execute_operation(target, role, context)
        return asdict(result)

    def execute_blue_detection(self, evidence: dict, role: AgentRole) -> dict:
        """
        执行 Blue Team 检测

        Args:
            evidence: 证据数据
            role: Agent 角色

        Returns:
            检测结果
        """
        if not self.config.blue_team_enabled:
            return {"error": "Blue Team is disabled"}

        if self.status != EngagementStatus.RUNNING:
            return {"error": "Engagement not running"}

        result = self.blue_team.detect_threat(evidence, role)
        return asdict(result)

    def get_status(self) -> dict:
        """获取当前状态"""
        return {
            "engagement_id": self.config.engagement_id,
            "status": self.status.value,
            "target": self.config.target,
            "red_team": self.red_team.get_stats(),
            "blue_team": self.blue_team.get_stats(),
            "evidence_stats": self.evidence_bus.get_stats(),
        }

    def get_results(self) -> EngagementResult:
        """获取对抗结果"""
        return self.result

    def _calculate_final_scores(self):
        """计算最终得分"""
        # Red Team 得分基于成功攻击
        self.result.red_final_score = self.red_team.result.total_score

        # Blue Team 得分基于检测率
        blue_detections = sum(1 for _ in self.evidence_bus.get_latest(EvidenceType.DETECTION))
        total_attacks = self.red_team.result.successful_operations
        detection_rate = blue_detections / total_attacks if total_attacks > 0 else 0
        self.result.blue_final_score = detection_rate * 100

        # MITRE 覆盖
        all_evidence = self.evidence_bus.get_latest()
        self.result.techniques_covered = list(set(
            e.technique_id for e in all_evidence if e.technique_id
        ))
        self.result.techniques_detected = list(set(
            e.technique_id for e in all_evidence
            if e.type == EvidenceType.DETECTION and e.technique_id
        ))

        # 证据统计
        self.result.total_evidence = len(all_evidence)
        self.result.red_evidence_count = len([e for e in all_evidence if e.team == "red"])
        self.result.blue_evidence_count = len([e for e in all_evidence if e.team == "blue"])

        # 攻击链统计
        chains = [c for c in self.evidence_bus._chains.values()]
        self.result.completed_chains = len([c for c in chains if c.completed])
        self.result.detected_chains = len([c for c in chains if c.detected_by_blue])
        self.result.blocked_chains = len([c for c in chains if c.blocked])


# 全局控制器实例
_controller = None


def get_controller() -> RedBlueController:
    """获取全局控制器"""
    global _controller
    if _controller is None:
        _controller = RedBlueController()
    return _controller
