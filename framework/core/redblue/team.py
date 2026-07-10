"""
红蓝团队管理
============
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Optional

from .agents import (
    AgentRole,
    BlueAgent,
    RedAgent,
    AttackResult,
    DetectionResult,
    create_red_team,
    create_blue_team,
)
from .evidence import Evidence, EvidenceBus, EvidenceType, get_evidence_bus

logger = logging.getLogger(__name__)


@dataclass
class TeamResult:
    """团队结果"""
    team: str                    # "red" or "blue"
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0
    total_score: float = 0.0
    agent_stats: dict = field(default_factory=dict)


class Team:
    """团队基类"""

    def __init__(self, name: str, team_type: str):
        self.name = name
        self.team_type = team_type
        self.agents = []
        self.result = TeamResult(team=team_type)

    def get_agent(self, role: AgentRole) -> Optional[RedAgent | BlueAgent]:
        """获取特定角色的 Agent"""
        for agent in self.agents:
            if agent.role == role:
                return agent
        return None

    def get_stats(self) -> dict:
        """获取团队统计"""
        return {
            "name": self.name,
            "type": self.team_type,
            "agent_count": len(self.agents),
            "active_agents": sum(1 for a in self.agents if a.active),
            "total_operations": self.result.total_operations,
            "successful_operations": self.result.successful_operations,
            "score": self.result.total_score,
        }


class RedTeam(Team):
    """Red Team"""

    def __init__(self):
        super().__init__("Red Team", "red")
        self.agents = create_red_team()
        self._subscribe_to_evidence()

    def _subscribe_to_evidence(self):
        """订阅 Blue Team 产生的检测证据"""
        bus = get_evidence_bus()
        bus.subscribe(EvidenceType.DETECTION, self._on_blue_detection)

    def _on_blue_detection(self, evidence: Evidence):
        """当 Blue Team 检测到威胁时的回调"""
        logger.info(f"Red Team received detection alert: {evidence.title}")

    def execute_operation(self, target: str, role: AgentRole, context: dict) -> AttackResult:
        """
        执行攻击操作

        Args:
            target: 目标
            role: Agent 角色
            context: 上下文

        Returns:
            AttackResult
        """
        agent = self.get_agent(role)
        if not agent:
            logger.warning(f"Red Agent role {role} not found")
            return AttackResult(success=False, error=f"Agent role {role} not found")

        result = agent.execute(target, context)
        self.result.total_operations += 1

        if result.success:
            self.result.successful_operations += 1
            self.result.total_score += result.score
        else:
            self.result.failed_operations += 1

        # 发布攻击证据
        if result.success:
            bus = get_evidence_bus()
            evidence = Evidence(
                team="red",
                agent_name=agent.name,
                type=self._attack_result_to_evidence_type(result),
                title=f"{agent.name} executed {result.technique_used}",
                data=result.data,
                technique_id=result.technique_used,
                confidence=result.score / 30.0,  # 归一化
            )
            bus.publish(evidence)

        return result

    def _attack_result_to_evidence_type(self, result: AttackResult) -> EvidenceType:
        """将攻击结果映射到证据类型"""
        technique_to_type = {
            "T1595": EvidenceType.RECON,
            "T1078": EvidenceType.CREDENTIALS,
            "T1110": EvidenceType.CREDENTIALS,
            "T1068": EvidenceType.PRIVESC,
            "T1021": EvidenceType.LATERAL_MOVEMENT,
            "T1484": EvidenceType.VULN_FOUND,
            "T1557": EvidenceType.LATERAL_MOVEMENT,
        }
        return technique_to_type.get(result.technique_used, EvidenceType.VULN_FOUND)

    def get_capabilities(self) -> dict:
        """获取团队能力"""
        capabilities = {}
        for agent in self.agents:
            capabilities[agent.role.value] = {
                "name": agent.name,
                "capabilities": agent.capabilities,
                "techniques": agent.techniques,
                "success_rate": agent.success_rate,
            }
        return capabilities


class BlueTeam(Team):
    """Blue Team"""

    def __init__(self):
        super().__init__("Blue Team", "blue")
        self.agents = create_blue_team()
        self._subscribe_to_evidence()

    def _subscribe_to_evidence(self):
        """订阅 Red Team 产生的攻击证据"""
        bus = get_evidence_bus()
        bus.subscribe(EvidenceType.VULN_FOUND, self._on_red_attack)
        bus.subscribe(EvidenceType.EXPLOIT_SUCCESS, self._on_red_attack)
        bus.subscribe(EvidenceType.CREDENTIALS, self._on_red_attack)
        bus.subscribe(EvidenceType.LATERAL_MOVEMENT, self._on_red_attack)

    def _on_red_attack(self, evidence: Evidence):
        """当 Red Team 发起攻击时的回调"""
        logger.info(f"Blue Team received attack evidence: {evidence.title}")

        # 触发检测
        for agent in self.agents:
            if agent.enabled and not agent.active:
                result = agent.detect(evidence.to_dict(), {})
                if result.detected:
                    self._publish_detection(evidence, result)

    def _publish_detection(self, attack_evidence: Evidence, detection: DetectionResult):
        """发布检测证据"""
        bus = get_evidence_bus()
        detection_evidence = Evidence(
            team="blue",
            agent_name=detection.technique_detected,
            type=EvidenceType.DETECTION,
            title=f"Detected {attack_evidence.technique_id}",
            description=f"Alert level: {detection.alert_level}",
            data={
                "attack_evidence_id": attack_evidence.evidence_id,
                "detection_confidence": detection.confidence,
                "iocs": detection.iocs,
            },
            technique_id=detection.technique_detected,
            confidence=detection.confidence,
        )
        bus.publish(detection_evidence)

    def detect_threat(self, evidence: dict, role: AgentRole) -> DetectionResult:
        """
        检测威胁

        Args:
            evidence: 证据数据
            role: Agent 角色

        Returns:
            DetectionResult
        """
        agent = self.get_agent(role)
        if not agent:
            logger.warning(f"Blue Agent role {role} not found")
            return DetectionResult(detected=False, error=f"Agent role {role} not found")

        result = agent.detect(evidence, {})
        if result.detected:
            self.result.total_operations += 1
            self.result.successful_operations += 1
        else:
            self.result.total_operations += 1
            self.result.failed_operations += 1

        return result

    def get_detection_coverage(self) -> dict:
        """获取检测覆盖"""
        coverage = {}
        for agent in self.agents:
            coverage[agent.role.value] = {
                "name": agent.name,
                "techniques": agent.detection_techniques,
                "detection_rate": agent.detection_rate,
            }
        return coverage
