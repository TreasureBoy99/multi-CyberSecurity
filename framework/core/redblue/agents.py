"""
红蓝对抗 Agent 定义
==================
Red Team 和 Blue Team 的专业 Agent
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class AgentRole(str, Enum):
    """Agent 角色"""
    # Red Team
    RED_RECON = "red_recon"
    RED_CREDENTIAL_ACCESS = "red_credential_access"
    RED_CRACKER = "red_cracker"
    RED_ACL = "red_acl"                    # Access Control List
    RED_PRIVESC = "red_privesc"
    RED_LATERAL = "red_lateral"
    RED_COERCION = "red_coercion"

    # Blue Team
    BLUE_TRIAGE = "blue_triage"
    BLUE_THREAT_HUNTER = "blue_threat_hunter"
    BLUE_LATERAL_ANALYST = "blue_lateral_analyst"
    BLUE_ESCALATION_TRIAGE = "blue_escalation_triage"


@dataclass
class AttackResult:
    """攻击结果"""
    success: bool = False
    technique_used: str = ""
    evidence_id: str = ""
    data: dict = field(default_factory=dict)
    error: str = ""
    score: float = 0.0                    # 攻击得分


@dataclass
class DetectionResult:
    """检测结果"""
    detected: bool = False
    detection_type: str = ""
    evidence_id: str = ""
    confidence: float = 0.0
    alert_level: str = "low"             # low, medium, high, critical
    iocs: list[str] = field(default_factory=list)
    technique_detected: str = ""
    error: str = ""


@dataclass
class RedAgent:
    """Red Team Agent"""
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    role: AgentRole = AgentRole.RED_RECON
    name: str = ""
    enabled: bool = True

    # 能力
    capabilities: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)  # ATT&CK 技术

    # 状态
    active: bool = False
    current_target: str = ""

    # 统计
    attack_count: int = 0
    successful_attacks: int = 0

    def __post_init__(self):
        if not self.name:
            self.name = self.role.value.replace("red_", "Red ").replace("_", " ").title()

    @property
    def success_rate(self) -> float:
        if self.attack_count == 0:
            return 0.0
        return self.successful_attacks / self.attack_count

    def execute(self, target: str, context: dict) -> AttackResult:
        """
        执行攻击

        Args:
            target: 目标
            context: 上下文信息

        Returns:
            AttackResult
        """
        result = AttackResult()

        if not self.enabled:
            result.error = "Agent is disabled"
            return result

        try:
            self.active = True
            self.current_target = target
            self.attack_count += 1

            # 根据角色执行不同攻击
            if self.role == AgentRole.RED_RECON:
                result = self._recon(target, context)
            elif self.role == AgentRole.RED_CREDENTIAL_ACCESS:
                result = self._credential_access(target, context)
            elif self.role == AgentRole.RED_CRACKER:
                result = self._cracker(target, context)
            elif self.role == AgentRole.RED_ACL:
                result = self._acl_attack(target, context)
            elif self.role == AgentRole.RED_PRIVESC:
                result = self._privesc(target, context)
            elif self.role == AgentRole.RED_LATERAL:
                result = self._lateral(target, context)
            elif self.role == AgentRole.RED_COERCION:
                result = self._coercion(target, context)

            if result.success:
                self.successful_attacks += 1

        except Exception as e:
            logger.error(f"RedAgent {self.role.value} error: {e}")
            result.error = str(e)

        finally:
            self.active = False

        return result

    def _recon(self, target: str, context: dict) -> AttackResult:
        """侦察"""
        # 实际实现会调用 recon 工具
        return AttackResult(
            success=True,
            technique_used="T1595",  # Active Scanning
            data={"discovered_assets": [], "open_ports": []},
            score=10.0,
        )

    def _credential_access(self, target: str, context: dict) -> AttackResult:
        """凭证访问"""
        return AttackResult(
            success=True,
            technique_used="T1078",  # Valid Accounts
            data={"credentials_found": []},
            score=25.0,
        )

    def _cracker(self, target: str, context: dict) -> AttackResult:
        """密码破解"""
        return AttackResult(
            success=False,
            technique_used="T1110",  # Brute Force
            score=0.0,
        )

    def _acl_attack(self, target: str, context: dict) -> AttackResult:
        """ACL 攻击"""
        return AttackResult(
            success=True,
            technique_used="T1484",  # Domain Policy Modification
            data={"acl_changes": []},
            score=20.0,
        )

    def _privesc(self, target: str, context: dict) -> AttackResult:
        """权限提升"""
        return AttackResult(
            success=True,
            technique_used="T1068",  # Exploitation for Privilege Escalation
            data={"new_privileges": ["root"]},
            score=30.0,
        )

    def _lateral(self, target: str, context: dict) -> AttackResult:
        """横向移动"""
        return AttackResult(
            success=True,
            technique_used="T1021",  # Remote Services
            data={"pivot_points": []},
            score=25.0,
        )

    def _coercion(self, target: str, context: dict) -> AttackResult:
        """强制认证"""
        return AttackResult(
            success=True,
            technique_used="T1557",  # Adversary-in-the-Middle
            data={"coerced_auths": []},
            score=20.0,
        )


@dataclass
class BlueAgent:
    """Blue Team Agent"""
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    role: AgentRole = AgentRole.BLUE_TRIAGE
    name: str = ""
    enabled: bool = True

    # 能力
    capabilities: list[str] = field(default_factory=list)
    detection_techniques: list[str] = field(default_factory=list)  # 能检测的技术

    # 状态
    active: bool = False
    alerts_generated: int = 0

    # 检测统计
    detections: int = 0
    false_positives: int = 0

    def __post_init__(self):
        if not self.name:
            self.name = self.role.value.replace("blue_", "Blue ").replace("_", " ").title()

    @property
    def detection_rate(self) -> float:
        if self.detections == 0:
            return 0.0
        return (self.detections - self.false_positives) / self.detections

    def detect(self, evidence: dict, context: dict) -> DetectionResult:
        """
        检测威胁

        Args:
            evidence: 证据数据
            context: 上下文信息

        Returns:
            DetectionResult
        """
        result = DetectionResult()

        if not self.enabled:
            return result

        try:
            self.active = True

            # 根据角色执行不同检测
            if self.role == AgentRole.BLUE_TRIAGE:
                result = self._triage(evidence, context)
            elif self.role == AgentRole.BLUE_THREAT_HUNTER:
                result = self._threat_hunt(evidence, context)
            elif self.role == AgentRole.BLUE_LATERAL_ANALYST:
                result = self._lateral_analysis(evidence, context)
            elif self.role == AgentRole.BLUE_ESCALATION_TRIAGE:
                result = self._escalation_triage(evidence, context)

            if result.detected:
                self.alerts_generated += 1

        except Exception as e:
            logger.error(f"BlueAgent {self.role.value} error: {e}")
            result.error = str(e)

        finally:
            self.active = False

        return result

    def _triage(self, evidence: dict, context: dict) -> DetectionResult:
        """威胁分类"""
        return DetectionResult(
            detected=False,
            detection_type="triage",
        )

    def _threat_hunt(self, evidence: dict, context: dict) -> DetectionResult:
        """威胁狩猎"""
        technique = evidence.get("technique", "")
        if technique in self.detection_techniques:
            return DetectionResult(
                detected=True,
                detection_type="threat_hunt",
                confidence=0.8,
                alert_level="high",
                technique_detected=technique,
            )
        return DetectionResult(detected=False)

    def _lateral_analysis(self, evidence: dict, context: dict) -> DetectionResult:
        """横向移动分析"""
        if evidence.get("type") == "lateral_movement":
            return DetectionResult(
                detected=True,
                detection_type="lateral_movement",
                confidence=0.9,
                alert_level="critical",
                iocs=evidence.get("iocs", []),
                technique_detected="T1021",
            )
        return DetectionResult(detected=False)

    def _escalation_triage(self, evidence: dict, context: dict) -> DetectionResult:
        """权限提升分类"""
        if evidence.get("type") == "privesc":
            return DetectionResult(
                detected=True,
                detection_type="escalation",
                confidence=0.85,
                alert_level="critical",
                technique_detected="T1068",
            )
        return DetectionResult(detected=False)


# Red Team Agent 工厂
def create_red_team() -> list[RedAgent]:
    """创建 Red Team"""
    return [
        RedAgent(role=AgentRole.RED_RECON, capabilities=["recon", "osint"]),
        RedAgent(role=AgentRole.RED_CREDENTIAL_ACCESS, capabilities=["credential_dump", "password_spray"]),
        RedAgent(role=AgentRole.RED_CRACKER, capabilities=["hash_cracking", "wordlist"]),
        RedAgent(role=AgentRole.RED_ACL, capabilities=["acl_enumeration", "permission_abuse"]),
        RedAgent(role=AgentRole.RED_PRIVESC, capabilities=["exploit", "bypass"]),
        RedAgent(role=AgentRole.RED_LATERAL, capabilities=["pivot", "wmi", "smb"]),
        RedAgent(role=AgentRole.RED_COERCION, capabilities=["ntlm_relay", "kerberoasting"]),
    ]


# Blue Team Agent 工厂
def create_blue_team() -> list[BlueAgent]:
    """创建 Blue Team"""
    return [
        BlueAgent(
            role=AgentRole.BLUE_TRIAGE,
            capabilities=["event_triage", "alert_classification"],
            detection_techniques=["T1078", "T1110", "T1484"],
        ),
        BlueAgent(
            role=AgentRole.BLUE_THREAT_HUNTER,
            capabilities=["threat_hunting", "anomaly_detection"],
            detection_techniques=["T1059", "T1566", "T1071"],
        ),
        BlueAgent(
            role=AgentRole.BLUE_LATERAL_ANALYST,
            capabilities=["lateral_movement_detection", "network_analysis"],
            detection_techniques=["T1021", "T1046", "T1570"],
        ),
        BlueAgent(
            role=AgentRole.BLUE_ESCALATION_TRIAGE,
            capabilities=["privilege_escalation_detection", "process_analysis"],
            detection_techniques=["T1068", "T1548", "T1134"],
        ),
    ]
