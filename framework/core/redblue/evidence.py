"""
证据驱动机制
============
参考 Ares 的证据总线设计

功能:
- 证据发布/订阅
- 证据链追踪
- 实时联动 Red Team 和 Blue Team
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class EvidenceType(str, Enum):
    """证据类型"""
    # Red Team 证据
    RECON = "recon"                      # 侦察结果
    VULN_FOUND = "vuln_found"            # 发现漏洞
    EXPLOIT_SUCCESS = "exploit_success"  # 利用成功
    CREDENTIALS = "credentials"          # 获取凭证
    LATERAL_MOVEMENT = "lateral_movement"  # 横向移动
    PRIVESC = "privesc"                  # 权限提升
    PERSISTENCE = "persistence"          # 持久化

    # Blue Team 证据
    DETECTION = "detection"              # 检测到攻击
    ALERT = "alert"                      # 触发告警
    IOC_FOUND = "ioc_found"              # 发现 IoC
    ANOMALY = "anomaly"                  # 异常行为
    HONEYPOT_TRIGGER = "honeypot_trigger"  # 蜜罐触发

    # 元证据
    ENGAGEMENT_START = "engagement_start"
    ENGAGEMENT_END = "engagement_end"


@dataclass
class Evidence:
    """
    证据

    Red Team 和 Blue Team 之间传递的信息单元
    """
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    team: str = ""                       # "red" or "blue"
    agent_name: str = ""                 # 来源 Agent
    type: EvidenceType = EvidenceType.RECON

    # 内容
    title: str = ""
    description: str = ""
    data: dict = field(default_factory=dict)  # 证据数据

    # 关联
    related_evidence_ids: list[str] = field(default_factory=list)  # 关联证据
    attack_chain_id: str = ""           # 攻击链 ID

    # MITRE ATT&CK
    technique_id: str = ""               # ATT&CK 技术 ID
    tactic: str = ""                     # ATT&CK 战术

    # 可信度
    confidence: float = 1.0              # 0.0 - 1.0
    validated: bool = False              # 是否经过验证

    # 时间戳
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    ttl_seconds: int = 3600             # 存活时间

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @property
    def is_expired(self) -> bool:
        """检查是否过期"""
        if self.ttl_seconds <= 0:
            return False
        created = datetime.fromisoformat(self.timestamp)
        age = (datetime.now() - created).total_seconds()
        return age > self.ttl_seconds


@dataclass
class EvidenceChain:
    """
    证据链

    追踪一次完整攻击的证据序列
    """
    chain_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None

    # 证据序列
    evidence_ids: list[str] = field(default_factory=list)

    # 状态
    completed: bool = False
    detected_by_blue: bool = False       # Blue Team 是否检测到
    blocked: bool = False                # 是否被阻断

    # 统计
    total_steps: int = 0
    red_score: float = 0.0               # Red Team 得分
    blue_score: float = 0.0              # Blue Team 得分

    def add_evidence(self, evidence_id: str):
        """添加证据到链"""
        self.evidence_ids.append(evidence_id)
        self.total_steps = len(self.evidence_ids)


class EvidenceBus:
    """
    证据总线

    实现发布-订阅模式，支持 Red Team 和 Blue Team 实时联动
    """

    def __init__(self):
        self._evidence: dict[str, Evidence] = {}
        self._chains: dict[str, EvidenceChain] = {}
        self._subscribers: dict[EvidenceType, list[Callable]] = {}
        self._chain_subscribers: dict[str, list[Callable]] = {}  # attack_chain_id -> callbacks

    def publish(self, evidence: Evidence) -> str:
        """
        发布证据

        Args:
            evidence: 证据对象

        Returns:
            evidence_id
        """
        self._evidence[evidence.evidence_id] = evidence

        # 更新证据链
        if evidence.attack_chain_id:
            if evidence.attack_chain_id not in self._chains:
                self._chains[evidence.attack_chain_id] = EvidenceChain(
                    chain_id=evidence.attack_chain_id,
                    target=evidence.data.get("target", ""),
                )
            self._chains[evidence.attack_chain_id].add_evidence(evidence.evidence_id)

        # 触发订阅者
        self._notify_subscribers(evidence)

        logger.debug(f"Published evidence: {evidence.evidence_id} ({evidence.type})")
        return evidence.evidence_id

    def subscribe(self, evidence_type: EvidenceType, callback: Callable[[Evidence], None]):
        """
        订阅证据

        Args:
            evidence_type: 感兴趣的证据类型
            callback: 回调函数
        """
        if evidence_type not in self._subscribers:
            self._subscribers[evidence_type] = []
        self._subscribers[evidence_type].append(callback)

    def subscribe_to_chain(self, attack_chain_id: str, callback: Callable[[Evidence], None]):
        """订阅特定攻击链的证据"""
        if attack_chain_id not in self._chain_subscribers:
            self._chain_subscribers[attack_chain_id] = []
        self._chain_subscribers[attack_chain_id].append(callback)

    def _notify_subscribers(self, evidence: Evidence):
        """通知订阅者"""
        # 按类型通知
        if evidence.type in self._subscribers:
            for callback in self._subscribers[evidence.type]:
                try:
                    callback(evidence)
                except Exception as e:
                    logger.error(f"Subscriber callback error: {e}")

        # 按攻击链通知
        if evidence.attack_chain_id in self._chain_subscribers:
            for callback in self._chain_subscribers[evidence.attack_chain_id]:
                try:
                    callback(evidence)
                except Exception as e:
                    logger.error(f"Chain subscriber callback error: {e}")

    def get(self, evidence_id: str) -> Optional[Evidence]:
        """获取证据"""
        return self._evidence.get(evidence_id)

    def get_chain(self, chain_id: str) -> Optional[EvidenceChain]:
        """获取证据链"""
        return self._chains.get(chain_id)

    def get_latest(self, evidence_type: Optional[EvidenceType] = None, limit: int = 10) -> list[Evidence]:
        """获取最新证据"""
        evidence_list = list(self._evidence.values())

        if evidence_type:
            evidence_list = [e for e in evidence_list if e.type == evidence_type]

        # 按时间排序
        evidence_list.sort(key=lambda e: e.timestamp, reverse=True)

        return evidence_list[:limit]

    def get_by_chain(self, chain_id: str) -> list[Evidence]:
        """获取攻击链的所有证据"""
        chain = self._chains.get(chain_id)
        if not chain:
            return []

        return [
            self._evidence[eid]
            for eid in chain.evidence_ids
            if eid in self._evidence
        ]

    def get_stats(self) -> dict:
        """获取统计信息"""
        evidence_list = list(self._evidence.values())
        by_type = {}
        for e in evidence_list:
            type_str = e.type.value
            by_type[type_str] = by_type.get(type_str, 0) + 1

        return {
            "total_evidence": len(evidence_list),
            "by_type": by_type,
            "active_chains": len([c for c in self._chains.values() if not c.completed]),
            "completed_chains": len([c for c in self._chains.values() if c.completed]),
        }

    def cleanup_expired(self):
        """清理过期证据"""
        expired_ids = [
            eid for eid, e in self._evidence.items()
            if e.is_expired
        ]
        for eid in expired_ids:
            del self._evidence[eid]

        if expired_ids:
            logger.info(f"Cleaned up {len(expired_ids)} expired evidence")


# 全局证据总线实例
_evidence_bus = None


def get_evidence_bus() -> EvidenceBus:
    """获取全局证据总线"""
    global _evidence_bus
    if _evidence_bus is None:
        _evidence_bus = EvidenceBus()
    return _evidence_bus
