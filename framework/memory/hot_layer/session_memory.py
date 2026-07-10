"""
运行记忆层 (Hot Layer)
======================
会话级热数据管理，模拟人类短期记忆。
在渗透测试过程中实时积累关键发现和上下文。
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


@dataclass
class HotFinding:
    """热发现结构 - 运行记忆层的基本单元"""
    finding_id: str
    title: str
    severity: str  # critical/high/medium/low/info
    description: str
    evidence: dict[str, Any]
    target: str
    finding_type: str  # vuln/misconfig/info
    created_at: datetime = field(default_factory=datetime.now)
    validated: bool = False
    reachable: bool = False
    agent_name: str = ""  # 发现该问题的Agent
    confidence: float = 1.0  # 置信度 0.0-1.0
    tags: list[str] = field(default_factory=list)  # 标签用于检索
    related_findings: list[str] = field(default_factory=list)  # 关联发现


@dataclass
class SessionContext:
    """会话上下文 - 当前渗透测试的运行时状态"""
    session_id: str
    target: str
    mission_type: str  # web/mobile/api/code-audit
    start_time: datetime = field(default_factory=datetime.now)

    # 进度追踪
    current_stage: str = "Recon"
    completed_stages: list[str] = field(default_factory=list)

    # 热数据
    recent_findings: list[HotFinding] = field(default_factory=list)
    attack_paths: list[dict] = field(default_factory=list)  # 发现的攻击路径
    scanned_assets: dict[str, Any] = field(default_factory=dict)  # 已扫描资产

    # 统计
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0

    # Agent协作
    agent_handoffs: list[dict] = field(default_factory=list)  # Agent间交接记录
    failed_attempts: list[dict] = field(default_factory=list)  # 失败尝试记录

    # 上下文持久化
    last_context_file: str = ""  # 上下文文件路径

    def add_finding(self, finding: HotFinding):
        """添加发现到热记忆"""
        self.recent_findings.append(finding)
        self.total_findings += 1

        # 更新计数
        severity = finding.severity.lower()
        if severity == "critical":
            self.critical_count += 1
        elif severity == "high":
            self.high_count += 1

    def get_recent_findings(self, limit: int = 10, severity: Optional[str] = None) -> list[HotFinding]:
        """获取最近的发现，支持按严重性过滤"""
        findings = self.recent_findings

        if severity:
            findings = [f for f in findings if f.severity.lower() == severity.lower()]

        return findings[-limit:]

    def add_attack_path(self, path: dict):
        """添加攻击路径"""
        self.attack_paths.append(path)

    def record_failure(self, attempt_type: str, reason: str, context: dict):
        """记录失败尝试，用于反思和学习"""
        self.failed_attempts.append({
            "type": attempt_type,
            "reason": reason,
            "context": context,
            "timestamp": datetime.now().isoformat(),
        })

    def to_dict(self) -> dict:
        """序列化为字典"""
        data = asdict(self)
        data["start_time"] = self.start_time.isoformat()
        data["recent_findings"] = [
            {**asdict(f), "created_at": f.created_at.isoformat()}
            for f in self.recent_findings
        ]
        return data

    @classmethod
    def from_dict(cls, data: dict) -> SessionContext:
        """从字典反序列化"""
        data["start_time"] = datetime.fromisoformat(data["start_time"])
        data["recent_findings"] = [
            HotFinding(**{**f, "created_at": datetime.fromisoformat(f["created_at"])})
            for f in data["recent_findings"]
        ]
        return cls(**data)


class SessionMemory:
    """
    会话内存管理器 - 运行记忆层的核心
    线程安全，支持多Agent并发写入
    """

    def __init__(self, session_dir: str = "~/.multi-cybersecurity/sessions"):
        self.session_dir = Path(session_dir).expanduser()
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._sessions: dict[str, SessionContext] = {}

    def create_session(self, session_id: str, target: str, mission_type: str = "web") -> SessionContext:
        """创建新会话"""
        with self._lock:
            ctx = SessionContext(
                session_id=session_id,
                target=target,
                mission_type=mission_type,
            )
            self._sessions[session_id] = ctx
            return ctx

    def get_session(self, session_id: str) -> Optional[SessionContext]:
        """获取会话"""
        with self._lock:
            return self._sessions.get(session_id)

    def save_session(self, session_id: str):
        """持久化会话到磁盘"""
        with self._lock:
            ctx = self._sessions.get(session_id)
            if not ctx:
                return

            path = self.session_dir / f"{session_id}.json"
            ctx.last_context_file = str(path)
            path.write_text(json.dumps(ctx.to_dict(), indent=2, ensure_ascii=False))

    def load_session(self, session_id: str) -> Optional[SessionContext]:
        """从磁盘加载会话"""
        with self._lock:
            path = self.session_dir / f"{session_id}.json"
            if not path.exists():
                return None

            try:
                data = json.loads(path.read_text())
                ctx = SessionContext.from_dict(data)
                self._sessions[session_id] = ctx
                return ctx
            except Exception:
                return None

    def list_sessions(self) -> list[dict]:
        """列出所有会话摘要"""
        sessions = []
        for path in self.session_dir.glob("*.json"):
            try:
                data = json.loads(path.read_text())
                sessions.append({
                    "session_id": path.stem,
                    "target": data.get("target", ""),
                    "mission_type": data.get("mission_type", ""),
                    "start_time": data.get("start_time", ""),
                    "total_findings": data.get("total_findings", 0),
                })
            except Exception:
                pass
        return sorted(sessions, key=lambda x: x.get("start_time", ""), reverse=True)

    def add_finding(self, session_id: str, finding: HotFinding):
        """添加发现到会话"""
        with self._lock:
            ctx = self._sessions.get(session_id)
            if ctx:
                ctx.add_finding(finding)

    def update_stage(self, session_id: str, stage: str):
        """更新当前阶段"""
        with self._lock:
            ctx = self._sessions.get(session_id)
            if ctx:
                if ctx.current_stage not in ctx.completed_stages:
                    ctx.completed_stages.append(ctx.current_stage)
                ctx.current_stage = stage
