"""
Memory Board 实现
=================
基于 SQLite 的黑板实现 (可升级为 PostgreSQL + pgvector)
"""

from __future__ import annotations

import json
import math
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .board import Board
from .types import (
    AgentBudget,
    Budget,
    CampaignConfig,
    Finding,
    FindingType,
    Predicate,
)


class MemoryBoard(Board):
    """
    内存黑板 - SQLite 实现

    设计参考:
    - PostgreSQL + pgvector 用于向量相似性搜索 (未来升级)
    - 内存缓存用于低延迟订阅
    """

    def __init__(self, db_path: str = "~/.multi-cybersecurity/blackboard.db"):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._subscriptions: dict[uuid.UUID, dict] = {}  # 内存订阅索引
        self._init_db()

    def _init_db(self):
        """初始化数据库"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # 发现表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    agent_name TEXT,
                    type TEXT NOT NULL,
                    target TEXT,
                    data TEXT,  -- JSON
                    pheromone_base REAL DEFAULT 1.0,
                    half_life_sec INTEGER DEFAULT 3600,
                    superseded_by TEXT,
                    parent_id TEXT,
                    created_at TEXT,
                    INDEX idx_campaign (campaign_id),
                    INDEX idx_type (type),
                    INDEX idx_created (created_at)
                )
            """)

            # 游标表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cursors (
                    campaign_id TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    PRIMARY KEY (campaign_id, agent_name)
                )
            """)

            # 预算表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS budgets (
                    campaign_id TEXT PRIMARY KEY,
                    max_hours REAL DEFAULT 0,
                    max_tokens INTEGER DEFAULT 0,
                    hours_used REAL DEFAULT 0,
                    tokens_used INTEGER DEFAULT 0
                )
            """)

            # Per-Agent 预算表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_budgets (
                    campaign_id TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    max_tokens INTEGER DEFAULT 0,
                    warn_at_tokens INTEGER DEFAULT 0,
                    tokens_used INTEGER DEFAULT 0,
                    warned INTEGER DEFAULT 0,
                    PRIMARY KEY (campaign_id, agent_name)
                )
            """)

            conn.commit()
            conn.close()

    def write(self, finding: Finding) -> uuid.UUID:
        """写入发现"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO findings (
                    id, campaign_id, agent_name, type, target, data,
                    pheromone_base, half_life_sec, superseded_by, parent_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(finding.id),
                str(finding.campaign_id),
                finding.agent_name,
                finding.type.value,
                finding.target,
                json.dumps(finding.data),
                finding.pheromone_base,
                finding.half_life_sec,
                str(finding.superseded_by) if finding.superseded_by else None,
                str(finding.parent_id) if finding.parent_id else None,
                finding.created_at.isoformat(),
            ))

            conn.commit()
            conn.close()

            # 通知订阅者
            self._notify_subscribers(finding)

            return finding.id

    def query(self, predicate: Predicate) -> list[Finding]:
        """查询匹配谓词的发现"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            sql_parts = ["SELECT * FROM findings WHERE 1=1"]
            params = []

            # 类型过滤
            if predicate.types:
                placeholders = ",".join("?" * len(predicate.types))
                sql_parts.append(f"type IN ({placeholders})")
                params.extend([t.value for t in predicate.types])

            # 目标前缀过滤
            if predicate.target_prefix:
                sql_parts.append("target LIKE ?")
                params.append(f"{predicate.target_prefix}%")

            # 游标过滤
            if predicate.since_id:
                sql_parts.append("id > ?")
                params.append(str(predicate.since_id))

            # 限制
            if predicate.limit > 0:
                sql_parts.append("LIMIT ?")
                params.append(predicate.limit)

            sql_parts.append("ORDER BY created_at DESC")

            sql = " ".join(sql_parts)
            cursor.execute(sql, params)

            findings = []
            for row in cursor.fetchall():
                finding = self._row_to_finding(row)
                # 信息素过滤
                if predicate.min_pheromone <= 0 or finding.pheromone >= predicate.min_pheromone:
                    findings.append(finding)

            conn.close()
            return findings

    def subscribe(self, predicate: Predicate) -> tuple[uuid.UUID, list[Finding]]:
        """订阅发现"""
        subscription_id = uuid.uuid4()

        # 先获取当前匹配的历史发现
        current = self.query(predicate)

        # 注册订阅
        self._subscriptions[subscription_id] = {
            "predicate": predicate,
            "last_ids": {f.id for f in current},  # 已知的 Finding ID
            "created_at": datetime.now(),
        }

        return subscription_id, current

    def poll_subscription(self, subscription_id: uuid.UUID, timeout_sec: float = 5.0) -> list[Finding]:
        """轮询订阅获取新发现"""
        start = time.time()
        while time.time() - start < timeout_sec:
            with self._lock:
                sub = self._subscriptions.get(subscription_id)
                if not sub:
                    return []

                predicate = sub["predicate"]

                # 查询新发现
                new_findings = []
                for finding in self.query(predicate):
                    if finding.id not in sub["last_ids"]:
                        new_findings.append(finding)
                        sub["last_ids"].add(finding.id)

                if new_findings:
                    return new_findings

            time.sleep(0.1)  # 避免 CPU 空转

        return []

    def unsubscribe(self, subscription_id: uuid.UUID):
        """取消订阅"""
        with self._lock:
            self._subscriptions.pop(subscription_id, None)

    def cursor(self, campaign_id: uuid.UUID, agent_name: str) -> uuid.UUID | None:
        """获取 Agent 游标"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                SELECT finding_id FROM cursors
                WHERE campaign_id = ? AND agent_name = ?
            """, (str(campaign_id), agent_name))

            row = cursor.fetchone()
            conn.close()

            return uuid.UUID(row[0]) if row else None

    def commit_cursor(self, campaign_id: uuid.UUID, agent_name: str, finding_id: uuid.UUID):
        """提交 Agent 游标"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                INSERT OR REPLACE INTO cursors (campaign_id, agent_name, finding_id)
                VALUES (?, ?, ?)
            """, (str(campaign_id), agent_name, str(finding_id)))

            conn.commit()
            conn.close()

    def pheromone(self, finding_id: uuid.UUID) -> float:
        """获取信息素强度"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                SELECT pheromone_base, half_life_sec, created_at FROM findings
                WHERE id = ?
            """, (str(finding_id),))

            row = cursor.fetchone()
            conn.close()

            if not row:
                return 0.0

            pheromone_base, half_life_sec, created_at = row
            created = datetime.fromisoformat(created_at)
            age = (datetime.now() - created).total_seconds()

            decay_rate = math.log(2) / half_life_sec if half_life_sec > 0 else 0
            current = pheromone_base * math.exp(-decay_rate * age)
            return max(0.0, min(1.0, current))

    def supersede(self, old_id: uuid.UUID, new_id: uuid.UUID):
        """标记替代关系"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE findings SET superseded_by = ? WHERE id = ?
            """, (str(new_id), str(old_id)))

            conn.commit()
            conn.close()

    # === 预算操作 ===

    def budget(self, campaign_id: uuid.UUID) -> Budget:
        """获取 Campaign 预算"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                SELECT max_hours, max_tokens, hours_used, tokens_used
                FROM budgets WHERE campaign_id = ?
            """, (str(campaign_id),))

            row = cursor.fetchone()
            conn.close()

            if not row:
                return Budget(campaign_id=campaign_id)

            return Budget(
                campaign_id=campaign_id,
                max_agent_hours=row[0],
                max_tokens=row[1],
                agent_hours_used=row[2],
                tokens_used=row[3],
            )

    def update_budget(self, campaign_id: uuid.UUID, delta_hours: float, delta_tokens: int):
        """更新预算使用"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO budgets (campaign_id, hours_used, tokens_used)
                VALUES (?, ?, ?)
                ON CONFLICT(campaign_id) DO UPDATE SET
                    hours_used = hours_used + excluded.hours_used,
                    tokens_used = tokens_used + excluded.tokens_used
            """, (str(campaign_id), delta_hours, delta_tokens))

            conn.commit()
            conn.close()

    def set_budget_limits(self, campaign_id: uuid.UUID, max_hours: float, max_tokens: int):
        """设置预算限制"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO budgets (campaign_id, max_hours, max_tokens, hours_used, tokens_used)
                VALUES (?, ?, ?, 0, 0)
                ON CONFLICT(campaign_id) DO UPDATE SET
                    max_hours = excluded.max_hours,
                    max_tokens = excluded.max_tokens
            """, (str(campaign_id), max_hours, max_tokens))

            conn.commit()
            conn.close()

    def agent_budget(self, campaign_id: uuid.UUID, agent_name: str) -> AgentBudget:
        """获取 Per-Agent 预算"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                SELECT max_tokens, warn_at_tokens, tokens_used, warned
                FROM agent_budgets
                WHERE campaign_id = ? AND agent_name = ?
            """, (str(campaign_id), agent_name))

            row = cursor.fetchone()
            conn.close()

            if not row:
                return AgentBudget(campaign_id=campaign_id, agent_name=agent_name)

            return AgentBudget(
                campaign_id=campaign_id,
                agent_name=agent_name,
                max_tokens=row[0],
                warn_at_tokens=row[1],
                tokens_used=row[2],
                warned=bool(row[3]),
            )

    def charge_agent(self, campaign_id: uuid.UUID, agent_name: str, tokens: int):
        """为 Agent 扣费"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO agent_budgets (campaign_id, agent_name, tokens_used)
                VALUES (?, ?, ?)
                ON CONFLICT(campaign_id, agent_name) DO UPDATE SET
                    tokens_used = tokens_used + excluded.tokens_used
            """, (str(campaign_id), agent_name, tokens))

            conn.commit()
            conn.close()

    def set_agent_budget(self, campaign_id: uuid.UUID, agent_name: str, max_tokens: int, warn_at_tokens: int = 0):
        """设置 Per-Agent 预算"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO agent_budgets (campaign_id, agent_name, max_tokens, warn_at_tokens, tokens_used)
                VALUES (?, ?, ?, ?, 0)
                ON CONFLICT(campaign_id, agent_name) DO UPDATE SET
                    max_tokens = excluded.max_tokens,
                    warn_at_tokens = excluded.warn_at_tokens
            """, (str(campaign_id), agent_name, max_tokens, warn_at_tokens))

            conn.commit()
            conn.close()

    def _notify_subscribers(self, finding: Finding):
        """通知订阅者有新发现 (被动通知模式)"""
        # 实际实现中，这里可以将 finding 放入各订阅的待处理队列
        # 但由于是内存实现，poll_subscription 已经足够
        pass

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        """将数据库行转换为 Finding"""
        return Finding(
            id=uuid.UUID(row["id"]),
            campaign_id=uuid.UUID(row["campaign_id"]),
            agent_name=row["agent_name"] or "",
            type=FindingType(row["type"]),
            target=row["target"] or "",
            data=json.loads(row["data"] or "{}"),
            pheromone_base=row["pheromone_base"],
            half_life_sec=row["half_life_sec"],
            superseded_by=uuid.UUID(row["superseded_by"]) if row["superseded_by"] else None,
            parent_id=uuid.UUID(row["parent_id"]) if row["parent_id"] else None,
            created_at=datetime.fromisoformat(row["created_at"]),
        )


# 全局单例
_board: Optional[MemoryBoard] = None
_board_lock = threading.Lock()


def get_board() -> MemoryBoard:
    """获取黑板单例"""
    global _board
    if _board is None:
        with _board_lock:
            if _board is None:
                _board = MemoryBoard()
    return _board
