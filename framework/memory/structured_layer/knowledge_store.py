"""
结构化经验层存储
================
基于 SQLite 的持久化知识库，支持多桶隔离和向量检索。

未来可升级为 PostgreSQL + pgvector 以获得更好的向量搜索能力。
当前使用 SQLite + 关键词匹配作为 fallback。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .schema import Category, KnowledgeRecord, Source

logger = logging.getLogger(__name__)

# 知识桶定义
KNOWLEDGE_BUCKET_MAIN = "main_battle_memory"
KNOWLEDGE_BUCKET_FORUM = "forum_memory"
KNOWLEDGE_BUCKET_EXTERNAL = "ctf_writeups_kb"

# 默认配置
DEFAULT_MIN_CONFIDENCE = 0.72
DEFAULT_TOP_K = 3

# 向量维度 (预留 pgvector 升级)
EMBEDDING_DIM = 1536


def simple_hash_embedding(text: str, dim: int = EMBEDDING_DIM) -> list[float]:
    """
    简单的基于哈希的伪嵌入向量

    注意: 这是 fallback 实现，用于没有真实嵌入模型时
    未来可替换为真实的嵌入模型 (OpenAI/LocalAI)

    Returns:
        固定维度的伪随机向量 (基于文本哈希)
    """
    import struct

    # 使用 SHA256 哈希
    hash_bytes = hashlib.sha256(text.encode()).digest()

    # 将哈希转换为固定维度的浮点数向量
    vector = []
    for i in range(dim):
        # 每8字节生成一个随机数种子
        idx = (i * 8) % len(hash_bytes)
        if idx + 8 <= len(hash_bytes):
            value = struct.unpack('>d', hash_bytes[idx:idx+8])[0]
            # 归一化到 [-1, 1]
            value = (value - 3e14) / 3e14  # 近似归一化
        else:
            value = 0.0
        vector.append(value)

    return vector


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """计算余弦相似度"""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot / (norm_a * norm_b)


class KnowledgeStore:
    """
    结构化知识存储

    支持:
    - 多桶隔离 (main/forum/external)
    - 关键词检索
    - 向量相似性搜索 (伪嵌入，预留真实嵌入升级)
    """

    def __init__(
        self,
        db_path: str = "~/.multi-cybersecurity/knowledge.db",
        use_embeddings: bool = True,
    ):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._use_embeddings = use_embeddings
        self._init_db()

    def _init_db(self):
        """初始化数据库表"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # 主知识表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS knowledge_records (
                    record_id TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    subcategory TEXT,
                    title TEXT NOT NULL,
                    description TEXT,
                    challenge_id TEXT,
                    solution_steps TEXT,  -- JSON
                    tools_used TEXT,      -- JSON list
                    key_insights TEXT,
                    failure_reasons TEXT, -- JSON
                    failed_attempts INTEGER DEFAULT 0,
                    related_cves TEXT,    -- JSON list
                    related_techniques TEXT, -- JSON list
                    related_weaknesses TEXT, -- JSON list
                    confidence REAL DEFAULT 0.0,
                    difficulty TEXT,
                    cvss_score REAL,
                    source TEXT DEFAULT 'main_battle',
                    source_url TEXT,
                    contributor TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    times_accessed INTEGER DEFAULT 0,
                    tags TEXT,            -- JSON list
                    target_tech TEXT,     -- JSON list
                    validated INTEGER DEFAULT 0,
                    validation_count INTEGER DEFAULT 0,
                    usefulness_score REAL DEFAULT 0.0,
                    bucket TEXT DEFAULT 'main_battle_memory'
                )
            """)

            # 全文搜索表
            cursor.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts
                USING fts5(title, description, key_insights, tags,
                           content='knowledge_records',
                           content_rowid='rowid')
            """)

            # 向量嵌入表 (预留 pgvector 升级)
            # 当前使用 JSON 存储伪嵌入，未来可迁移到 pgvector
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS knowledge_embeddings (
                    record_id TEXT PRIMARY KEY,
                    title_embedding TEXT,  -- JSON 存储的向量
                    content_embedding TEXT,
                    created_at TEXT,
                    FOREIGN KEY (record_id) REFERENCES knowledge_records(record_id)
                )
            """)

            # 索引
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_category
                ON knowledge_records(category)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_confidence
                ON knowledge_records(confidence)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_bucket
                ON knowledge_records(bucket)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_challenge_id
                ON knowledge_records(challenge_id)
            """)

            conn.commit()
            conn.close()

    def add_record(self, record: KnowledgeRecord, bucket: str = KNOWLEDGE_BUCKET_MAIN) -> bool:
        """添加知识记录"""
        with self._lock:
            try:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()

                cursor.execute("""
                    INSERT OR REPLACE INTO knowledge_records (
                        record_id, category, subcategory, title, description,
                        challenge_id, solution_steps, tools_used, key_insights,
                        failure_reasons, failed_attempts, related_cves,
                        related_techniques, related_weaknesses, confidence,
                        difficulty, cvss_score, source, source_url, contributor,
                        created_at, updated_at, times_accessed, tags, target_tech,
                        validated, validation_count, usefulness_score, bucket
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.record_id,
                    record.category.value,
                    record.subcategory,
                    record.title,
                    record.description,
                    record.challenge_id,
                    json.dumps([s.__dict__ for s in record.solution_steps]),
                    json.dumps(record.tools_used),
                    record.key_insights,
                    json.dumps([f.__dict__ for f in record.failure_reasons]),
                    record.failed_attempts,
                    json.dumps(record.related_cves),
                    json.dumps(record.related_techniques),
                    json.dumps(record.related_weaknesses),
                    record.confidence,
                    record.difficulty,
                    record.cvss_score,
                    record.source.value,
                    record.source_url,
                    record.contributor,
                    record.created_at.isoformat(),
                    record.updated_at.isoformat(),
                    record.times_accessed,
                    json.dumps(record.tags),
                    json.dumps(record.target_tech),
                    int(record.validated),
                    record.validation_count,
                    record.usefulness_score,
                    bucket,
                ))

                conn.commit()
                conn.close()
                return True
            except Exception as e:
                logger.error(f"Failed to add knowledge record: {e}")
                return False

    def search(
        self,
        query: str,
        bucket: str = KNOWLEDGE_BUCKET_MAIN,
        category: Optional[Category] = None,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
        top_k: int = DEFAULT_TOP_K,
        challenge_id: Optional[str] = None,
    ) -> list[KnowledgeRecord]:
        """
        搜索知识记录

        Args:
            query: 搜索关键词
            bucket: 知识桶 (main_battle_memory/forum_memory/ctf_writeups_kb)
            category: 可选，按分类过滤
            min_confidence: 最低置信度
            top_k: 返回数量
            challenge_id: 可选，按挑战ID精确匹配
        """
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            sql_parts = ["SELECT * FROM knowledge_records WHERE bucket = ?"]
            params = [bucket]

            # 分类过滤
            if category:
                sql_parts.append("AND category = ?")
                params.append(category.value)

            # 置信度过滤
            sql_parts.append("AND confidence >= ?")
            params.append(min_confidence)

            # 挑战ID精确匹配
            if challenge_id:
                sql_parts.append("AND challenge_id = ?")
                params.append(challenge_id)

            # FTS 全文搜索
            if query:
                sql_parts.append("""
                    AND (title LIKE ? OR description LIKE ? OR key_insights LIKE ?)
                """)
                like_query = f"%{query}%"
                params.extend([like_query, like_query, like_query])

            sql_parts.append("ORDER BY confidence DESC, times_accessed DESC LIMIT ?")
            params.append(top_k)

            sql = " ".join(sql_parts)
            cursor.execute(sql, params)

            records = []
            for row in cursor.fetchall():
                records.append(self._row_to_record(row))

            conn.close()
            return records

    def get_by_challenge(self, challenge_id: str, bucket: str = KNOWLEDGE_BUCKET_MAIN) -> list[KnowledgeRecord]:
        """根据挑战ID获取所有相关记录"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM knowledge_records
                WHERE challenge_id = ? AND bucket = ?
                ORDER BY confidence DESC
            """, (challenge_id, bucket))

            records = [self._row_to_record(row) for row in cursor.fetchall()]
            conn.close()
            return records

    def update_confidence(self, record_id: str, delta: float):
        """更新置信度 (用于反馈循环)"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE knowledge_records
                SET confidence = MAX(0.0, MIN(1.0, confidence + ?)),
                    updated_at = ?
                WHERE record_id = ?
            """, (delta, datetime.now().isoformat(), record_id))

            conn.commit()
            conn.close()

    def record_access(self, record_id: str):
        """记录访问"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE knowledge_records
                SET times_accessed = times_accessed + 1,
                    updated_at = ?
                WHERE record_id = ?
            """, (datetime.now().isoformat(), record_id))

            conn.commit()
            conn.close()

    def semantic_search(
        self,
        query: str,
        bucket: str = KNOWLEDGE_BUCKET_MAIN,
        category: Optional[Category] = None,
        min_confidence: float = 0.5,
        top_k: int = DEFAULT_TOP_K,
    ) -> list[tuple[KnowledgeRecord, float]]:
        """
        语义搜索 (基于向量相似性)

        注意: 当前使用伪嵌入向量，未来可升级为真实嵌入模型

        Args:
            query: 搜索文本
            bucket: 知识桶
            category: 可选，按分类过滤
            min_confidence: 最低置信度
            top_k: 返回数量

        Returns:
            [(record, similarity_score), ...] 按相似度倒序
        """
        if not self._use_embeddings:
            # Fallback 到关键词搜索
            results = self.search(
                query=query,
                bucket=bucket,
                category=category,
                min_confidence=min_confidence,
                top_k=top_k,
            )
            return [(r, 1.0) for r in results]

        # 生成查询向量
        query_embedding = simple_hash_embedding(query)

        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # 构建 SQL (复用 search 的过滤条件)
            sql_parts = ["SELECT * FROM knowledge_records WHERE bucket = ?"]
            params = [bucket]

            if category:
                sql_parts.append("AND category = ?")
                params.append(category.value)

            sql_parts.append("AND confidence >= ?")
            params.append(min_confidence)

            cursor.execute(" ".join(sql_parts), params)
            rows = cursor.fetchall()

            # 计算相似度
            scored_results = []
            for row in rows:
                record = self._row_to_record(row)

                # 获取嵌入向量
                cursor.execute("""
                    SELECT title_embedding, content_embedding
                    FROM knowledge_embeddings
                    WHERE record_id = ?
                """, (record.record_id,))

                emb_row = cursor.fetchone()
                if emb_row and emb_row["title_embedding"]:
                    try:
                        title_emb = json.loads(emb_row["title_embedding"])
                        title_sim = cosine_similarity(query_embedding, title_emb)

                        content_emb = json.loads(emb_row["content_embedding"]) if emb_row["content_embedding"] else None
                        content_sim = cosine_similarity(query_embedding, content_emb) if content_emb else 0

                        # 综合相似度
                        similarity = title_sim * 0.7 + content_sim * 0.3
                        scored_results.append((record, max(0, similarity)))
                    except Exception:
                        # 嵌入解析失败，跳过
                        pass
                else:
                    # 没有嵌入，使用标题关键词匹配作为 fallback
                    if query.lower() in record.title.lower():
                        scored_results.append((record, 0.5))

            conn.close()

        # 按相似度排序
        scored_results.sort(key=lambda x: x[1], reverse=True)
        return scored_results[:top_k]

    def get_stats(self) -> dict:
        """获取统计信息"""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            stats = {}

            # 总记录数
            cursor.execute("SELECT COUNT(*) FROM knowledge_records")
            stats["total_records"] = cursor.fetchone()[0]

            # 按桶统计
            cursor.execute("""
                SELECT bucket, COUNT(*) as count
                FROM knowledge_records
                GROUP BY bucket
            """)
            stats["by_bucket"] = {row[0]: row[1] for row in cursor.fetchall()}

            # 按分类统计
            cursor.execute("""
                SELECT category, COUNT(*) as count
                FROM knowledge_records
                GROUP BY category
            """)
            stats["by_category"] = {row[0]: row[1] for row in cursor.fetchall()}

            # 平均置信度
            cursor.execute("SELECT AVG(confidence) FROM knowledge_records")
            stats["avg_confidence"] = cursor.fetchone()[0] or 0.0

            conn.close()
            return stats

    def _row_to_record(self, row: sqlite3.Row) -> KnowledgeRecord:
        """将数据库行转换为 KnowledgeRecord"""
        data = dict(row)

        # 解析 JSON 字段
        data["solution_steps"] = json.loads(data.get("solution_steps") or "[]")
        data["tools_used"] = json.loads(data.get("tools_used") or "[]")
        data["failure_reasons"] = json.loads(data.get("failure_reasons") or "[]")
        data["related_cves"] = json.loads(data.get("related_cves") or "[]")
        data["related_techniques"] = json.loads(data.get("related_techniques") or "[]")
        data["related_weaknesses"] = json.loads(data.get("related_weaknesses") or "[]")
        data["tags"] = json.loads(data.get("tags") or "[]")
        data["target_tech"] = json.loads(data.get("target_tech") or "[]")

        # 转换类型
        data["category"] = Category(data["category"])
        data["source"] = Source(data.get("source", "main_battle"))
        data["created_at"] = datetime.fromisoformat(data["created_at"])
        data["updated_at"] = datetime.fromisoformat(data["updated_at"])
        data["validated"] = bool(data["validated"])

        return KnowledgeRecord(**{k: v for k, v in data.items() if k in KnowledgeRecord.__dataclass_fields__})


# 全局单例
_knowledge_store: Optional[KnowledgeStore] = None
_store_lock = threading.Lock()


def get_knowledge_store() -> KnowledgeStore:
    """获取知识存储单例"""
    global _knowledge_store
    if _knowledge_store is None:
        with _store_lock:
            if _knowledge_store is None:
                db_path = os.environ.get(
                    "MULTI_CYBERSECURITY_KNOWLEDGE_DB",
                    "~/.multi-cybersecurity/knowledge.db"
                )
                _knowledge_store = KnowledgeStore(db_path)
    return _knowledge_store
