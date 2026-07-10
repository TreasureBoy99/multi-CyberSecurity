"""
外部知识层网关
==============
统一的外部知识检索入口，实现门控策略：
1. 本地结构化经验层优先 (主战场/论坛分桶)
2. 受控触发的外部 WP 参考层
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from ..structured_layer.schema import Category, KnowledgeRecord
from ..structured_layer.knowledge_store import (
    KNOWLEDGE_BUCKET_MAIN,
    KNOWLEDGE_BUCKET_FORUM,
    KNOWLEDGE_BUCKET_EXTERNAL,
    get_knowledge_store,
)

logger = logging.getLogger(__name__)

# 配置
_EXTERNAL_KB_MODE = os.getenv("LING_XI_EXTERNAL_KB_MODE", "gated")  # gated / open
_EXTERNAL_KB_TRIGGER_FAILURES = int(os.getenv("EXTERNAL_KB_TRIGGER_FAILURES", "2"))
_DEFAULT_TOP_K = 3


class KnowledgeGateway:
    """
    知识网关 - 实现三层记忆的统一检索入口

    门控策略:
    - 本地经验永远高优先级
    - forum bucket 与 main bucket 严格隔离
    - 外部 WP 只有在门控条件满足时才进入主提示
    """

    def __init__(self):
        self.store = get_knowledge_store()
        self._failure_counts: dict[str, int] = {}  # 追踪每个目标的失败次数

    def search(
        self,
        query: str,
        challenge_id: Optional[str] = None,
        category: Optional[Category] = None,
        target_tech: Optional[list[str]] = None,
        mission_type: str = "web",
        failure_count: Optional[int] = None,
        top_k: int = _DEFAULT_TOP_K,
    ) -> list[KnowledgeRecord]:
        """
        统一知识检索入口

        Args:
            query: 搜索关键词
            challenge_id: 挑战/目标ID
            category: 知识分类
            target_tech: 目标技术栈
            mission_type: 任务类型 (web/mobile/api)
            failure_count: 当前失败次数 (用于门控判断)
            top_k: 返回数量

        Returns:
            检索到的知识记录列表
        """
        # 确定使用哪个桶
        bucket = KNOWLEDGE_BUCKET_MAIN if mission_type != "forum" else KNOWLEDGE_BUCKET_FORUM

        # 1. 首先检索本地结构化经验
        local_results = self._search_local(
            query=query,
            bucket=bucket,
            category=category,
            challenge_id=challenge_id,
            top_k=top_k,
        )

        # 本地经验高优先级，直接返回
        if local_results and local_results[0].confidence >= 0.72:
            logger.debug(f"Using local knowledge: {local_results[0].title}")
            return local_results

        # 2. 检查是否触发外部知识检索
        fc = failure_count if failure_count is not None else self._failure_counts.get(challenge_id or query, 0)

        if fc >= _EXTERNAL_KB_TRIGGER_FAILURES:
            # 触发外部知识检索
            external_results = self._search_external(
                query=query,
                category=category,
                top_k=top_k // 2,  # 外部知识只取一半
            )
            if external_results:
                # 合并结果，本地在前
                combined = local_results + external_results
                return combined[:top_k]

        # 3. 返回本地结果 (可能为空)
        return local_results

    def _search_local(
        self,
        query: str,
        bucket: str,
        category: Optional[Category],
        challenge_id: Optional[str],
        top_k: int,
    ) -> list[KnowledgeRecord]:
        """检索本地结构化经验"""
        try:
            return self.store.search(
                query=query,
                bucket=bucket,
                category=category,
                challenge_id=challenge_id,
                min_confidence=0.5,  # 本地经验阈值较低
                top_k=top_k,
            )
        except Exception as e:
            logger.error(f"Local search failed: {e}")
            return []

    def _search_external(
        self,
        query: str,
        category: Optional[Category],
        top_k: int,
    ) -> list[KnowledgeRecord]:
        """检索外部知识 (CTF WP 等)"""
        if _EXTERNAL_KB_MODE != "gated":
            try:
                return self.store.search(
                    query=query,
                    bucket=KNOWLEDGE_BUCKET_EXTERNAL,
                    category=category,
                    min_confidence=0.6,
                    top_k=top_k,
                )
            except Exception as e:
                logger.error(f"External search failed: {e}")
        return []

    def record_failure(self, challenge_id: str):
        """记录失败次数"""
        self._failure_counts[challenge_id] = self._failure_counts.get(challenge_id, 0) + 1

    def record_success(self, challenge_id: str):
        """记录成功，清除失败计数"""
        if challenge_id in self._failure_counts:
            del self._failure_counts[challenge_id]

    def writeback_experience(
        self,
        challenge_id: str,
        title: str,
        description: str,
        solution_steps: list[dict],
        tools_used: list[str],
        key_insights: str,
        category: Category = Category.WEB,
        related_cves: Optional[list[str]] = None,
        failure_reasons: Optional[list[dict]] = None,
        target_tech: Optional[list[str]] = None,
        mission_type: str = "main_battle",
    ) -> bool:
        """
        将经验写回知识库

        Args:
            challenge_id: 挑战ID
            title: 标题
            description: 描述
            solution_steps: 解决步骤
            tools_used: 使用的工具
            key_insights: 关键洞察
            category: 分类
            related_cves: 关联CVE
            failure_reasons: 失败原因
            target_tech: 目标技术
            mission_type: 经验来源 (main_battle/forum/manual)

        Returns:
            是否成功
        """
        from ..structured_layer.schema import SolutionStep, FailureReason, Source

        bucket = KNOWLEDGE_BUCKET_MAIN if mission_type == "main_battle" else KNOWLEDGE_BUCKET_FORUM

        record = KnowledgeRecord(
            record_id=f"{challenge_id}_{int(datetime.now().timestamp())}",
            category=category,
            subcategory="",
            title=title,
            description=description,
            challenge_id=challenge_id,
            solution_steps=[SolutionStep(**s) for s in solution_steps],
            tools_used=tools_used,
            key_insights=key_insights,
            failure_reasons=[FailureReason(**f) for f in (failure_reasons or [])],
            related_cves=related_cves or [],
            confidence=0.8,  # 新记录初始置信度
            source=Source.MAIN_BATTLE if mission_type == "main_battle" else Source.FORUM,
            tags=target_tech or [],
            target_tech=target_tech or [],
        )

        return self.store.add_record(record, bucket=bucket)

    def get_context_for_prompt(
        self,
        query: str,
        challenge_id: Optional[str] = None,
        category: Category = Category.WEB,
        mission_type: str = "web",
        max_contexts: int = 3,
    ) -> str:
        """
        生成用于注入到 Agent Prompt 的上下文

        Returns:
            格式化的知识上下文字符串
        """
        results = self.search(
            query=query,
            challenge_id=challenge_id,
            category=category,
            mission_type=mission_type,
            top_k=max_contexts,
        )

        if not results:
            return ""

        contexts = []
        for i, record in enumerate(results, 1):
            # 标记访问
            self.store.record_access(record.record_id)

            context = f"""
## 相关经验 {i}: {record.title}
**置信度**: {record.confidence:.0%}
**工具**: {', '.join(record.tools_used)}
**关键洞察**: {record.key_insights}
"""
            if record.solution_steps:
                steps = "\n".join(
                    f"  {s.step_order}. {s.action} ({s.tool_used})"
                    for s in record.solution_steps[:5]  # 最多5步
                )
                context += f"**步骤**:\n{steps}\n"

            contexts.append(context)

        return "\n---\n".join(contexts)


# 全局单例
_gateway: Optional[KnowledgeGateway] = None
_gateway_lock = threading.Lock()


def get_knowledge_gateway() -> KnowledgeGateway:
    """获取知识网关单例"""
    global _gateway
    if _gateway is None:
        with _gateway_lock:
            if _gateway is None:
                _gateway = KnowledgeGateway()
    return _gateway


# 需要 threading 模块
import threading
from datetime import datetime
