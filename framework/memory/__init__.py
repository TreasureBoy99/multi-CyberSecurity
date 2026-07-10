"""
三层记忆系统 (Three-Layer Memory System)
=========================================

架构:
┌─────────────────────────────────────────────────────────────┐
│                    Knowledge Gateway                         │
│  门控策略: 本地经验优先 > 外部WP(受控触发)                   │
└─────────────────────────────────────────────────────────────┘
         ↓                  ↓                  ↓
┌────────────────┐  ┌────────────────┐  ┌────────────────┐
│   Hot Layer    │  │ Structured     │  │   External     │
│ (SessionMemory)│  │ (KnowledgeStore)│  │ (KnowledgeGW)  │
│   运行记忆     │  │   结构化经验    │  │   外部知识     │
└────────────────┘  └────────────────┘  └────────────────┘

使用示例:
    from framework.memory import get_knowledge_gateway, get_knowledge_store

    # 知识检索
    gateway = get_knowledge_gateway()
    results = gateway.search("SQL injection", category=Category.WEB)

    # 经验写入
    gateway.writeback_experience(
        challenge_id="vuln-001",
        title="SQL Injection in login form",
        solution_steps=[...],
        tools_used=["sqlmap", "burpsuite"],
        key_insights="使用 OR 1=1 绕过认证",
    )

    # 获取用于Prompt的上下文
    context = gateway.get_context_for_prompt("SQL injection", max_contexts=3)
"""

from .hot_layer import SessionMemory, SessionContext, HotFinding
from .structured_layer import (
    Category,
    KnowledgeRecord,
    SolutionStep,
    FailureReason,
    Source,
    KnowledgeStore,
    get_knowledge_store,
)
from .external_layer import KnowledgeGateway, get_knowledge_gateway

__all__ = [
    # Hot Layer
    "SessionMemory",
    "SessionContext",
    "HotFinding",
    # Structured Layer
    "Category",
    "KnowledgeRecord",
    "SolutionStep",
    "FailureReason",
    "Source",
    "KnowledgeStore",
    "get_knowledge_store",
    # External Layer
    "KnowledgeGateway",
    "get_knowledge_gateway",
]
