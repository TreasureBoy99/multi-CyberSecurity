"""
Framework Core
==============

核心模块:
- orchestrator: 任务编排器 (增强多级预算控制)
- pipeline: 8阶段安全审计管道
- blackboard: 信息素黑板 (Phase 2)
- agent_registry: Agent 注册表
- redteam_gateway: 红队网关
"""

from .orchestrator import MissionOrchestrator, BudgetController
from .pipeline import Pipeline, Stage
from .agent_registry import AgentRegistry, get_registry

# Blackboard (Phase 2)
from .blackboard import (
    FindingType,
    Finding,
    Predicate,
    Budget,
    AgentBudget,
    CampaignConfig,
    Board,
    MemoryBoard,
    get_board,
    Scheduler,
    Agent,
    SchedulerEvent,
)

__all__ = [
    # Core
    "MissionOrchestrator",
    "BudgetController",
    "Pipeline",
    "Stage",
    "AgentRegistry",
    "get_registry",
    # Blackboard
    "FindingType",
    "Finding",
    "Predicate",
    "Budget",
    "AgentBudget",
    "CampaignConfig",
    "Board",
    "MemoryBoard",
    "get_board",
    "Scheduler",
    "Agent",
    "SchedulerEvent",
]
