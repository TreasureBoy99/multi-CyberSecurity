"""
LangGraph 集成
==============
将 LangGraph 用于复杂状态管理

设计参考:
- ai-pentester: LangGraph 编排复杂渗透测试流程
- 状态机 + 图结构

功能:
- 定义渗透测试状态图
- 条件边路由
- 状态持久化
- 断点恢复
"""

from .state import (
    PentestState,
    Stage,
    Finding,
    Target,
)
from .graph import (
    PentestGraph,
    create_pentest_graph,
)
from .nodes import (
    # 节点
    ReconNode,
    HuntNode,
    ValidateNode,
    ExploitNode,
    ReportNode,
    # 工厂
    create_standard_graph,
)

__all__ = [
    # State
    "PentestState",
    "Stage",
    "Finding",
    "Target",
    # Graph
    "PentestGraph",
    "create_pentest_graph",
    # Nodes
    "ReconNode",
    "HuntNode",
    "ValidateNode",
    "ExploitNode",
    "ReportNode",
    "create_standard_graph",
]
