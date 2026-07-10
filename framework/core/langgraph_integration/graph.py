"""
LangGraph 图构建器
=================
创建 LangGraph 工作流
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from .state import PentestState, Stage
from .nodes import create_standard_graph, BaseNode

logger = logging.getLogger(__name__)


# LangGraph 可选导入
LANGGRAPH_AVAILABLE = False
try:
    from langgraph.graph import StateGraph, END
    from langgraph.checkpoint import MemorySaver
    LANGGRAPH_AVAILABLE = True
except ImportError:
    logger.warning("LangGraph not installed. Graph functionality will be limited.")


class PentestGraph:
    """
    渗透测试图

    基于 LangGraph 的工作流编排器
    """

    def __init__(self, checkpointer=None):
        """
        初始化

        Args:
            checkpointer: 状态持久化检查点
        """
        self.checkpointer = checkpointer or (MemorySaver() if LANGGRAPH_AVAILABLE else None)
        self.graph = None
        self.compiled = None
        self._nodes = {}
        self._edges = []

    def add_node(self, name: str, node: BaseNode):
        """添加节点"""
        self._nodes[name] = node
        logger.debug(f"Added node: {name}")

    def add_edge(self, from_node: str, to_node: str, condition: Optional[Any] = None):
        """添加边"""
        self._edges.append({
            "from": from_node,
            "to": to_node,
            "condition": condition,
        })

    def build(self) -> Any:
        """构建图"""
        if not LANGGRAPH_AVAILABLE:
            logger.error("LangGraph not available, cannot build graph")
            return None

        # 创建 StateGraph
        workflow = StateGraph(PentestState)

        # 添加节点
        for name, node in self._nodes.items():
            workflow.add_node(name, node)

        # 设置入口点
        workflow.set_entry_point("recon")

        # 添加边
        for edge in self._edges:
            if edge["condition"]:
                # 条件边
                workflow.add_conditional_edges(
                    edge["from"],
                    edge["condition"],
                    {
                        edge["to"]: edge["to"],
                    }
                )
            else:
                # 普通边
                workflow.add_edge(edge["from"], edge["to"])

        # 设置结束点
        workflow.add_edge("report", END)

        # 编译
        if self.checkpointer:
            self.compiled = workflow.compile(checkpointer=self.checkpointer)
        else:
            self.compiled = workflow.compile()

        self.graph = workflow
        return self.compiled

    def run(self, initial_state: PentestState) -> PentestState:
        """
        运行工作流

        Args:
            initial_state: 初始状态

        Returns:
            最终状态
        """
        if not self.compiled:
            self.build()

        if not self.compiled:
            logger.error("Graph not compiled")
            return initial_state

        try:
            result = self.compiled.invoke(initial_state)
            return result
        except Exception as e:
            logger.error(f"Graph execution error: {e}")
            initial_state.add_error(str(e))
            return initial_state

    def run_with_history(self, initial_state: PentestState, thread_id: str = "default"):
        """
        带历史的运行（支持断点恢复）

        Args:
            initial_state: 初始状态
            thread_id: 线程 ID

        Returns:
            最终状态
        """
        if not self.compiled:
            self.build()

        if not self.compiled:
            return initial_state

        try:
            result = self.compiled.invoke(
                initial_state,
                config={"configurable": {"thread_id": thread_id}}
            )
            return result
        except Exception as e:
            logger.error(f"Graph execution error: {e}")
            initial_state.add_error(str(e))
            return initial_state


def create_pentest_graph(config: Optional[dict] = None) -> PentestGraph:
    """
    创建渗透测试图

    Args:
        config: 配置

    Returns:
        PentestGraph 实例
    """
    graph = PentestGraph()

    # 获取标准节点
    standard = create_standard_graph()

    # 添加节点
    for name, node in standard["nodes"].items():
        graph.add_node(name, node)

    # 添加边
    graph.add_edge("recon", "hunt")
    graph.add_edge("hunt", "validate")
    graph.add_edge("validate", "hunt")
    graph.add_edge("validate", "exploit")
    graph.add_edge("exploit", "report")
    graph.add_edge("hunt", "report")
    graph.add_edge("validate", "report")

    return graph


# 兼容性别名
def create_langgraph_workflow() -> PentestGraph:
    """创建 LangGraph 工作流 (兼容性别名)"""
    return create_pentest_graph()
