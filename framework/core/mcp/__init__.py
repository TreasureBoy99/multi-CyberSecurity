"""
MCP Server 标准化
=================
统一工具接口规范和注册机制

设计参考:
- CyberStrike Intelligence Layer (Schema Normalization)
- HexStrike AI MCP (150+ 工具)
- pentest-ai (47 MCP 调用 200+ 工具)

功能:
- 统一工具注册表
- 工具元数据规范
- 工具路由和调用
- 参数验证
"""

from .registry import (
    ToolMetadata,
    ToolCategory,
    ToolRegistry,
    get_registry,
    register_tool,
    list_tools,
)
from .router import (
    ToolRouter,
    RouteContext,
    route_tool,
)
from .validators import (
    ValidationResult,
    validate_tool_params,
)

__all__ = [
    # Registry
    "ToolMetadata",
    "ToolCategory",
    "ToolRegistry",
    "get_registry",
    "register_tool",
    "list_tools",
    # Router
    "ToolRouter",
    "RouteContext",
    "route_tool",
    # Validators
    "ValidationResult",
    "validate_tool_params",
]
