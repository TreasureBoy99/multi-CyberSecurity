"""
Context Guard - 上下文保护
=========================
防止 prompt 泄漏和保护敏感信息

设计参考:
- CyberStrike Intelligence Layer - Context Guard

功能:
- 敏感信息检测和脱敏
- Prompt 泄漏防护
- 上下文边界控制
- 输出过滤
"""

from .scanner import (
    SensitivityLevel,
    SensitiveInfo,
    ContextScanner,
    scan_text,
    scan_prompt,
)
from .redactor import (
    RedactionRule,
    Redactor,
    redact_sensitive,
)
from .guard import (
    GuardConfig,
    ContextGuard,
    protect_prompt,
    verify_output,
)

__all__ = [
    # Scanner
    "SensitivityLevel",
    "SensitiveInfo",
    "ContextScanner",
    "scan_text",
    "scan_prompt",
    # Redactor
    "RedactionRule",
    "Redactor",
    "redact_sensitive",
    # Guard
    "GuardConfig",
    "ContextGuard",
    "protect_prompt",
    "verify_output",
]
