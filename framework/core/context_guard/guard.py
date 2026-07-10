"""
Context Guard - 上下文保护器
===========================
整合扫描和脱敏，保护 prompt 安全
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .scanner import ContextScanner, SensitivityLevel, SensitiveInfo, scan_prompt
from .redactor import Redactor, redact_sensitive


class GuardAction(str, Enum):
    """Guard 动作"""
    ALLOW = "allow"                 # 允许
    REDACT = "redact"              # 脱敏后允许
    BLOCK = "block"                 # 阻止
    WARN = "warn"                   # 警告


@dataclass
class GuardConfig:
    """Guard 配置"""
    # 敏感等级阈值
    block_level: SensitivityLevel = SensitivityLevel.SECRET
    warn_level: SensitivityLevel = SensitivityLevel.CONFIDENTIAL
    redact_level: SensitivityLevel = SensitivityLevel.CONFIDENTIAL

    # 动作
    on_secret: GuardAction = GuardAction.BLOCK
    on_confidential: GuardAction = GuardAction.REDACT
    on_internal: GuardAction = GuardAction.WARN

    # 白名单 (不脱敏的模式)
    whitelist_patterns: list[str] = field(default_factory=list)

    # 是否启用
    enabled: bool = True

    # 日志
    log_all: bool = False          # 记录所有检测
    log_blocks: bool = True        # 记录阻止


class GuardResult:
    """Guard 结果"""
    def __init__(
        self,
        action: GuardAction,
        safe: bool,
        level: SensitivityLevel,
        redacted_text: Optional[str] = None,
        findings: list[dict] = None,
        message: str = "",
    ):
        self.action = action
        self.safe = safe
        self.level = level
        self.redacted_text = redacted_text
        self.findings = findings or []
        self.message = message

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "safe": self.safe,
            "level": self.level.value,
            "redacted_text": self.redacted_text,
            "findings": self.findings,
            "message": self.message,
        }


class ContextGuard:
    """
    上下文保护器

    功能:
    - 检测敏感信息
    - 自动脱敏
    - 阻止高危内容
    - 审计日志
    """

    def __init__(self, config: Optional[GuardConfig] = None):
        self.config = config or GuardConfig()
        self.scanner = ContextScanner()
        self.redactor = Redactor()

    def protect(self, text: str, allow_redacted: bool = True) -> GuardResult:
        """
        保护文本

        Args:
            text: 待保护文本
            allow_redacted: 是否允许脱敏后的文本通过

        Returns:
            GuardResult
        """
        if not self.config.enabled:
            return GuardResult(
                action=GuardAction.ALLOW,
                safe=True,
                level=SensitivityLevel.PUBLIC,
                message="Guard disabled",
            )

        # 扫描
        findings = self.scanner.scan(text)

        # 确定敏感等级
        level = SensitivityLevel.PUBLIC
        for f in findings:
            if f.sensitivity == SensitivityLevel.SECRET:
                level = SensitivityLevel.SECRET
                break
            elif f.sensitivity == SensitivityLevel.CONFIDENTIAL and level != SensitivityLevel.SECRET:
                level = SensitivityLevel.CONFIDENTIAL
            elif f.sensitivity == SensitivityLevel.INTERNAL and level not in (SensitivityLevel.SECRET, SensitivityLevel.CONFIDENTIAL):
                level = SensitivityLevel.INTERNAL

        # 根据等级决定动作
        if level >= self.config.block_level:
            action = GuardAction.BLOCK
            safe = False
            message = f"Blocked: contains {level.value} information"
            redacted_text = None

        elif level >= self.config.redact_level:
            if allow_redacted:
                action = GuardAction.REDACT
                safe = True
                redacted_text, _ = self.redactor.redact(text)
                message = f"Redacted: contains {level.value} information"
            else:
                action = GuardAction.BLOCK
                safe = False
                redacted_text = None
                message = f"Blocked: contains {level.value} information (redaction not allowed)"

        elif level >= self.config.warn_level:
            action = GuardAction.WARN
            safe = True
            redacted_text = text
            message = f"Warning: contains {level.value} information"

        else:
            action = GuardAction.ALLOW
            safe = True
            redacted_text = text
            message = "Allowed"

        return GuardResult(
            action=action,
            safe=safe,
            level=level,
            redacted_text=redacted_text,
            findings=[f.to_dict() for f in findings],
            message=message,
        )

    def protect_prompt(self, prompt: str) -> GuardResult:
        """
        保护 prompt

        专门用于保护 LLM prompt
        """
        return self.protect(prompt, allow_redacted=True)

    def verify_output(self, output: str) -> GuardResult:
        """
        验证输出

        检查输出中是否包含敏感信息（如泄露的上下文）
        """
        return self.protect(output, allow_redacted=False)

    def check(self, text: str) -> bool:
        """
        快速检查文本是否安全

        Returns:
            是否安全
        """
        result = self.protect(text, allow_redacted=False)
        return result.safe


# 全局 Guard 实例
_guard = None


def get_guard() -> ContextGuard:
    global _guard
    if _guard is None:
        _guard = ContextGuard()
    return _guard


def protect_prompt(prompt: str) -> GuardResult:
    """便捷函数：保护 prompt"""
    return get_guard().protect_prompt(prompt)


def verify_output(output: str) -> GuardResult:
    """便捷函数：验证输出"""
    return get_guard().verify_output(output)
