"""
敏感信息脱敏器
==============
将敏感信息替换为占位符
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .scanner import SENSITIVE_PATTERNS, SensitivityLevel, SensitiveInfo


@dataclass
class RedactionRule:
    """脱敏规则"""
    name: str
    pattern: str
    replacement: str
    sensitivity: SensitivityLevel = SensitivityLevel.CONFIDENTIAL


class Redactor:
    """
    敏感信息脱敏器
    """

    # 默认脱敏映射
    DEFAULT_REDACTIONS = [
        # API Keys
        RedactionRule("api_key", r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})', '[REDACTED_API_KEY]', SensitivityLevel.SECRET),
        RedactionRule("github_token", r'(ghp_[a-zA-Z0-9]{36})', '[REDACTED_GITHUB_TOKEN]', SensitivityLevel.SECRET),
        RedactionRule("aws_key", r'(AKIA[0-9A-Z]{16})', '[REDACTED_AWS_KEY]', SensitivityLevel.SECRET),
        RedactionRule("password", r'(password["\']?\s*[:=]\s*["\'])([^"\']{8,})', r'\1[REDACTED_PASSWORD]', SensitivityLevel.SECRET),
        RedactionRule("private_key", r'(-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+\2?PRIVATE\s+KEY-----)', '[REDACTED_PRIVATE_KEY]', SensitivityLevel.SECRET),
        RedactionRule("jwt", r'(eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)', '[REDACTED_JWT]', SensitivityLevel.SECRET),

        # Internal IPs
        RedactionRule("internal_ip", r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3})', '[REDACTED_INTERNAL_IP]', SensitivityLevel.CONFIDENTIAL),
        RedactionRule("private_ip", r'(192\.168\.\d{1,3}\.\d{1,3})', '[REDACTED_PRIVATE_IP]', SensitivityLevel.CONFIDENTIAL),
        RedactionRule("localhost_ip", r'(127\.\d{1,3}\.\d{1,3}\.\d{1,3})', '[REDACTED_LOCALHOST_IP]', SensitivityLevel.INTERNAL),

        # Database connections
        RedactionRule("db_connection", r'(mysql|postgresql|mongodb(\+srv)?)://[^@]+@[^\s]+', '[REDACTED_DB_CONNECTION]', SensitivityLevel.SECRET),

        # URLs with credentials
        RedactionRule("url_creds", r'https?://[^:]+:[^@]+@[^\s]+', '[REDACTED_URL]', SensitivityLevel.SECRET),
    ]

    def __init__(self, custom_rules: list[RedactionRule] = None):
        self.rules = custom_rules or self.DEFAULT_REDACTIONS

    def redact(self, text: str) -> tuple[str, list[dict]]:
        """
        脱敏文本

        Args:
            text: 原始文本

        Returns:
            (脱敏后文本, 脱敏记录列表)
        """
        redactions = []
        redacted = text

        for rule in self.rules:
            matches = list(re.finditer(rule.pattern, redacted, re.IGNORECASE))
            if matches:
                redactions.append({
                    "rule": rule.name,
                    "count": len(matches),
                    "sensitivity": rule.sensitivity.value,
                })
                redacted = re.sub(rule.pattern, rule.replacement, redacted, flags=re.IGNORECASE)

        return redacted, redactions

    def redact_findings(self, text: str, findings: list[SensitiveInfo]) -> str:
        """
        根据扫描结果脱敏

        Args:
            text: 原始文本
            findings: 扫描发现

        Returns:
            脱敏后文本
        """
        redacted = text
        offset = 0

        for finding in sorted(findings, key=lambda f: f.start_pos):
            # 根据类型选择脱敏方式
            replacement = self._get_replacement(finding.info_type)
            start = finding.start_pos + offset
            end = finding.end_pos + offset

            if 0 <= start < end <= len(redacted):
                redacted = redacted[:start] + replacement + redacted[end:]
                offset += len(replacement) - (end - start)

        return redacted

    def _get_replacement(self, info_type: str) -> str:
        """获取类型的脱敏占位符"""
        replacements = {
            "api_key": "[REDACTED_API_KEY]",
            "api_secret": "[REDACTED_API_SECRET]",
            "google_api_key": "[REDACTED_GOOGLE_API_KEY]",
            "openai_api_key": "[REDACTED_OPENAI_KEY]",
            "github_token": "[REDACTED_GITHUB_TOKEN]",
            "gitlab_token": "[REDACTED_GITLAB_TOKEN]",
            "aws_access_key": "[REDACTED_AWS_KEY]",
            "aws_secret_key": "[REDACTED_AWS_SECRET]",
            "password": "[REDACTED_PASSWORD]",
            "secret": "[REDACTED_SECRET]",
            "token": "[REDACTED_TOKEN]",
            "bearer_token": "[REDACTED_BEARER_TOKEN]",
            "access_token": "[REDACTED_ACCESS_TOKEN]",
            "private_key": "[REDACTED_PRIVATE_KEY]",
            "ec_private_key": "[REDACTED_EC_KEY]",
            "ssh_private_key": "[REDACTED_SSH_KEY]",
            "jwt": "[REDACTED_JWT]",
            "db_connection": "[REDACTED_DB_CONNECTION]",
            "url_with_creds": "[REDACTED_URL]",
            "internal_ip": "[REDACTED_INTERNAL_IP]",
            "private_ip": "[REDACTED_PRIVATE_IP]",
            "localhost_ip": "[REDACTED_LOCALHOST_IP]",
            "internal_hostname": "[REDACTED_INTERNAL_HOST]",
            "system_file": "[REDACTED_SYSTEM_PATH]",
        }
        return replacements.get(info_type, "[REDACTED]")


# 全局脱敏器
_redactor = None


def get_redactor() -> Redactor:
    global _redactor
    if _redactor is None:
        _redactor = Redactor()
    return _redactor


def redact_sensitive(text: str) -> tuple[str, list[dict]]:
    """便捷脱敏函数"""
    return get_redactor().redact(text)
