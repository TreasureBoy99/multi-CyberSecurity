"""
敏感信息扫描器
==============
检测文本中的敏感信息
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SensitivityLevel(str, Enum):
    """敏感等级"""
    PUBLIC = "public"           # 公开
    INTERNAL = "internal"       # 内部
    CONFIDENTIAL = "confidential"  # 机密
    SECRET = "secret"           # 绝密


@dataclass
class SensitiveInfo:
    """敏感信息"""
    info_type: str              # 类型: api_key, password, token, etc.
    value: str                  # 原始值 (已脱敏)
    pattern: str                # 检测使用的模式
    start_pos: int             # 起始位置
    end_pos: int               # 结束位置
    sensitivity: SensitivityLevel = SensitivityLevel.CONFIDENTIAL

    def to_dict(self) -> dict:
        return {
            "type": self.info_type,
            "value": self.value,
            "sensitivity": self.sensitivity.value,
        }


# 敏感信息检测规则
SENSITIVE_PATTERNS = [
    # API Keys
    (r'api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}', "api_key", SensitivityLevel.SECRET),
    (r'api[_-]?secret["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}', "api_secret", SensitivityLevel.SECRET),
    (r'AIza[a-zA-Z0-9_\-]{35}', "google_api_key", SensitivityLevel.SECRET),
    (r'SK-[a-zA-Z0-9]{48}', "openai_api_key", SensitivityLevel.SECRET),
    (r'ghp_[a-zA-Z0-9]{36}', "github_token", SensitivityLevel.SECRET),
    (r'gho_[a-zA-Z0-9]{36}', "github_oauth", SensitivityLevel.SECRET),
    (r'glpat-[a-zA-Z0-9_\-]{20}', "gitlab_token", SensitivityLevel.SECRET),

    # AWS Keys
    (r'AKIA[0-9A-Z]{16}', "aws_access_key", SensitivityLevel.SECRET),
    (r'[A-Za-z0-9/+=]{40}', "aws_secret_key", SensitivityLevel.SECRET),

    # Passwords
    (r'password["\']?\s*[:=]\s*["\'][^"\']{8,}', "password", SensitivityLevel.SECRET),
    (r'passwd["\']?\s*[:=]\s*["\'][^"\']{8,}', "password", SensitivityLevel.SECRET),
    (r'secret["\']?\s*[:=]\s*["\'][^"\']{8,}', "secret", SensitivityLevel.SECRET),

    # Tokens
    (r'bearer\s+[a-zA-Z0-9_\-\.]{20,}', "bearer_token", SensitivityLevel.SECRET),
    (r'token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-\.]{20,}', "token", SensitivityLevel.SECRET),
    (r'access[_-]?token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-\.]{20,}', "access_token", SensitivityLevel.SECRET),

    # Private Keys
    (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', "private_key", SensitivityLevel.SECRET),
    (r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----', "ec_private_key", SensitivityLevel.SECRET),
    (r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----', "ssh_private_key", SensitivityLevel.SECRET),

    # Database Connection
    (r'mysql:\/\/[a-zA-Z0-9]+:[^@\s]+@', "db_connection", SensitivityLevel.SECRET),
    (r'postgresql:\/\/[a-zA-Z0-9]+:[^@\s]+@', "db_connection", SensitivityLevel.SECRET),
    (r'mongodb(\+srv)?:\/\/[a-zA-Z0-9]+:[^@\s]+@', "db_connection", SensitivityLevel.SECRET),

    # JWT
    (r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+', "jwt", SensitivityLevel.SECRET),

    # IP Addresses (内部)
    (r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', "internal_ip", SensitivityLevel.CONFIDENTIAL),
    (r'172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}', "internal_ip", SensitivityLevel.CONFIDENTIAL),
    (r'192\.168\.\d{1,3}\.\d{1,3}', "internal_ip", SensitivityLevel.CONFIDENTIAL),
    (r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}', "localhost_ip", SensitivityLevel.INTERNAL),

    # Hostnames
    (r'[a-zA-Z0-9]+\.internal\.[a-zA-Z]+', "internal_hostname", SensitivityLevel.CONFIDENTIAL),
    (r'[a-zA-Z0-9]+\.localdomain', "local_hostname", SensitivityLevel.INTERNAL),

    # URLs with credentials
    (r'https?:\/\/[a-zA-Z0-9]+:[^@\s]+@[^\s]+', "url_with_creds", SensitivityLevel.SECRET),

    # Internal paths
    (r'/etc/shadow', "system_file", SensitivityLevel.SECRET),
    (r'/etc/passwd', "system_file", SensitivityLevel.INTERNAL),
    (r'C:\\Windows\\System32', "system_path", SensitivityLevel.INTERNAL),
]


class ContextScanner:
    """
    敏感信息扫描器
    """

    def __init__(self):
        self.rules = SENSITIVE_PATTERNS

    def scan(self, text: str) -> list[SensitiveInfo]:
        """
        扫描文本中的敏感信息

        Args:
            text: 待扫描文本

        Returns:
            发现的敏感信息列表
        """
        findings = []

        for pattern, info_type, sensitivity in self.rules:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                findings.append(SensitiveInfo(
                    info_type=info_type,
                    value=match.group(0)[:20] + "..." if len(match.group(0)) > 20 else match.group(0),
                    pattern=pattern,
                    start_pos=match.start(),
                    end_pos=match.end(),
                    sensitivity=sensitivity,
                ))

        return findings

    def scan_and_classify(self, text: str) -> dict[SensitivityLevel, list[SensitiveInfo]]:
        """
        扫描并按敏感等级分类

        Args:
            text: 待扫描文本

        Returns:
            按敏感等级分类的结果
        """
        findings = self.scan(text)
        classified = {
            SensitivityLevel.PUBLIC: [],
            SensitivityLevel.INTERNAL: [],
            SensitivityLevel.CONFIDENTIAL: [],
            SensitivityLevel.SECRET: [],
        }

        for f in findings:
            classified[f.sensitivity].append(f)

        return classified

    def has_secrets(self, text: str) -> bool:
        """检查是否包含机密信息"""
        findings = self.scan(text)
        return any(f.sensitivity == SensitivityLevel.SECRET for f in findings)

    def has_internal(self, text: str) -> bool:
        """检查是否包含内部信息"""
        findings = self.scan(text)
        return any(f.sensitivity in (SensitivityLevel.INTERNAL, SensitivityLevel.CONFIDENTIAL, SensitivityLevel.SECRET) for f in findings)


# 全局扫描器
_scanner = None


def get_scanner() -> ContextScanner:
    global _scanner
    if _scanner is None:
        _scanner = ContextScanner()
    return _scanner


def scan_text(text: str) -> list[SensitiveInfo]:
    """便捷扫描函数"""
    return get_scanner().scan(text)


def scan_prompt(prompt: str) -> dict:
    """
    扫描 prompt 并返回安全评估

    Returns:
        {"safe": bool, "findings": [...], "level": "public|internal|confidential|secret"}
    """
    scanner = get_scanner()
    findings = scanner.scan(prompt)

    level = SensitivityLevel.PUBLIC
    if any(f.sensitivity == SensitivityLevel.SECRET for f in findings):
        level = SensitivityLevel.SECRET
    elif any(f.sensitivity == SensitivityLevel.CONFIDENTIAL for f in findings):
        level = SensitivityLevel.CONFIDENTIAL
    elif any(f.sensitivity == SensitivityLevel.INTERNAL for f in findings):
        level = SensitivityLevel.INTERNAL

    return {
        "safe": level == SensitivityLevel.PUBLIC,
        "findings": [f.to_dict() for f in findings],
        "level": level.value,
        "has_secrets": level == SensitivityLevel.SECRET,
    }
