"""
Oracle 验证器核心
================
漏洞重放验证引擎

功能:
- 生成 proof capsule (可重放验证包)
- 执行漏洞重放验证
- 返回验证结果和可信度
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

logger = logging.getLogger(__name__)


class VerificationStatus(str, Enum):
    """验证状态"""
    PENDING = "pending"           # 待验证
    VERIFIED = "verified"         # 已验证 (真实漏洞)
    EXPLOITABLE = "exploitable"   # 可利用
    FALSE_POSITIVE = "false_positive"  # 误报
    UNCERTAIN = "uncertain"       # 不确定
    ERROR = "error"               # 验证错误
    TIMEOUT = "timeout"           # 验证超时


@dataclass
class ProofCapsule:
    """
    漏洞验证胶囊 (Proof Capsule)

    包含验证漏洞所需的所有信息，可重放验证
    """
    capsule_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""          # 原始发现 ID
    vulnerability_type: str = ""  # 漏洞类型: sql_injection, xss, etc.
    target_url: str = ""
    method: str = "GET"           # HTTP 方法
    path: str = ""
    params: dict = field(default_factory=dict)  # 查询参数
    headers: dict = field(default_factory=dict)
    body: Optional[str] = None

    # Payload 信息
    original_payload: str = ""    # 原始 payload
    verification_payload: str = ""  # 验证用 payload

    # 预期响应
    expected_response_pattern: str = ""  # 响应匹配模式
    time_based_check: bool = False  # 是否时间盲注

    # 元数据
    confidence: float = 0.0       # 置信度
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    expires_at: str = ""

    def to_dict(self) -> dict:
        """序列化为字典"""
        return asdict(self)

    def to_json(self) -> str:
        """序列化为 JSON"""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @property
    def checksum(self) -> str:
        """计算校验和"""
        data = f"{self.target_url}{self.method}{self.path}{self.verification_payload}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]


@dataclass
class VerificationResult:
    """验证结果"""
    capsule_id: str
    status: VerificationStatus
    finding_id: str

    # 验证详情
    is_verified: bool = False
    is_exploitable: bool = False
    is_false_positive: bool = False

    # 响应信息
    response_code: int = 0
    response_body_preview: str = ""
    response_time_ms: float = 0.0

    # 可信度
    confidence: float = 0.0       # 最终置信度
    verification_confidence: float = 0.0  # 验证过程置信度

    # 错误信息
    error_message: str = ""

    # 重放详情
    replay_count: int = 0
    last_replay_at: str = ""

    def to_dict(self) -> dict:
        return {
            "capsule_id": self.capsule_id,
            "status": self.status.value,
            "finding_id": self.finding_id,
            "is_verified": self.is_verified,
            "is_exploitable": self.is_exploitable,
            "is_false_positive": self.is_false_positive,
            "response_code": self.response_code,
            "confidence": self.confidence,
            "verification_confidence": self.verification_confidence,
            "error_message": self.error_message,
            "replay_count": self.replay_count,
        }


class OracleVerifier:
    """
    Oracle 验证器

    通过重放漏洞验证其真实性和可利用性
    """

    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        verify_ssl: bool = False,
    ):
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl

        # 验证规则
        self._verification_rules = self._init_verification_rules()

    def _init_verification_rules(self) -> dict:
        """初始化验证规则"""
        return {
            "sql_injection": {
                "method": "response_diff",
                "true_payloads": ["' OR '1'='1", "' OR 1=1--", "1' AND 1=1--"],
                "false_payloads": ["' AND '1'='2", "1' AND 1=2--"],
                "true_indicators": ["error", "syntax", "mysql", "oracle", "sql"],
                "false_indicators": ["invalid", "not found"],
                "time_based": True,
                "time_threshold_ms": 3000,
            },
            "xss": {
                "method": "reflection",
                "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
                "reflection_indicators": ["<script>", "<img", "alert(1)"],
            },
            "command_injection": {
                "method": "time_based",
                "payloads": [";sleep 3", "|sleep 3", "&&sleep 3"],
                "time_threshold_ms": 2500,
            },
            "ssrf": {
                "method": "out_of_band",
                "payloads": ["http://127.0.0.1", "http://localhost"],
                "indicators": ["connected", "refused", "timeout"],
            },
            "xxe": {
                "method": "response_diff",
                "payloads": ["<?xml version=\"1.0\"?><!DOCTYPE foo SYSTEM \"file:///etc/passwd\">"],
                "indicators": ["root:x:", "daemon:", "bin:"],
            },
            "path_traversal": {
                "method": "file_check",
                "payloads": ["../../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
                "indicators": ["root:x:", "[extensions]"],
            },
        }

    def generate_capsule(
        self,
        finding_id: str,
        vuln_type: str,
        target_url: str,
        original_payload: str,
        **kwargs,
    ) -> ProofCapsule:
        """
        为发现生成验证胶囊

        Args:
            finding_id: 发现 ID
            vuln_type: 漏洞类型
            target_url: 目标 URL
            original_payload: 原始 payload
            **kwargs: 其他参数 (method, params, headers, body)

        Returns:
            ProofCapsule
        """
        rule = self._verification_rules.get(vuln_type, {})
        method = kwargs.get("method", "GET")
        params = kwargs.get("params", {})
        headers = kwargs.get("headers", {})
        body = kwargs.get("body", None)

        parsed = urlparse(target_url)
        path = kwargs.get("path", parsed.path or "/")

        # 选择验证 payload
        verification_payloads = rule.get("true_payloads", [original_payload])
        verification_payload = verification_payloads[0] if verification_payloads else original_payload

        # 构建验证胶囊
        capsule = ProofCapsule(
            capsule_id=str(uuid.uuid4()),
            finding_id=finding_id,
            vulnerability_type=vuln_type,
            target_url=target_url,
            method=method,
            path=path,
            params=params,
            headers=headers,
            body=body,
            original_payload=original_payload,
            verification_payload=verification_payload,
            time_based_check=rule.get("time_based", False),
            confidence=0.0,
        )

        return capsule

    def verify(self, capsule: ProofCapsule) -> VerificationResult:
        """
        验证漏洞

        Args:
            capsule: 验证胶囊

        Returns:
            VerificationResult
        """
        rule = self._verification_rules.get(capsule.vulnerability_type, {})

        result = VerificationResult(
            capsule_id=capsule.capsule_id,
            status=VerificationStatus.PENDING,
            finding_id=capsule.finding_id,
        )

        try:
            start_time = time.time()

            # 根据验证方法执行
            method = rule.get("method", "response_diff")

            if method == "response_diff":
                result = self._verify_response_diff(capsule, rule, result)
            elif method == "reflection":
                result = self._verify_reflection(capsule, rule, result)
            elif method == "time_based":
                result = self._verify_time_based(capsule, rule, result)
            elif method == "out_of_band":
                result = self._verify_out_of_band(capsule, rule, result)
            else:
                result.status = VerificationStatus.ERROR
                result.error_message = f"Unknown verification method: {method}"

            result.response_time_ms = (time.time() - start_time) * 1000

        except Exception as e:
            logger.error(f"Verification error: {e}")
            result.status = VerificationStatus.ERROR
            result.error_message = str(e)

        return result

    def _verify_response_diff(
        self,
        capsule: ProofCapsule,
        rule: dict,
        result: VerificationResult,
    ) -> VerificationResult:
        """响应差异验证"""
        import urllib.request

        # 构造测试请求
        true_payloads = rule.get("true_payloads", [])
        false_payloads = rule.get("false_payloads", [])

        # 简单实现：发送正常请求和恶意请求，比较响应
        try:
            # 发送验证 payload
            test_url = capsule.target_url
            if capsule.params:
                # 替换或添加 payload
                test_params = capsule.params.copy()
                test_params["q"] = capsule.verification_payload
                test_url = f"{test_url}?{urlencode(test_params)}"

            req = urllib.request.Request(
                test_url,
                headers=capsule.headers,
                method=capsule.method,
            )
            if capsule.body:
                req.data = capsule.body.encode()

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                response_body = resp.read().decode('utf-8', errors='ignore')
                result.response_code = resp.getcode()
                result.response_body_preview = response_body[:500]

            # 检查响应中是否包含 true indicators
            true_indicators = rule.get("true_indicators", [])
            body_lower = response_body.lower()

            matched_indicators = [
                ind for ind in true_indicators
                if ind.lower() in body_lower
            ]

            if matched_indicators:
                result.status = VerificationStatus.VERIFIED
                result.is_verified = True
                result.confidence = 0.85
                result.verification_confidence = len(matched_indicators) / len(true_indicators)
            else:
                result.status = VerificationStatus.FALSE_POSITIVE
                result.is_false_positive = True
                result.confidence = 0.7

        except urllib.error.HTTPError as e:
            result.response_code = e.code
            result.status = VerificationStatus.UNCERTAIN
            result.confidence = 0.5
        except Exception as e:
            result.status = VerificationStatus.ERROR
            result.error_message = str(e)

        return result

    def _verify_reflection(
        self,
        capsule: ProofCapsule,
        rule: dict,
        result: VerificationResult,
    ) -> VerificationResult:
        """反射验证 (XSS)"""
        import urllib.request

        try:
            # 发送 XSS payload
            test_url = capsule.target_url
            if capsule.params:
                test_params = capsule.params.copy()
                test_params["q"] = capsule.verification_payload
                test_url = f"{test_url}?{urlencode(test_params)}"

            req = urllib.request.Request(test_url, headers=capsule.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                response_body = resp.read().decode('utf-8', errors='ignore')
                result.response_code = resp.getcode()
                result.response_body_preview = response_body[:500]

            # 检查 payload 是否被反射
            if capsule.verification_payload in response_body:
                result.status = VerificationStatus.VERIFIED
                result.is_verified = True
                result.confidence = 0.8
            else:
                result.status = VerificationStatus.FALSE_POSITIVE
                result.is_false_positive = True
                result.confidence = 0.75

        except Exception as e:
            result.status = VerificationStatus.ERROR
            result.error_message = str(e)

        return result

    def _verify_time_based(
        self,
        capsule: ProofCapsule,
        rule: dict,
        result: VerificationResult,
    ) -> VerificationResult:
        """时间盲注验证"""
        import urllib.request

        time_threshold = rule.get("time_threshold_ms", 3000)

        try:
            # 发送带延时的 payload
            test_url = capsule.target_url
            if capsule.params:
                test_params = capsule.params.copy()
                test_params["q"] = capsule.verification_payload
                test_url = f"{test_url}?{urlencode(test_params)}"

            start = time.time()
            req = urllib.request.Request(test_url, headers=capsule.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                response_body = resp.read().decode('utf-8', errors='ignore')
                elapsed_ms = (time.time() - start) * 1000

            result.response_code = resp.getcode()
            result.response_body_preview = response_body[:500]
            result.response_time_ms = elapsed_ms

            # 检查响应时间
            if elapsed_ms >= time_threshold:
                result.status = VerificationStatus.VERIFIED
                result.is_verified = True
                result.confidence = 0.9
            else:
                result.status = VerificationStatus.UNCERTAIN
                result.confidence = 0.4

        except urllib.error.HTTPError:
            result.status = VerificationStatus.UNCERTAIN
            result.confidence = 0.3
        except Exception as e:
            result.status = VerificationStatus.ERROR
            result.error_message = str(e)

        return result

    def _verify_out_of_band(
        self,
        capsule: ProofCapsule,
        rule: dict,
        result: VerificationResult,
    ) -> VerificationResult:
        """外带验证 (SSRF)"""
        import urllib.request

        try:
            # 发送 SSRF payload
            test_url = capsule.target_url
            if capsule.params:
                test_params = capsule.params.copy()
                test_params["url"] = capsule.verification_payload
                test_url = f"{test_url}?{urlencode(test_params)}"

            req = urllib.request.Request(test_url, headers=capsule.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                response_body = resp.read().decode('utf-8', errors='ignore')
                result.response_code = resp.getcode()
                result.response_body_preview = response_body[:500]

            # 检查响应
            indicators = rule.get("indicators", [])
            body_lower = response_body.lower()

            # 简单检查：如果请求成功发往内部地址，可能是 SSRF
            if result.response_code == 200:
                result.status = VerificationStatus.VERIFIED
                result.is_verified = True
                result.confidence = 0.75
            else:
                result.status = VerificationStatus.UNCERTAIN
                result.confidence = 0.4

        except urllib.error.HTTPError:
            result.status = VerificationStatus.UNCERTAIN
            result.confidence = 0.3
        except Exception as e:
            result.status = VerificationStatus.ERROR
            result.error_message = str(e)

        return result


# ============================================================
# 便捷函数
# ============================================================

_verifier = None


def get_verifier() -> OracleVerifier:
    """获取全局验证器实例"""
    global _verifier
    if _verifier is None:
        _verifier = OracleVerifier()
    return _verifier


def verify_finding(
    finding_id: str,
    vuln_type: str,
    target_url: str,
    original_payload: str,
    **kwargs,
) -> VerificationResult:
    """
    便捷验证函数

    Args:
        finding_id: 发现 ID
        vuln_type: 漏洞类型
        target_url: 目标 URL
        original_payload: 原始 payload
        **kwargs: 其他参数

    Returns:
        VerificationResult
    """
    verifier = get_verifier()

    # 生成胶囊
    capsule = verifier.generate_capsule(
        finding_id=finding_id,
        vuln_type=vuln_type,
        target_url=target_url,
        original_payload=original_payload,
        **kwargs,
    )

    # 执行验证
    return verifier.verify(capsule)
