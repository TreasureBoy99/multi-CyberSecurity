"""
MITRE ATT&CK 映射
================
将 CVE 与 ATT&CK 战术/技术关联

数据来源:
- CVE-CWE 映射
- 常见漏洞利用链
- 预设规则库
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ATTACKTactic(str, Enum):
    """ATT&CK 战术"""
    RECONNAISSANCE = "TA0043"      # 侦察
    RESOURCE_DEVELOPMENT = "TA0042"  # 资源开发
    INITIAL_ACCESS = "TA0001"      # 初始访问
    EXECUTION = "TA0002"           # 执行
    PERSISTENCE = "TA0003"         # 持久化
    PRIVILEGE_ESCALATION = "TA0004"  # 权限提升
    DEFENSE_EVASION = "TA0005"     # 防御规避
    CREDENTIAL_ACCESS = "TA0006"   # 凭证访问
    DISCOVERY = "TA0007"           # 发现
    LATERAL_MOVEMENT = "TA0008"     # 横向移动
    COLLECTION = "TA0009"          # 收集
    COMMAND_AND_CONTROL = "TA0011"  # 命令与控制
    EXFILTRATION = "TA0010"        # 数据泄露
    IMPACT = "TA0010"              # 影响


class ATTACKTechnique(str, Enum):
    """ATT&CK 技术"""
    # Initial Access
    PHISHING = "T1566"           # 网络钓鱼
    EXPLOIT_PUBLIC_FACING = "T1190"  # 漏洞利用
    BRUTE_FORCE = "T1110"         # 暴力破解

    # Execution
    COMMAND_SCRIPTING = "T1059"   # 命令和脚本解释器
    USER_EXECUTION = "T1204"       # 用户执行

    # Persistence
    BOOT_OR_LOGON = "T1060"       # 启动或登录自启动
    SCHEDULED_TASK = "T1053"       # 计划任务

    # Privilege Escalation
    ESCALATION = "T1068"          # 权限提升
    SUDO = "T1169"                # Sudo

    # Defense Evasion
    IMPAIR_DEFENSES = "T1562"     # 损害防御
    OBFUSCATION = "T1027"          # 混淆

    # Credential Access
    CREDENTIALS = "T1003"          # 凭证访问
    BRUTE_FORCE_CRED = "T1110"     # 暴力破解凭证

    # Discovery
    NETWORK = "T1046"             # 网络发现
    FILE_AND_DIR = "T1083"         # 文件和目录发现

    # Lateral Movement
    SSH = "T1021"                # 远程服务
    WMI = "T1047"                # Windows 管理工具

    # Command and Control
    C2 = "T1071"                # C2 协议
    ENCRYPTION = "T1573"          # 加密


@dataclass
class ATTACKMapping:
    """CVE 到 ATT&CK 的映射"""
    cve_id: str
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float  # 0.0-1.0


# CVE-ATT&CK 映射规则
CVE_ATTACK_RULES = [
    # SQL Injection -> Initial Access + Execution
    (r"sql.*injection|sqli", "T1190", "Exploit Public-Facing Application", "INITIAL_ACCESS", 0.9),
    (r"sql.*injection|sqli", "T1059", "Command and Scripting Interpreter", "EXECUTION", 0.7),

    # RCE -> Execution + Impact
    (r"rce|remote.*code.*execut|远程代码执行|远程命令执行", "T1059", "Command and Scripting Interpreter", "EXECUTION", 0.9),
    (r"rce|remote.*code.*execut|远程代码执行", "T1499", "Endpoint Denial of Service", "IMPACT", 0.6),

    # Command Injection -> Execution
    (r"command.*injection|cmd.*inject|命令注入|命令执行", "T1059", "Command and Scripting Interpreter", "EXECUTION", 0.95),

    # XSS -> Initial Access + Discovery
    (r"xss|cross.*site.*script", "T1211", "Exploitation for Bypass", "DEFENSE_EVASION", 0.7),
    (r"xss|cross.*site.*script", "T1059", "User Execution", "EXECUTION", 0.6),

    # SSRF -> Initial Access + Discovery
    (r"ssrf|server.*side.*request.*forg", "T1211", "Exploitation for Bypass", "INITIAL_ACCESS", 0.8),
    (r"ssrf|server.*side.*request.*forg", "T1046", "Network Service Discovery", "DISCOVERY", 0.7),

    # File Inclusion -> Execution
    (r"file.*inclusion|lfi|rfi|local.*file.*inclusion", "T1059", "Command and Scripting Interpreter", "EXECUTION", 0.8),

    # File Read -> Discovery + Collection
    (r"file.*read|arbitrary.*file.*read|任意文件读取", "T1083", "File and Directory Discovery", "DISCOVERY", 0.8),
    (r"file.*read|arbitrary.*file.*read", "T1005", "Data from Local System", "COLLECTION", 0.6),

    # Auth Bypass -> Initial Access + Privilege Escalation
    (r"auth.*bypass|privilege.*escal|认证绕过|权限提升|未授权|unauthorized", "T1068", "Exploitation for Privilege Escalation", "PRIVILEGE_ESCALATION", 0.85),
    (r"auth.*bypass|认证绕过", "T1078", "Valid Accounts", "INITIAL_ACCESS", 0.7),

    # Information Disclosure -> Discovery
    (r"info.*disclosure|information.*leak|信息泄露|sensitive.*data", "T1005", "Data from Local System", "COLLECTION", 0.8),

    # Buffer Overflow -> Execution
    (r"buffer.*overflow|栈溢出|堆溢出", "T1068", "Exploitation for Privilege Escalation", "PRIVILEGE_ESCALATION", 0.9),
    (r"buffer.*overflow", "T1059", "Command and Scripting Interpreter", "EXECUTION", 0.8),

    # Deserialization -> Execution
    (r"deserializ|反序列化", "T1059", "Command and Scripting Interpreter", "EXECUTION", 0.9),

    # XXE -> Discovery + Execution
    (r"xxe|xml.*external.*entity", "T1046", "Network Service Discovery", "DISCOVERY", 0.7),
    (r"xxe", "T1059", "Command and Scripting Interpreter", "EXECUTION", 0.8),
]


def map_cve_to_attack(cve_id: str, description: str, title: str = "") -> list[ATTACKMapping]:
    """
    将 CVE 映射到 ATT&CK 技术和战术

    Args:
        cve_id: CVE ID
        description: CVE 描述
        title: CVE 标题

    Returns:
        ATT&CK 映射列表
    """
    text = f"{cve_id} {title} {description}".lower()
    mappings = []
    seen_techniques = set()

    for pattern, tech_id, tech_name, tactic, confidence in CVE_ATTACK_RULES:
        if re.search(pattern, text, re.IGNORECASE):
            if tech_id not in seen_techniques:
                seen_techniques.add(tech_id)
                mappings.append(ATTACKMapping(
                    cve_id=cve_id,
                    technique_id=tech_id,
                    technique_name=tech_name,
                    tactic=tactic,
                    confidence=confidence,
                ))

    return mappings


def get_tactics_for_technique(technique_id: str) -> list[str]:
    """获取指定技术所属的战术"""
    for rule in CVE_ATTACK_RULES:
        if rule[1] == technique_id:
            return [rule[3]]
    return []


# 常用漏洞利用链模板
EXPLOIT_CHAINS = [
    {
        "name": "SQL Injection to RCE",
        "steps": [
            ("SQLi", "T1190", "Exploit Public-Facing Application"),
            ("Command Injection", "T1059", "Command and Scripting Interpreter"),
        ],
        "typical_cves": ["CVE-2019-1234", "CVE-2020-5678"],
    },
    {
        "name": "Auth Bypass to Admin",
        "steps": [
            ("Auth Bypass", "T1068", "Exploitation for Privilege Escalation"),
            ("Admin Access", "T1078", "Valid Accounts"),
        ],
        "typical_cves": ["CVE-2019-1234"],
    },
    {
        "name": "SSRF to Data Breach",
        "steps": [
            ("SSRF", "T1211", "Exploitation for Bypass"),
            ("File Read", "T1005", "Data from Local System"),
        ],
        "typical_cves": ["CVE-2020-1234"],
    },
]


def match_exploit_chain(discovered_vulns: list[str]) -> list[dict]:
    """
    根据发现的漏洞匹配可能的利用链

    Args:
        discovered_vulns: 已发现漏洞的描述列表

    Returns:
        匹配的利用链
    """
    matched_chains = []

    for chain in EXPLOIT_CHAINS:
        chain_vulns = set(chain["typical_cves"])
        found_vulns = set(discovered_vulns)

        overlap = chain_vulns & found_vulns
        if overlap:
            matched_chains.append({
                "name": chain["name"],
                "matched_cves": list(overlap),
                "steps": chain["steps"],
            })

    return matched_chains
