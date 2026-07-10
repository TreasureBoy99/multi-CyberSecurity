"""
MITRE ATT&CK 映射增强版
=======================
将 CVE 与 ATT&CK 战术/技术关联

增强特性:
- CWE->ATT&CK 官方映射表
- CVE 描述自动提取 CWE ID
- 攻击阶段推断
- 置信度计算
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ATTACKTactic(str, Enum):
    """ATT&CK 战术"""
    RECONNAISSANCE = "TA0043"        # 侦察
    RESOURCE_DEVELOPMENT = "TA0042"  # 资源开发
    INITIAL_ACCESS = "TA0001"        # 初始访问
    EXECUTION = "TA0002"             # 执行
    PERSISTENCE = "TA0003"           # 持久化
    PRIVILEGE_ESCALATION = "TA0004"  # 权限提升
    DEFENSE_EVASION = "TA0005"       # 防御规避
    CREDENTIAL_ACCESS = "TA0006"     # 凭证访问
    DISCOVERY = "TA0007"             # 发现
    LATERAL_MOVEMENT = "TA0008"      # 横向移动
    COLLECTION = "TA0009"            # 收集
    COMMAND_AND_CONTROL = "TA0011"   # 命令与控制
    EXFILTRATION = "TA0010"          # 数据泄露
    IMPACT = "TA0040"                # 影响

    @property
    def name(self) -> str:
        """战术名称"""
        names = {
            "TA0043": "Reconnaissance",
            "TA0042": "Resource Development",
            "TA0001": "Initial Access",
            "TA0002": "Execution",
            "TA0003": "Persistence",
            "TA0004": "Privilege Escalation",
            "TA0005": "Defense Evasion",
            "TA0006": "Credential Access",
            "TA0007": "Discovery",
            "TA0008": "Lateral Movement",
            "TA0009": "Collection",
            "TA0011": "Command and Control",
            "TA0010": "Exfiltration/Impact",
            "TA0040": "Impact",
        }
        return names.get(self.value, self.value)


class ATTACKTechnique(str, Enum):
    """ATT&CK 技术 (部分枚举)"""
    PHISHING = "T1566"               # 网络钓鱼
    EXPLOIT_PUBLIC_FACING = "T1190"  # 漏洞利用
    BRUTE_FORCE = "T1110"            # 暴力破解
    COMMAND_SCRIPTING = "T1059"      # 命令和脚本解释器
    USER_EXECUTION = "T1204"         # 用户执行
    BOOT_OR_LOGON = "T1060"          # 启动或登录自启动
    SCHEDULED_TASK = "T1053"         # 计划任务
    ESCALATION = "T1068"             # 权限提升
    SUDO = "T1169"                   # Sudo
    IMPAIR_DEFENSES = "T1562"        # 损害防御
    OBFUSCATION = "T1027"            # 混淆
    CREDENTIALS = "T1003"            # 凭证访问
    NETWORK = "T1046"                # 网络发现
    FILE_AND_DIR = "T1083"           # 文件和目录发现
    SSH = "T1021"                    # 远程服务
    WMI = "T1047"                    # Windows 管理工具
    C2 = "T1071"                     # C2 协议
    ENCRYPTION = "T1573"             # 加密
    SQL_INJECTION = "T1190"          # SQL 注入
    XSS = "T1211"                    # XSS
    SSRF = "T1190"                   # SSRF
    XXE = "T1190"                    # XXE


@dataclass
class ATTACKMapping:
    """CVE 到 ATT&CK 的映射"""
    cve_id: str
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float  # 0.0-1.0
    source: str = "inferred"  # "cwe", "keyword", "pattern"
    cwe_id: Optional[str] = None  # 如果从 CWE 映射来的


# ============================================================
# 官方 CWE-ATT&CK 映射表 (MITRE 官方映射 + 常见映射)
# 数据来源: https://attack.mitre.org/mappings/
# ============================================================

CWE_TO_ATTACK: dict[str, list[tuple[str, str, float]]] = {
    # CWE-89: SQL 注入
    "CWE-89": [
        ("T1190", "Exploit Public-Facing Application", 0.95, "INITIAL_ACCESS"),
        ("T1059", "Command and Scripting Interpreter", 0.7, "EXECUTION"),
    ],
    # CWE-79: XSS (跨站脚本)
    "CWE-79": [
        ("T1211", "Exploitation for Defense Evasion", 0.7, "DEFENSE_EVASION"),
        ("T1059", "User Execution", 0.6, "EXECUTION"),
    ],
    # CWE-78: OS 命令注入
    "CWE-78": [
        ("T1059", "Command and Scripting Interpreter", 0.95, "EXECUTION"),
    ],
    # CWE-88: 参数注入
    "CWE-88": [
        ("T1059", "Command and Scripting Interpreter", 0.8, "EXECUTION"),
    ],
    # CWE-90: LDAP 注入
    "CWE-90": [
        ("T1059", "Command and Scripting Interpreter", 0.8, "EXECUTION"),
    ],
    # CWE-91: XML 注入 (XPath 注入)
    "CWE-91": [
        ("T1059", "Command and Scripting Interpreter", 0.7, "EXECUTION"),
    ],
    # CWE-94: 代码注入
    "CWE-94": [
        ("T1059", "Command and Scripting Interpreter", 0.95, "EXECUTION"),
    ],
    # CWE-95: 动态表达式注入 (Eval 注入)
    "CWE-95": [
        ("T1059", "Command and Scripting Interpreter", 0.9, "EXECUTION"),
    ],
    # CWE-98: 路径遍历
    "CWE-22": [
        ("T1059", "Command and Scripting Interpreter", 0.6, "EXECUTION"),
        ("T1005", "Data from Local System", 0.7, "COLLECTION"),
    ],
    # CWE-22: 路径遍历
    "CWE-22": [
        ("T1059", "Command and Scripting Interpreter", 0.6, "EXECUTION"),
        ("T1005", "Data from Local System", 0.7, "COLLECTION"),
    ],
    # CWE-352: CSRF
    "CWE-352": [
        ("T1059", "User Execution", 0.8, "EXECUTION"),
    ],
    # CWE-287: 认证绕过
    "CWE-287": [
        ("T1078", "Valid Accounts", 0.8, "INITIAL_ACCESS"),
        ("T1068", "Exploitation for Privilege Escalation", 0.7, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-306: 认证缺失
    "CWE-306": [
        ("T1078", "Valid Accounts", 0.9, "INITIAL_ACCESS"),
    ],
    # CWE-862: 授权缺失
    "CWE-862": [
        ("T1078", "Valid Accounts", 0.7, "INITIAL_ACCESS"),
    ],
    # CWE-863: 授权错误
    "CWE-863": [
        ("T1078", "Valid Accounts", 0.7, "INITIAL_ACCESS"),
    ],
    # CWE-798: 硬编码凭证
    "CWE-798": [
        ("T1078", "Valid Accounts", 0.95, "INITIAL_ACCESS"),
    ],
    # CWE-259: 硬编码密码
    "CWE-259": [
        ("T1078", "Valid Accounts", 0.9, "INITIAL_ACCESS"),
    ],
    # CWE-200: 信息泄露
    "CWE-200": [
        ("T1005", "Data from Local System", 0.8, "COLLECTION"),
    ],
    # CWE-201: 敏感数据泄露
    "CWE-201": [
        ("T1005", "Data from Local System", 0.8, "COLLECTION"),
        ("T1041", "Exfiltration Over C2 Channel", 0.6, "EXFILTRATION"),
    ],
    # CWE-295: 证书验证不当
    "CWE-295": [
        ("T1556", "Modify Authentication Process", 0.7, "CREDENTIAL_ACCESS"),
    ],
    # CWE-347: 密码学不安全
    "CWE-347": [
        ("T1552", "Unsecured Credentials", 0.7, "CREDENTIAL_ACCESS"),
    ],
    # CWE-310: 密码学问题
    "CWE-310": [
        ("T1552", "Unsecured Credentials", 0.7, "CREDENTIAL_ACCESS"),
    ],
    # CWE-311: 敏感数据加密缺失
    "CWE-311": [
        ("T1041", "Exfiltration Over C2 Channel", 0.6, "EXFILTRATION"),
    ],
    # CWE-312: 敏感数据明文存储
    "CWE-312": [
        ("T1005", "Data from Local System", 0.8, "COLLECTION"),
    ],
    # CWE-319: 敏感数据明文传输
    "CWE-319": [
        ("T1041", "Exfiltration Over C2 Channel", 0.7, "EXFILTRATION"),
    ],
    # CWE-327: 弱密码学使用
    "CWE-327": [
        ("T1552", "Unsecured Credentials", 0.6, "CREDENTIAL_ACCESS"),
    ],
    # CWE-329: 弱 IV (初始化向量)
    "CWE-329": [
        ("T1552", "Unsecured Credentials", 0.5, "CREDENTIAL_ACCESS"),
    ],
    # CWE-338: 弱随机数生成器
    "CWE-338": [
        ("T1552", "Unsecured Credentials", 0.7, "CREDENTIAL_ACCESS"),
    ],
    # CWE-345: 证书验证不充分
    "CWE-345": [
        ("T1556", "Modify Authentication Process", 0.6, "CREDENTIAL_ACCESS"),
    ],
    # CWE-347: 密码学签名字验证不足
    "CWE-347": [
        ("T1556", "Modify Authentication Process", 0.6, "CREDENTIAL_ACCESS"),
    ],
    # CWE-502: 反序列化
    "CWE-502": [
        ("T1059", "Command and Scripting Interpreter", 0.9, "EXECUTION"),
    ],
    # CWE-915: 动态墨认属性操作
    "CWE-915": [
        ("T1059", "Command and Scripting Interpreter", 0.7, "EXECUTION"),
    ],
    # CWE-434: 危险类型文件上传
    "CWE-434": [
        ("T1059", "Command and Scripting Interpreter", 0.85, "EXECUTION"),
    ],
    # CWE-78: OS 命令注入 (重复映射)
    "CWE-78": [
        ("T1059", "Command and Scripting Interpreter", 0.95, "EXECUTION"),
    ],
    # CWE-77: 命令注入
    "CWE-77": [
        ("T1059", "Command and Scripting Interpreter", 0.95, "EXECUTION"),
    ],
    # CWE-74: 注入
    "CWE-74": [
        ("T1059", "Command and Scripting Interpreter", 0.8, "EXECUTION"),
    ],
    # CWE-20: 输入验证不足
    "CWE-20": [
        ("T1059", "Command and Scripting Interpreter", 0.5, "EXECUTION"),
    ],
    # CWE-601: URL 重定向
    "CWE-601": [
        ("T1567", "Exfiltration Over Web Service", 0.6, "EXFILTRATION"),
    ],
    # CWE-918: SSRF
    "CWE-918": [
        ("T1059", "Command and Scripting Interpreter", 0.6, "EXECUTION"),
        ("T1005", "Data from Local System", 0.7, "COLLECTION"),
    ],
    # CWE-611: XXE
    "CWE-611": [
        ("T1059", "Command and Scripting Interpreter", 0.7, "EXECUTION"),
    ],
    # CWE-643: XPath 注入
    "CWE-643": [
        ("T1059", "Command and Scripting Interpreter", 0.8, "EXECUTION"),
    ],
    # CWE-77: 命令注入 (标准化)
    "CWE-77": [
        ("T1059", "Command and Scripting Interpreter", 0.95, "EXECUTION"),
    ],
    # CWE-190: 整数溢出
    "CWE-190": [
        ("T1068", "Exploitation for Privilege Escalation", 0.7, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-191: 整数下溢
    "CWE-191": [
        ("T1068", "Exploitation for Privilege Escalation", 0.7, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-193: 字符转换错误
    "CWE-193": [
        ("T1068", "Exploitation for Privilege Escalation", 0.7, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-119: 缓冲区溢出
    "CWE-119": [
        ("T1068", "Exploitation for Privilege Escalation", 0.9, "PRIVILEGE_ESCALATION"),
        ("T1059", "Command and Scripting Interpreter", 0.6, "EXECUTION"),
    ],
    # CWE-120: 经典缓冲区溢出
    "CWE-120": [
        ("T1068", "Exploitation for Privilege Escalation", 0.9, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-122: 堆溢出
    "CWE-122": [
        ("T1068", "Exploitation for Privilege Escalation", 0.9, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-124: 栈溢出
    "CWE-124": [
        ("T1068", "Exploitation for Privilege Escalation", 0.9, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-126: 栈缓冲区溢出
    "CWE-126": [
        ("T1068", "Exploitation for Privilege Escalation", 0.9, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-127: 栈缓冲区下溢
    "CWE-127": [
        ("T1068", "Exploitation for Privilege Escalation", 0.8, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-131: 缓冲区大小计算错误
    "CWE-131": [
        ("T1068", "Exploitation for Privilege Escalation", 0.8, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-135: 字符串长度计算错误
    "CWE-135": [
        ("T1068", "Exploitation for Privilege Escalation", 0.7, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-122: 堆溢出 (标准化)
    "CWE-122": [
        ("T1068", "Exploitation for Privilege Escalation", 0.9, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-416: 释放后使用
    "CWE-416": [
        ("T1068", "Exploitation for Privilege Escalation", 0.9, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-822: 指针不可信
    "CWE-822": [
        ("T1068", "Exploitation for Privilege Escalation", 0.8, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-823: 指针偏移错误
    "CWE-823": [
        ("T1068", "Exploitation for Privilege Escalation", 0.8, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-824: 指针访问超出边界
    "CWE-824": [
        ("T1068", "Exploitation for Privilege Escalation", 0.8, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-825: 指针超时
    "CWE-825": [
        ("T1068", "Exploitation for Privilege Escalation", 0.8, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-415: 双重释放
    "CWE-415": [
        ("T1068", "Exploitation for Privilege Escalation", 0.85, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-401: 内存泄漏
    "CWE-401": [
        ("T1068", "Exploitation for Privilege Escalation", 0.6, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-755: 异常处理不当
    "CWE-755": [
        ("T1068", "Exploitation for Privilege Escalation", 0.6, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-252: 未检查返回值
    "CWE-252": [
        ("T1068", "Exploitation for Privilege Escalation", 0.5, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-253: 错误检查返回值
    "CWE-253": [
        ("T1068", "Exploitation for Privilege Escalation", 0.5, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-754: 异常处理不当检查
    "CWE-754": [
        ("T1068", "Exploitation for Privilege Escalation", 0.5, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-755: 异常处理不当 (标准化)
    "CWE-755": [
        ("T1068", "Exploitation for Privilege Escalation", 0.6, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-362: 竞态条件
    "CWE-362": [
        ("T1068", "Exploitation for Privilege Escalation", 0.7, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-367: TOCTOU 竞态条件
    "CWE-367": [
        ("T1068", "Exploitation for Privilege Escalation", 0.7, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-369: 除以零
    "CWE-369": [
        ("T1499", "Endpoint Denial of Service", 0.6, "IMPACT"),
    ],
    # CWE-400: 未控制资源消耗
    "CWE-400": [
        ("T1499", "Endpoint Denial of Service", 0.8, "IMPACT"),
    ],
    # CWE-404: 资源释放不当
    "CWE-404": [
        ("T1499", "Endpoint Denial of Service", 0.6, "IMPACT"),
    ],
    # CWE-410: 资源耗尽
    "CWE-410": [
        ("T1499", "Endpoint Denial of Service", 0.8, "IMPACT"),
    ],
    # CWE-672: 资源过期或关闭后操作
    "CWE-672": [
        ("T1499", "Endpoint Denial of Service", 0.6, "IMPACT"),
    ],
    # CWE-834: 无限循环
    "CWE-834": [
        ("T1499", "Endpoint Denial of Service", 0.8, "IMPACT"),
    ],
    # CWE-835: 无限循环 (标准化)
    "CWE-835": [
        ("T1499", "Endpoint Denial of Service", 0.8, "IMPACT"),
    ],
    # CWE-674: 未控制递归
    "CWE-674": [
        ("T1499", "Endpoint Denial of Service", 0.7, "IMPACT"),
    ],
    # CWE-770: 资源分配无限制
    "CWE-770": [
        ("T1499", "Endpoint Denial of Service", 0.7, "IMPACT"),
    ],
    # CWE-681: 数字类型转换错误
    "CWE-681": [
        ("T1068", "Exploitation for Privilege Escalation", 0.6, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-682: 计算错误
    "CWE-682": [
        ("T1068", "Exploitation for Privilege Escalation", 0.5, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-697: 错误比较
    "CWE-697": [
        ("T1068", "Exploitation for Privilege Escalation", 0.5, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-703: 异常保护不足
    "CWE-703": [
        ("T1068", "Exploitation for Privilege Escalation", 0.5, "PRIVILEGE_ESCALATION"),
    ],
    # CWE-754: 异常处理不当 (标准化)
    "CWE-754": [
        ("T1068", "Exploitation for Privilege Escalation", 0.5, "PRIVILEGE_ESCALATION"),
    ],
}


# ============================================================
# CVE 描述关键词 -> CWE 映射
# ============================================================

CVE_KEYWORD_TO_CWE: dict[str, list[str]] = {
    # SQL 注入
    r"sql\s*injection": ["CWE-89"],
    r"sqli": ["CWE-89"],
    r"sql\s*injection\s*vulnerab": ["CWE-89"],
    r"database\s*injection": ["CWE-89"],

    # XSS
    r"cross[\s-]*site\s*script": ["CWE-79"],
    r"xss": ["CWE-79"],
    r"javascript\s*injection": ["CWE-79"],

    # 命令注入
    r"command\s*injection": ["CWE-78"],
    r"os\s*command\s*injection": ["CWE-78"],
    r"shell\s*injection": ["CWE-78"],
    r"cmd\s*injection": ["CWE-78"],
    r"arbitrary\s*command\s*execut": ["CWE-78"],

    # 代码注入
    r"code\s*injection": ["CWE-94"],
    r"php\s*code\s*injection": ["CWE-94"],
    r"remote\s*code\s*execut": ["CWE-94"],
    r"rce": ["CWE-94"],

    # 路径遍历
    r"path\s*traversal": ["CWE-22"],
    r"directory\s*traversal": ["CWE-22"],
    r"arbitrary\s*file\s*read": ["CWE-22"],
    r"arbitrary\s*file\s*access": ["CWE-22"],
    r"file\s*inclusion": ["CWE-22"],
    r"lfi": ["CWE-22"],
    r"rfi": ["CWE-22"],

    # SSRF
    r"server[\s-]*side\s*request\s*forg": ["CWE-918"],
    r"ssrf": ["CWE-918"],

    # XXE
    r"xml\s*external\s*entity": ["CWE-611"],
    r"xxe": ["CWE-611"],

    # 反序列化
    r"deserializ": ["CWE-502"],
    r"unsafe\s*deserializ": ["CWE-502"],

    # 缓冲区溢出
    r"buffer\s*overflow": ["CWE-119"],
    r"heap\s*overflow": ["CWE-122"],
    r"stack\s*overflow": ["CWE-121"],
    r"memory\s*corruption": ["CWE-119"],

    # 认证绕过
    r"authentication\s*bypass": ["CWE-287"],
    r"auth\s*bypass": ["CWE-287"],
    r"bypass\s*authent": ["CWE-287"],
    r"privilege\s*escal": ["CWE-269"],
    r"priv[\s-]*escal": ["CWE-269"],
    r"local\s*privilege\s*escal": ["CWE-269"],
    r"root\s*privilege": ["CWE-269"],

    # CSRF
    r"csrf": ["CWE-352"],
    r"cross[\s-]*site\s*request\s*forg": ["CWE-352"],

    # 信息泄露
    r"information\s*disclosure": ["CWE-200"],
    r"info\s*disclosure": ["CWE-200"],
    r"information\s*leak": ["CWE-200"],
    r"sensitive\s*information": ["CWE-200"],
    r"credentials?\s*exposed": ["CWE-200"],
    r"api\s*key\s*exposed": ["CWE-200"],

    # 文件上传
    r"arbitrary\s*file\s*upload": ["CWE-434"],
    r"unspecified\s*file\s*upload": ["CWE-434"],
    r"dangerous\s*file\s*upload": ["CWE-434"],

    # 弱密码学
    r"weak\s*crypt": ["CWE-327"],
    r"insecure\s*crypt": ["CWE-327"],
    r"hardcoded\s*crypt": ["CWE-327"],
    r"default\s*crypt": ["CWE-327"],
    r"weak\s*cipher": ["CWE-327"],

    # 硬编码凭证
    r"hardcoded\s*credential": ["CWE-798"],
    r"hardcoded\s*password": ["CWE-259"],
    r"hardcoded\s*key": ["CWE-798"],
    r"default\s*password": ["CWE-798"],

    # 拒绝服务
    r"denial\s*of\s*service": ["CWE-400"],
    r"dos\s*vulnerab": ["CWE-400"],
    r"resource\s*exhaustion": ["CWE-400"],

    # URL 重定向
    r"open\s*redirect": ["CWE-601"],
    r"url\s*redirect": ["CWE-601"],
    r"unvalidated\s*redirect": ["CWE-601"],

    # 注入 (通用)
    r"code\s*injection": ["CWE-94"],
    r"ldap\s*injection": ["CWE-90"],
    r"xpath\s*injection": ["CWE-643"],
    r"template\s*injection": ["CWE-1336"],
    r"ssti": ["CWE-1336"],

    # 内存损坏
    r"use[\s-]*after[\s-]*free": ["CWE-416"],
    r"uaf": ["CWE-416"],
    r"double[\s-]*free": ["CWE-415"],
    r"heap\s*corruption": ["CWE-122"],
    r"stack\s*corruption": ["CWE-121"],

    # 竞态条件
    r"race\s*condition": ["CWE-362"],
    r"toctou": ["CWE-367"],

    # 整数相关
    r"integer\s*overflow": ["CWE-190"],
    r"integer\s*underflow": ["CWE-191"],
}


def extract_cwe_from_description(description: str) -> list[str]:
    """
    从 CVE 描述中提取 CWE ID

    Args:
        description: CVE 描述文本

    Returns:
        CWE ID 列表，如 ["CWE-89", "CWE-287"]
    """
    cwe_ids = set()

    # 直接匹配 CWE-XXX 格式
    matches = re.findall(r'CWE[-\s]?(\d+)', description, re.IGNORECASE)
    for m in matches:
        cwe_ids.add(f"CWE-{m}")

    # 关键词匹配
    text_lower = description.lower()
    for pattern, cwe_list in CVE_KEYWORD_TO_CWE.items():
        if re.search(pattern, text_lower, re.IGNORECASE):
            cwe_ids.update(cwe_list)

    return list(cwe_ids)


def map_cve_to_attack(
    cve_id: str,
    description: str,
    title: str = "",
    cwe_ids: Optional[list[str]] = None,
) -> list[ATTACKMapping]:
    """
    将 CVE 映射到 ATT&CK 技术和战术

    Args:
        cve_id: CVE ID
        description: CVE 描述
        title: CVE 标题
        cwe_ids: 已知 CWE ID 列表 (可选)

    Returns:
        ATT&CK 映射列表
    """
    mappings = []
    seen_techniques = set()

    # 1. 首先尝试从 CWE 映射 (高置信度)
    if cwe_ids is None:
        cwe_ids = extract_cwe_from_description(description)

    for cwe_id in cwe_ids:
        if cwe_id in CWE_TO_ATTACK:
            for tech_id, tech_name, confidence, tactic in CWE_TO_ATTACK[cwe_id]:
                if tech_id not in seen_techniques:
                    seen_techniques.add(tech_id)
                    mappings.append(ATTACKMapping(
                        cve_id=cve_id,
                        technique_id=tech_id,
                        technique_name=tech_name,
                        tactic=tactic,
                        confidence=confidence,
                        source="cwe",
                        cwe_id=cwe_id,
                    ))

    # 2. 补充关键词推断 (低置信度)
    text = f"{cve_id} {title} {description}".lower()

    # 关键词推断规则
    keyword_rules = [
        # SQL Injection -> Initial Access
        (r"sql\s*injection|sqli", "T1190", "Exploit Public-Facing Application", "INITIAL_ACCESS", 0.85),
        # RCE -> Execution
        (r"remote\s*code\s*execut|rce", "T1059", "Command and Scripting Interpreter", "EXECUTION", 0.9),
        # Auth Bypass -> Initial Access
        (r"auth.*bypass|authent.*bypass", "T1078", "Valid Accounts", "INITIAL_ACCESS", 0.75),
        # Privilege Escalation
        (r"privilege\s*escal|priv.*escal", "T1068", "Exploitation for Privilege Escalation", "PRIVILEGE_ESCALATION", 0.8),
        # XSS -> User Execution
        (r"xss|cross[\s-]*site\s*script", "T1204", "User Execution", "EXECUTION", 0.7),
        # SSRF -> Exfiltration
        (r"ssrf|server[\s-]*side\s*request\s*forg", "T1059", "Command and Scripting Interpreter", "EXECUTION", 0.6),
        # File Read -> Collection
        (r"arbitrary\s*file\s*read|file\s*disclosure", "T1005", "Data from Local System", "COLLECTION", 0.7),
        # Buffer Overflow -> Privilege Escalation
        (r"buffer\s*overflow|heap\s*overflow", "T1068", "Exploitation for Privilege Escalation", "PRIVILEGE_ESCALATION", 0.85),
        # Deserialization -> Execution
        (r"deserializ", "T1059", "Command and Scripting Interpreter", "EXECUTION", 0.85),
        # CSRF -> Execution
        (r"csrf|cross[\s-]*site\s*request\s*forg", "T1204", "User Execution", "EXECUTION", 0.65),
        # XXE -> Execution
        (r"xxe|xml\s*external\s*entity", "T1059", "Command and Scripting Interpreter", "EXECUTION", 0.75),
        # DoS -> Impact
        (r"denial\s*of\s*service|dos\s*vulnerab", "T1499", "Endpoint Denial of Service", "IMPACT", 0.8),
        # Information Disclosure -> Collection
        (r"information\s*disclosure|info\s*leak", "T1005", "Data from Local System", "COLLECTION", 0.7),
        # Open Redirect -> Exfiltration
        (r"open\s*redirect|url\s*redirect", "T1567", "Exfiltration Over Web Service", "EXFILTRATION", 0.6),
    ]

    for pattern, tech_id, tech_name, tactic, confidence in keyword_rules:
        if re.search(pattern, text, re.IGNORECASE):
            if tech_id not in seen_techniques:
                seen_techniques.add(tech_id)
                mappings.append(ATTACKMapping(
                    cve_id=cve_id,
                    technique_id=tech_id,
                    technique_name=tech_name,
                    tactic=tactic,
                    confidence=confidence,
                    source="keyword",
                    cwe_id=None,
                ))

    # 3. 按置信度排序
    mappings.sort(key=lambda x: x.confidence, reverse=True)

    return mappings


def get_tactics_for_technique(technique_id: str) -> list[str]:
    """获取指定技术所属的战术"""
    # 简化的反向映射
    technique_to_tactics = {
        "T1190": ["INITIAL_ACCESS"],
        "T1059": ["EXECUTION"],
        "T1204": ["EXECUTION"],
        "T1068": ["PRIVILEGE_ESCALATION"],
        "T1078": ["INITIAL_ACCESS", "LATERAL_MOVEMENT"],
        "T1005": ["COLLECTION"],
        "T1041": ["EXFILTRATION"],
        "T1499": ["IMPACT"],
        "T1211": ["DEFENSE_EVASION"],
        "T1567": ["EXFILTRATION"],
        "T1556": ["CREDENTIAL_ACCESS"],
        "T1552": ["CREDENTIAL_ACCESS"],
        "T1046": ["DISCOVERY"],
        "T1083": ["DISCOVERY"],
    }
    return technique_to_tactics.get(technique_id, [])


# ============================================================
# 攻击链模板
# ============================================================

EXPLOIT_CHAINS = [
    {
        "name": "SQL Injection to RCE",
        "steps": [
            ("SQLi", "T1190", "Exploit Public-Facing Application"),
            ("Command Injection", "T1059", "Command and Scripting Interpreter"),
        ],
        "cwe_chain": ["CWE-89", "CWE-78"],
        "description": "SQL注入获取数据库访问权限后，通过命令执行获取系统权限",
    },
    {
        "name": "Auth Bypass to RCE",
        "steps": [
            ("Auth Bypass", "T1078", "Valid Accounts"),
            ("Command Injection", "T1059", "Command and Scripting Interpreter"),
        ],
        "cwe_chain": ["CWE-287", "CWE-78"],
        "description": "绕过认证后利用命令执行漏洞获取系统权限",
    },
    {
        "name": "SSRF to Data Breach",
        "steps": [
            ("SSRF", "T1190", "Exploit Public-Facing Application"),
            ("File Read", "T1005", "Data from Local System"),
        ],
        "cwe_chain": ["CWE-918", "CWE-22"],
        "description": "利用SSRF访问内部资源并读取敏感文件",
    },
    {
        "name": "XSS to Account Takeover",
        "steps": [
            ("XSS", "T1211", "Exploitation for Defense Evasion"),
            ("User Execution", "T1204", "User Execution"),
        ],
        "cwe_chain": ["CWE-79", "CWE-287"],
        "description": "XSS窃取用户Cookie或凭据后接管账户",
    },
    {
        "name": "Deserialization to RCE",
        "steps": [
            ("Deserialization", "T1059", "Command and Scripting Interpreter"),
            ("Command Execution", "T1059", "Command and Scripting Interpreter"),
        ],
        "cwe_chain": ["CWE-502", "CWE-94"],
        "description": "利用反序列化漏洞执行任意代码",
    },
    {
        "name": "File Upload to RCE",
        "steps": [
            ("Malicious File Upload", "T1059", "Command and Scripting Interpreter"),
            ("Command Execution", "T1059", "Command and Scripting Interpreter"),
        ],
        "cwe_chain": ["CWE-434", "CWE-94"],
        "description": "上传恶意文件（WebShell）后执行命令",
    },
    {
        "name": "XXE to File Read",
        "steps": [
            ("XXE", "T1059", "Command and Scripting Interpreter"),
            ("File Read", "T1005", "Data from Local System"),
        ],
        "cwe_chain": ["CWE-611", "CWE-22"],
        "description": "利用XXE读取服务器敏感文件",
    },
    {
        "name": "Path Traversal to RCE",
        "steps": [
            ("Path Traversal", "T1059", "Command and Scripting Interpreter"),
            ("Command Execution", "T1059", "Command and Scripting Interpreter"),
        ],
        "cwe_chain": ["CWE-22", "CWE-94"],
        "description": "路径遍历读取配置或上传shell后RCE",
    },
]


def match_exploit_chain(
    discovered_vulns: list[str],
    cwe_ids: Optional[list[str]] = None,
) -> list[dict]:
    """
    根据发现的漏洞匹配可能的利用链

    Args:
        discovered_vulns: 已发现漏洞的描述列表
        cwe_ids: 已知 CWE ID 列表

    Returns:
        匹配的利用链
    """
    if cwe_ids is None:
        # 从漏洞描述中提取 CWE
        all_cwes = set()
        for vuln in discovered_vulns:
            all_cwes.update(extract_cwe_from_description(vuln))
        cwe_ids = list(all_cwes)

    cwe_set = set(cwe_ids)
    matched_chains = []

    for chain in EXPLOIT_CHAINS:
        chain_cwes = set(chain.get("cwe_chain", []))

        # 检查是否有匹配的 CWE 链
        if chain_cwes & cwe_set:  # 有交集
            matched_chains.append({
                "name": chain["name"],
                "description": chain["description"],
                "steps": chain["steps"],
                "matched_cwes": list(chain_cwes & cwe_set),
                "confidence": len(chain_cwes & cwe_set) / len(chain_cwes) if chain_cwes else 0,
            })

    # 按置信度排序
    matched_chains.sort(key=lambda x: x["confidence"], reverse=True)

    return matched_chains


def infer_attack_phase(cvss: float, pre_auth: bool, rce: bool) -> list[str]:
    """
    根据漏洞特征推断攻击阶段

    Args:
        cvss: CVSS 评分
        pre_auth: 是否预认证可利用
        rce: 是否 RCE

    Returns:
        最可能的攻击阶段列表
    """
    phases = []

    # 初始访问
    if pre_auth and cvss >= 7.0:
        phases.append("INITIAL_ACCESS")

    # 执行
    if rce or cvss >= 9.0:
        phases.append("EXECUTION")

    # 持久化
    if cvss >= 8.0 and not pre_auth:
        phases.append("PERSISTENCE")

    # 权限提升
    if cvss >= 7.0:
        phases.append("PRIVILEGE_ESCALATION")

    # 影响
    if cvss >= 9.0:
        phases.append("IMPACT")

    return phases


# ============================================================
# 导出
# ============================================================

__all__ = [
    "ATTACKTactic",
    "ATTACKTechnique",
    "ATTACKMapping",
    "CWE_TO_ATTACK",
    "CVE_KEYWORD_TO_CWE",
    "EXPLOIT_CHAINS",
    "extract_cwe_from_description",
    "map_cve_to_attack",
    "get_tactics_for_technique",
    "match_exploit_chain",
    "infer_attack_phase",
]
