"""
攻击模式定义
============
参考 pentest-mcp 的 ATTACK_PATTERNS 设计
定义常见的攻击路径和关联的 CVE
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(str, Enum):
    """风险等级"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AttackPattern:
    """
    攻击模式

    描述一个常见的攻击向量，包括:
    - 节点序列: 构成攻击路径的要素
    - 关联 CVE: 可能利用的漏洞
    - CVSS 评分: 严重程度
    """
    name: str                           # 模式名称
    description: str                    # 描述

    # 构成此攻击的节点
    nodes: list[str] = field(default_factory=list)
    # 例如: ["tomcat", "manager", "admin"] → Tomcat Manager 暴力破解/弱密码

    # 关联的 CVE ID
    cves: list[str] = field(default_factory=list)
    # 例如: ["CVE-2017-12615", "CVE-2020-1938"]

    # 风险等级
    risk: RiskLevel = RiskLevel.HIGH

    # CVSS 评分 (如果已知)
    cvss: Optional[float] = None

    # 需要的条件
    conditions: list[str] = field(default_factory=list)
    # 例如: ["需要认证", "需要 HTTP PUT 方法"]

    # 建议的利用方式
    exploitation: str = ""

    def matches(self, discovered_nodes: list[str]) -> bool:
        """检查发现的节点是否匹配此攻击模式"""
        return all(node in discovered_nodes for node in self.nodes)

    def match_count(self, discovered_nodes: list[str]) -> int:
        """返回匹配的节点数量"""
        return sum(1 for node in self.nodes if node in discovered_nodes)


# 预定义的攻击模式
ATTACK_PATTERNS: list[AttackPattern] = [
    # === Web 应用攻击模式 ===

    AttackPattern(
        name="Tomcat Manager",
        description="Apache Tomcat Manager 接口暴露或弱密码",
        nodes=["tomcat", "manager", "admin"],
        cves=["CVE-2017-12615", "CVE-2020-1938"],
        risk=RiskLevel.HIGH,
        cvss=9.8,
        conditions=["开放 8080 端口", "存在 /manager/html"],
        exploitation="CVE-2017-12615: PUT 方法上传webshell",
    ),

    AttackPattern(
        name="Apache Struts RCE",
        description="Apache Struts2 远程代码执行",
        nodes=["struts", "s2", "ognl"],
        cves=["CVE-2017-5638", "CVE-2018-11776", "CVE-2021-31805"],
        risk=RiskLevel.CRITICAL,
        cvss=10.0,
        conditions=["使用 Struts2 框架"],
        exploitation="Content-Type 字段 OGNL 注入",
    ),

    AttackPattern(
        name="WordPress 插件漏洞",
        description="WordPress 插件漏洞利用链",
        nodes=["wordpress", "wp-plugin"],
        cves=["CVE-2021-24288", "CVE-2022-0062"],
        risk=RiskLevel.HIGH,
        conditions=["WordPress CMS"],
        exploitation="插件漏洞利用",
    ),

    AttackPattern(
        name="Log4j RCE",
        description="Apache Log4j 远程代码执行",
        nodes=["log4j", "java", "logging"],
        cves=["CVE-2021-44228", "CVE-2021-45046"],
        risk=RiskLevel.CRITICAL,
        cvss=10.0,
        conditions=["使用 Log4j 1.x/2.x"],
        exploitation="${jndi:ldap://...} 注入",
    ),

    AttackPattern(
        name="Spring Framework RCE",
        description="Spring Core RCE (Spring4Shell)",
        nodes=["spring", "java", "tomcat"],
        cves=["CVE-2022-22965"],
        risk=RiskLevel.CRITICAL,
        cvss=9.8,
        conditions=["Spring Framework < 5.3.18", "JDK9+"],
        exploitation="Class 数据绑定参数注入",
    ),

    AttackPattern(
        name="Jenkins RCE",
        description="Jenkins 远程代码执行",
        nodes=["jenkins", "ci", "cd"],
        cves=["CVE-2018-1000861", "CVE-2019-1003030"],
        risk=RiskLevel.HIGH,
        cvss=9.8,
        conditions=["Jenkins < 2.138", "允许注册用户"],
        exploitation="Groovy 脚本执行",
    ),

    # === 中间件攻击模式 ===

    AttackPattern(
        name="Redis 未授权访问",
        description="Redis 未授权访问",
        nodes=["redis", "6379"],
        cves=["CVE-2015-2141"],
        risk=RiskLevel.HIGH,
        cvss=7.5,
        conditions=["Redis 开放 6379 端口", "无密码或弱密码"],
        exploitation="写 crontab/SSH key/webshell",
    ),

    AttackPattern(
        name="MongoDB 未授权访问",
        description="MongoDB 未授权访问",
        nodes=["mongodb", "27017"],
        cves=["CVE-2019-2389"],
        risk=RiskLevel.MEDIUM,
        cvss=6.5,
        conditions=["MongoDB 开放 27017", "未启用认证"],
        exploitation="数据库导出/敏感信息读取",
    ),

    AttackPattern(
        name="MySQL 弱密码/注入",
        description="MySQL 弱密码或 SQL 注入",
        nodes=["mysql", "3306", "root"],
        cves=["CVE-2012-2122"],
        risk=RiskLevel.HIGH,
        conditions=["MySQL 开放 3306", "root 弱密码"],
        exploitation="UDF 提权/读文件",
    ),

    # === 服务攻击模式 ===

    AttackPattern(
        name="SMB 永恒之蓝",
        description="MS17-010 SMB 远程代码执行",
        nodes=["smb", "445", "windows"],
        cves=["CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0146", "CVE-2017-0147", "CVE-2017-0148"],
        risk=RiskLevel.CRITICAL,
        cvss=9.8,
        conditions=["Windows SMBv1", "开放 445 端口"],
        exploitation="EternalBlue 攻击链",
    ),

    AttackPattern(
        name="OpenSSH 用户枚举",
        description="OpenSSH 用户枚举漏洞",
        nodes=["ssh", "openssh", "22"],
        cves=["CVE-2018-15473", "CVE-2023-28531"],
        risk=RiskLevel.LOW,
        conditions=["OpenSSH < 7.7"],
        exploitation="用户名枚举",
    ),

    AttackPattern(
        name="VSFTPD 后门",
        description="VSFTPD 2.3.4 后门命令执行",
        nodes=["ftp", "vsftpd", "21"],
        cves=["CVE-2011-2523"],
        risk=RiskLevel.HIGH,
        conditions=["VSFTPD 2.3.4"],
        exploitation=":) 用户触发后门",
    ),

    # === API 攻击模式 ===

    AttackPattern(
        name="GraphQL 注入",
        description="GraphQL API 注入",
        nodes=["graphql", "api", "endpoint"],
        cves=[],
        risk=RiskLevel.MEDIUM,
        conditions=["GraphQL 端点暴露"],
        exploitation="Introspection 探测/查询注入",
    ),

    AttackPattern(
        name="JWT 弱密钥",
        description="JWT 算法混淆/弱密钥",
        nodes=["jwt", "token", "auth"],
        cves=[],
        risk=RiskLevel.MEDIUM,
        conditions=["使用 JWT 认证"],
        exploitation="alg:none/弱密钥爆破",
    ),

    AttackPattern(
        name="OAuth 配置错误",
        description="OAuth 2.0 配置错误",
        nodes=["oauth", "sso", "auth"],
        cves=[],
        risk=RiskLevel.MEDIUM,
        conditions=["使用 OAuth 2.0"],
        exploitation="redirect_uri 劫持/凭证泄漏",
    ),
]


def match_patterns(discovered_nodes: list[str]) -> list[tuple[AttackPattern, int]]:
    """
    根据发现的节点匹配攻击模式

    Returns:
        [(pattern, match_count), ...] 按匹配数倒序
    """
    matches = []
    for pattern in ATTACK_PATTERNS:
        count = pattern.match_count(discovered_nodes)
        if count > 0:
            matches.append((pattern, count))

    return sorted(matches, key=lambda x: x[1], reverse=True)


def get_top_patterns(discovered_nodes: list[str], top_k: int = 3) -> list[AttackPattern]:
    """获取最匹配的前 K 个攻击模式"""
    matches = match_patterns(discovered_nodes)
    return [p for p, _ in matches[:top_k] if _ > 0]
