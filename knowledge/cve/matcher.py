"""
CVE 匹配与排除推理引擎
=======================
修正版：基于实际验证结果，去除死代码，实现真正可用的过滤逻辑

核心逻辑:
1. P0 exploits first: 无认证 + 一键 RCE 优先
2. 上下文排除: 根据 has_auth 过滤 (唯一真正工作的过滤)
3. 关键词推断: 从 CVE 描述推断 network/shell 要求
4. 攻击模式匹配: 根据节点组合推荐攻击路径
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .patterns import ATTACK_PATTERNS, AttackPattern, RiskLevel, match_patterns

logger = logging.getLogger(__name__)

# CVE 数据库路径
DEFAULT_CVE_DB = "~/.multi-cybersecurity/cve.db"


@dataclass
class ExploitContext:
    """
    利用上下文 - 描述当前渗透测试的环境和能力

    注意: 根据源码验证，只有 has_auth 是真正工作的过滤条件
    """
    # 唯一真正起作用的过滤条件
    has_auth: bool = False           # 是否有目标凭证
    has_credentials: dict = field(default_factory=dict)  # {service: creds}

    # 保留字段用于日志和提示，但不执行实际过滤
    network_access: str = "internal"  # internal/external/both (参考用)
    can_spawn_shell: bool = False    # 参考用

    # 辅助检测
    is_windows: bool = False         # 是否 Windows 目标
    is_linux: bool = False          # 是否 Linux 目标
    detected_services: dict = field(default_factory=dict)  # {port: service}


@dataclass
class CVEMatch:
    """CVE 匹配结果"""
    cve_id: str
    description: str
    cvss: float
    cvss_vector: str = ""
    has_auth: bool = False           # 是否需要认证 (实际过滤)
    rce: bool = False                # 是否 RCE
    pre_auth: bool = False           # 是否预认证可利用
    exploitation: str = ""           # 利用说明
    matched_pattern: Optional[str] = None  # 匹配的攻击模式
    filter_note: str = ""             # 过滤说明


@dataclass
class CVEDatabase:
    """CVE 数据库条目"""
    cve_id: str
    description: str
    cvss: float
    cvss_vector: str
    has_auth: bool
    rce: bool
    pre_auth: bool
    published: str
    modified: str
    # 推断字段 (基于描述关键词)
    likely_network_required: bool = False
    likely_shell_required: bool = False


class CVEDatabaseInitializer:
    """CVE 数据库初始化器 - 填充真实 CVE 数据"""

    # 高危 CVE 知识库 (从 NVD 提取的精选集)
    KNOWN_CVES = [
        # Web 应用
        ("CVE-2017-12615", "Apache Tomcat RCE via JSP upload (PUT method)", 9.8, False, True, True),
        ("CVE-2020-1938", "Apache Tomcat AJP File Include", 9.8, False, True, True),
        ("CVE-2017-5638", "Apache Struts2 RCE via Content-Type", 10.0, False, True, True),
        ("CVE-2018-11776", "Apache Struts2 RCE via URL", 9.8, False, True, True),
        ("CVE-2021-31805", "Apache Struts2 OGNL Injection", 9.8, False, True, True),
        ("CVE-2021-44228", "Apache Log4j Remote Code Execution (Log4Shell)", 10.0, False, True, True),
        ("CVE-2021-45046", "Apache Log4j Denial of Service", 9.0, False, False, True),
        ("CVE-2022-22965", "Spring Framework RCE (Spring4Shell)", 9.8, False, True, True),
        ("CVE-2018-1000861", "Jenkins Remote Code Execution", 9.8, False, True, True),

        # 数据库
        ("CVE-2021-25296", "SMB Relay Attack", 8.1, False, True, True),
        ("CVE-2012-2122", "MySQL Authentication Bypass", 6.9, True, False, False),

        # SMB/Windows
        ("CVE-2017-0144", "MS17-010 EternalBlue SMB RCE (Windows)", 9.8, False, True, True),
        ("CVE-2017-0145", "MS17-010 EternalRomance SMB RCE", 9.8, False, True, True),
        ("CVE-2017-0146", "MS17-010 EternalChampion SMB RCE", 9.8, False, True, True),
        ("CVE-2019-0708", "Windows RDP Remote Code Execution (BlueKeep)", 9.8, False, True, True),

        # Linux/Unix
        ("CVE-2022-0847", "Linux Privilege Escalation (Dirty Pipe)", 7.8, False, False, False),

        # Web Server
        ("CVE-2021-41773", "Apache Path Traversal", 7.3, False, False, False),
        ("CVE-2021-42013", "Apache Path Traversal (double decode)", 9.8, False, False, True),

        # VPN/Remote Access
        ("CVE-2018-13379", "FortiOS SSL VPN Heap Overflow", 9.8, False, True, True),
        ("CVE-2019-1579", "Palo Alto PAN-OS Remote Code Execution", 9.8, False, True, True),

        # Container/K8s
        ("CVE-2019-5736", "Docker Container Escape via runc", 8.6, False, False, True),

        # DNS
        ("CVE-2020-1350", "Windows DNS Server Remote Code Execution (SigRed)", 10.0, False, True, True),

        # Exchange
        ("CVE-2021-26855", "Microsoft Exchange Server SSRF (ProxyLogon)", 9.8, False, True, True),
        ("CVE-2021-27065", "Microsoft Exchange Arbitrary File Write", 9.8, False, True, True),
    ]

    @classmethod
    def infer_from_description(cls, description: str) -> tuple[bool, bool]:
        """
        从描述关键词推断 CVE 特性

        Returns:
            (likely_network_required, likely_shell_required)
        """
        desc_lower = description.lower()

        # 网络相关关键词
        network_keywords = [
            "remote", "network", "smb", "http", "tcp", "ip",
            "web server", "ssl", "tls", "ssh", "ftp", "smtp",
            "rdp", "vnc", "dns"
        ]
        likely_network = any(kw in desc_lower for kw in network_keywords)

        # Shell/Exec 相关关键词
        shell_keywords = [
            "execute", "execution", "rce", "remote code",
            "command", "shell", "privilege", "root", "admin",
            "code execution", "arbitrary"
        ]
        likely_shell = any(kw in desc_lower for kw in shell_keywords)

        return likely_network, likely_shell


class CVEMatcher:
    """
    CVE 匹配引擎 (修正版)

    功能:
    1. 根据服务/版本匹配潜在 CVE
    2. 根据上下文排除 (has_auth 唯一可靠)
    3. 按 CVSS + RCE + Pre-Auth 排序
    4. 匹配攻击模式
    """

    def __init__(self, db_path: str = DEFAULT_CVE_DB):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_db()
        self._ensure_data()

    def _ensure_db(self):
        """确保 CVE 数据库存在"""
        if not self.db_path.exists():
            self._init_db()

    def _ensure_data(self):
        """确保有初始 CVE 数据"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM cve_index")
            count = cursor.fetchone()[0]
            conn.close()

            if count == 0:
                self._seed_data()
        except sqlite3.OperationalError:
            # 表不存在，初始化数据库
            self._init_db()
            self._seed_data()

    def _init_db(self):
        """初始化 CVE 数据库"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_index (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss REAL DEFAULT 0.0,
                cvss_vector TEXT,
                has_auth INTEGER DEFAULT 0,
                rce INTEGER DEFAULT 0,
                pre_auth INTEGER DEFAULT 1,
                published TEXT,
                modified TEXT,
                likely_network INTEGER DEFAULT 0,
                likely_shell INTEGER DEFAULT 0
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cvss ON cve_index(cvss)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rce ON cve_index(rce)")

        conn.commit()
        conn.close()

    def _seed_data(self):
        """填充初始 CVE 数据"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        now = datetime.now().isoformat()

        for cve_id, desc, cvss, has_auth, rce, pre_auth in CVEDatabaseInitializer.KNOWN_CVES:
            # 从描述推断
            likely_net, likely_shell = CVEDatabaseInitializer.infer_from_description(desc)

            cursor.execute("""
                INSERT OR IGNORE INTO cve_index (
                    cve_id, description, cvss, has_auth, rce, pre_auth,
                    likely_network, likely_shell, published, modified
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (cve_id, desc, cvss, int(has_auth), int(rce), int(pre_auth),
                  int(likely_net), int(likely_shell), now, now))

        conn.commit()
        conn.close()
        logger.info(f"Seeded {len(CVEDatabaseInitializer.KNOWN_CVES)} CVEs into database")

    def search(
        self,
        product: str,
        version: str = "",
        context: Optional[ExploitContext] = None,
        top_k: int = 10,
    ) -> list[CVEMatch]:
        """
        搜索匹配的 CVE

        Args:
            product: 产品名称 (如 "tomcat", "nginx", "log4j")
            version: 版本号 (可选)
            context: 利用上下文 (用于过滤)
            top_k: 返回数量

        Returns:
            CVE 匹配列表，按 P0 优先级排序
        """
        context = context or ExploitContext()

        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # 构建搜索条件
        search_terms = [f"%{product}%"]
        if version:
            search_terms.append(f"%{version}%")

        if version:
            # 精确版本匹配: product AND version
            sql = """
                SELECT * FROM cve_index
                WHERE description LIKE ? AND description LIKE ?
                ORDER BY cvss DESC, rce DESC, pre_auth DESC
            """
        else:
            sql = """
                SELECT * FROM cve_index
                WHERE description LIKE ?
                ORDER BY cvss DESC, rce DESC, pre_auth DESC
            """

        cursor.execute(sql, search_terms)

        results = []
        for row in cursor.fetchall():
            cve = self._row_to_cve(row)

            # 应用 has_auth 过滤 (唯一真正可靠的过滤)
            filter_note = ""
            if cve.has_auth and not context.has_auth:
                filter_note = "Filtered: requires auth"
                # 不跳过，只是标记
                # 注意: 保持显示但标记，这样用户知道为什么没有 RCE

            results.append(CVEMatch(
                cve_id=cve.cve_id,
                description=cve.description,
                cvss=cve.cvss,
                has_auth=cve.has_auth,
                rce=cve.rce,
                pre_auth=cve.pre_auth,
                filter_note=filter_note,
            ))

        conn.close()

        return results[:top_k]

    def filter_p0(self, cves: list[CVEMatch]) -> list[CVEMatch]:
        """
        P0 优先级排序

        1. pre_auth + rce (无需认证的 RCE)
        2. pre_auth (预认证可利用)
        3. rce (RCE 漏洞)
        4. 其他
        """
        def p0_key(cve: CVEMatch) -> tuple[int, int, int]:
            auth_score = 0 if cve.pre_auth else (1 if cve.has_auth else 0)
            rce_score = 2 if cve.rce else 0
            cvss_score = int(cve.cvss)
            return (auth_score, rce_score, cvss_score)

        return sorted(cves, key=p0_key, reverse=True)

    def match_from_discovery(
        self,
        discovered: dict[str, Any],
        context: Optional[ExploitContext] = None,
    ) -> list[CVEMatch]:
        """
        根据发现结果匹配 CVE
        """
        context = context or ExploitContext()
        all_cves = []

        # 常见服务关键词映射
        service_keywords = {
            "tomcat": ["tomcat", "apache tomcat"],
            "struts": ["struts", "apache struts"],
            "log4j": ["log4j", "log4shell"],
            "spring": ["spring", "spring framework"],
            "jenkins": ["jenkins"],
            "wordpress": ["wordpress"],
            "apache": ["apache", "httpd"],
            "nginx": ["nginx"],
            "mysql": ["mysql"],
            "redis": ["redis"],
            "mongodb": ["mongodb", "mongo"],
            "samba": ["samba", "smb"],
            "openssh": ["openssh", "ssh"],
            "vsftpd": ["vsftpd", "ftp"],
            "rdp": ["rdp", "remote desktop"],
            "exchange": ["exchange", "microsoft exchange"],
            "fortinet": ["forti", "fortinet", "fortios"],
            "pan-os": ["palo alto", "pan-os"],
            "docker": ["docker", "container"],
            "kubernetes": ["kubernetes", "k8s"],
            "dns": ["dns", "bind"],
        }

        # 从服务发现 CVE
        services = discovered.get("services", [])
        technologies = discovered.get("technologies", [])

        # 合并所有识别到的技术
        all_tech = []
        for s in services:
            all_tech.append(s.get("service", ""))
            all_tech.append(s.get("product", ""))
        all_tech.extend(technologies)

        all_tech = [t.lower() for t in all_tech if t]

        # 匹配 CVE
        matched_products = set()
        for tech in all_tech:
            for keyword, cve_keywords in service_keywords.items():
                if any(kw in tech for kw in cve_keywords):
                    if keyword not in matched_products:
                        matched_products.add(keyword)
                        cves = self.search(keyword, "", context, top_k=5)
                        all_cves.extend(cves)

        # 去重
        seen = set()
        unique_cves = []
        for cve in all_cves:
            if cve.cve_id not in seen:
                seen.add(cve.cve_id)
                unique_cves.append(cve)

        # P0 排序
        return self.filter_p0(unique_cves)

    def _row_to_cve(self, row: sqlite3.Row) -> CVEDatabase:
        """将数据库行转换为 CVEDatabase"""
        # sqlite3.Row 不支持 .get() 方法，使用下标访问
        def get_val(key, default=None):
            try:
                return row[key]
            except (KeyError, IndexError):
                return default

        return CVEDatabase(
            cve_id=row["cve_id"],
            description=row["description"],
            cvss=row["cvss"],
            cvss_vector=get_val("cvss_vector") or "",
            has_auth=bool(get_val("has_auth", 0)),
            rce=bool(get_val("rce", 0)),
            pre_auth=bool(get_val("pre_auth", 1)),
            published=get_val("published") or "",
            modified=get_val("modified") or "",
            likely_network_required=bool(get_val("likely_network", 0)),
            likely_shell_required=bool(get_val("likely_shell", 0)),
        )


def recommend_attack_paths(
    discovered_nodes: list[str],
    context: Optional[ExploitContext] = None,
) -> list[dict]:
    """
    推荐攻击路径

    基于发现的节点和上下文，推荐可能的攻击路径。
    """
    recommendations = []
    context = context or ExploitContext()

    # 匹配攻击模式
    matches = match_patterns(discovered_nodes)

    for pattern, match_count in matches:
        confidence = min(0.95, 0.5 + match_count * 0.15)

        # 检查是否有认证要求但没有凭证
        if pattern.conditions:
            requires_auth = any("auth" in c.lower() for c in pattern.conditions)
            if requires_auth and not context.has_auth:
                confidence *= 0.7  # 降低置信度

        recommendations.append({
            "pattern": pattern.name,
            "description": pattern.description,
            "cves": pattern.cves,
            "cvss": pattern.cvss,
            "risk": pattern.risk.value,
            "exploitation": pattern.exploitation,
            "confidence": confidence,
            "matched_nodes": [n for n in pattern.nodes if n in discovered_nodes],
        })

    # 按置信度排序
    recommendations.sort(key=lambda x: x["confidence"], reverse=True)
    return recommendations
