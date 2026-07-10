"""
CVE 数据加载器
=============
从多种数据源加载 CVE 数据：

1. cve_monitor.db (13599 条) - 本地 SQLite
   - OSCS1024, NVD, Tenable, 等来源
2. Vulnerability-Wiki-PoC - 中文 PoC 目录
3. cve.org NVD API - 实时获取完整 NVD 数据

数据整合后输出标准化的 CVE 条目。
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# 默认路径
DEFAULT_CVE_MONITOR_DB = "~/.multi-cybersecurity/cve_monitor.db"
DEFAULT_OUTPUT_DB = "~/.multi-cybersecurity/cve.db"


@dataclass
class CVERecord:
    """标准化的 CVE 记录"""
    cve_id: str
    title: str
    description: str = ""
    cvss: float = 0.0
    cvss_vector: str = ""

    # 利用条件
    has_auth: bool = False  # 需要认证
    rce: bool = False  # 远程代码执行
    pre_auth: bool = True  # 预认证可利用

    # 来源信息
    source: str = ""
    detail_url: str = ""
    poc_path: str = ""  # PoC 路径 (如果有)

    # ATT&CK 映射
    mitre_attack_id: str = ""
    mitre_attack_name: str = ""

    # 附加数据
    affected_product: str = ""
    affected_version: str = ""
    published_date: str = ""
    modified_date: str = ""

    # 原始数据
    raw_data: dict = field(default_factory=dict)


class CVELoader:
    """
    CVE 数据加载器

    从多个数据源加载并整合 CVE 数据。
    """

    def __init__(
        self,
        cve_monitor_db: str = DEFAULT_CVE_MONITOR_DB,
        output_db: str = DEFAULT_OUTPUT_DB,
    ):
        self.cve_monitor_db = Path(cve_monitor_db).expanduser()
        self.output_db = Path(output_db).expanduser()
        self.output_db.parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._ensure_output_db()

    def _ensure_output_db(self):
        """初始化输出数据库"""
        conn = sqlite3.connect(str(self.output_db))
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_records (
                cve_id TEXT PRIMARY KEY,
                title TEXT,
                description TEXT,
                cvss REAL DEFAULT 0.0,
                cvss_vector TEXT,
                has_auth INTEGER DEFAULT 0,
                rce INTEGER DEFAULT 0,
                pre_auth INTEGER DEFAULT 1,
                source TEXT,
                detail_url TEXT,
                poc_path TEXT,
                mitre_attack_id TEXT,
                mitre_attack_name TEXT,
                affected_product TEXT,
                affected_version TEXT,
                published_date TEXT,
                modified_date TEXT,
                raw_data TEXT,
                updated_at TEXT
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cvss ON cve_records(cvss)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rce ON cve_records(rce)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_source ON cve_records(source)")

        conn.commit()
        conn.close()

    def load_from_cve_monitor(self) -> int:
        """
        从 cve_monitor 数据库加载 CVE 数据

        Returns:
            加载的记录数
        """
        if not self.cve_monitor_db.exists():
            logger.warning(f"cve_monitor.db not found: {self.cve_monitor_db}")
            return 0

        conn = sqlite3.connect(str(self.cve_monitor_db))
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM vulnerabilities LIMIT 10000")
        rows = cursor.fetchall()

        loaded = 0
        for row in rows:
            try:
                # 假设列: id, title, time, source, detail_url, cve_ids
                cve_id = row[0]
                title = row[1]
                time = row[2]
                source = row[3]
                detail_url = row[4]

                # 解析 CVE ID
                if not cve_id.startswith("CVE-"):
                    continue

                # 提取产品信息
                product = self._extract_product(title)

                record = CVERecord(
                    cve_id=cve_id,
                    title=title,
                    source=source or "OSCS",
                    detail_url=detail_url,
                    affected_product=product,
                    published_date=time,
                    raw_data={"source_row": str(row)},
                )

                self._upsert_record(record)
                loaded += 1

            except Exception as e:
                logger.debug(f"Failed to load row: {e}")
                continue

        conn.close()
        logger.info(f"Loaded {loaded} CVEs from cve_monitor")
        return loaded

    def _extract_product(self, title: str) -> str:
        """从标题提取受影响产品"""
        # 常见产品模式
        patterns = [
            r"(.+?)\s+CVE-\d+-\d+",
            r"(.+?)\s+\d+\.\d+\.\d+",
            r"^(Apache|Tomcat|Struts|Log4j|Nginx|WordPress|Jenkins|MongoDB|Redis)",
        ]

        for pattern in patterns:
            match = re.search(pattern, title, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        return title.split()[0] if title else ""

    def load_from_vulnerability_wiki(self, wiki_root: str) -> int:
        """
        从 Vulnerability-Wiki-PoC 目录加载 CVE + PoC 信息

        Args:
            wiki_root: Vulnerability-Wiki-PoC 根目录

        Returns:
            加载的记录数
        """
        wiki_path = Path(wiki_root)
        if not wiki_path.exists():
            logger.warning(f"Vulnerability-Wiki-PoC not found: {wiki_root}")
            return 0

        loaded = 0

        # 遍历所有年份目录
        for year_dir in wiki_path.iterdir():
            if not year_dir.is_dir():
                continue

            year = year_dir.name
            if not year.isdigit():
                continue

            # 遍历月份目录
            for month_dir in year_dir.iterdir():
                if not month_dir.is_dir():
                    continue

                # 遍历每个 CVE PoC 目录
                for poc_dir in month_dir.iterdir():
                    if not poc_dir.is_dir():
                        continue

                    try:
                        record = self._parse_poc_dir(poc_dir, year)
                        if record and record.cve_id:
                            self._upsert_record(record)
                            loaded += 1

                    except Exception as e:
                        logger.debug(f"Failed to parse {poc_dir}: {e}")
                        continue

        logger.info(f"Loaded {loaded} CVEs from Vulnerability-Wiki-PoC")
        return loaded

    def _parse_poc_dir(self, poc_dir: Path, year: str) -> Optional[CVERecord]:
        """解析 PoC 目录名"""
        dir_name = poc_dir.name

        # CVE ID 提取模式
        cve_match = re.search(r"CVE-(\d{4})-(\d+)", dir_name)
        if not cve_match:
            return None

        cve_id = f"CVE-{cve_match.group(1)}-{cve_match.group(2)}"

        # 提取漏洞类型
        vuln_type = self._infer_vuln_type(dir_name)

        # 推断利用难度 - 更全面的关键词
        dir_lower = dir_name.lower()
        rce_keywords = [
            "rce", "remote code execution", "code execution",
            "command injection", "arbitrary code", "arbitrary command",
            "远程代码执行", "远程命令执行", "命令执行", "命令注入",
        ]
        rce = any(kw in dir_lower for kw in rce_keywords)

        # 认证相关
        auth_keywords = [
            "auth", "login", "认证", "登录", "后台", "admin",
            "privilege", "权限", "未授权", "unauthorized", "bypass",
        ]
        has_auth = any(kw in dir_lower for kw in auth_keywords)

        return CVERecord(
            cve_id=cve_id,
            title=dir_name,
            description=f"{vuln_type}漏洞",
            rce=rce,
            has_auth=has_auth,
            pre_auth=not has_auth,
            source="Vulnerability-Wiki-PoC",
            poc_path=str(poc_dir),
            published_date=f"{year}-01-01",
        )

    def _infer_vuln_type(self, title: str) -> str:
        """推断漏洞类型"""
        title_lower = title.lower()

        if any(k in title_lower for k in ["sql注入", "sqli", "sql injection"]):
            return "SQL Injection"
        if any(k in title_lower for k in ["xss", "跨站脚本"]):
            return "XSS"
        if any(k in title_lower for k in ["rce", "远程代码执行", "命令执行"]):
            return "RCE"
        if any(k in title_lower for k in ["ssrf", "服务器端请求伪造"]):
            return "SSRF"
        if any(k in title_lower for k in ["文件包含", "file inclusion", "lfi", "rfi"]):
            return "File Inclusion"
        if any(k in title_lower for k in ["文件读取", "任意文件读取", "file read"]):
            return "File Read"
        if any(k in title_lower for k in ["命令注入", "command injection"]):
            return "Command Injection"
        if any(k in title_lower for k in ["认证绕过", "bypass", "权限绕过"]):
            return "Auth Bypass"
        if any(k in title_lower for k in ["信息泄露", "information disclosure"]):
            return "Info Disclosure"
        if any(k in title_lower for k in ["未授权", "unauthorized", "unauth"]):
            return "Unauthorized Access"

        return "Other"

    def _upsert_record(self, record: CVERecord):
        """插入或更新 CVE 记录"""
        with self._lock:
            conn = sqlite3.connect(str(self.output_db))
            cursor = conn.cursor()

            cursor.execute("""
                INSERT OR REPLACE INTO cve_records (
                    cve_id, title, description, cvss, cvss_vector,
                    has_auth, rce, pre_auth, source, detail_url, poc_path,
                    mitre_attack_id, mitre_attack_name,
                    affected_product, affected_version,
                    published_date, modified_date, raw_data, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.cve_id,
                record.title,
                record.description,
                record.cvss,
                record.cvss_vector,
                int(record.has_auth),
                int(record.rce),
                int(record.pre_auth),
                record.source,
                record.detail_url,
                record.poc_path,
                record.mitre_attack_id,
                record.mitre_attack_name,
                record.affected_product,
                record.affected_version,
                record.published_date,
                record.modified_date,
                json.dumps(record.raw_data),
                datetime.now().isoformat(),
            ))

            conn.commit()
            conn.close()

    def search(
        self,
        keyword: str = "",
        min_cvss: float = 0,
        has_rce: bool = None,
        pre_auth: bool = None,
        source: str = "",
        limit: int = 100,
    ) -> list[CVERecord]:
        """
        搜索 CVE 记录

        Args:
            keyword: 关键词
            min_cvss: 最低 CVSS 评分
            has_rce: 是否 RCE
            pre_auth: 是否预认证可利用
            source: 数据来源
            limit: 返回数量

        Returns:
            CVE 记录列表
        """
        conn = sqlite3.connect(str(self.output_db))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        sql_parts = ["SELECT * FROM cve_records WHERE 1=1"]
        params = []

        if keyword:
            sql_parts.append("AND (title LIKE ? OR description LIKE ? OR cve_id LIKE ?)")
            like = f"%{keyword}%"
            params.extend([like, like, like])

        if min_cvss > 0:
            sql_parts.append("AND cvss >= ?")
            params.append(min_cvss)

        if has_rce is not None:
            sql_parts.append("AND rce = ?")
            params.append(int(has_rce))

        if pre_auth is not None:
            sql_parts.append("AND pre_auth = ?")
            params.append(int(pre_auth))

        if source:
            sql_parts.append("AND source = ?")
            params.append(source)

        sql_parts.append("ORDER BY cvss DESC, cve_id DESC LIMIT ?")
        params.append(limit)

        cursor.execute(" ".join(sql_parts), params)
        rows = cursor.fetchall()
        conn.close()

        return [self._row_to_record(row) for row in rows]

    def get_by_cve_id(self, cve_id: str) -> Optional[CVERecord]:
        """根据 CVE ID 获取记录"""
        conn = sqlite3.connect(str(self.output_db))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM cve_records WHERE cve_id = ?", (cve_id,))
        row = cursor.fetchone()
        conn.close()

        return self._row_to_record(row) if row else None

    def get_stats(self) -> dict:
        """获取统计信息"""
        conn = sqlite3.connect(str(self.output_db))
        cursor = conn.cursor()

        stats = {}

        cursor.execute("SELECT COUNT(*) FROM cve_records")
        stats["total"] = cursor.fetchone()[0]

        cursor.execute("SELECT AVG(cvss) FROM cve_records WHERE cvss > 0")
        stats["avg_cvss"] = cursor.fetchone()[0] or 0

        cursor.execute("SELECT COUNT(*) FROM cve_records WHERE rce = 1")
        stats["rce_count"] = cursor.fetchone()[0]

        cursor.execute("SELECT source, COUNT(*) FROM cve_records GROUP BY source")
        stats["by_source"] = dict(cursor.fetchall())

        cursor.execute("SELECT COUNT(*) FROM cve_records WHERE poc_path != ''")
        stats["with_poc"] = cursor.fetchone()[0]

        conn.close()
        return stats

    def _row_to_record(self, row: sqlite3.Row) -> CVERecord:
        """将数据库行转换为 CVERecord"""
        return CVERecord(
            cve_id=row["cve_id"],
            title=row["title"] or "",
            description=row["description"] or "",
            cvss=row["cvss"] or 0,
            cvss_vector=row["cvss_vector"] or "",
            has_auth=bool(row["has_auth"]),
            rce=bool(row["rce"]),
            pre_auth=bool(row["pre_auth"]),
            source=row["source"] or "",
            detail_url=row["detail_url"] or "",
            poc_path=row["poc_path"] or "",
            mitre_attack_id=row["mitre_attack_id"] or "",
            mitre_attack_name=row["mitre_attack_name"] or "",
            affected_product=row["affected_product"] or "",
            affected_version=row["affected_version"] or "",
            published_date=row["published_date"] or "",
            modified_date=row["modified_date"] or "",
            raw_data=json.loads(row["raw_data"] or "{}"),
        )


# 全局单例
_loader: Optional[CVELoader] = None
_loader_lock = threading.Lock()


def get_cve_loader() -> CVELoader:
    """获取 CVE 加载器单例"""
    global _loader
    if _loader is None:
        with _loader_lock:
            if _loader is None:
                _loader = CVELoader()
    return _loader


def load_all_sources() -> dict:
    """
    从所有数据源加载 CVE 数据

    Returns:
        加载统计
    """
    loader = get_cve_loader()
    stats = {}

    # 1. 从 cve_monitor 加载
    stats["cve_monitor"] = loader.load_from_cve_monitor()

    # 2. 从 Vulnerability-Wiki-PoC 加载 (如果存在)
    wiki_paths = [
        "D:/code_tmp/multi-CyberSecurity/external/Vulnerability-Wiki-PoC",
        os.path.expanduser("~/Vulnerability-Wiki-PoC"),
    ]

    for wiki_path in wiki_paths:
        if os.path.exists(wiki_path):
            stats["vulnerability_wiki"] = loader.load_from_vulnerability_wiki(wiki_path)
            break

    # 3. 合并统计
    stats["total_in_db"] = loader.get_stats()["total"]

    return stats
