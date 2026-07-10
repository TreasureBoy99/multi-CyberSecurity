"""
NVD API 客户端
================
从 NIST NVD 获取完整 CVE 数据 (CVSS, CWE, CPE)

API 文档: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

# NVD API 配置
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # 注意: 2.0 不是 2

# 请求限制 (NVD API: 10 秒 5 个请求，有 API key 可 10 秒 50 个)
REQUEST_INTERVAL = 2.0  # 秒
REQUEST_INTERVAL_WITH_KEY = 0.5  # 有 API key 时


@dataclass
class NVDCVERecord:
    """NVD CVE 完整记录"""
    cve_id: str
    source_identifier: str = ""
    published: str = ""
    last_modified: str = ""
    vuln_status: str = ""

    # 描述
    descriptions: list[dict] = field(default_factory=list)  # [{"lang": "en", "value": "..."}]

    # 度量
    metrics: dict = field(default_factory=dict)
    # {
    #   "cvssMetricV31": [{"cvssData": {...}, ...],
    #   "cvssMetricV2": [...],
    # }

    # CWE
    weaknesses: list[dict] = field(default_factory=list)
    # [{"description": [{"lang": "en", "value": "CWE-79"}]}]

    # CPE
    configurations: list[dict] = field(default_factory=list)

    # references
    references: list[dict] = field(default_factory=list)

    # 原始数据
    raw_data: dict = field(default_factory=dict)


@dataclass
class CVSSData:
    """CVSS 评分数据"""
    version: str = ""  # "3.1", "3.0", "2.0"
    vector_string: str = ""
    attack_vector: str = ""
    attack_complexity: str = ""
    privileges_required: str = ""
    user_interaction: str = ""
    scope: str = ""
    confidentiality_impact: str = ""
    integrity_impact: str = ""
    availability_impact: str = ""
    base_score: float = 0.0
    base_severity: str = ""  # LOW, MEDIUM, HIGH, CRITICAL


class NVDClient:
    """
    NVD API 客户端

    功能:
    - CVE ID 查询
    - 批量更新 CVSS 评分
    - CWE 映射
    """

    def __init__(self, api_key: str = NVD_API_KEY, db_path: str = "~/.multi-cybersecurity/cve.db"):
        self.api_key = api_key or NVD_API_KEY
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._request_count = 0
        self._last_request_time = 0.0

    def _get_headers(self) -> dict:
        """获取请求头"""
        headers = {
            "Accept": "application/json",
            "User-Agent": "multi-cybersecurity-cve-client/1.0",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _rate_limit(self):
        """速率限制"""
        interval = REQUEST_INTERVAL_WITH_KEY if self.api_key else REQUEST_INTERVAL
        elapsed = time.time() - self._last_request_time
        if elapsed < interval:
            time.sleep(interval - elapsed)
        self._last_request_time = time.time()
        self._request_count += 1

    def fetch_cve_by_id(self, cve_id: str) -> Optional[NVDCVERecord]:
        """
        根据 CVE ID 获取完整信息

        Args:
            cve_id: CVE ID (如 "CVE-2021-44228")

        Returns:
            NVDCVERecord 或 None
        """
        self._rate_limit()

        url = f"{NVD_BASE_URL}?cveId={cve_id}"

        try:
            req = urllib.request.Request(url, headers=self._get_headers())
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None

            vuln = vulnerabilities[0].get("cve", {})
            return self._parse_cve(vuln)

        except urllib.error.HTTPError as e:
            logger.warning(f"NVD API HTTP error for {cve_id}: {e.code} {e.reason}")
            return None
        except Exception as e:
            logger.error(f"NVD API error for {cve_id}: {e}")
            return None

    def fetch_cvss_for_cves(self, cve_ids: list[str]) -> dict[str, CVSSData]:
        """
        批量获取 CVSS 评分

        Args:
            cve_ids: CVE ID 列表

        Returns:
            {cve_id: CVSSData}
        """
        results = {}

        for cve_id in cve_ids:
            record = self.fetch_cve_by_id(cve_id)
            if record:
                cvss = self._extract_cvss(record)
                if cvss:
                    results[cve_id] = cvss

        return results

    def update_cvss_in_db(self, cve_ids: Optional[list[str]] = None, limit: int = 100) -> int:
        """
        更新数据库中 CVE 的 CVSS 数据

        Args:
            cve_ids: 要更新的 CVE ID 列表，None 表示更新所有
            limit: 限制更新数量

        Returns:
            更新的数量
        """
        import sqlite3

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # 获取需要更新的 CVE
        if cve_ids:
            placeholders = ",".join("?" * len(cve_ids))
            cursor.execute(f"""
                SELECT cve_id FROM cve_records
                WHERE cve_id IN ({placeholders})
                AND cvss = 0
                ORDER BY cve_id DESC
                LIMIT ?
            """, (*cve_ids, limit))
        else:
            cursor.execute("""
                SELECT cve_id FROM cve_records
                WHERE cvss = 0
                ORDER BY cve_id DESC
                LIMIT ?
            """, (limit,))

        rows = cursor.fetchall()
        cve_ids_to_fetch = [row[0] for row in rows]
        conn.close()

        if not cve_ids_to_fetch:
            logger.info("No CVEs need CVSS update")
            return 0

        logger.info(f"Updating CVSS for {len(cve_ids_to_fetch)} CVEs...")

        updated = 0
        for cve_id in cve_ids_to_fetch:
            record = self.fetch_cve_by_id(cve_id)
            if record:
                cvss = self._extract_cvss(record)
                if cvss:
                    self._update_cvss_in_db(cve_id, cvss)
                    updated += 1

        return updated

    def _update_cvss_in_db(self, cve_id: str, cvss: CVSSData):
        """更新数据库中的 CVSS 数据"""
        import sqlite3

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE cve_records
            SET cvss = ?, cvss_vector = ?, updated_at = ?
            WHERE cve_id = ?
        """, (cvss.base_score, cvss.vector_string, datetime.now().isoformat(), cve_id))

        conn.commit()
        conn.close()

    def _extract_cvss(self, record: NVDCVERecord) -> Optional[CVSSData]:
        """从 NVD 记录提取 CVSS 数据"""
        metrics = record.metrics or {}

        # 优先使用 CVSS 3.1, 其次 3.0, 最后 2.0
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                metric = metrics[version][0]
                cvss_data = metric.get("cvssData", {})
                if cvss_data:
                    return CVSSData(
                        version=cvss_data.get("version", ""),
                        vector_string=cvss_data.get("vectorString", ""),
                        attack_vector=cvss_data.get("attackVector", ""),
                        attack_complexity=cvss_data.get("attackComplexity", ""),
                        privileges_required=cvss_data.get("privilegesRequired", ""),
                        user_interaction=cvss_data.get("userInteraction", ""),
                        scope=cvss_data.get("scope", ""),
                        confidentiality_impact=cvss_data.get("confidentialityImpact", ""),
                        integrity_impact=cvss_data.get("integrityImpact", ""),
                        availability_impact=cvss_data.get("availabilityImpact", ""),
                        base_score=cvss_data.get("baseScore", 0.0),
                        base_severity=cvss_data.get("baseSeverity", ""),
                    )

        return None

    def _parse_cve(self, vuln: dict) -> NVDCVERecord:
        """解析 NVD CVE 响应"""
        return NVDCVERecord(
            cve_id=vuln.get("id", ""),
            source_identifier=vuln.get("sourceIdentifier", ""),
            published=vuln.get("published", ""),
            last_modified=vuln.get("lastModified", ""),
            vuln_status=vuln.get("vulnStatus", ""),
            descriptions=vuln.get("descriptions", []),
            metrics=vuln.get("metrics", {}),
            weaknesses=vuln.get("weaknesses", []),
            configurations=vuln.get("configurations", []),
            references=vuln.get("references", []),
            raw_data=vuln,  # 保留原始数据
        )


def enrich_cvss_batch(cve_ids: Optional[list[str]] = None, limit: int = 500) -> dict:
    """
    批量从 NVD 补充 CVSS 数据

    Args:
        cve_ids: 指定 CVE ID 列表，None 表示更新所有缺 CVSS 的
        limit: 最大更新数量

    Returns:
        {"updated": N, "failed": M, "total": K}
    """
    client = NVDClient()

    updated = client.update_cvss_in_db(cve_ids, limit)

    return {"updated": updated, "limit": limit}


if __name__ == "__main__":
    # 测试
    client = NVDClient()
    record = client.fetch_cve_by_id("CVE-2021-44228")
    if record:
        print(f"CVE: {record.cve_id}")
        print(f"Published: {record.published}")
        cvss = client._extract_cvss(record)
        if cvss:
            print(f"CVSS: {cvss.base_score} ({cvss.base_severity})")
            print(f"Vector: {cvss.vector_string}")
    else:
        print("Not found")
